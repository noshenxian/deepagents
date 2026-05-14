"""Custom tools for the security analysis agent.

The agent already has shell access (`execute`), filesystem tools (`read_file`,
`grep`, `glob`), and todo planning. These tools fill the gaps:

- `osv_query`: Query OSV.dev for known vulnerabilities in a package.
- `secret_pattern_scan`: Regex-match common credential patterns in a string.
- `cvss_severity`: Map a CVSS base score to a severity label.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

OSV_API = "https://api.osv.dev/v1/query"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
MAX_SCAN_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "dist", "build"}
TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".env",
    ".go",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_access_key": re.compile(
        r"(?i)aws.{0,20}?[\"']([0-9a-zA-Z/+]{40})[\"']"
    ),
    "github_pat": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "github_fine_grained_pat": re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    "github_oauth": re.compile(r"gho_[A-Za-z0-9]{36}"),
    "openai_api_key": re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"),
    "openai_project_api_key": re.compile(r"sk-proj-[A-Za-z0-9_-]{24,}"),
    "openai_service_account_key": re.compile(r"sk-svcacct-[A-Za-z0-9_-]{24,}"),
    "anthropic_api_key": re.compile(r"sk-ant-[A-Za-z0-9_\-]{40,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    ),
    "jwt": re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    ),
    "generic_password": re.compile(
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']"
    ),
    "generic_secret": re.compile(
        r"(?i)(?:secret|token|api[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']"
    ),
}

STATIC_PATTERNS: dict[str, tuple[re.Pattern[str], str, str]] = {
    "python_eval": (
        re.compile(r"\beval\s*\("),
        "High",
        "Python dynamic code execution",
    ),
    "python_exec": (
        re.compile(r"\bexec\s*\("),
        "High",
        "Python dynamic code execution",
    ),
    "python_pickle_loads": (
        re.compile(r"\bpickle\.loads\s*\("),
        "High",
        "Python unsafe deserialization",
    ),
    "python_yaml_load": (
        re.compile(r"\byaml\.load\s*\((?![^)]*SafeLoader)"),
        "High",
        "Python unsafe YAML loading",
    ),
    "python_subprocess_shell_true": (
        re.compile(r"\bsubprocess\.[\w_]+\s*\([^)]*shell\s*=\s*True"),
        "High",
        "Shell command execution with shell=True",
    ),
    "js_inner_html": (
        re.compile(r"\.innerHTML\s*="),
        "Medium",
        "DOM assignment may introduce XSS",
    ),
    "react_dangerously_set_inner_html": (
        re.compile(r"dangerouslySetInnerHTML"),
        "Medium",
        "Raw HTML rendering may introduce XSS",
    ),
}

PYTHON_PACKAGE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|>|<=|<)\s*([A-Za-z0-9_.!*+-]+)"
)


def _redact_secret(text: str) -> str:
    """Redact a matched secret while preserving enough shape for review."""
    if len(text) <= 12:
        return "<short-match>"
    return f"{text[:6]}...{text[-4:]}"


def _iter_text_files(target_path: str) -> Iterator[Path]:
    """Yield likely text files under a target path, skipping noisy directories."""
    root = Path(target_path).expanduser().resolve()
    if root.is_file():
        if _is_text_candidate(root):
            yield root
        return
    if not root.exists():
        return

    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and _is_text_candidate(path):
            yield path


def _is_text_candidate(path: Path) -> bool:
    """Return whether a file should be scanned as text."""
    if path.name.startswith(".env"):
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def _read_scan_text(path: Path) -> str | None:
    """Read a bounded text file for scanning."""
    try:
        if path.stat().st_size > MAX_SCAN_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _finding(
    *,
    rule_id: str,
    severity: str,
    file: Path,
    line: int,
    evidence: str,
    message: str,
    confidence: str = "high",
) -> dict[str, object]:
    """Build the shared finding shape returned by scanner tools."""
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": str(file),
        "line": line,
        "evidence": evidence,
        "message": message,
        "confidence": confidence,
    }


def _json_findings(findings: list[dict[str, object]]) -> str:
    """Serialize findings in a stable JSON envelope."""
    return json.dumps({"findings": findings}, indent=2, sort_keys=True)


def _json_dependencies(dependencies: list[dict[str, str]]) -> str:
    """Serialize dependency records in a stable JSON envelope."""
    return json.dumps({"dependencies": dependencies}, indent=2, sort_keys=True)


def _json_poc_intel(payload: dict[str, object]) -> str:
    """Serialize POC intelligence in a stable JSON envelope."""
    return json.dumps(payload, indent=2, sort_keys=True)


def _dependency(
    *,
    name: str,
    version: str,
    ecosystem: str,
    manifest: Path,
    source: str,
) -> dict[str, str]:
    """Build the shared dependency shape returned by manifest scans."""
    return {
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "manifest": str(manifest),
        "source": source,
    }


def _parse_python_requirement_line(line: str) -> tuple[str, str] | None:
    """Parse a pinned or lower-bounded Python requirement line."""
    requirement = line.split("#", 1)[0].strip()
    if not requirement or requirement.startswith(("-e ", "--", ".")):
        return None
    requirement = requirement.split(";", 1)[0].strip()
    requirement = re.sub(r"\[[^\]]+\]", "", requirement)
    match = PYTHON_PACKAGE_RE.match(requirement)
    if not match:
        return None
    return match.group(1), match.group(2)


def _parse_requirements_file(path: Path) -> list[dict[str, str]]:
    """Parse a `requirements*.txt` file into dependency records."""
    content = _read_scan_text(path)
    if content is None:
        return []
    dependencies: list[dict[str, str]] = []
    for line in content.splitlines():
        parsed = _parse_python_requirement_line(line)
        if parsed is None:
            continue
        name, version = parsed
        dependencies.append(
            _dependency(
                name=name,
                version=version,
                ecosystem="PyPI",
                manifest=path,
                source=path.name,
            )
        )
    return dependencies


def _parse_pyproject_file(path: Path) -> list[dict[str, str]]:
    """Parse direct `[project].dependencies` from `pyproject.toml`."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    raw_dependencies = data.get("project", {}).get("dependencies", [])
    if not isinstance(raw_dependencies, list):
        return []
    dependencies: list[dict[str, str]] = []
    for raw in raw_dependencies:
        if not isinstance(raw, str):
            continue
        parsed = _parse_python_requirement_line(raw)
        if parsed is None:
            continue
        name, version = parsed
        dependencies.append(
            _dependency(
                name=name,
                version=version,
                ecosystem="PyPI",
                manifest=path,
                source=path.name,
            )
        )
    return dependencies


def _classify_poc_url(url: str) -> dict[str, str]:
    """Classify an external vulnerability reference URL."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if "projectdiscovery" in path and "nuclei-templates" in path:
        return {
            "source": "nuclei-templates",
            "kind": "nuclei_template",
            "trust": "medium_high",
            "execution_risk": "network_probe",
            "summary": "Public nuclei template candidate",
        }
    if "metasploit-framework" in path:
        return {
            "source": "metasploit",
            "kind": "metasploit_module",
            "trust": "medium_high",
            "execution_risk": "exploit_framework",
            "summary": "Metasploit module reference",
        }
    if "exploit-db.com" in host:
        return {
            "source": "exploit-db",
            "kind": "exploit_db",
            "trust": "medium",
            "execution_risk": "untrusted_code",
            "summary": "Exploit-DB public exploit reference",
        }
    if "github.com" in host:
        return {
            "source": "github",
            "kind": "github_poc",
            "trust": "low",
            "execution_risk": "untrusted_code",
            "summary": "GitHub public repository reference",
        }
    if any(name in host for name in ("nist.gov", "osv.dev", "github.com/advisories")):
        return {
            "source": "advisory",
            "kind": "reference",
            "trust": "high",
            "execution_risk": "none",
            "summary": "Advisory reference",
        }
    return {
        "source": "vendor",
        "kind": "vendor_advisory",
        "trust": "high",
        "execution_risk": "none",
        "summary": "Vendor or project advisory reference",
    }


def _candidate_from_url(url: str) -> dict[str, str]:
    """Build a normalized POC candidate from a URL."""
    classification = _classify_poc_url(url)
    return {
        **classification,
        "url": url,
        "execution_status": "not_run",
    }


def _safe_artifact_id(raw: str) -> str:
    """Convert a CVE or query label into a filesystem-safe artifact id."""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw.strip()).strip("-")
    return safe or "poc-intel"


@tool(parse_docstring=True)
def osv_query(package: str, version: str, ecosystem: str) -> str:
    """Query OSV.dev for known vulnerabilities affecting a package version.

    Use after parsing a dependency manifest (requirements.txt, package.json,
    Cargo.toml, go.mod). Free, no auth required.

    Args:
        package: Package name as listed in the ecosystem (e.g., "django", "lodash").
        version: Exact version string (e.g., "4.2.1"). Do not pass version ranges.
        ecosystem: One of "PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io",
            "Packagist", "NuGet", "Hex".

    Returns:
        A summary of vulnerabilities (id, summary, severity, fixed versions),
        or "no vulnerabilities found" when the package/version is clean.
    """
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }
    try:
        resp = httpx.post(OSV_API, json=payload, timeout=15.0)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        return f"OSV query failed for {package}@{version}: {exc}"

    data = resp.json()
    vulns = data.get("vulns", []) or []
    if not vulns:
        return f"No vulnerabilities found for {package}@{version} in {ecosystem}."

    lines: list[str] = [f"{len(vulns)} vulnerability/ies for {package}@{version}:\n"]
    for v in vulns:
        vid = v.get("id", "<no-id>")
        summary = (v.get("summary") or v.get("details") or "").strip().splitlines()[:2]
        summary_str = " ".join(summary)[:300]
        sev = ""
        for s in v.get("severity") or []:
            sev = f" [{s.get('type', '')}={s.get('score', '')}]"
            break
        fixed: list[str] = []
        for aff in v.get("affected") or []:
            for r in aff.get("ranges") or []:
                for ev in r.get("events") or []:
                    if "fixed" in ev:
                        fixed.append(ev["fixed"])
        fixed_str = f" (fixed in: {', '.join(sorted(set(fixed)))})" if fixed else ""
        lines.append(f"- {vid}{sev}{fixed_str}: {summary_str}")
    return "\n".join(lines)


@tool(parse_docstring=True)
def secret_pattern_scan(content: str) -> str:
    """Scan a string for hardcoded credentials using a curated pattern set.

    Designed to run on the contents of a single file (read it via `read_file` first)
    or a small snippet. For large codebase sweeps, use `grep` with provider-specific
    regexes instead; this tool is for confirming a suspicious chunk.

    Patterns covered: AWS keys, GitHub PAT/OAuth, OpenAI/Anthropic/Google API keys,
    Slack tokens, private keys (RSA/EC/DSA/OpenSSH/PGP), JWTs, and generic
    `password=`/`secret=` assignments.

    Args:
        content: Text to scan. Pass raw file content; do not pre-process.

    Returns:
        A list of matches with the pattern name and a redacted snippet, or
        "no matches" when nothing fires.
    """
    if not content:
        return "no matches (empty input)"
    findings: list[str] = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            text = match.group(0)
            redacted = text[:6] + "…" + text[-4:] if len(text) > 12 else "<short-match>"
            line_no = content.count("\n", 0, match.start()) + 1
            findings.append(f"- {name} @ line {line_no}: {redacted}")
    if not findings:
        return "no matches"
    return f"{len(findings)} potential secret(s):\n" + "\n".join(findings)


@tool(parse_docstring=True)
def secret_path_scan(target_path: str) -> str:
    """Scan a file or directory for hardcoded credentials.

    This deterministic scanner walks likely text files, skips dependency/build
    directories, applies the curated `SECRET_PATTERNS`, and returns structured
    JSON findings with redacted evidence.

    Args:
        target_path: File or directory to scan.

    Returns:
        JSON object with a `findings` list. Each finding has `rule_id`,
        `severity`, `file`, `line`, `evidence`, `message`, and `confidence`.
    """
    findings: list[dict[str, object]] = []
    for path in _iter_text_files(target_path):
        content = _read_scan_text(path)
        if content is None:
            continue
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                line_no = content.count("\n", 0, match.start()) + 1
                findings.append(
                    _finding(
                        rule_id=name,
                        severity="High",
                        file=path,
                        line=line_no,
                        evidence=_redact_secret(match.group(0)),
                        message="Potential hardcoded credential",
                    )
                )
    return _json_findings(findings)


@tool(parse_docstring=True)
def static_pattern_scan(target_path: str) -> str:
    """Scan a file or directory for high-confidence static security red flags.

    This is a deterministic fallback/baseline scanner for patterns such as
    `eval(`, unsafe deserialization, `shell=True`, and raw HTML sinks.

    Args:
        target_path: File or directory to scan.

    Returns:
        JSON object with a `findings` list. Each finding has `rule_id`,
        `severity`, `file`, `line`, `evidence`, `message`, and `confidence`.
    """
    findings: list[dict[str, object]] = []
    for path in _iter_text_files(target_path):
        content = _read_scan_text(path)
        if content is None:
            continue
        for rule_id, (pattern, severity, message) in STATIC_PATTERNS.items():
            for match in pattern.finditer(content):
                line_no = content.count("\n", 0, match.start()) + 1
                line = content.splitlines()[line_no - 1].strip()
                findings.append(
                    _finding(
                        rule_id=rule_id,
                        severity=severity,
                        file=path,
                        line=line_no,
                        evidence=line[:300],
                        message=message,
                    )
                )
    return _json_findings(findings)


@tool(parse_docstring=True)
def dependency_manifest_scan(target_path: str) -> str:
    """Parse direct dependencies from supported manifest files.

    Currently supports Python `requirements*.txt` and `[project].dependencies`
    in `pyproject.toml`. Version ranges are normalized to the explicit bound so
    the dependency auditor can query OSV with concrete versions.

    Args:
        target_path: File or directory to scan for dependency manifests.

    Returns:
        JSON object with a `dependencies` list. Each dependency has `name`,
        `version`, `ecosystem`, `manifest`, and `source`.
    """
    root = Path(target_path).expanduser().resolve()
    candidates = [root] if root.is_file() else list(root.rglob("*"))
    dependencies: list[dict[str, str]] = []
    for path in candidates:
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.name.startswith("requirements") and path.suffix == ".txt":
            dependencies.extend(_parse_requirements_file(path))
        elif path.name == "pyproject.toml":
            dependencies.extend(_parse_pyproject_file(path))
    return _json_dependencies(dependencies)


@tool(parse_docstring=True)
def poc_source_lookup(
    cve_id: str | None = None,
    package: str | None = None,
    version: str | None = None,
    ecosystem: str | None = None,
) -> str:
    """Look up public POC intelligence for a vulnerability identifier.

    The lookup imports metadata only. It does not clone repositories, download
    exploit code, run templates, or contact target services.

    Args:
        cve_id: CVE identifier to query, such as `CVE-2024-1234`.
        package: Optional affected package name for report context.
        version: Optional affected package version for report context.
        ecosystem: Optional package ecosystem for report context.

    Returns:
        JSON object with `query`, `candidates`, and optional `epss` metadata.
    """
    query = {
        "cve_id": cve_id,
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
    }
    candidates: list[dict[str, str]] = []
    epss: dict[str, float] | None = None

    if cve_id:
        try:
            response = httpx.get(NVD_API, params={"cveId": cve_id}, timeout=15.0)
            response.raise_for_status()
            for item in response.json().get("vulnerabilities", []):
                references = item.get("cve", {}).get("references", {})
                for reference in references.get("referenceData", []):
                    url = reference.get("url")
                    if isinstance(url, str) and url:
                        candidates.append(_candidate_from_url(url))
        except httpx.HTTPError:
            candidates.append(
                {
                    "source": "nvd",
                    "kind": "lookup_error",
                    "trust": "unknown",
                    "execution_risk": "none",
                    "execution_status": "not_run",
                    "url": NVD_API,
                    "summary": "NVD lookup failed",
                }
            )

        try:
            response = httpx.get(EPSS_API, params={"cve": cve_id}, timeout=15.0)
            response.raise_for_status()
            rows = response.json().get("data", [])
            if rows:
                epss = {
                    "probability": float(rows[0]["epss"]),
                    "percentile": float(rows[0]["percentile"]),
                }
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            epss = None

    payload: dict[str, object] = {"query": query, "candidates": candidates}
    if epss is not None:
        payload["epss"] = epss
    return _json_poc_intel(payload)


@tool(parse_docstring=True)
def write_poc_intel_artifact(intel_json: str, artifact_root: str) -> str:
    """Write external POC intelligence as safe documentation artifacts.

    This tool writes `POC.md` and `sources.json`. It does not execute external
    POC code, clone repositories, or run network probes.

    Args:
        intel_json: JSON returned by `poc_source_lookup`.
        artifact_root: Directory where `security_artifacts/pocs/<id>/` is written.

    Returns:
        JSON object with the artifact directory and written files.
    """
    try:
        intel = json.loads(intel_json)
    except json.JSONDecodeError as exc:
        return _json_poc_intel({"error": f"invalid intel_json: {exc}"})

    query = intel.get("query", {}) if isinstance(intel, dict) else {}
    cve_id = query.get("cve_id") if isinstance(query, dict) else None
    artifact_id = _safe_artifact_id(str(cve_id or "poc-intel"))
    root = Path(artifact_root).expanduser().resolve()
    artifact_dir = root / "security_artifacts" / "pocs" / artifact_id
    artifact_dir.mkdir(parents=True, exist_ok=True)

    sources_path = artifact_dir / "sources.json"
    sources_path.write_text(
        json.dumps(intel, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    candidates = intel.get("candidates", []) if isinstance(intel, dict) else []
    lines = [
        f"# External POC Intelligence: {artifact_id}",
        "",
        "## Execution Policy",
        "",
        "Not executed by default. Requires sandbox + HITL before any reproduction attempt.",
        "",
        "## Sources",
        "",
        "| Source | Trust | Type | Risk | URL |",
        "| --- | --- | --- | --- | --- |",
    ]
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            lines.append(
                "| {source} | {trust} | {kind} | {risk} | {url} |".format(
                    source=candidate.get("source", ""),
                    trust=candidate.get("trust", ""),
                    kind=candidate.get("kind", ""),
                    risk=candidate.get("execution_risk", ""),
                    url=candidate.get("url", ""),
                )
            )
    lines.extend(
        [
            "",
            "## Safety Boundary",
            "",
            "- References are imported as documentation only.",
            "- External code is not cloned or executed.",
            "- Network probes require explicit approval and an authorized target.",
        ]
    )
    poc_path = artifact_dir / "POC.md"
    poc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return _json_poc_intel(
        {
            "artifact_dir": str(artifact_dir),
            "files": [str(poc_path), str(sources_path)],
        }
    )


@tool(parse_docstring=True)
def cvss_severity(base_score: float) -> str:
    """Map a CVSS v3 base score (0.0-10.0) to a severity label.

    Use when normalizing scores from different scanners into a consistent rating
    for the final report.

    Args:
        base_score: CVSS v3 base score from 0.0 to 10.0.

    Returns:
        Severity label: "None", "Low", "Medium", "High", or "Critical".
    """
    if base_score < 0.0 or base_score > 10.0:
        return f"invalid score {base_score} (must be 0.0-10.0)"
    if base_score == 0.0:
        return "None"
    if base_score < 4.0:
        return "Low"
    if base_score < 7.0:
        return "Medium"
    if base_score < 9.0:
        return "High"
    return "Critical"
