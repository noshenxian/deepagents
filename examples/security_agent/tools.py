"""Custom tools for the security analysis agent.

The agent already has shell access (`execute`), filesystem tools (`read_file`,
`grep`, `glob`), and todo planning. These tools fill the gaps:

- `osv_query`: Query OSV.dev for known vulnerabilities in a package.
- `secret_pattern_scan`: Regex-match common credential patterns in a string.
- `cvss_severity`: Map a CVSS base score to a severity label.
"""

from __future__ import annotations

import re

import httpx
from langchain_core.tools import tool

OSV_API = "https://api.osv.dev/v1/query"

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_access_key": re.compile(r"(?i)aws.{0,20}?[\"']([0-9a-zA-Z/+]{40})[\"']"),
    "github_pat":            re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "github_oauth":          re.compile(r"gho_[A-Za-z0-9]{36}"),
    "openai_api_key":        re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"),
    "anthropic_api_key":     re.compile(r"sk-ant-[A-Za-z0-9_\-]{40,}"),
    "google_api_key":        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "slack_token":           re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "private_key":           re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "jwt":                   re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "generic_password":      re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']"),
    "generic_secret":        re.compile(r"(?i)(?:secret|token|api[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']"),
}


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
