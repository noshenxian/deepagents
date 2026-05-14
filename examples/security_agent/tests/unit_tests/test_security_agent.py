"""Unit tests for the security agent example."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

EXAMPLE_DIR = Path(__file__).resolve().parents[2]
if str(EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(EXAMPLE_DIR))


def _import_agent(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import `agent` without constructing a real chat model."""
    sys.modules.pop("agent", None)
    monkeypatch.setenv("SECURITY_AGENT_MODEL", "fake:model")
    return importlib.import_module("agent")


def test_build_agent_configures_human_review_for_dangerous_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Require HITL review for shell execution and filesystem writes."""
    agent_module = _import_agent(monkeypatch)
    calls: list[dict[str, Any]] = []

    def fake_create_deep_agent(**kwargs: Any) -> object:
        calls.append(kwargs)
        return object()

    monkeypatch.setattr(agent_module, "create_deep_agent", fake_create_deep_agent)
    monkeypatch.setattr(agent_module, "_build_model", lambda: object())

    agent_module.build_agent()

    interrupt_on = calls[0]["interrupt_on"]
    assert interrupt_on["execute"] is True
    assert interrupt_on["write_file"] is True
    assert interrupt_on["edit_file"] is True


def test_build_agent_preserves_scanner_path_without_inheriting_all_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expose common scanner install directories while avoiding full env inheritance."""
    agent_module = _import_agent(monkeypatch)
    backends: list[object] = []

    class FakeBackend:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs
            backends.append(self)

    monkeypatch.setattr(agent_module, "LocalShellBackend", FakeBackend)
    monkeypatch.setattr(agent_module, "_build_model", lambda: object())
    monkeypatch.setattr(agent_module, "create_deep_agent", lambda **_kwargs: object())

    agent_module.build_agent()

    kwargs = backends[0].kwargs
    assert kwargs["inherit_env"] is False
    assert kwargs["env"]["PATH"]
    assert ".local/bin" in kwargs["env"]["PATH"]


def test_orchestrator_prompt_accepts_runtime_report_path() -> None:
    """The system prompt should not contradict a caller-provided report path."""
    import prompts

    prompt = prompts.ORCHESTRATOR_PROMPT.format(
        date="2026-05-14",
        report_path="/tmp/security.md",
    )

    assert "Write the final report to `/tmp/security.md`" in prompt


def test_prompt_uses_requested_report_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`build_agent` should inject the selected report path into the system prompt."""
    agent_module = _import_agent(monkeypatch)
    calls: list[dict[str, Any]] = []

    def fake_create_deep_agent(**kwargs: Any) -> object:
        calls.append(kwargs)
        return object()

    monkeypatch.setenv("SECURITY_AGENT_REPORT_PATH", "/tmp/security.md")
    monkeypatch.setattr(agent_module, "create_deep_agent", fake_create_deep_agent)
    monkeypatch.setattr(agent_module, "_build_model", lambda: object())

    agent_module.build_agent()

    assert "Write the final report to `/tmp/security.md`" in calls[0]["system_prompt"]


@pytest.mark.parametrize(
    "secret",
    [
        "github_pat_11AAABBBBBBBBBBBBBBBBBB_222222222222222222222222222222222222222",
        "sk-proj-abc1234567890abcdefghijklmnopqrstuvwxyz",
        "sk-svcacct-abc1234567890abcdefghijklmnopqrstuvwxyz",
    ],
)
def test_secret_pattern_scan_detects_modern_tokens(secret: str) -> None:
    """Detect modern provider token formats used by GitHub and OpenAI."""
    from tools import secret_pattern_scan

    result = secret_pattern_scan.invoke({"content": f"credential candidate: {secret}"})

    assert "potential secret" in result
    assert "no matches" not in result


def test_secret_path_scan_returns_structured_redacted_findings(
    tmp_path: Path,
) -> None:
    """Scan files deterministically and return redacted structured findings."""
    from tools import secret_path_scan

    target = tmp_path / "app.py"
    target.write_text(
        "OPENAI_API_KEY='sk-proj-abc1234567890abcdefghijklmnopqrstuvwxyz'\n",
        encoding="utf-8",
    )

    data = json.loads(secret_path_scan.invoke({"target_path": str(tmp_path)}))

    finding = data["findings"][0]
    assert finding["rule_id"] == "openai_project_api_key"
    assert finding["severity"] == "High"
    assert finding["line"] == 1
    assert finding["file"].endswith("app.py")
    assert "..." in finding["evidence"]
    assert "sk-proj-abc1234567890abcdefghijklmnopqrstuvwxyz" not in finding["evidence"]


def test_secret_path_scan_skips_dependency_directories(tmp_path: Path) -> None:
    """Skip dependency directories to avoid noisy and expensive scans."""
    from tools import secret_path_scan

    skipped_dir = tmp_path / "node_modules"
    skipped_dir.mkdir()
    (skipped_dir / "package.js").write_text(
        "const token = 'sk-proj-abc1234567890abcdefghijklmnopqrstuvwxyz'\n",
        encoding="utf-8",
    )

    data = json.loads(secret_path_scan.invoke({"target_path": str(tmp_path)}))

    assert data["findings"] == []


def test_static_pattern_scan_returns_structured_findings(tmp_path: Path) -> None:
    """Detect high-confidence static red flags without relying on the LLM."""
    from tools import static_pattern_scan

    target = tmp_path / "app.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")

    data = json.loads(static_pattern_scan.invoke({"target_path": str(tmp_path)}))

    finding = data["findings"][0]
    assert finding["rule_id"] == "python_eval"
    assert finding["severity"] == "High"
    assert finding["line"] == 1
    assert finding["file"].endswith("app.py")


def test_dependency_manifest_scan_parses_requirements(tmp_path: Path) -> None:
    """Parse pinned Python requirements into structured dependency records."""
    from tools import dependency_manifest_scan

    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "django==4.2.1\nrequests>=2.31.0\n# comment\n-e ../local-package\n",
        encoding="utf-8",
    )

    data = json.loads(dependency_manifest_scan.invoke({"target_path": str(tmp_path)}))

    assert data["dependencies"] == [
        {
            "name": "django",
            "version": "4.2.1",
            "ecosystem": "PyPI",
            "manifest": str(requirements),
            "source": "requirements.txt",
        },
        {
            "name": "requests",
            "version": "2.31.0",
            "ecosystem": "PyPI",
            "manifest": str(requirements),
            "source": "requirements.txt",
        },
    ]


def test_dependency_manifest_scan_parses_pyproject_dependencies(
    tmp_path: Path,
) -> None:
    """Parse direct project dependencies from `pyproject.toml`."""
    from tools import dependency_manifest_scan

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "fastapi==0.110.0",
  "httpx>=0.28.0",
]
""".strip(),
        encoding="utf-8",
    )

    data = json.loads(dependency_manifest_scan.invoke({"target_path": str(tmp_path)}))

    assert data["dependencies"] == [
        {
            "name": "fastapi",
            "version": "0.110.0",
            "ecosystem": "PyPI",
            "manifest": str(pyproject),
            "source": "pyproject.toml",
        },
        {
            "name": "httpx",
            "version": "0.28.0",
            "ecosystem": "PyPI",
            "manifest": str(pyproject),
            "source": "pyproject.toml",
        },
    ]


def test_poc_source_lookup_classifies_reference_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize external POC intelligence without executing referenced code."""
    from tools import poc_source_lookup

    class FakeResponse:
        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self._payload

    def fake_get(url: str, **kwargs: Any) -> FakeResponse:
        if "services.nvd.nist.gov" in url:
            return FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "references": {
                                    "referenceData": [
                                        {
                                            "url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1234.yaml"
                                        },
                                        {
                                            "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/example.rb"
                                        },
                                        {
                                            "url": "https://www.exploit-db.com/exploits/12345"
                                        },
                                        {"url": "https://vendor.example/advisory"},
                                    ]
                                }
                            }
                        }
                    ]
                }
            )
        assert "api.first.org" in url
        return FakeResponse(
            {
                "data": [
                    {
                        "cve": "CVE-2024-1234",
                        "epss": "0.42",
                        "percentile": "0.96",
                    }
                ]
            }
        )

    monkeypatch.setattr("tools.httpx.get", fake_get)

    data = json.loads(poc_source_lookup.invoke({"cve_id": "CVE-2024-1234"}))

    kinds = {candidate["kind"] for candidate in data["candidates"]}
    assert "nuclei_template" in kinds
    assert "metasploit_module" in kinds
    assert "exploit_db" in kinds
    assert "vendor_advisory" in kinds
    assert data["epss"] == {"probability": 0.42, "percentile": 0.96}
    assert all(
        candidate["execution_status"] == "not_run" for candidate in data["candidates"]
    )


def test_write_poc_intel_artifact_writes_safe_markdown(tmp_path: Path) -> None:
    """Write external POC intelligence as documentation, not executable code."""
    from tools import write_poc_intel_artifact

    intel = {
        "query": {"cve_id": "CVE-2024-1234"},
        "candidates": [
            {
                "source": "nuclei-templates",
                "url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-1234.yaml",
                "kind": "nuclei_template",
                "trust": "medium_high",
                "execution_risk": "network_probe",
                "execution_status": "not_run",
                "summary": "Public nuclei template candidate",
            }
        ],
        "epss": {"probability": 0.42, "percentile": 0.96},
    }

    data = json.loads(
        write_poc_intel_artifact.invoke(
            {
                "intel_json": json.dumps(intel),
                "artifact_root": str(tmp_path),
            }
        )
    )

    artifact_dir = Path(data["artifact_dir"])
    assert (artifact_dir / "POC.md").exists()
    assert (artifact_dir / "sources.json").exists()
    assert "Not executed by default" in (artifact_dir / "POC.md").read_text(
        encoding="utf-8"
    )
