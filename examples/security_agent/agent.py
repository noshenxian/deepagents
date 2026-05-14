"""Security analysis agent built on deepagents.

Architecture:

    [Orchestrator] (write_todos, task, read_file, glob, grep, execute, write_file,
                    osv_query, secret_pattern_scan, cvss_severity)
         │
         ├──> [secret-hunter]   → grep + secret_pattern_scan
         ├──> [dep-auditor]     → manifest parsing + osv_query
         └──> [sast-analyzer]   → execute (semgrep / bandit) + parsing

The orchestrator plans, delegates in parallel, and writes a final markdown
report. Sub-agents have isolated context windows so their tool noise (large
JSON dumps from scanners, file lists) doesn't pollute the orchestrator's
reasoning.

Usage:

    from agent import build_agent
    agent = build_agent()
    result = agent.invoke({
        "messages": [{"role": "user",
                     "content": "Audit the codebase at /path/to/target"}]
    })
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from typing import Any

from langchain.chat_models import init_chat_model
from langchain_anthropic import ChatAnthropic

from deepagents import create_deep_agent
from deepagents.backends.local_shell import LocalShellBackend
from prompts import (
    DEP_AUDITOR_PROMPT,
    ORCHESTRATOR_PROMPT,
    POC_INTEL_PROMPT,
    SAST_ANALYZER_PROMPT,
    SECRET_HUNTER_PROMPT,
)
from tools import (
    cvss_severity,
    dependency_manifest_scan,
    osv_query,
    poc_source_lookup,
    secret_path_scan,
    secret_pattern_scan,
    static_pattern_scan,
    write_poc_intel_artifact,
)


DEFAULT_REPORT_PATH = "./SECURITY_REPORT.md"
"""Default path for the generated report."""

DEFAULT_INTERRUPT_ON = {
    "execute": True,
    "write_file": True,
    "edit_file": True,
}
"""Dangerous tools that require human review by default."""


def _scanner_env() -> dict[str, str]:
    """Return a minimal environment that can still find common scanner installs."""
    paths = [
        str(Path.home() / ".local" / "bin"),
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ]
    return {"PATH": os.pathsep.join(paths)}


def _build_model():
    """Build the chat model.

    Honors:
    - SECURITY_AGENT_MODEL env var, e.g. "anthropic:claude-sonnet-4-5"
    - The DeepSeek-via-Anthropic-protocol setup if API_KEY + BASE_URL are present.
    - Falls back to claude-sonnet-4-5.
    """
    explicit = os.environ.get("SECURITY_AGENT_MODEL")
    if explicit:
        return init_chat_model(explicit, temperature=0.0)

    if os.environ.get("API_KEY") and os.environ.get("BASE_URL"):
        return ChatAnthropic(
            model=os.environ.get("MODELS", "deepseek-v4-flash"),
            api_key=os.environ["API_KEY"],
            base_url=os.environ["BASE_URL"],
            temperature=0.0,
        )

    return init_chat_model("anthropic:claude-sonnet-4-5", temperature=0.0)


# Sub-agent definitions. Each one inherits the parent's tool set unless `tools` is
# specified — we pass tools explicitly to keep their context narrow and the system
# prompt aligned with what they actually have.

SECRET_HUNTER = {
    "name": "secret-hunter",
    "description": (
        "Scans a codebase for hardcoded credentials. Give it a target path. "
        "Returns a list of (pattern, file:line, redacted match)."
    ),
    "system_prompt": SECRET_HUNTER_PROMPT,
    "tools": [secret_path_scan, secret_pattern_scan],
}

DEP_AUDITOR = {
    "name": "dep-auditor",
    "description": (
        "Audits direct dependencies against OSV.dev. Give it a target path. "
        "Returns a markdown table of (package, version, CVE, severity, fixed-in)."
    ),
    "system_prompt": DEP_AUDITOR_PROMPT,
    "tools": [dependency_manifest_scan, osv_query],
}

SAST_ANALYZER = {
    "name": "sast-analyzer",
    "description": (
        "Runs static analysis tools (semgrep, bandit, gosec) and parses output. "
        "Give it a target path. Returns a list of high-confidence code findings."
    ),
    "system_prompt": SAST_ANALYZER_PROMPT,
    "tools": [static_pattern_scan],
}

POC_INTEL = {
    "name": "poc-intel",
    "description": (
        "Collects public POC intelligence for CVE/GHSA-backed findings and "
        "writes safe documentation artifacts. Does not execute external POC code."
    ),
    "system_prompt": POC_INTEL_PROMPT,
    "tools": [poc_source_lookup, write_poc_intel_artifact],
}


def build_agent(
    *,
    report_path: str | None = None,
    interrupt_on: dict[str, bool | dict[str, Any]] | None = None,
):
    """Construct the security-analysis deep agent.

    Uses `LocalShellBackend` so the agent sees the real filesystem (not the
    default in-memory virtual fs). Without this, `ls`/`read_file`/`glob`/`grep`
    return empty results — exactly what we hit on the first smoke run.

    `virtual_mode=False` is explicit (the 0.6.0 default flips to True). We
    *want* absolute-path access here because the user passes a target path
    like `/path/to/repo` and the agent needs to read it directly. The
    security trade-off is accepted: this agent is opt-in, read-mostly, and
    only used in trusted local audits.
    """
    resolved_report_path = report_path or os.environ.get(
        "SECURITY_AGENT_REPORT_PATH", DEFAULT_REPORT_PATH
    )
    resolved_interrupt_on = (
        DEFAULT_INTERRUPT_ON if interrupt_on is None else interrupt_on
    )

    return create_deep_agent(
        model=_build_model(),
        system_prompt=ORCHESTRATOR_PROMPT.format(
            date=date.today().isoformat(),
            report_path=resolved_report_path,
        ),
        tools=[
            dependency_manifest_scan,
            osv_query,
            poc_source_lookup,
            secret_path_scan,
            secret_pattern_scan,
            static_pattern_scan,
            write_poc_intel_artifact,
            cvss_severity,
        ],
        subagents=[SECRET_HUNTER, DEP_AUDITOR, SAST_ANALYZER, POC_INTEL],
        backend=LocalShellBackend(
            virtual_mode=False,
            env=_scanner_env(),
            inherit_env=False,
        ),
        interrupt_on=resolved_interrupt_on,
    )


def get_agent():
    """Build an agent instance for LangGraph Studio or programmatic use."""
    return build_agent()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python agent.py <target_codebase_path>")
        sys.exit(1)

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(f"Path does not exist: {target}")
        sys.exit(1)

    report_path = os.environ.get("SECURITY_AGENT_REPORT_PATH", DEFAULT_REPORT_PATH)
    agent = build_agent(report_path=report_path)
    prompt = (
        f"Audit the codebase at {target}. Follow the workflow strictly. "
        f"Write the final report to {report_path}."
    )
    result = agent.invoke({"messages": [{"role": "user", "content": prompt}]})

    # Print the final assistant message
    final = result["messages"][-1]
    print(final.content if hasattr(final, "content") else final)
