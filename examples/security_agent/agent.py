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
from pathlib import Path

from langchain.chat_models import init_chat_model
from langchain_anthropic import ChatAnthropic

from deepagents import create_deep_agent
from deepagents.backends.local_shell import LocalShellBackend
from prompts import (
    DEP_AUDITOR_PROMPT,
    ORCHESTRATOR_PROMPT,
    SAST_ANALYZER_PROMPT,
    SECRET_HUNTER_PROMPT,
)
from tools import cvss_severity, osv_query, secret_pattern_scan


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
    "tools": [secret_pattern_scan],
}

DEP_AUDITOR = {
    "name": "dep-auditor",
    "description": (
        "Audits direct dependencies against OSV.dev. Give it a target path. "
        "Returns a markdown table of (package, version, CVE, severity, fixed-in)."
    ),
    "system_prompt": DEP_AUDITOR_PROMPT,
    "tools": [osv_query],
}

SAST_ANALYZER = {
    "name": "sast-analyzer",
    "description": (
        "Runs static analysis tools (semgrep, bandit, gosec) and parses output. "
        "Give it a target path. Returns a list of high-confidence code findings."
    ),
    "system_prompt": SAST_ANALYZER_PROMPT,
    "tools": [],  # uses execute (built-in) for the scanners; no custom tools needed
}


def build_agent():
    """Construct the security-analysis deep agent.

    Uses `LocalShellBackend` so the agent sees the real filesystem (not the
    default in-memory virtual fs). Without this, `ls`/`read_file`/`glob`/`grep`
    return empty results — exactly what we hit on the first smoke run.
    """
    return create_deep_agent(
        model=_build_model(),
        system_prompt=ORCHESTRATOR_PROMPT,
        tools=[osv_query, secret_pattern_scan, cvss_severity],
        subagents=[SECRET_HUNTER, DEP_AUDITOR, SAST_ANALYZER],
        backend=LocalShellBackend(),
    )


# Module-level instance for `langgraph dev` / Studio.
agent = build_agent()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python agent.py <target_codebase_path>")
        sys.exit(1)

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(f"Path does not exist: {target}")
        sys.exit(1)

    report_path = os.environ.get("SECURITY_AGENT_REPORT_PATH", "./SECURITY_REPORT.md")
    prompt = (
        f"Audit the codebase at {target}. Follow the workflow strictly. "
        f"Write the final report to {report_path}."
    )
    result = agent.invoke({"messages": [{"role": "user", "content": prompt}]})

    # Print the final assistant message
    final = result["messages"][-1]
    print(final.content if hasattr(final, "content") else final)
