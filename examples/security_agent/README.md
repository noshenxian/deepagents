# Security Analysis Agent

A deep agent that audits a codebase and produces a structured security report.
Built on `deepagents` to demonstrate the customization patterns: custom tools,
sub-agents with isolated context, and a workflow-driven system prompt.

## Architecture

```
[Orchestrator]
    │   built-ins: write_todos, task, read_file, glob, grep, execute, write_file
    │   custom:    osv_query, secret_pattern_scan, cvss_severity
    │
    ├─> [secret-hunter]   - grep patterns + secret_pattern_scan
    ├─> [dep-auditor]     - manifest parsing + osv_query (OSV.dev API)
    ├─> [sast-analyzer]   - shell out to semgrep / bandit / gosec
    └─> [poc-intel]       - public POC references + safe artifacts
```

The orchestrator plans with `write_todos`, dispatches sub-agents in parallel via
`task`, and writes the final report to `SECURITY_REPORT.md`. Secret, dependency,
and fallback static scans run through deterministic Python tools that return
structured records before the LLM triages and summarizes them. Each sub-agent has
its own context window so noisy tool output (JSON from semgrep, file lists from
glob) doesn't pollute the orchestrator's reasoning.

For CVE/GHSA-backed findings, the `poc-intel` sub-agent can collect public POC
references from advisory sources and write documentation-only artifacts under
`security_artifacts/pocs/`. It does not clone, download, or execute external
exploit code.

## Setup

```bash
cd examples/security_agent
uv sync
```

For SAST coverage, install at least one scanner:

```bash
pipx install semgrep bandit
# or for Go:
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

The agent works without scanners installed — it falls back to deterministic
static pattern scanning — but findings are weaker.

## Running

### Standalone CLI

```bash
# Default: tries DeepSeek (via API_KEY/BASE_URL/MODELS env), then Anthropic
uv run python agent.py /path/to/target/codebase

# Pick an explicit model
SECURITY_AGENT_MODEL="anthropic:claude-sonnet-4-5" uv run python agent.py /path/to/target
SECURITY_AGENT_MODEL="openai:gpt-4o"               uv run python agent.py /path/to/target
```

### LangGraph Studio / dev server

The module exports a `get_agent` factory, so `langgraph dev` works after
adding a `langgraph.json`:

```json
{
  "graphs": { "security_agent": "./agent.py:get_agent" },
  "python_version": "3.11"
}
```

Then `langgraph dev` to inspect the run in Studio.

## Customization points (where to edit)

- **Add a tool**: drop a `@tool`-decorated function in `tools.py`, append to the
  list passed to `create_deep_agent(tools=[...])` or to a sub-agent's `tools`.
- **Add a sub-agent**: define a dict with `name`, `description`, `system_prompt`,
  optional `tools`, and append to `subagents=[...]`. The orchestrator can call it
  via `task` once it's registered.
- **Tighten the workflow**: edit `ORCHESTRATOR_PROMPT` in `prompts.py`. The
  numbered workflow section is the load-bearing part — sub-agent prompts are
  invoked through `task`, not via prompt inheritance.
- **Change the model**: edit `_build_model()` in `agent.py` or set
  `SECURITY_AGENT_MODEL`.

## What the agent does NOT do

- **No exploitation.** The agent is read-only: scan, report, recommend. It will
  not run payloads, modify the target, or attempt active exploitation.
- **No DAST / runtime testing.** Static-only. For runtime checks, add a sub-agent
  with appropriate tools and explicit operator authorization.
- **No false-positive triage at scale.** The current SAST sub-agent does basic
  filtering (drops test paths, dedupes); for production use, add a triage pass
  that cross-references findings against your suppressions file.
