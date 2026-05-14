# Security Agent POC Intelligence Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add external POC intelligence ingestion to `examples/security_agent` without executing untrusted exploit code.

**Architecture:** Add deterministic tools that normalize public vulnerability references into POC candidates and write safe documentation artifacts. Add a `poc-intel` subagent that uses those tools after dependency/SAST findings produce CVE or advisory identifiers.

**Tech Stack:** Python 3.11+, LangChain `@tool`, httpx, pytest, ruff, Deep Agents subagents.

### Task 1: Add POC Intelligence Tool Tests

**Files:**
- Modify: `examples/security_agent/tests/unit_tests/test_security_agent.py`
- Modify later: `examples/security_agent/tools.py`

**Step 1: Write failing tests**

Add tests for:

```python
def test_poc_source_lookup_classifies_reference_links(monkeypatch):
    ...
```

and:

```python
def test_write_poc_intel_artifact_writes_safe_markdown(tmp_path):
    ...
```

**Step 2: Run RED**

Run:

```bash
env UV_CACHE_DIR=/tmp/uv-cache-security-agent uv run --project examples/security_agent --with pytest pytest examples/security_agent/tests/unit_tests/test_security_agent.py -q
```

Expected: FAIL because the tools do not exist.

### Task 2: Implement POC Intelligence Tools

**Files:**
- Modify: `examples/security_agent/tools.py`

**Step 1: Add URL classifier**

Classify references into `nuclei_template`, `metasploit_module`, `exploit_db`, `github_poc`, `vendor_advisory`, or `reference`.

**Step 2: Add `poc_source_lookup`**

Implement a tool that accepts `cve_id`, optional `package`, `version`, and `ecosystem`, queries public APIs when possible, and returns normalized JSON candidates. Keep the first implementation conservative and testable by allowing monkeypatched `httpx.get`.

**Step 3: Add `write_poc_intel_artifact`**

Write `POC.md` and `sources.json` under `security_artifacts/pocs/<id>/`. Do not execute or download referenced code.

### Task 3: Wire `poc-intel`

**Files:**
- Modify: `examples/security_agent/agent.py`
- Modify: `examples/security_agent/prompts.py`
- Modify: `examples/security_agent/README.md`

**Step 1:** Add `POC_INTEL_PROMPT`.

**Step 2:** Add `POC_INTEL` subagent with `poc_source_lookup` and `write_poc_intel_artifact`.

**Step 3:** Update orchestrator workflow to request POC intelligence for CVE/GHSA-backed findings.

**Step 4:** Update README to document external POC intelligence behavior and safety boundary.

### Task 4: Verify

Run:

```bash
env UV_CACHE_DIR=/tmp/uv-cache-security-agent uv run --project examples/security_agent --with pytest pytest examples/security_agent/tests/unit_tests/test_security_agent.py -q
env UV_CACHE_DIR=/tmp/uv-cache-security-agent uv run --project examples/security_agent --with ruff ruff check examples/security_agent/agent.py examples/security_agent/tools.py examples/security_agent/prompts.py examples/security_agent/tests/unit_tests/test_security_agent.py
env UV_CACHE_DIR=/tmp/uv-cache-security-agent uv run --project examples/security_agent --with ruff ruff format --check examples/security_agent/agent.py examples/security_agent/tools.py examples/security_agent/prompts.py examples/security_agent/tests/unit_tests/test_security_agent.py
```
