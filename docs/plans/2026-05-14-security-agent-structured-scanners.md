# Security Agent Structured Scanners Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `examples/security_agent` more reliable by moving high-noise scanner work into deterministic Python tools that return structured findings.

**Architecture:** Keep the Deep Agents orchestrator and subagents, but add Python tools for repeatable file traversal, pattern matching, redaction, and finding serialization. The LLM should use structured scanner outputs for triage and report writing instead of manually grepping and parsing everything from prompt instructions.

**Tech Stack:** Python 3.11+, LangChain `@tool`, pytest, ruff, existing Deep Agents `create_deep_agent`.

### Task 1: Add Structured Finding Tests

**Files:**
- Modify: `examples/security_agent/tests/unit_tests/test_security_agent.py`
- Modify later: `examples/security_agent/tools.py`

**Step 1: Write the failing tests**

Add tests that call the desired tools:

```python
def test_secret_path_scan_returns_structured_redacted_findings(tmp_path: Path) -> None:
    from tools import secret_path_scan

    target = tmp_path / "app.py"
    target.write_text("OPENAI_API_KEY='sk-proj-abc1234567890abcdefghijklmnopqrstuvwxyz'\n")

    data = json.loads(secret_path_scan.invoke({"target_path": str(tmp_path)}))

    assert data["findings"][0]["rule_id"] == "openai_project_api_key"
    assert data["findings"][0]["severity"] == "High"
    assert data["findings"][0]["line"] == 1
    assert "..." in data["findings"][0]["evidence"]
```

Add a second test for static pattern scanning:

```python
def test_static_pattern_scan_returns_structured_findings(tmp_path: Path) -> None:
    from tools import static_pattern_scan

    target = tmp_path / "app.py"
    target.write_text("eval(user_input)\n")

    data = json.loads(static_pattern_scan.invoke({"target_path": str(tmp_path)}))

    assert data["findings"][0]["rule_id"] == "python_eval"
    assert data["findings"][0]["severity"] == "High"
```

**Step 2: Run test to verify it fails**

Run:

```bash
env UV_CACHE_DIR=/tmp/uv-cache-security-agent uv run --project examples/security_agent --with pytest pytest examples/security_agent/tests/unit_tests/test_security_agent.py -q
```

Expected: FAIL because `secret_path_scan` and `static_pattern_scan` do not exist.

### Task 2: Implement Deterministic Scanner Tools

**Files:**
- Modify: `examples/security_agent/tools.py`

**Step 1: Add helpers**

Implement private helpers:

```python
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "dist", "build"}
TEXT_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".php", ".env", ".txt", ".md", ".toml", ".yaml", ".yml", ".json"}

def _iter_text_files(target_path: str) -> Iterator[Path]:
    ...

def _finding(...) -> dict[str, object]:
    ...
```

**Step 2: Add tools**

Add:

```python
@tool(parse_docstring=True)
def secret_path_scan(target_path: str) -> str:
    ...

@tool(parse_docstring=True)
def static_pattern_scan(target_path: str) -> str:
    ...
```

Both tools return JSON:

```json
{"findings": [{ "rule_id": "...", "severity": "...", "file": "...", "line": 1, "evidence": "...", "confidence": "high" }]}
```

**Step 3: Run tests**

Run the same pytest command. Expected: PASS.

### Task 3: Wire Tools Into Agent and Prompts

**Files:**
- Modify: `examples/security_agent/agent.py`
- Modify: `examples/security_agent/prompts.py`
- Modify: `examples/security_agent/README.md`

**Step 1: Update imports and tool lists**

Add `secret_path_scan` to the orchestrator and `secret-hunter` tools. Add `static_pattern_scan` to orchestrator and `sast-analyzer` tools.

**Step 2: Update prompts**

Tell `secret-hunter` to call `secret_path_scan` first, then inspect high-risk context as needed. Tell `sast-analyzer` to use `static_pattern_scan` as fallback and as a baseline even when external scanners are missing.

**Step 3: Update README**

Mention that deterministic scanner tools produce structured findings and external SAST tools improve coverage when installed.

**Step 4: Verify**

Run:

```bash
env UV_CACHE_DIR=/tmp/uv-cache-security-agent uv run --project examples/security_agent --with pytest pytest examples/security_agent/tests/unit_tests/test_security_agent.py -q
env UV_CACHE_DIR=/tmp/uv-cache-security-agent uv run --project examples/security_agent --with ruff ruff check examples/security_agent/agent.py examples/security_agent/tools.py examples/security_agent/prompts.py examples/security_agent/tests/unit_tests/test_security_agent.py
env UV_CACHE_DIR=/tmp/uv-cache-security-agent uv run --project examples/security_agent --with ruff ruff format --check examples/security_agent/agent.py examples/security_agent/tools.py examples/security_agent/prompts.py examples/security_agent/tests/unit_tests/test_security_agent.py
```

Expected: all pass.
