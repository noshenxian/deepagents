#!/usr/bin/env bash
# Launch the security analysis agent against a target codebase.
#
# Usage:
#   ./sec-audit.sh <target_path> [--model <provider:model>] [--report <path>]
#
# Examples:
#   ./sec-audit.sh /path/to/repo
#   ./sec-audit.sh /path/to/repo --model anthropic:claude-sonnet-4-5
#   ./sec-audit.sh . --report /tmp/audit.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---- helpers ----
info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[!]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

need() { command -v "$1" >/dev/null 2>&1 || { err "missing: $1"; exit 127; }; }

# ---- parse args ----
TARGET=""
MODEL="${SECURITY_AGENT_MODEL:-}"
REPORT=""

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --model)   MODEL="${2:?--model requires a value}"; shift 2 ;;
    --report)  REPORT="${2:?--report requires a value}"; shift 2 ;;
    --) shift; break ;;
    -*) err "unknown flag: $1"; usage 2 ;;
    *)  if [ -z "$TARGET" ]; then TARGET="$1"; shift
        else err "unexpected arg: $1"; usage 2; fi ;;
  esac
done

[ -n "$TARGET" ] || { err "target path required"; usage 2; }

# ---- resolve target ----
TARGET_ABS="$(cd "$TARGET" 2>/dev/null && pwd || true)"
if [ -z "$TARGET_ABS" ]; then
  err "target does not exist or is not a directory: $TARGET"
  exit 1
fi

# ---- prerequisites ----
need uv

# ---- load credentials from repo .env ----
# .env at the repo root carries API_KEY / BASE_URL / MODELS for the DeepSeek
# (Anthropic-protocol) endpoint. Sourcing here exports them to the Python child.
if [ -f "$REPO_ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$REPO_ROOT/.env"
  set +a
  info "loaded $REPO_ROOT/.env"
fi

# Explicit model override from CLI flag wins.
if [ -n "$MODEL" ]; then
  export SECURITY_AGENT_MODEL="$MODEL"
  info "model: $MODEL"
fi

# ---- sync deps if venv missing ----
cd "$SCRIPT_DIR"
if [ ! -d ".venv" ]; then
  info "first run — syncing dependencies"
  uv sync
  ok  "deps installed"
fi

# ---- run ----
info "auditing: $TARGET_ABS"
[ -n "$REPORT" ] && info "report   : $REPORT"

# Pass target as positional arg; agent.py reads sys.argv[1].
# When --report is given, override the default ./SECURITY_REPORT.md path
# by injecting it into the user prompt via env var.
if [ -n "$REPORT" ]; then
  export SECURITY_AGENT_REPORT_PATH="$REPORT"
fi

exec uv run python agent.py "$TARGET_ABS"
