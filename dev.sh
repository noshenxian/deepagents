#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$SCRIPT_DIR/libs/cli"

# ---- helpers ----
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
err()   { echo -e "\033[1;31m[ERR]\033[0m   $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m    $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Missing: $1"; exit 1; }; }

# ---- load .env ----
# Source project .env so env vars (API keys, base URLs) are available
# before uv run starts the Python process. This avoids a bootstrap timing
# issue where _get_default_model_spec() can return early without loading .env.
_load_env() {
  local env_file="$SCRIPT_DIR/.env"
  if [ -f "$env_file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi
}

usage() {
  cat <<EOF
Usage: dev.sh [subcommand] [args...]

Subcommands:
  sync         Install/update all dependencies (recommended first step)
  run          Launch the interactive CLI (TUI)
  shell        Shell agent — non-interactive one-shot
  test         Run unit tests
  lint         Run ruff check + format check + type check
  clean        Remove virtualenvs and caches

Model:
  Uses DeepSeek by default (configured in ~/.deepagents/config.toml).
  Override with --model:  ./dev.sh run --model openai:gpt-4o

Environment:
  DEEPAGENTS_CLI_DEBUG=1    Preserve server subprocess logs on shutdown

EOF
  exit 0
}

# ---- prerequisites ----
need_cmd uv
need_cmd python3

PY_VER=$(python3 -c 'import sys; v=sys.version_info; print(f"{v.major}.{v.minor}")')
MAJOR=$(echo "$PY_VER" | cut -d. -f1)
MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 11 ]; }; then
  err "Python >= 3.11 required (have $PY_VER)"
  exit 1
fi

# ---- subcommands ----
cmd_sync() {
  info "Syncing dependencies in libs/cli ..."
  cd "$CLI_DIR"
  uv sync --group test
  ok "Sync done."
}

cmd_run() {
  _load_env
  info "Launching Deep Agents CLI (TUI mode)..."
  cd "$CLI_DIR"
  exec uv run deepagents "$@"
}

cmd_shell() {
  _load_env
  local prompt="${1:-}"
  info "Shell agent mode ..."
  cd "$CLI_DIR"
  exec uv run deepagents --shell ${prompt:+-p "$prompt"}
}

cmd_test() {
  info "Running tests..."
  cd "$CLI_DIR"
  uv run --group test pytest -n auto --benchmark-disable --disable-socket --allow-unix-socket tests/unit_tests/ "$@" \
    --cov=deepagents_cli --cov-report=term-missing
}

cmd_lint() {
  info "Linting..."
  cd "$CLI_DIR"
  uv run --all-groups ruff check deepagents_cli tests
  uv run --all-groups ruff format deepagents_cli tests --diff
  uv run --all-groups ty check deepagents_cli tests
  ok "Lint passed."
}

cmd_clean() {
  info "Removing .venv ..."
  rm -rf "$CLI_DIR/.venv"
  info "Cleaning __pycache__ ..."
  find "$SCRIPT_DIR" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
  ok "Clean done."
}

# ---- dispatch ----
case "${1:-}" in
  sync)     shift; cmd_sync "$@" ;;
  run)      shift; cmd_run "$@" ;;
  shell)    shift; cmd_shell "$@" ;;
  test)     shift; cmd_test "$@" ;;
  lint)     shift; cmd_lint "$@" ;;
  clean)    shift; cmd_clean "$@" ;;
  -h|--help|help) usage ;;
  *)
    # Default: if no args, sync then run
    if [ $# -eq 0 ]; then
      if [ ! -d "$CLI_DIR/.venv" ]; then
        cmd_sync
      fi
      cmd_run
    else
      err "Unknown subcommand: $1"
      usage
    fi
    ;;
esac
