#!/usr/bin/env bash
# Pre-release content audit for Singularity AIDR.
# Runs gitleaks against both Git history and the checked-out tree using the
# versioned repository policy. Running both modes catches historical leaks and
# files that have not entered history yet.
#
# Exit codes: 0 = pass, 1 = violation found, 2 = script error
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$REPO_ROOT/.gitleaks.toml"
REQUIRED_GITLEAKS_VERSION="8.30.0"
GITLEAKS_BIN="${GITLEAKS_BIN:-gitleaks}"

# ── Phase 1: Check prerequisites ──────────────────────────────────────────────

if ! command -v "$GITLEAKS_BIN" &>/dev/null; then
  echo -e "${RED}ERROR:${RESET} gitleaks is not installed."
  echo "  Install: brew install gitleaks  (or see https://github.com/gitleaks/gitleaks)"
  exit 2
fi

actual_gitleaks_version="$("$GITLEAKS_BIN" version 2>/dev/null | tr -d '\r\n[:space:]')"
if [[ "$actual_gitleaks_version" != "$REQUIRED_GITLEAKS_VERSION" ]]; then
  echo -e "${RED}ERROR:${RESET} gitleaks ${REQUIRED_GITLEAKS_VERSION} is required; found '${actual_gitleaks_version:-unknown}'."
  echo "  Use the checksum-pinned release workflow or install the exact audited version."
  exit 2
fi

if [[ ! -f "$CONFIG" ]]; then
  echo -e "${RED}ERROR:${RESET} .gitleaks.toml not found at ${CONFIG}"
  echo ""
  echo "  The versioned gitleaks config is required for a reproducible audit."
  exit 1
fi

# ── Phase 2: Run gitleaks ─────────────────────────────────────────────────────

echo -e "${BOLD}Pre-release audit${RESET}"
echo "  Config: $CONFIG"
echo "  Source: $REPO_ROOT"
echo ""

history_status=0
current_status=0
"$GITLEAKS_BIN" git "$REPO_ROOT" --config "$CONFIG" --redact --verbose || history_status=$?
GITLEAKS_BIN="$(command -v "$GITLEAKS_BIN")" node "$REPO_ROOT/scripts/scan-current-secrets.mjs" || current_status=$?

if [[ "$history_status" -eq 0 && "$current_status" -eq 0 ]]; then
  echo ""
  echo -e "${GREEN}PASS${RESET} — no violations found."
  exit 0
else
  status="$history_status"
  [[ "$status" -ne 0 ]] || status="$current_status"
  echo ""
  echo -e "${RED}FAIL${RESET} — gitleaks found violations (exit code $status)."
  echo "  Fix the issues above, or add inline '# gitleaks:allow' for false positives."
  exit 1
fi
