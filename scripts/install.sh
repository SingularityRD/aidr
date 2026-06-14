#!/usr/bin/env bash
# AIDR CLI installer
# Usage: curl -fsSL https://aidr.dev/install.sh | sh
#
# Closed-source tool. License: SingularityRD CLA v1.0.
# See https://aidr.dev/license for terms.

set -euo pipefail

REPO="https://github.com/SingularityRD/aidr"
PACKAGE="@singularityrd/aidr-cli"
VERSION="${AIDR_VERSION:-latest}"

# ── Detect OS / Arch ──────────────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)  OS="linux" ;;
  darwin) OS="darwin" ;;
  *) echo "❌ Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "❌ Unsupported arch: $ARCH"; exit 1 ;;
esac

PLATFORM="${OS}-${ARCH}"
echo "🛡️  AIDR CLI installer"
echo "   Platform: $PLATFORM"
echo "   Version:  $VERSION"
echo ""

# ── Pick install method ─────────────────────────────────────────────────
install_with_npm() {
  echo "→ Installing via npm..."
  if ! command -v npm >/dev/null 2>&1; then
    echo "❌ npm not found. Install Node.js 18+ first: https://nodejs.org"
    exit 1
  fi
  if [[ "$VERSION" == "latest" ]]; then
    npm install -g "$PACKAGE"
  else
    npm install -g "${PACKAGE}@${VERSION}"
  fi
  echo ""
  echo "✅ AIDR installed!"
  echo "   Run: aidr --version"
  echo "   Get started: aidr setup"
}

install_with_pnpm() {
  echo "→ Installing via pnpm..."
  if ! command -v pnpm >/dev/null 2>&1; then
    echo "❌ pnpm not found. Install pnpm first: npm i -g pnpm"
    exit 1
  fi
  if [[ "$VERSION" == "latest" ]]; then
    pnpm add -g "$PACKAGE"
  else
    pnpm add -g "${PACKAGE}@${VERSION}"
  fi
  echo ""
  echo "✅ AIDR installed!"
  echo "   Run: aidr --version"
  echo "   Get started: aidr setup"
}

# ── Detect package manager preference ────────────────────────────────────
if [[ "${AIDR_INSTALLER:-}" == "pnpm" ]]; then
  install_with_pnpm
elif [[ "${AIDR_INSTALLER:-}" == "npm" ]] || command -v pnpm >/dev/null 2>&1; then
  install_with_pnpm
else
  install_with_npm
fi

# ── Post-install verify ────────────────────────────────────────────────
if command -v aidr >/dev/null 2>&1; then
  echo ""
  echo "→ Verifying..."
  aidr --version
  echo ""
  echo "→ Engine stats:"
  aidr scan stats || true
  echo ""
  echo "🛡️  AIDR is installed and ready."
  echo "   Docs: https://aidr.dev"
  echo "   Trust: https://aidr.dev/trust"
else
  echo ""
  echo "⚠️  aidr not in PATH. Try:"
  echo "   - Restart your terminal"
  echo "   - Add npm/pnpm global bin to PATH"
  echo "   - Run with: npx $PACKAGE --version"
fi
