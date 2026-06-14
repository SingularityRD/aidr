# AIDR CLI installer (Windows PowerShell)
# Usage: irm https://aidr.dev/install.ps1 | iex
#
# Closed-source tool. License: SingularityRD CLA v1.0.

$ErrorActionPreference = "Stop"
$PACKAGE = "@singularityrd/aidr-cli"
$VERSION = if ($env:AIDR_VERSION) { $env:AIDR_VERSION } else { "latest" }

Write-Host "🛡️  AIDR CLI installer" -ForegroundColor Cyan
Write-Host "   Version:  $VERSION"
Write-Host ""

# Check Node.js
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
  Write-Host "❌ Node.js not found. Install Node.js 18+ first: https://nodejs.org" -ForegroundColor Red
  exit 1
}

# Check npm
$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) {
  Write-Host "❌ npm not found." -ForegroundColor Red
  exit 1
}

# Install
Write-Host "→ Installing via npm..."
if ($VERSION -eq "latest") {
  npm install -g $PACKAGE
} else {
  npm install -g "${PACKAGE}@${VERSION}"
}

# Verify
$aidr = Get-Command aidr -ErrorAction SilentlyContinue
if ($aidr) {
  Write-Host ""
  Write-Host "✅ AIDR installed!" -ForegroundColor Green
  & aidr --version
  Write-Host ""
  Write-Host "→ Engine stats:"
  & aidr scan stats
  Write-Host ""
  Write-Host "🛡️  AIDR is installed and ready."
  Write-Host "   Docs: https://aidr.dev"
  Write-Host "   Trust: https://aidr.dev/trust"
} else {
  Write-Host ""
  Write-Host "⚠️  aidr not in PATH. Try:" -ForegroundColor Yellow
  Write-Host "   - Restart your PowerShell"
  Write-Host "   - Add npm global bin to PATH"
  Write-Host "   - Run with: npx $PACKAGE --version"
}
