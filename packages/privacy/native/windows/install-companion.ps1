# Per-user installer of the AIDR Privacy companion (Browser Guard native host + Windows OCR).
# No administrator rights: writes only %LOCALAPPDATA%\SingularityAIDR\PrivacyCompanion and
# HKCU\Software\{Google\Chrome,Microsoft\Edge}\NativeMessagingHosts\com.singularity.aidr_privacy.
# It reads (never writes) the Chrome/Edge profile Preferences to find Browser Guard's extension id.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File install-companion.ps1 [-ExtensionId <id>] [-UnpackedPath <dir>] [-Json]
#
# Needs Node.js >= 22.16 and Python >= 3.11 (per-user python.org install is fine). The only
# download is pip with --require-hashes from vision/requirements.lock.txt (Pillow, pyzbar).
[CmdletBinding()]
param(
    [string[]]$ExtensionId = @(),
    [string]$UnpackedPath,
    [string]$InstallDir,
    [string]$Node,
    [string]$Python,
    [ValidateSet('chrome', 'edge', 'chromium')][string[]]$Browser = @('chrome', 'edge'),
    [switch]$NoOcr,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
$cli = Join-Path $PSScriptRoot '..\..\dist\companion\cli.js'
if (-not (Test-Path -LiteralPath $cli)) { throw "BUILD_REQUIRED: $cli (pnpm --filter @singularityrd/aidr-privacy build)" }
if (-not $Node) { $Node = (Get-Command node -ErrorAction SilentlyContinue).Source }
if (-not $Node) { throw 'NODE_MISSING: install Node.js 22.16 or newer, or pass -Node' }
$version = & $Node -p 'process.versions.node'
$parts = $version.Split('.') | ForEach-Object { [int]$_ }
if ($parts[0] -lt 22 -or ($parts[0] -eq 22 -and $parts[1] -lt 16)) { throw "NODE_TOO_OLD: $version (22.16 or newer required)" }
$arguments = @($cli, 'install', '--node', $Node, '--browser', ($Browser -join ','))
foreach ($id in $ExtensionId) { $arguments += @('--extension-id', $id) }
if ($UnpackedPath) { $arguments += @('--unpacked-path', $UnpackedPath) }
if ($InstallDir) { $arguments += @('--install-dir', $InstallDir) }
if ($Python) { $arguments += @('--python', $Python) }
if ($NoOcr) { $arguments += '--no-ocr' }
if ($Json) { $arguments += '--json' }
& $Node @arguments
exit $LASTEXITCODE
