# Removes the per-user AIDR Privacy companion: the HKCU native messaging registrations that point
# at its manifest (Chrome, Edge, Chromium; another product's registration is left alone) and its
# install directory (only when it holds the companion's install.json receipt). No admin rights.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File uninstall-companion.ps1 [-InstallDir <dir>] [-KeepFiles] [-Json]
[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$Node,
    [switch]$KeepFiles,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
$cli = Join-Path $PSScriptRoot '..\..\dist\companion\cli.js'
if (-not (Test-Path -LiteralPath $cli)) { throw "BUILD_REQUIRED: $cli" }
if (-not $Node) { $Node = (Get-Command node -ErrorAction SilentlyContinue).Source }
if (-not $Node) { throw 'NODE_MISSING: pass -Node' }
$arguments = @($cli, 'uninstall')
if ($InstallDir) { $arguments += @('--install-dir', $InstallDir) }
if ($KeepFiles) { $arguments += '--keep-files' }
if ($Json) { $arguments += '--json' }
& $Node @arguments
exit $LASTEXITCODE
