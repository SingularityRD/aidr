[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$ExpectedThumbprint,
    [string]$ScriptRoot
)

if (-not $ScriptRoot) { $ScriptRoot = $PSScriptRoot }
. (Join-Path $PSScriptRoot 'Common.ps1')

try {
    $count = Assert-AidrFleetScriptAuthenticodeSignatures -ScriptRoot $ScriptRoot -ExpectedThumbprint $ExpectedThumbprint
    Write-Output "Verified Authenticode signatures for $count Windows fleet PowerShell scripts."
    exit 0
} catch {
    Write-Error "Fleet Authenticode preflight failed closed: $($_.Exception.Message)"
    exit 1
}
