[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$ExpectedManifestSha256,
    [Parameter(Mandatory)][string]$TargetHome,
    [string]$StateRoot = (Join-Path $env:ProgramData 'SingularityAIDR/Fleet'),
    [string]$LogPath
)

$installer = Join-Path $PSScriptRoot 'Install-Aidr.ps1'
$arguments = @{
    ManifestPath = $ManifestPath
    ExpectedManifestSha256 = $ExpectedManifestSha256
    TargetHome = $TargetHome
    StateRoot = $StateRoot
    RequireUpgrade = $true
}
if (-not [string]::IsNullOrWhiteSpace($LogPath)) { $arguments.LogPath = $LogPath }
& $installer @arguments
exit $LASTEXITCODE
