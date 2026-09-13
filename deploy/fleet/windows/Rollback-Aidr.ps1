[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetHome,
    [string]$StateRoot = (Join-Path $env:ProgramData 'SingularityAIDR/Fleet'),
    [string]$LogPath
)

. (Join-Path $PSScriptRoot 'Common.ps1')

try {
    $target = Get-AidrValidatedTargetHome $TargetHome
    $paths = Get-AidrFleetPaths -TargetHome $target -StateRoot $StateRoot
    if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = $paths.DefaultLog }
    $state = Read-AidrFleetState $paths.State
    if ($null -eq $state -or $state.installed -ne $true -or $null -eq $state.active) { throw "No active fleet installation exists" }
    $candidate = @($state.history) | Select-Object -First 1
    if ($null -eq $candidate) { throw "No verified rollback candidate is retained" }
    if (-not (Test-AidrSha256 ([string]$candidate.manifest_sha256))) { throw "Rollback state has an invalid manifest digest" }
    $candidateManifest = [string]$candidate.cached_manifest
    $cachePrefix = [IO.Path]::GetFullPath($paths.Cache).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($candidateManifest).StartsWith($cachePrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Rollback manifest is outside the protected fleet cache" }
    Write-AidrFleetLog -LogPath $LogPath -Event 'rollback.started' -Fields @{ target_id = $paths.TargetId; version = [string]$candidate.package_version; manifest_sha256 = [string]$candidate.manifest_sha256 }
    $installer = Join-Path $PSScriptRoot 'Install-Aidr.ps1'
    & $installer -ManifestPath $candidateManifest -ExpectedManifestSha256 ([string]$candidate.manifest_sha256) -TargetHome $target -StateRoot $StateRoot -LogPath $LogPath -AllowDowngrade
    if ($LASTEXITCODE -ne 0) { throw "Verified rollback candidate could not be installed" }
    Write-AidrFleetLog -LogPath $LogPath -Event 'rollback.completed' -Fields @{ target_id = $paths.TargetId; version = [string]$candidate.package_version; result = 'local_canary_deny' }
    exit 0
} catch {
    try { Write-AidrFleetLog -LogPath $LogPath -Event 'rollback.failed' -Level error -Fields @{ result = 'failed_closed' } } catch { }
    Write-Error "AIDR rollback failed closed: $($_.Exception.Message)"
    exit 1
}
