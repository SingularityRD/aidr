[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$ExpectedManifestSha256,
    [Parameter(Mandatory)][string]$TargetHome,
    [string]$StateRoot = (Join-Path $env:ProgramData 'SingularityAIDR/Fleet'),
    [string]$LogPath,
    [switch]$RequireUpgrade,
    [switch]$AllowDowngrade
)

. (Join-Path $PSScriptRoot 'Common.ps1')

$target = Get-AidrValidatedTargetHome $TargetHome
$paths = Get-AidrFleetPaths -TargetHome $target -StateRoot $StateRoot
if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = $paths.DefaultLog }
$manifestRecord = $null
try {
    Initialize-AidrFleetStateRoot -StateRoot $paths.Root
    $manifestRecord = Read-AidrFleetManifest -ManifestPath $ManifestPath -ExpectedManifestSha256 $ExpectedManifestSha256
    $payload = Assert-AidrManifestPayload $manifestRecord
    $state = Read-AidrFleetState $paths.State
    $newVersion = [version]$manifestRecord.Value.package_version
    if ($null -ne $state -and $null -ne $state.active) {
        $currentVersion = [version]$state.active.package_version
        if ($RequireUpgrade -and $newVersion -le $currentVersion) { throw "Update package must have a newer semantic version" }
        if (-not $AllowDowngrade -and $newVersion -lt $currentVersion) { throw "Downgrade refused; use the rollback workflow" }
    } elseif ($RequireUpgrade) { throw "No active fleet installation exists to update" }

    Write-AidrFleetLog -LogPath $LogPath -Event 'install.started' -Fields @{ version = $newVersion; target_id = $paths.TargetId; manifest_sha256 = $manifestRecord.Sha256 }
    [IO.Directory]::CreateDirectory($paths.Cache) | Out-Null
    $cachedManifest = Copy-AidrManifestPackageToCache -ManifestRecord $manifestRecord -Payload $payload -CacheRoot $paths.Cache
    $cachedRecord = Read-AidrFleetManifest -ManifestPath $cachedManifest -ExpectedManifestSha256 $manifestRecord.Sha256
    $cachedPayload = Assert-AidrManifestPayload $cachedRecord
    $result = Invoke-AidrEndpointInstaller -ManifestRecord $cachedRecord -Payload $cachedPayload -TargetHome $target
    $connectorFiles = @(Get-AidrConnectorInventory -ConnectorPath $result.ConnectorPath)

    $history = @()
    if ($null -ne $state -and $null -ne $state.active -and [string]$state.active.manifest_sha256 -ne $manifestRecord.Sha256) { $history += $state.active }
    if ($null -ne $state -and $null -ne $state.history) { $history += @($state.history) }
    $history = @($history | Group-Object manifest_sha256 | ForEach-Object { $_.Group[0] } | Select-Object -First 3)
    $active = [ordered]@{
        package_version = [string]$manifestRecord.Value.package_version
        manifest_sha256 = $manifestRecord.Sha256
        cached_manifest = $cachedManifest
        artifact_sha256 = [string]$manifestRecord.Value.artifact.sha256
        connector_digest = $result.ConnectorDigest
        connector_path = $result.ConnectorPath
        connector_files = $connectorFiles
        signer_thumbprint = $cachedPayload.SignerThumbprint
        installed_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $newState = [ordered]@{
        schema_version = 1
        product = 'singularity-aidr'
        target_id = $paths.TargetId
        target_home = $target
        installed = $true
        active = $active
        history = $history
    }
    Write-AidrFleetState -Path $paths.State -Value $newState
    Write-AidrFleetLog -LogPath $LogPath -Event 'install.completed' -Fields @{ version = $newVersion; target_id = $paths.TargetId; artifact_sha256 = $active.artifact_sha256; result = 'local_canary_deny' }
    Write-Output "AIDR fleet installation completed; local deny canary passed. Native host acceptance remains required."
    exit 0
} catch {
    $manifestSha = if ($null -ne $manifestRecord) { $manifestRecord.Sha256 } else { '' }
    try { Write-AidrFleetLog -LogPath $LogPath -Event 'install.failed' -Level error -Fields @{ target_id = $paths.TargetId; manifest_sha256 = $manifestSha; result = 'failed_closed' } } catch { }
    Write-Error "AIDR fleet installation failed closed: $($_.Exception.Message)"
    exit 1
}
