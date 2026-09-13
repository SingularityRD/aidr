[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetHome,
    [string]$StateRoot = (Join-Path $env:ProgramData 'SingularityAIDR/Fleet'),
    [switch]$Json
)

. (Join-Path $PSScriptRoot 'Common.ps1')

$stage = 'target'
try {
    $target = Get-AidrValidatedTargetHome $TargetHome
    $paths = Get-AidrFleetPaths -TargetHome $target -StateRoot $StateRoot
    $stage = 'state'
    $state = Read-AidrFleetState $paths.State
    if ($null -eq $state -or $state.schema_version -ne 1 -or $state.product -ne 'singularity-aidr' -or $state.installed -ne $true -or $null -eq $state.active) { throw "Fleet state does not report an active installation" }
    if (-not (Test-AidrSha256 ([string]$state.active.manifest_sha256))) { throw "Active manifest digest is invalid" }
    $manifestPath = [string]$state.active.cached_manifest
    $cachePrefix = [IO.Path]::GetFullPath($paths.Cache).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not [IO.Path]::GetFullPath($manifestPath).StartsWith($cachePrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Active manifest is outside the fleet cache" }
    $stage = 'package'
    $record = Read-AidrFleetManifest -ManifestPath $manifestPath -ExpectedManifestSha256 ([string]$state.active.manifest_sha256)
    $payload = Assert-AidrManifestPayload $record
    if (-not (Test-AidrFixedStringEqual ([string]$state.active.artifact_sha256) ([string]$record.Value.artifact.sha256))) { throw "Fleet state artifact does not match its manifest" }
    $receiptPath = Join-Path $target '.singularity-aidr/installation.json'
    $stage = 'receipt'
    try { $receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding utf8 | ConvertFrom-Json } catch { throw "Endpoint receipt is missing or invalid" }
    if ([string]$receipt.connector -ne 'claude-code' -or [string]$receipt.local_canary -ne 'deny' -or -not (Test-AidrFixedStringEqual ([string]$receipt.artifact_sha256) ([string]$state.active.connector_digest))) { throw "Endpoint receipt does not match active fleet state" }
    $connectorPath = [IO.Path]::GetFullPath([string]$receipt.path)
    if (-not $connectorPath.Equals([IO.Path]::GetFullPath([string]$state.active.connector_path), [StringComparison]::OrdinalIgnoreCase)) { throw "Endpoint receipt path does not match active fleet state" }
    foreach ($bundle in @('pre-tool-use.cjs', 'post-tool-use.cjs', 'session-start.cjs')) {
        if (-not (Test-Path -LiteralPath (Join-Path $connectorPath "dist/$bundle") -PathType Leaf)) { throw "Managed connector bundle is missing" }
    }
    $stage = 'installed_files'
    $expectedInventory = @($state.active.connector_files)
    $actualInventory = @(Get-AidrConnectorInventory -ConnectorPath $connectorPath)
    if ($expectedInventory.Count -eq 0 -or $expectedInventory.Count -ne $actualInventory.Count) { throw "Managed connector inventory does not match fleet state" }
    for ($index = 0; $index -lt $expectedInventory.Count; $index++) {
        if ([string]$expectedInventory[$index].path -ne [string]$actualInventory[$index].path -or -not (Test-AidrFixedStringEqual ([string]$expectedInventory[$index].sha256) ([string]$actualInventory[$index].sha256))) {
            throw "Managed connector file integrity check failed"
        }
    }
    $settingsPath = Join-Path $target '.claude/settings.json'
    $stage = 'hook_registration'
    try { $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding utf8 | ConvertFrom-Json } catch { throw "Claude settings are missing or invalid" }
    $managedCount = 0
    $eventBundles = [ordered]@{ PreToolUse = 'pre-tool-use.cjs'; PostToolUse = 'post-tool-use.cjs'; SessionStart = 'session-start.cjs' }
    foreach ($event in $eventBundles.Keys) {
        $stage = "hook_registration_$event"
        $managed = @($settings.hooks.$event | Where-Object { $_.hooks | Where-Object { $_.statusMessage -eq 'Singularity AIDR managed installation' } })
        if ($managed.Count -ne 1) { throw "Managed hook registration is missing or duplicated" }
        $stage = "hook_command_$event"
        # Windows PowerShell can expand an 8.3 path when reading the receipt,
        # while Node preserves the spelling originally passed on the command
        # line. Build the command form from the protected target-home state.
        $commandConnectorPath = Join-Path ([string]$state.target_home) ".singularity-aidr/connectors/claude/$([string]$state.active.connector_digest)"
        $expectedBundlePath = (Join-Path $commandConnectorPath "dist/$($eventBundles[$event])").Replace('\', '/')
        $commands = @($managed[0].hooks | Where-Object { $_.statusMessage -eq 'Singularity AIDR managed installation' } | ForEach-Object { [string]$_.command })
        if ($commands.Count -ne 1 -or $commands[0].IndexOf(('"' + $expectedBundlePath + '"'), [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw "Managed hook command does not point to the active connector"
        }
        $managedCount += $managed.Count
    }
    $result = [ordered]@{ detected = $true; version = [string]$state.active.package_version; manifest_sha256 = [string]$state.active.manifest_sha256; artifact_sha256 = [string]$state.active.artifact_sha256; managed_hook_events = $managedCount; host_execution = 'unverified' }
    if ($Json) { $result | ConvertTo-Json -Compress } else { Write-Output "Singularity AIDR $($result.version) detected" }
    exit 0
} catch {
    if ($Json) { [ordered]@{ detected = $false; reason = 'local_installation_validation_failed'; stage = $stage } | ConvertTo-Json -Compress }
    exit 1
}
