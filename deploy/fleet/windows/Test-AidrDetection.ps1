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
    foreach ($bundle in @('pre-tool-use.cjs', 'pre-tool-use.bundle.cjs', 'post-tool-use.cjs', 'post-tool-use.bundle.cjs', 'session-start.cjs', 'session-start.bundle.cjs')) {
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
    Assert-AidrSettingsShape $settings
    if ((Get-AidrProperty $settings 'disableAllHooks') -eq $true) { throw "Claude hooks are globally disabled" }
    $node = (Get-Command node.exe -ErrorAction Stop).Source
    $managedCount = 0
    $eventBundles = [ordered]@{ PreToolUse = @('pre-tool-use.cjs', 15); PostToolUse = @('post-tool-use.cjs', 5); SessionStart = @('session-start.cjs', 30) }
    foreach ($event in $eventBundles.Keys) {
        $stage = "hook_registration_$event"
        $managed = @($settings.hooks.$event | Where-Object { $_.hooks | Where-Object { (Get-AidrProperty $_ 'statusMessage') -ceq 'Singularity AIDR managed installation' } })
        if ($managed.Count -ne 1) { throw "Managed hook registration is missing or duplicated" }
        $stage = "hook_command_$event"
        # Windows PowerShell can expand an 8.3 path when reading the receipt,
        # while Node preserves the spelling originally passed on the command
        # line. Build the command form from the protected target-home state.
        $commandConnectorPath = Join-Path ([string]$state.target_home) ".singularity-aidr/connectors/claude/$([string]$state.active.connector_digest)"
        $expectedBundlePath = Join-Path $commandConnectorPath "dist/$($eventBundles[$event][0])"
        $hooks = @($managed[0].hooks | Where-Object { (Get-AidrProperty $_ 'statusMessage') -ceq 'Singularity AIDR managed installation' })
        if ($hooks.Count -ne 1 -or -not (Test-AidrManagedHookRegistration -Entry $managed[0] -Hook $hooks[0] -NodePath $node -BundlePath $expectedBundlePath -Event $event -Timeout $eventBundles[$event][1])) {
            throw "Managed hook command does not point to the active connector"
        }
        $managedCount += $managed.Count
    }
    $responseWorker = 'not_configured'
    $runtimePath = Join-Path $target '.singularity-aidr/config.json'
    $responseRequired = $false
    if (Test-Path -LiteralPath $runtimePath -PathType Leaf) {
        try { $runtime = Get-Content -LiteralPath $runtimePath -Raw -Encoding utf8 | ConvertFrom-Json }
        catch { throw 'Agent configuration is invalid' }
        $controlPlane = Get-AidrProperty $runtime 'control_plane'
        if ($null -ne $controlPlane) { $responseRequired = (Get-AidrProperty $controlPlane 'response_worker_required') -eq $true }
    }
    if ($responseRequired -or (Test-Path -LiteralPath (Join-Path $target '.singularity-aidr/response-control/config.json'))) {
        $stage = 'response_worker'
        $responseContext = Get-AidrResponseWorkerContext -TargetHome $target -StateRoot $StateRoot
        $responseTask = Get-ScheduledTask -TaskPath $responseContext.TaskPath -TaskName $responseContext.TaskName -ErrorAction Stop
        Assert-AidrResponseTaskOwnership -Task $responseTask -Context $responseContext
        if ($responseTask.State -eq 'Disabled' -or [string]$responseTask.Actions[0].Arguments -cne ('"' + $responseContext.Worker + '"')) { throw 'The required response task is disabled or does not use the active connector' }
        Invoke-AidrResponseWorkerProvisioning -Context $responseContext -Mode '--validate'
        $responseWorker = 'configured_native_acceptance_unverified'
    }
    $result = [ordered]@{ detected = $true; version = [string]$state.active.package_version; manifest_sha256 = [string]$state.active.manifest_sha256; artifact_sha256 = [string]$state.active.artifact_sha256; managed_hook_events = $managedCount; response_worker = $responseWorker; host_execution = 'unverified' }
    if ($Json) { $result | ConvertTo-Json -Compress } else { Write-Output "Singularity AIDR $($result.version) detected" }
    exit 0
} catch {
    if ($Json) { [ordered]@{ detected = $false; reason = 'local_installation_validation_failed'; stage = $stage } | ConvertTo-Json -Compress }
    exit 1
}
