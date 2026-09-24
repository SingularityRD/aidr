[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetHome,
    [string]$StateRoot = (Join-Path $env:ProgramData 'SingularityAIDR/Fleet'),
    [string]$LogPath,
    [switch]$RemoveAgentConfig
)

. (Join-Path $PSScriptRoot 'Common.ps1')

try {
    $target = Get-AidrValidatedTargetHome $TargetHome
    $paths = Get-AidrFleetPaths -TargetHome $target -StateRoot $StateRoot
    if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = $paths.DefaultLog }
    $settingsPath = Join-Path $target '.claude/settings.json'
    if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
        $settingsBytes = [IO.File]::ReadAllBytes($settingsPath)
        try { $settings = [Text.UTF8Encoding]::new($false, $true).GetString($settingsBytes) | ConvertFrom-Json } catch { throw "Claude settings are invalid; no configuration was changed" }
        $removed = 0
        if ($null -ne $settings.hooks) {
            foreach ($event in @('PreToolUse', 'PostToolUse', 'SessionStart')) {
                $eventProperty = $settings.hooks.PSObject.Properties[$event]
                if ($null -eq $eventProperty -or $null -eq $eventProperty.Value) { continue }
                $kept = @()
                foreach ($entry in @($eventProperty.Value)) {
                    if ($null -eq $entry -or $null -eq $entry.hooks) { $kept += $entry; continue }
                    $hooks = @($entry.hooks)
                    $remaining = @($hooks | Where-Object {
                        $status = if ($null -ne $_) { $_.PSObject.Properties['statusMessage'] } else { $null }
                        $null -eq $status -or [string]$status.Value -ne 'Singularity AIDR managed installation'
                    })
                    if ($remaining.Count -eq $hooks.Count) { $kept += $entry; continue }
                    $removed += $hooks.Count - $remaining.Count
                    if ($remaining.Count -gt 0) {
                        $entry.hooks = $remaining
                        $kept += $entry
                    }
                }
                $eventProperty.Value = @($kept)
            }
        }
        if ($removed -gt 0) {
            Assert-AidrJsonDepth $settings
            $parent = Split-Path -Parent $settingsPath
            Assert-AidrFileUnchanged -Path $settingsPath -OriginalBytes $settingsBytes
            $backup = Join-Path $parent ("settings.json.aidr-uninstall-backup-{0}" -f [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
            Copy-Item -LiteralPath $settingsPath -Destination $backup
            $temporary = Join-Path $parent ("settings.{0}.tmp" -f [Guid]::NewGuid().ToString('N'))
            try {
                [IO.File]::WriteAllText($temporary, (($settings | ConvertTo-Json -Depth 100) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
                Assert-AidrFileUnchanged -Path $settingsPath -OriginalBytes $settingsBytes
                $replaceBackup = Join-Path $parent ("settings.{0}.replace-backup" -f [Guid]::NewGuid().ToString('N'))
                [IO.File]::Replace($temporary, $settingsPath, $replaceBackup)
                [IO.File]::Delete($replaceBackup)
            } finally {
                if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
            }
        }
    }
    if ($RemoveAgentConfig) {
        $configPath = Join-Path $target '.singularity-aidr/config.json'
        if (Test-Path -LiteralPath $configPath -PathType Leaf) {
            $preserved = "$configPath.removed-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
            Move-Item -LiteralPath $configPath -Destination $preserved
        }
    }
    $state = Read-AidrFleetState $paths.State
    if ($null -ne $state) {
        $state.installed = $false
        $state | Add-Member -NotePropertyName uninstalled_at -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
        Write-AidrFleetState -Path $paths.State -Value $state
    }
    Write-AidrFleetLog -LogPath $LogPath -Event 'uninstall.completed' -Fields @{ target_id = $paths.TargetId; result = $(if ($RemoveAgentConfig) { 'config_preserved_as_removed_file' } else { 'config_preserved' }) }
    Write-Output "AIDR managed hooks removed. Cached packages and configuration were preserved for recovery."
    exit 0
} catch {
    try { Write-AidrFleetLog -LogPath $LogPath -Event 'uninstall.failed' -Level error -Fields @{ result = 'failed_closed' } } catch { }
    Write-Error "AIDR uninstall failed closed: $($_.Exception.Message)"
    exit 1
}
