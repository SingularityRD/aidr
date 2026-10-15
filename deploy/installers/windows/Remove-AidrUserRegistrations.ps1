<#
.SYNOPSIS
  Remove the Singularity AIDR hook registrations of the CURRENT Windows user after
  AIDR was uninstalled from the machine.

.DESCRIPTION
  The MSI uninstall runs `aidr uninstall` for the user who uninstalls. Every other
  profile on a shared machine still has hook entries that point at the removed
  aidr.exe. The uninstall therefore registers this script (installed permanently
  under Program Files\Singularity AIDR\cleanup) as an Active Setup component:
  Windows runs it once for every user at their next logon, AS THAT USER, so no
  privileged process ever edits files inside a user profile.

  It removes only what AIDR registered:
    ~/.claude/settings.json  hook handlers whose statusMessage is
                             "Singularity AIDR managed installation"
    ~/.codex/hooks.json      hook handlers whose command names aidr-codex-hook
  Every other key, hook and setting stays. A file that changes, is not valid JSON
  or is a link is left untouched and reported. The previous content is kept next
  to the file as <name>.aidr-uninstall-backup-<unix ms>.

  When AIDR is installed again (aidr.exe present under the install folder) it does
  nothing: the reinstalled product owns the registrations.

  Fleet use: the same script can run as each user from Intune ("run this script
  using the logged on credentials"), a GPO logon script or any tool that runs in
  the user's context. It never needs administrator rights.

.PARAMETER InstallFolder
  The AIDR install folder whose bundle\bin\aidr.exe means "installed" (default: the
  per-machine location).
#>
[CmdletBinding()]
param(
    [string]$InstallFolder = (Join-Path ${env:ProgramFiles} 'Singularity AIDR')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Marker = 'Singularity AIDR managed installation'
$CodexHook = '\baidr-codex-hook\b'

function Write-AidrCleanupLog([string]$Message) {
    Write-Output "Singularity AIDR cleanup: $Message"
}

function Test-AidrLinkFree([string]$Path, [string]$Root) {
    $candidate = [IO.Path]::GetFullPath($Path)
    $stop = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    while ($candidate.Length -ge $stop.Length) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        }
        if ($candidate -ieq $stop) { break }
        $candidate = Split-Path -Parent $candidate
    }
    return $true
}

<#
  Drop the handlers $IsOurs matches from a { "hooks": { "<Event>": [ { "hooks": [ ... ] } ] } }
  document. Returns the number removed; empty groups and events are dropped.
#>
function Remove-AidrHandlers($Document, [scriptblock]$IsOurs) {
    $hooksProperty = $Document.PSObject.Properties['hooks']
    if ($null -eq $hooksProperty -or $null -eq $hooksProperty.Value) { return 0 }
    if ($hooksProperty.Value -isnot [Management.Automation.PSCustomObject]) { throw 'hooks is not an object' }
    $removed = 0
    foreach ($eventProperty in @($hooksProperty.Value.PSObject.Properties)) {
        $kept = @()
        foreach ($group in @($eventProperty.Value)) {
            $handlersProperty = if ($null -ne $group -and $group -is [Management.Automation.PSCustomObject]) { $group.PSObject.Properties['hooks'] } else { $null }
            if ($null -eq $handlersProperty -or $null -eq $handlersProperty.Value) { $kept += , $group; continue }
            $handlers = @($handlersProperty.Value)
            $remaining = @($handlers | Where-Object { -not (& $IsOurs $_) })
            if ($remaining.Count -eq $handlers.Count) { $kept += , $group; continue }
            $removed += $handlers.Count - $remaining.Count
            if ($remaining.Count -gt 0) { $group.hooks = $remaining; $kept += , $group }
        }
        if ($kept.Count -gt 0) { $eventProperty.Value = $kept } else { $hooksProperty.Value.PSObject.Properties.Remove($eventProperty.Name) }
    }
    return $removed
}

function Update-AidrHookFile([string]$Path, [scriptblock]$IsOurs, [string]$Label) {
    if (-not [IO.File]::Exists($Path)) { return }
    if (-not (Test-AidrLinkFree $Path $HOME)) { Write-AidrCleanupLog "$Label is behind a link; left unchanged."; return }
    $original = [IO.File]::ReadAllBytes($Path)
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($original)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
        $document = $text | ConvertFrom-Json
    } catch {
        Write-AidrCleanupLog "$Label is not valid JSON; left unchanged."
        return
    }
    if ($document -isnot [Management.Automation.PSCustomObject]) { Write-AidrCleanupLog "$Label is not a JSON object; left unchanged."; return }
    try { $removed = Remove-AidrHandlers $document $IsOurs } catch { Write-AidrCleanupLog "$Label has an unexpected hooks shape; left unchanged."; return }
    if ($removed -eq 0) { return }
    $backup = '{0}.aidr-uninstall-backup-{1}' -f $Path, [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    [IO.File]::WriteAllBytes($backup, $original)
    $temporary = '{0}.{1}.tmp' -f $Path, [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText($temporary, (($document | ConvertTo-Json -Depth 100) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
        $current = [IO.File]::ReadAllBytes($Path)
        if (-not [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($current, $original)) { Write-AidrCleanupLog "$Label changed while it was read; left unchanged."; return }
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
    Write-AidrCleanupLog "removed $removed AIDR hook registration(s) from $Label (backup: $backup)."
}

if ([IO.File]::Exists((Join-Path $InstallFolder 'bundle\bin\aidr.exe'))) {
    Write-AidrCleanupLog 'AIDR is installed on this machine; nothing to clean up.'
    exit 0
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.IsWellKnown([Security.Principal.WellKnownSidType]::LocalSystemSid)) {
    Write-AidrCleanupLog 'runs only as the user whose profile it cleans, never as SYSTEM.'
    exit 0
}
Update-AidrHookFile (Join-Path $HOME '.claude\settings.json') {
    param($handler)
    $status = if ($null -ne $handler -and $handler -is [Management.Automation.PSCustomObject]) { $handler.PSObject.Properties['statusMessage'] } else { $null }
    $null -ne $status -and [string]$status.Value -ceq $Marker
} 'Claude Code settings'
Update-AidrHookFile (Join-Path $HOME '.codex\hooks.json') {
    param($handler)
    $command = if ($null -ne $handler -and $handler -is [Management.Automation.PSCustomObject]) { $handler.PSObject.Properties['command'] } else { $null }
    $null -ne $command -and [string]$command.Value -match $CodexHook
} 'Codex hooks'
exit 0
