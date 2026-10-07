Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows Task Scheduler mirror of the systemd units in this directory. The task
# folder and names are fixed: scripts/deployment-doctor.mjs queries exactly
# these names, so do not rename them per host.
$script:AidrMaintenanceTaskPath = '\AIDR\'
$script:AidrMaintenanceDeclarationName = 'windows-maintenance-tasks.json'

function Get-AidrMaintenanceTaskDefinitions {
    # Each entry mirrors one <name>.timer / <name>.service pair.
    return @(
        [pscustomobject]@{
            Name = 'aidr-siem-delivery'
            Description = 'AIDR signing, durable queue and SIEM maintenance (mirrors aidr-siem-delivery.timer: 30s after boot, then every minute)'
            Worker = 'readiness-evidence-worker.mjs'
            TimeLimit = New-TimeSpan -Minutes 5
        },
        [pscustomobject]@{
            Name = 'aidr-export-retention'
            Description = 'AIDR expired audit export cleanup (mirrors aidr-export-retention.timer: hourly with up to 5 minutes random delay)'
            Worker = 'deployment-maintenance.mjs'
            TimeLimit = New-TimeSpan -Minutes 15
        }
    )
}

function Assert-AidrElevatedWindows {
    if ($env:OS -ne 'Windows_NT') { throw 'AIDR maintenance tasks are registered with Windows Task Scheduler and must run on Windows' }
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Registering AIDR maintenance tasks requires an elevated administrator session'
    }
}

function Resolve-AidrMaintenanceDirectory {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    if (-not [IO.Path]::IsPathRooted($Path)) { throw "$Label must be an explicit absolute path" }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath.TrimEnd('\', '/')
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { throw "$Label must be an existing directory" }
    if ($resolved.Equals([IO.Path]::GetPathRoot($resolved).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) { throw "$Label cannot be a filesystem root" }
    # Task Scheduler stores the action as one argument string; a quote would split it.
    if ($resolved.Contains('"')) { throw "$Label cannot contain a quote character" }
    return $resolved
}

function Get-AidrMaintenanceDeclarationPath {
    param([Parameter(Mandatory)][string]$DeploymentDirectory)
    return Join-Path $DeploymentDirectory $script:AidrMaintenanceDeclarationName
}

function Invoke-AidrIcacls {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    $output = & $icacls @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for '$($Arguments[0])': $($output -join ' ')" }
}
