<#
.SYNOPSIS
Removes the AIDR maintenance Scheduled Tasks registered by Install-AidrMaintenanceTasks.ps1.

.DESCRIPTION
Unregisters \AIDR\aidr-siem-delivery and \AIDR\aidr-export-retention, removes
the \AIDR\ task folder when it is empty, revokes the file access granted to the
recorded service account, and deletes the deployment's Windows maintenance
declaration. Evidence files are left in place: the dashboard's freshness
checks turn them red once the workers stop. Running it again is a no-op.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DeploymentDirectory
)

. (Join-Path $PSScriptRoot 'AidrMaintenanceTasks.Common.ps1')

try {
    Assert-AidrElevatedWindows
    $deployment = Resolve-AidrMaintenanceDirectory -Path $DeploymentDirectory -Label 'DeploymentDirectory'
    foreach ($definition in Get-AidrMaintenanceTaskDefinitions) {
        $task = Get-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName $definition.Name -ErrorAction SilentlyContinue
        if ($null -ne $task) {
            Stop-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName $definition.Name -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName $definition.Name -Confirm:$false
        }
    }

    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    try {
        $folder = $scheduler.GetFolder($script:AidrMaintenanceTaskPath.TrimEnd('\'))
        if ($folder.GetTasks(1).Count -eq 0 -and $folder.GetFolders(0).Count -eq 0) { $scheduler.GetFolder('\').DeleteFolder('AIDR', 0) }
    } catch [Runtime.InteropServices.COMException] {
        # The folder does not exist; nothing to remove.
    }

    $declarationPath = Get-AidrMaintenanceDeclarationPath $deployment
    if (Test-Path -LiteralPath $declarationPath -PathType Leaf) {
        $declaration = Get-Content -LiteralPath $declarationPath -Raw | ConvertFrom-Json
        if ([string]$declaration.principal -ne 'LocalSystem' -and -not [string]::IsNullOrWhiteSpace([string]$declaration.principal)) {
            $sid = ([Security.Principal.NTAccount]::new([string]$declaration.principal)).Translate([Security.Principal.SecurityIdentifier]).Value
            foreach ($path in @($declaration.granted_paths)) {
                if (Test-Path -LiteralPath ([string]$path)) { Invoke-AidrIcacls @([string]$path, '/remove:g', "*$sid") }
            }
        }
        Remove-Item -LiteralPath $declarationPath -Force
    }
    Write-Output "AIDR maintenance tasks removed from $($script:AidrMaintenanceTaskPath). Readiness evidence will go stale and fail its freshness checks."
    exit 0
} catch {
    Write-Error "AIDR maintenance task removal failed: $($_.Exception.Message)"
    exit 1
}
