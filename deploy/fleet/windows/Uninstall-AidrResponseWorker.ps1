[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetHome,
    [string]$StateRoot = (Join-Path $env:ProgramData 'SingularityAIDR/Fleet')
)

. (Join-Path $PSScriptRoot 'Common.ps1')
try {
    $context = Get-AidrResponseWorkerContext -TargetHome $TargetHome -StateRoot $StateRoot
    $task = Get-AidrResponseScheduledTask -Context $context
    if ($null -ne $task) {
        Assert-AidrResponseTaskOwnership -Task $task -Context $context
        Stop-ScheduledTask -TaskPath $context.TaskPath -TaskName $context.TaskName -ErrorAction Stop
    }
    try {
        Invoke-AidrResponseWorkerProvisioning -Context $context -Mode '--validate-safe-removal'
        if ($null -ne $task) { Unregister-ScheduledTask -TaskPath $context.TaskPath -TaskName $context.TaskName -Confirm:$false -ErrorAction Stop }
    } catch {
        if ($null -ne $task) { try { Start-ScheduledTask -TaskPath $context.TaskPath -TaskName $context.TaskName -ErrorAction Stop } catch { } }
        throw
    }
    Write-Output 'AIDR response task removed after authenticated idle and native-state checks. Required-worker configuration, vault and journal were preserved.'
    exit 0
} catch {
    Write-Error "Response worker removal failed closed: $($_.Exception.Message)"
    exit 1
}
