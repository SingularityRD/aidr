[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetHome,
    [string]$StateRoot = (Join-Path $env:ProgramData 'SingularityAIDR/Fleet'),
    [string]$ResponseWorkerConfigPath,
    [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedResponseWorkerConfigSha256,
    [switch]$RunElevated
)

. (Join-Path $PSScriptRoot 'Common.ps1')
try {
    $context = Get-AidrResponseWorkerContext -TargetHome $TargetHome -StateRoot $StateRoot
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($RunElevated -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated network response requires the enrolled user to be an administrator and the installer to run elevated' }
    $inputJson = $null
    if (-not [string]::IsNullOrWhiteSpace($ResponseWorkerConfigPath)) {
        if ([string]::IsNullOrWhiteSpace($ExpectedResponseWorkerConfigSha256)) { throw 'The operator response configuration requires an explicit SHA256 pin' }
        Assert-AidrNoReparsePath $ResponseWorkerConfigPath
        $null = Assert-AidrFileDigest -Path $ResponseWorkerConfigPath -ExpectedSha256 $ExpectedResponseWorkerConfigSha256 -Label 'Response worker operator configuration'
        $bytes = [IO.File]::ReadAllBytes($ResponseWorkerConfigPath)
        if ($bytes.Length -gt 65536) { throw 'Response configuration is too large' }
        $inputJson = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    $existing = Get-AidrResponseScheduledTask -Context $context
    if ($null -ne $existing) { Assert-AidrResponseTaskOwnership -Task $existing -Context $context }
    if (Test-Path -LiteralPath $context.Configuration) {
        Invoke-AidrResponseWorkerProvisioning -Context $context -Mode '--validate' -InputJson $inputJson
    } else {
        if ($null -eq $inputJson) { throw 'First response worker activation requires the pinned operator trust, enrollment and recovery configuration' }
        Invoke-AidrResponseWorkerProvisioning -Context $context -Mode '--initialize' -InputJson $inputJson
        Invoke-AidrResponseWorkerProvisioning -Context $context -Mode '--validate'
    }
    $action = New-ScheduledTaskAction -Execute $context.Node -Argument ('"' + $context.Worker + '"')
    $logon = New-ScheduledTaskTrigger -AtLogOn -User $context.Sid
    $retry = New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $level = if ($RunElevated) { 'Highest' } elseif ($null -ne $existing -and [string]$existing.Principal.RunLevel -eq 'Highest') { 'Highest' } else { 'Limited' }
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $context.Sid -LogonType Interactive -RunLevel $level
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask -Action $action -Trigger @($logon, $retry) -Principal $taskPrincipal -Settings $settings -Description $context.Description
    if ($null -ne $existing) { Stop-ScheduledTask -TaskPath $context.TaskPath -TaskName $context.TaskName -ErrorAction Stop }
    Register-ScheduledTask -TaskPath $context.TaskPath -TaskName $context.TaskName -InputObject $task -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskPath $context.TaskPath -TaskName $context.TaskName -ErrorAction Stop
    Write-Output "AIDR signed response worker registered for the enrolled user ($level). Native execution acceptance remains required."
    exit 0
} catch {
    Write-Error "Response worker installation failed closed: $($_.Exception.Message)"
    exit 1
}
