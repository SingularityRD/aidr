<#
.SYNOPSIS
Registers the AIDR maintenance workers as Windows Scheduled Tasks.

.DESCRIPTION
Windows mirror of install-systemd.sh plus the retention reaper timer. It
registers \AIDR\aidr-siem-delivery and \AIDR\aidr-export-retention with the
schedules, commands, working directories and time limits of the systemd units
in this directory. The same readiness inputs are validated first and the
evidence worker is run once through the task before the installer reports
success; a missing key, queue or configuration fails closed and leaves the
task disabled.

With -WithNotifications it also registers \AIDR\aidr-notification-dispatch,
the mirror of install-systemd.sh --with-notifications. The dispatcher token and
notification encryption keys must be present in .env.functions, and the
dispatcher is run once through its task, after the evidence worker, before the
installer reports success.

Re-running is idempotent: tasks are re-registered in place, access grants are
replaced rather than duplicated, and the declaration file is rewritten.

.PARAMETER DeploymentDirectory
Prepared deployment directory (the Windows equivalent of /srv/aidr).

.PARAMETER KitDirectory
Customer kit directory holding scripts/deployment-maintenance.mjs (the Windows
equivalent of /opt/aidr-kit).

.PARAMETER ServiceAccount
Group managed service account (DOMAIN\name$) the tasks run as. It is granted
only the file access the two workers need. Preferred.

.PARAMETER RunAsSystem
Run as LocalSystem, matching the root user of the systemd units. Use only where
no gMSA is available; LocalSystem already has full access to the private
deployment directory.

.PARAMETER NodePath
Node.js 24 or newer executable. Defaults to node.exe on PATH.

.PARAMETER WithNotifications
Also register the alert notification dispatcher (aidr-notification-dispatch),
like install-systemd.sh --with-notifications. Off by default.
#>
[CmdletBinding(DefaultParameterSetName = 'ServiceAccount')]
param(
    [Parameter(Mandatory)][string]$DeploymentDirectory,
    [Parameter(Mandatory)][string]$KitDirectory,
    [Parameter(Mandatory, ParameterSetName = 'ServiceAccount')]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,63}\\[A-Za-z0-9][A-Za-z0-9._-]{0,14}\$$')]
    [string]$ServiceAccount,
    [Parameter(Mandatory, ParameterSetName = 'System')][switch]$RunAsSystem,
    [string]$NodePath,
    [switch]$WithNotifications
)

. (Join-Path $PSScriptRoot 'AidrMaintenanceTasks.Common.ps1')

function Read-AidrEnvironmentFile {
    param([Parameter(Mandatory)][string]$Path)
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^([A-Z][A-Z0-9_]*)=(.*)$') {
            if ($values.ContainsKey($Matches[1])) { throw "$([IO.Path]::GetFileName($Path)) defines $($Matches[1]) more than once" }
            $values[$Matches[1]] = $Matches[2]
        }
    }
    return $values
}

function Test-AidrSamePath {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)
    if (-not [IO.Path]::IsPathRooted($Left)) { return $false }
    return [IO.Path]::GetFullPath($Left).TrimEnd('\', '/').Equals([IO.Path]::GetFullPath($Right).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)
}

function Wait-AidrInitialRun {
    param([Parameter(Mandatory)][string]$TaskName, [Parameter(Mandatory)][TimeSpan]$Timeout)
    $before = (Get-ScheduledTaskInfo -TaskPath $script:AidrMaintenanceTaskPath -TaskName $TaskName).LastRunTime
    Start-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName $TaskName
    $deadline = [DateTime]::UtcNow.Add($Timeout).AddSeconds(30)
    do {
        Start-Sleep -Seconds 2
        $task = Get-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName $TaskName
        $info = Get-ScheduledTaskInfo -TaskPath $script:AidrMaintenanceTaskPath -TaskName $TaskName
        $finished = [string]$task.State -ne 'Running' -and $info.LastRunTime -ne $before
    } until ($finished -or [DateTime]::UtcNow -gt $deadline)
    if (-not $finished) { throw "Initial run of $TaskName did not finish within $Timeout" }
    return [int64]$info.LastTaskResult
}

try {
    Assert-AidrElevatedWindows
    $deployment = Resolve-AidrMaintenanceDirectory -Path $DeploymentDirectory -Label 'DeploymentDirectory'
    $kit = Resolve-AidrMaintenanceDirectory -Path $KitDirectory -Label 'KitDirectory'

    # Same prerequisites install-systemd.sh enforces, plus the retention reaper inputs.
    $readinessEnvPath = Join-Path $deployment '.env.readiness'
    $worker = Join-Path $deployment 'maintenance\readiness-evidence-worker.mjs'
    $retentionScript = Join-Path $kit 'scripts\deployment-maintenance.mjs'
    $secretFiles = @('deployment.json', '.env', '.env.functions', '.env.readiness', 'agent-config.json') | ForEach-Object { Join-Path $deployment $_ }
    foreach ($required in @($secretFiles + @(
        (Join-Path $deployment 'maintenance\aidr-siem-delivery.service'),
        (Join-Path $deployment 'maintenance\aidr-siem-delivery.timer'),
        (Join-Path $deployment 'maintenance\aidr-export-retention.service'),
        (Join-Path $deployment 'maintenance\aidr-export-retention.timer'),
        $worker,
        $retentionScript
    ))) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Prepared maintenance input is missing: $required" }
    }

    $readiness = Read-AidrEnvironmentFile $readinessEnvPath
    $healthDirectory = Join-Path $deployment 'health'
    # The prepared file names the Linux path /srv/aidr. Node gives the process
    # environment precedence over --env-file, but a task has no per-task
    # environment, so the file itself must name this host's directories.
    if (-not $readiness.ContainsKey('AIDR_DEPLOYMENT_DIR') -or -not (Test-AidrSamePath $readiness['AIDR_DEPLOYMENT_DIR'] $deployment)) {
        throw "Set AIDR_DEPLOYMENT_DIR=$deployment in .env.readiness before activation"
    }
    if (-not $readiness.ContainsKey('AIDR_HEALTH_STATE_DIR') -or -not (Test-AidrSamePath $readiness['AIDR_HEALTH_STATE_DIR'] $healthDirectory)) {
        throw "Set AIDR_HEALTH_STATE_DIR=$healthDirectory in .env.readiness before activation"
    }
    foreach ($name in @('AIDR_SIGNING_KEY_EXPIRES_AT', 'AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT')) {
        if (-not $readiness.ContainsKey($name) -or $readiness[$name] -notmatch '^\d{4}-') { throw "$name is missing from .env.readiness" }
    }
    foreach ($name in @('AIDR_TELEMETRY_QUEUE_ROOTS', 'AIDR_SIGNING_KEY_EXPIRES_AT', 'AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT')) {
        if ($readiness.ContainsKey($name) -and $readiness[$name] -match 'REPLACE_') { throw 'Replace readiness placeholders before activation' }
    }
    $queueRoots = @()
    if ($readiness.ContainsKey('AIDR_TELEMETRY_QUEUE_ROOTS') -and -not [string]::IsNullOrWhiteSpace($readiness['AIDR_TELEMETRY_QUEUE_ROOTS'])) {
        foreach ($root in $readiness['AIDR_TELEMETRY_QUEUE_ROOTS'].Split(',')) {
            $root = $root.Trim()
            if (-not [IO.Path]::IsPathRooted($root)) { throw 'Telemetry queue roots must be absolute paths' }
            $item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Telemetry queue roots must be real directories' }
            if (-not (Get-ChildItem -LiteralPath $root -Directory -Force | Where-Object { $_.Name -match '^[a-f0-9]{64}$' })) {
                throw 'Telemetry queue roots must already contain a real fleet-aggregated queue namespace'
            }
            $queueRoots += $item.FullName
        }
    }
    $siemConfig = $null
    $siemStateDirectory = $null
    if ($readiness.ContainsKey('SINGULARITY_AIDR_SIEM_CONFIG_PATH') -and -not [string]::IsNullOrWhiteSpace($readiness['SINGULARITY_AIDR_SIEM_CONFIG_PATH'])) {
        $siemConfig = $readiness['SINGULARITY_AIDR_SIEM_CONFIG_PATH']
        if (-not [IO.Path]::IsPathRooted($siemConfig) -or -not (Test-Path -LiteralPath $siemConfig -PathType Leaf)) { throw 'SIEM configuration is missing' }
        $stateFile = [string](Get-Content -LiteralPath $siemConfig -Raw | ConvertFrom-Json).state_file
        if ([string]::IsNullOrWhiteSpace($stateFile) -or -not [IO.Path]::IsPathRooted($stateFile)) { throw 'SIEM state_file must be an absolute path' }
        $siemStateDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($stateFile))
        [IO.Directory]::CreateDirectory($siemStateDirectory) | Out-Null
    }
    if ($queueRoots.Count -eq 0 -and $null -eq $siemConfig) { throw 'Configure at least one real durable queue source' }

    # Same --with-notifications prerequisites as install-systemd.sh. The
    # dispatcher reads deployment.json and .env.functions only, both already in
    # the read grants below, and writes nothing.
    $notificationWorker = Join-Path $deployment 'maintenance\notification-dispatch.mjs'
    if ($WithNotifications) {
        foreach ($required in @(
            (Join-Path $deployment 'maintenance\aidr-notification-dispatch.service'),
            (Join-Path $deployment 'maintenance\aidr-notification-dispatch.timer'),
            $notificationWorker
        )) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Prepared notification dispatcher input is missing: $required" }
        }
        $functions = Read-AidrEnvironmentFile (Join-Path $deployment '.env.functions')
        if (-not $functions.ContainsKey('AIDR_NOTIFICATION_DISPATCH_TOKEN') -or $functions['AIDR_NOTIFICATION_DISPATCH_TOKEN'].Trim().Length -lt 32) {
            throw 'AIDR_NOTIFICATION_DISPATCH_TOKEN (32+ characters) is missing from .env.functions'
        }
        if (-not $functions.ContainsKey('AIDR_NOTIFICATION_ENCRYPTION_KEYS') -or $functions['AIDR_NOTIFICATION_ENCRYPTION_KEYS'] -cnotmatch '^[a-z0-9][a-z0-9_-]*:') {
            throw 'AIDR_NOTIFICATION_ENCRYPTION_KEYS is missing from .env.functions'
        }
        foreach ($name in @('AIDR_NOTIFICATION_DISPATCH_TOKEN', 'AIDR_NOTIFICATION_ENCRYPTION_KEYS')) {
            if ($functions[$name] -match 'REPLACE_') { throw "Replace the $name placeholder in .env.functions before activation" }
        }
    }

    if ([string]::IsNullOrWhiteSpace($NodePath)) { $NodePath = (Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source }
    $node = (Resolve-Path -LiteralPath $NodePath -ErrorAction Stop).ProviderPath
    if ($node.Contains('"') -or [IO.Path]::GetFileName($node) -ne 'node.exe') { throw 'NodePath must name node.exe' }
    $nodeVersion = [string](& $node --version)
    if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^v(\d+)\.' -or [int]$Matches[1] -lt 24) { throw 'Node.js 24 or newer is required' }

    # Least privilege: the gMSA gets read access to exactly the files the
    # workers read, write access only where they write evidence and queue
    # state, and no inherited access to the rest of the private deployment root.
    [IO.Directory]::CreateDirectory($healthDirectory) | Out-Null
    $retentionEvidence = Join-Path $deployment 'maintenance-evidence.json'
    if (-not (Test-Path -LiteralPath $retentionEvidence -PathType Leaf)) {
        # Same not-yet-complete record deployment-maintenance.mjs writes before
        # each run; it is never a success claim.
        $pending = [ordered]@{
            checked_at = [DateTimeOffset]::UtcNow.ToString('o'); applied = $true; status = 'incomplete'; complete = $false
            scope = 'Run has not completed. Pending export authorizations require fenced-worker reconciliation, not blind Storage retries.'
        }
        [IO.File]::WriteAllText($retentionEvidence, ($pending | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    }
    $grants = @()
    if ($PSCmdlet.ParameterSetName -eq 'ServiceAccount') {
        $sid = ([Security.Principal.NTAccount]::new($ServiceAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
        $grants = @(
            @{ Path = $deployment; Rights = '(RX)' },
            @{ Path = (Join-Path $deployment 'maintenance'); Rights = '(OI)(CI)(RX)' },
            @{ Path = $healthDirectory; Rights = '(OI)(CI)(M)' },
            @{ Path = $retentionEvidence; Rights = '(M)' },
            @{ Path = $kit; Rights = '(OI)(CI)(RX)' }
        )
        $grants += @($secretFiles | ForEach-Object { @{ Path = $_; Rights = '(R)' } })
        $grants += @($queueRoots | ForEach-Object { @{ Path = $_; Rights = '(OI)(CI)(M)' } })
        if ($null -ne $siemConfig) {
            $grants += @{ Path = $siemConfig; Rights = '(R)' }
            $grants += @{ Path = $siemStateDirectory; Rights = '(OI)(CI)(M)' }
        }
        foreach ($grant in $grants) { Invoke-AidrIcacls @($grant.Path, '/grant:r', "*${sid}:$($grant.Rights)") }
        $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType Password -RunLevel Limited
        $principalLabel = $ServiceAccount
    } else {
        Write-Warning 'Running AIDR maintenance as LocalSystem; prefer -ServiceAccount with a dedicated gMSA.'
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Limited
        $principalLabel = 'LocalSystem'
    }

    # Persistent=true -> StartWhenAvailable; oneshot units never overlap -> IgnoreNew.
    function Register-AidrMaintenanceTask {
        param([Parameter(Mandatory)]$Definition)
        # The dispatcher is registered after the evidence run, so each task gets its own start.
        $start = [DateTime]::Now.AddMinutes(1)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit $Definition.TimeLimit -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        switch ($Definition.Name) {
            'aidr-siem-delivery' {
                # OnBootSec=30s, OnUnitActiveSec=1min, EnvironmentFile=-/srv/aidr/.env.readiness, WorkingDirectory=/srv/aidr
                $boot = New-ScheduledTaskTrigger -AtStartup
                $boot.Delay = 'PT30S'
                $triggers = @($boot, (New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Minutes 1)))
                $action = New-ScheduledTaskAction -Execute $node -Argument "`"--env-file=$readinessEnvPath`" `"$worker`"" -WorkingDirectory $deployment
            }
            'aidr-export-retention' {
                # OnCalendar=hourly, RandomizedDelaySec=5min, WorkingDirectory=/opt/aidr-kit
                $triggers = @(New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Hours 1) -RandomDelay (New-TimeSpan -Minutes 5))
                $action = New-ScheduledTaskAction -Execute $node -Argument "`"$retentionScript`" `"$deployment`" --apply" -WorkingDirectory $kit
            }
            'aidr-notification-dispatch' {
                # OnBootSec=45s, OnUnitActiveSec=1min, no EnvironmentFile, WorkingDirectory=/srv/aidr,
                # ExecStart=node /srv/aidr/maintenance/notification-dispatch.mjs /srv/aidr
                $boot = New-ScheduledTaskTrigger -AtStartup
                $boot.Delay = 'PT45S'
                $triggers = @($boot, (New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Minutes 1)))
                $action = New-ScheduledTaskAction -Execute $node -Argument "`"$notificationWorker`" `"$deployment`"" -WorkingDirectory $deployment
            }
            default { throw "No Windows task mapping for $($Definition.Name)" }
        }
        Register-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName $Definition.Name -Description $Definition.Description `
            -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Force | Out-Null
        Enable-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName $Definition.Name | Out-Null
    }

    $definitions = @(Get-AidrMaintenanceTaskDefinitions | Where-Object { -not $_.Optional })
    $notificationDefinition = Get-AidrMaintenanceTaskDefinitions | Where-Object { $_.Name -eq 'aidr-notification-dispatch' }
    $declaredTasks = @($definitions | ForEach-Object { $_.Name })
    if ($WithNotifications) {
        $declaredTasks += $notificationDefinition.Name
    } elseif ($null -ne (Get-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName $notificationDefinition.Name -ErrorAction SilentlyContinue)) {
        # Like install-systemd.sh without --with-notifications, an existing
        # dispatcher is left as it is; it stays declared so the doctor keeps checking it.
        Write-Warning "$($notificationDefinition.Name) is already registered and was left unchanged; run Uninstall-AidrMaintenanceTasks.ps1 to remove it."
        $declaredTasks += $notificationDefinition.Name
    }
    foreach ($definition in $definitions) { Register-AidrMaintenanceTask $definition }

    # Declares Windows maintenance to scripts/deployment-doctor.mjs: from now on a
    # missing or disabled task is reported as a failure, not as unverified. An
    # opt-in task is declared before it is registered, so an aborted activation
    # leaves the doctor red rather than silent.
    $declaration = [ordered]@{
        schema_version = 1
        scheduler = 'windows-task-scheduler'
        task_path = $script:AidrMaintenanceTaskPath
        tasks = $declaredTasks
        principal = $principalLabel
        granted_paths = @($grants | ForEach-Object { $_.Path })
        installed_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    [IO.File]::WriteAllText((Get-AidrMaintenanceDeclarationPath $deployment), (($declaration | ConvertTo-Json) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

    # install-systemd.sh starts the service once before enabling the timer.
    $result = Wait-AidrInitialRun -TaskName 'aidr-siem-delivery' -Timeout (New-TimeSpan -Minutes 5)
    if ($result -ne 0) {
        Disable-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName 'aidr-siem-delivery' | Out-Null
        throw "Initial readiness evidence run failed (task result $result); aidr-siem-delivery was left disabled"
    }

    if ($WithNotifications) {
        # install-systemd.sh: one supervised dispatch after the evidence worker;
        # a missing function, token or key fails here.
        Register-AidrMaintenanceTask $notificationDefinition
        $result = Wait-AidrInitialRun -TaskName 'aidr-notification-dispatch' -Timeout $notificationDefinition.TimeLimit
        if ($result -ne 0) {
            Disable-ScheduledTask -TaskPath $script:AidrMaintenanceTaskPath -TaskName 'aidr-notification-dispatch' | Out-Null
            throw "Initial notification dispatch failed (task result $result); aidr-notification-dispatch was left disabled"
        }
    }
    Write-Output "AIDR maintenance tasks registered under $($script:AidrMaintenanceTaskPath) as $principalLabel. Run scripts/deployment-doctor.mjs to verify."
    exit 0
} catch {
    Write-Error "AIDR maintenance task installation failed closed: $($_.Exception.Message)"
    exit 1
}
