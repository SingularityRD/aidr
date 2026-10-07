Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows Task Scheduler mirror of the systemd units in this directory. The task
# folder and names are fixed: scripts/deployment-doctor.mjs queries exactly
# these names, so do not rename them per host.
$script:AidrMaintenanceTaskPath = '\AIDR\'
$script:AidrMaintenanceDeclarationName = 'windows-maintenance-tasks.json'

function Get-AidrMaintenanceTaskDefinitions {
    # Each entry mirrors one <name>.timer / <name>.service pair. Optional tasks
    # are registered only on request, like install-systemd.sh's opt-in flags.
    return @(
        [pscustomobject]@{
            Name = 'aidr-siem-delivery'
            Description = 'AIDR signing, durable queue and SIEM maintenance (mirrors aidr-siem-delivery.timer: 30s after boot, then every minute)'
            Worker = 'readiness-evidence-worker.mjs'
            TimeLimit = New-TimeSpan -Minutes 5
            Optional = $false
        },
        [pscustomobject]@{
            Name = 'aidr-export-retention'
            Description = 'AIDR expired audit export cleanup (mirrors aidr-export-retention.timer: hourly with up to 5 minutes random delay)'
            Worker = 'deployment-maintenance.mjs'
            TimeLimit = New-TimeSpan -Minutes 15
            Optional = $false
        },
        [pscustomobject]@{
            # Opt-in: -WithNotifications, the mirror of install-systemd.sh --with-notifications.
            Name = 'aidr-notification-dispatch'
            Description = 'AIDR alert notification dispatcher (mirrors aidr-notification-dispatch.timer: 45s after boot, then every minute)'
            Worker = 'notification-dispatch.mjs'
            TimeLimit = New-TimeSpan -Minutes 2
            Optional = $true
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

# The tasks run node.exe and kit/deployment scripts as LocalSystem or a gMSA, so
# only these principals may be able to write or replace that code: SYSTEM,
# BUILTIN\Administrators and NT SERVICE\TrustedInstaller.
$script:AidrTrustedWriterSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$script:AidrCreatorOwnerSid = 'S-1-3-0'
# WriteData/CreateFiles 0x2, AppendData/CreateDirectories 0x4, DeleteSubdirectoriesAndFiles 0x40,
# Delete 0x10000, ChangePermissions 0x40000, TakeOwnership 0x80000, GENERIC_ALL 0x10000000,
# GENERIC_WRITE 0x40000000. Write, Modify and FullControl all contain one of these bits.
$script:AidrWriteRightsMask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
# On an ancestor directory only the rights that let a principal replace (rename,
# delete or re-ACL) the path below it matter; creating a new sibling does not.
$script:AidrReplaceRightsMask = 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000

function Format-AidrSid {
    param($Sid)
    if ($null -eq $Sid) { return '<no owner>' }
    $value = [string]$Sid
    try { return "$(([Security.Principal.SecurityIdentifier]::new($value)).Translate([Security.Principal.NTAccount]).Value) ($value)" } catch { return $value }
}

function Get-AidrUntrustedWriterFinding {
    # Pure over the ACL object (no filesystem access), so tests can pass an
    # in-memory security descriptor. Returns one message per offending owner or
    # Allow ACE; an empty result means only trusted principals can write the path.
    param(
        [Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Security,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Ancestor
    )
    $findings = @()
    $owner = $Security.GetOwner([Security.Principal.SecurityIdentifier])
    if ($null -eq $owner -or $owner.Value -notin $script:AidrTrustedWriterSids) {
        $findings += "$Path is owned by $(Format-AidrSid $owner)"
    }
    $mask = if ($Ancestor) { $script:AidrReplaceRightsMask } else { $script:AidrWriteRightsMask }
    foreach ($rule in $Security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Value
        if ($sid -in $script:AidrTrustedWriterSids) { continue }
        if (([int]$rule.FileSystemRights -band $mask) -eq 0) { continue }
        # An inherit-only ACE grants nothing on this object itself. On an ancestor
        # it reappears (and is checked) on the descendant; CREATOR OWNER only ever
        # resolves to a principal that could already create the child.
        $inheritOnly = ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
        if ($inheritOnly -and ($Ancestor -or $sid -eq $script:AidrCreatorOwnerSid)) { continue }
        $findings += "$Path grants $(Format-AidrSid $sid) $($rule.FileSystemRights)"
    }
    return $findings
}

function Get-AidrPathSecurity {
    # .NET directly rather than Get-Acl, whose module fails to load in Windows
    # PowerShell when it is started from PowerShell 7 with an inherited PSModulePath.
    param([Parameter(Mandatory)][IO.FileSystemInfo]$Item)
    $sections = [Security.AccessControl.AccessControlSections]'Owner, Access'
    if ('System.IO.FileSystemAclExtensions' -as [type]) {
        return [IO.FileSystemAclExtensions]::GetAccessControl($Item, $sections)
    }
    if ($Item -is [IO.DirectoryInfo]) { return [IO.Directory]::GetAccessControl($Item.FullName, $sections) }
    return [IO.File]::GetAccessControl($Item.FullName, $sections)
}

function Assert-AidrTrustedWriterPaths {
    # Refuses registration unless every file and directory a task executes, and
    # every ancestor that could be used to replace it, is writable only by
    # SYSTEM, Administrators or TrustedInstaller. Reparse points are refused:
    # the ACL that matters would be the target's, not the link's.
    param([Parameter(Mandatory)][string[]]$Path)
    $targets = @($Path | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') } | Sort-Object -Unique)
    $findings = @()
    $checked = @{}
    foreach ($target in $targets) {
        $checked[$target.ToLowerInvariant()] = $true
        $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $findings += "$target is a symbolic link or junction" }
        $findings += @(Get-AidrUntrustedWriterFinding -Security (Get-AidrPathSecurity $item) -Path $target)
    }
    foreach ($target in $targets) {
        $parent = Split-Path -Parent $target
        while (-not [string]::IsNullOrWhiteSpace($parent)) {
            $key = $parent.ToLowerInvariant()
            if (-not $checked.ContainsKey($key)) {
                $checked[$key] = $true
                $item = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $findings += "$parent is a symbolic link or junction" }
                $findings += @(Get-AidrUntrustedWriterFinding -Security (Get-AidrPathSecurity $item) -Path $parent -Ancestor)
            }
            $parent = Split-Path -Parent $parent
        }
    }
    if ($findings.Count -ne 0) {
        throw ("Refusing to register tasks that run as LocalSystem or a gMSA: code they execute can be replaced by a principal other than SYSTEM, " +
            "Administrators or TrustedInstaller. $($findings -join '; '). Remove those grants (for example icacls <path> /setowner *S-1-5-32-544 " +
            'and icacls <path> /remove:g <identity>) and re-run.')
    }
}

function Resolve-AidrNodeExecutable {
    # Resolves node.exe to one explicit absolute local path; an ambiguous PATH
    # lookup is refused rather than guessed.
    param([string]$NodePath)
    if ([string]::IsNullOrWhiteSpace($NodePath)) {
        $candidates = @(Get-Command node.exe -CommandType Application -All -ErrorAction Stop |
            ForEach-Object { $_.Source } | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_) } | Sort-Object -Unique)
        if ($candidates.Count -ne 1) { throw "node.exe resolves to $($candidates.Count) locations on PATH ($($candidates -join ', ')); pass -NodePath with an explicit absolute path" }
        $NodePath = $candidates[0]
    }
    if ($NodePath -notmatch '^[A-Za-z]:\\') { throw 'NodePath must be an explicit absolute local path such as C:\Program Files\nodejs\node.exe' }
    $item = Get-Item -LiteralPath $NodePath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.FullName.Contains('"') -or $item.Name -ne 'node.exe') { throw 'NodePath must name node.exe' }
    return $item.FullName
}

function Invoke-AidrIcacls {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    $output = & $icacls @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls failed for '$($Arguments[0])': $($output -join ' ')" }
}
