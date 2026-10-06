[CmdletBinding()]
param([switch]$WhatIf)

# This process never elevates. Its caller verifies the Ed25519 delivery against
# installed trust before passing this closed DTO; no executable/config paths are accepted.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Add-Type -AssemblyName System.Numerics

function Assert-AidrResponseObject {
    param($Value, [string[]]$Fields)
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'invalid_response_request' }
    $names = @($Value.PSObject.Properties | ForEach-Object Name)
    if ($names.Count -ne $Fields.Count) { throw 'invalid_response_request' }
    foreach ($field in $Fields) { if ($field -cnotin $names) { throw 'invalid_response_request' } }
}

function Test-AidrResponseUuid {
    param($Value)
    return $Value -is [string] -and $Value -match '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
}

function Get-AidrResponseTimestamp {
    param($Value)
    if ($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$') { throw 'invalid_response_timestamp' }
    $parsed = [DateTimeOffset]::ParseExact($Value, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
    return $parsed.ToUniversalTime()
}

function Assert-AidrResponseDelivery {
    param($Delivery, $Identity, $Command)
    Assert-AidrResponseObject $Delivery @('alg', 'key_id', 'sig_b64', 'payload')
    if ($Delivery.alg -cne 'ed25519' -or $Delivery.key_id -isnot [string] -or $Delivery.key_id.Length -notin 1..128 -or
        $Delivery.sig_b64 -isnot [string] -or $Delivery.sig_b64 -cnotmatch '^[A-Za-z0-9+/]{86}==$') { throw 'invalid_response_delivery' }
    $payload = $Delivery.payload
    Assert-AidrResponseObject $payload @('schema_version', 'purpose', 'key_id', 'tenant_id', 'agent_id', 'installation_id', 'key_hash', 'id', 'command_type', 'payload', 'rollback_of', 'created_at', 'expires_at', 'attempt')
    Assert-AidrResponseObject $payload.payload @()
    if ($payload.schema_version -is [bool] -or $payload.schema_version -ne 1 -or $payload.purpose -cne 'aidr.fleet-response.command' -or $payload.key_id -cne $Delivery.key_id -or
        $payload.tenant_id -cne $Identity.tenant_id -or $payload.agent_id -cne $Identity.agent_id -or $payload.installation_id -cne $Identity.installation_id -or
        $payload.key_hash -isnot [string] -or $payload.key_hash -cnotmatch '^[a-f0-9]{64}$' -or
        $payload.id -cne $Command.id -or $payload.command_type -cne $Command.command_type -or $payload.expires_at -cne $Command.expires_at -or
        $payload.attempt -ne $Command.attempt -or $payload.rollback_of -cne $Command.rollback_of) { throw 'response_delivery_mismatch' }
    $created = Get-AidrResponseTimestamp $payload.created_at
    $expires = Get-AidrResponseTimestamp $payload.expires_at
    if ($expires -le $created) { throw 'invalid_response_timestamp' }
}

function Get-AidrResponseIp {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 45 -or $Value -match '[%/\s-]') { throw 'invalid_recovery_address' }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$ip)) { throw 'invalid_recovery_address' }
    $bytes = $ip.GetAddressBytes()
    if ($bytes.Length -eq 4) {
        if ($Value -cne $ip.ToString()) { throw 'invalid_recovery_address' }
    } elseif ($bytes.Length -ne 16 -or $ip.IsIPv4MappedToIPv6) { throw 'invalid_recovery_address' }
    $number = [Numerics.BigInteger]::Zero
    foreach ($byte in $bytes) { $number = $number * 256 + $byte }
    return [pscustomobject]@{ Address = $ip.ToString(); Bits = $bytes.Length * 8; Number = $number }
}

function ConvertFrom-AidrResponseNumber {
    param([Numerics.BigInteger]$Number, [int]$Bits)
    $bytes = [byte[]]::new($Bits / 8)
    for ($index = $bytes.Length - 1; $index -ge 0; $index--) {
        $bytes[$index] = [byte]($Number % 256)
        $Number = [Numerics.BigInteger]::Divide($Number, 256)
    }
    return ([Net.IPAddress]::new($bytes)).ToString()
}

function Format-AidrResponseInterval {
    param([Numerics.BigInteger]$Start, [Numerics.BigInteger]$End, [int]$Bits)
    $first = ConvertFrom-AidrResponseNumber $Start $Bits
    if ($Start -eq $End) { return $first }
    return $first + '-' + (ConvertFrom-AidrResponseNumber $End $Bits)
}

function Get-AidrResponseComplement {
    param([object[]]$Addresses, [int]$Bits)
    $cursor = [Numerics.BigInteger]::Zero
    $maximum = [Numerics.BigInteger]::Pow(2, $Bits) - 1
    foreach ($ip in @($Addresses | Where-Object Bits -eq $Bits | Sort-Object Number -Unique)) {
        if ($ip.Number -gt $cursor) { Format-AidrResponseInterval $cursor ($ip.Number - 1) $Bits }
        if ($ip.Number -ge $cursor) { $cursor = $ip.Number + 1 }
    }
    if ($cursor -le $maximum) { Format-AidrResponseInterval $cursor $maximum $Bits }
}

function Get-AidrResponseHash {
    param([string]$Value)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))) -replace '-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}

function Assert-AidrResponseRequest {
    param($Request)
    Assert-AidrResponseObject $Request @('schema_version', 'operation', 'identity', 'command', 'delivery', 'state_root', 'recovery_addresses')
    if ($Request.schema_version -is [bool] -or $Request.schema_version -ne 1 -or $Request.operation -cnotin @('execute', 'verify', 'dry_run', 'inspect_removal')) { throw 'invalid_response_request' }
    Assert-AidrResponseObject $Request.identity @('tenant_id', 'agent_id', 'installation_id')
    if (-not (Test-AidrResponseUuid $Request.identity.tenant_id) -or -not (Test-AidrResponseUuid $Request.identity.agent_id) -or
        $Request.identity.installation_id -isnot [string] -or $Request.identity.installation_id.Length -notin 1..128 -or $Request.identity.installation_id -match '[\x00-\x20\x7f]') { throw 'invalid_response_identity' }
    if ($Request.operation -ceq 'inspect_removal') {
        if ($null -ne $Request.command -or $null -ne $Request.delivery -or $Request.recovery_addresses -isnot [array] -or $Request.recovery_addresses.Count -ne 0 -or
            $Request.state_root -isnot [string] -or -not [IO.Path]::IsPathRooted($Request.state_root)) { throw 'invalid_response_request' }
        return @()
    }
    Assert-AidrResponseObject $Request.command @('id', 'command_type', 'expires_at', 'attempt', 'rollback_of')
    $command = $Request.command
    if (-not (Test-AidrResponseUuid $command.id) -or $command.command_type -cnotin @('agent_pause', 'agent_resume', 'network_isolate', 'network_release') -or
        $command.attempt -isnot [ValueType] -or $command.attempt -notin 1..5 -or $command.attempt -is [bool]) { throw 'invalid_response_command' }
    $rollback = $command.command_type -cin @('agent_resume', 'network_release')
    if (($rollback -and (-not (Test-AidrResponseUuid $command.rollback_of) -or $command.rollback_of -ceq $command.id)) -or
        (-not $rollback -and $null -ne $command.rollback_of)) { throw 'invalid_response_rollback' }
    $expires = Get-AidrResponseTimestamp $command.expires_at
    if ($Request.operation -cne 'verify' -and $expires -le [DateTimeOffset]::UtcNow) { throw 'response_command_expired' }
    Assert-AidrResponseDelivery $Request.delivery $Request.identity $command
    if ($Request.state_root -isnot [string] -or -not [IO.Path]::IsPathRooted($Request.state_root)) { throw 'invalid_response_state_path' }
    if ($Request.recovery_addresses -isnot [array] -or $Request.recovery_addresses.Count -gt 64) { throw 'invalid_recovery_addresses' }
    $ips = @($Request.recovery_addresses | ForEach-Object {
        if ($_ -isnot [string]) { throw 'invalid_recovery_address' }
        Get-AidrResponseIp $_
    })
    if ($command.command_type -clike 'network_*' -and $ips.Count -eq 0) { throw 'missing_recovery_addresses' }
    return @($ips | Sort-Object Bits, Number -Unique)
}

function Assert-AidrResponseStatePath {
    param([string]$Root, [switch]$CurrentUser)
    $full = [IO.Path]::GetFullPath($Root)
    if ($CurrentUser) {
        $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        if ([string]::IsNullOrWhiteSpace($profile)) { throw 'response_user_profile_unavailable' }
        $expected = [IO.Path]::GetFullPath((Join-Path $profile '.singularity-aidr\response-control'))
        if (-not [string]::Equals($full, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw 'response_state_path_mismatch' }
    }
    Assert-AidrNoReparsePath $full
    if ((Test-Path -LiteralPath $full) -and -not (Test-Path -LiteralPath $full -PathType Container)) { throw 'invalid_response_state_path' }
    foreach ($name in @('barrier.json', 'pause-state.json', 'network-state.json', 'action.lock')) { Assert-AidrNoReparsePath (Join-Path $full $name) }
}

function Initialize-AidrResponseStateRoot {
    param([string]$Root)
    Assert-AidrResponseStatePath $Root
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($sid)
    foreach ($owner in @($sid.Value, 'S-1-5-18', 'S-1-5-32-544') | Select-Object -Unique) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($owner), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [IO.Directory]::SetAccessControl($Root, $acl)
}

function Assert-AidrResponsePrivateState {
    param([string]$Root)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $owners = @($sid, 'S-1-5-18', 'S-1-5-32-544')
    $acl = [IO.Directory]::GetAccessControl($Root)
    if (-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $owners) { throw 'response_state_acl_invalid' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $owners) { throw 'response_state_acl_invalid' }
    }
    foreach ($name in @('barrier.json', 'pause-state.json', 'network-state.json', 'action.lock')) {
        $path = Join-Path $Root $name
        if (-not [IO.File]::Exists($path)) { continue }
        $fileAcl = [IO.File]::GetAccessControl($path)
        if ($fileAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $owners) { throw 'response_state_acl_invalid' }
        foreach ($rule in $fileAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $owners) { throw 'response_state_acl_invalid' }
        }
    }
    # A writable parent can replace a protected child directory via DeleteChild.
    $parent = Split-Path -Parent $Root
    $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    $replaceRights = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    while (-not [string]::IsNullOrWhiteSpace($parent)) {
        $parentAcl = [IO.Directory]::GetAccessControl($parent)
        if ($parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $owners) { throw 'response_state_parent_acl_invalid' }
        foreach ($rule in $parentAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $owners -and
                -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                (([int]$rule.FileSystemRights -band [int]$replaceRights) -ne 0)) { throw 'response_state_parent_acl_invalid' }
        }
        if ([string]::Equals($parent, $profile, [StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = Split-Path -Parent $parent
    }
}

function Read-AidrResponseState {
    param([string]$Path, $Identity)
    Assert-AidrNoReparsePath $Path
    if (-not [IO.File]::Exists($Path)) { return $null }
    $info = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($info.Length -gt 32768) { throw 'response_state_invalid' }
    $value = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true)) | ConvertFrom-Json -ErrorAction Stop
    Assert-AidrResponseObject $value @('schema_version', 'tenant_id', 'agent_id', 'installation_id', 'command', 'command_signed', 'original_command_id', 'recovery_addresses', 'phase', 'created_at')
    if ($value.schema_version -ne 1 -or $value.tenant_id -cne $Identity.tenant_id -or $value.agent_id -cne $Identity.agent_id -or $value.installation_id -cne $Identity.installation_id -or
        $value.phase -cnotin @('intent', 'applied')) { throw 'response_state_identity_mismatch' }
    Assert-AidrResponseObject $value.command @('id', 'command_type', 'expires_at', 'attempt', 'rollback_of')
    if (-not (Test-AidrResponseUuid $value.original_command_id) -or
        ($value.command.command_type -cin @('agent_pause', 'network_isolate') -and $value.original_command_id -cne $value.command.id) -or
        ($value.command.command_type -cin @('agent_resume', 'network_release') -and $value.original_command_id -cne $value.command.rollback_of) -or
        $value.recovery_addresses -isnot [array] -or $value.recovery_addresses.Count -gt 64) { throw 'response_state_invalid' }
    $null = Get-AidrResponseTimestamp $value.created_at
    $savedRequest = [pscustomobject]@{ schema_version = 1; operation = 'verify'; identity = $Identity; command = $value.command; delivery = $value.command_signed; state_root = (Split-Path -Parent $Path); recovery_addresses = $value.recovery_addresses }
    $canonical = @(Assert-AidrResponseRequest $savedRequest | ForEach-Object Address)
    if ((@($value.recovery_addresses) -join ',') -cne ($canonical -join ',')) { throw 'response_state_invalid' }
    return $value
}

function New-AidrResponseState {
    param($Request, [string]$OriginalId, [string[]]$Addresses)
    return [pscustomobject]@{ schema_version = 1; tenant_id = $Request.identity.tenant_id; agent_id = $Request.identity.agent_id; installation_id = $Request.identity.installation_id;
        command = $Request.command; command_signed = $Request.delivery; original_command_id = $OriginalId; recovery_addresses = @($Addresses); phase = 'intent'; created_at = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") }
}

function Write-AidrResponseState {
    param([string]$Path, $Value)
    Assert-AidrNoReparsePath $Path
    Write-AidrFleetState $Path $Value
}

function Read-AidrResponseBarrier {
    param([string]$Path, $Identity)
    Assert-AidrNoReparsePath $Path
    if (-not [IO.File]::Exists($Path)) { return $null }
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 16384) { throw 'response_barrier_invalid' }
    $barrier = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true)) | ConvertFrom-Json -ErrorAction Stop
    Assert-AidrResponseObject $barrier @('schema_version', 'tenant_id', 'agent_id', 'installation_id', 'command_id', 'created_at', 'command_signed')
    if ($barrier.schema_version -ne 1 -or $barrier.tenant_id -cne $Identity.tenant_id -or $barrier.agent_id -cne $Identity.agent_id -or $barrier.installation_id -cne $Identity.installation_id -or
        -not (Test-AidrResponseUuid $barrier.command_id)) { throw 'response_barrier_identity_mismatch' }
    $payload = $barrier.command_signed.payload
    $command = [pscustomobject]@{ id = $barrier.command_id; command_type = 'agent_pause'; expires_at = $payload.expires_at; attempt = $payload.attempt; rollback_of = $null }
    Assert-AidrResponseDelivery $barrier.command_signed $Identity $command
    $null = Get-AidrResponseTimestamp $barrier.created_at
    return $barrier
}

function Test-AidrResponseAdmin {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AidrResponseRules {
    param($Identity, [string]$CommandId, [object[]]$Addresses)
    $binding = Get-AidrResponseHash ($Identity.tenant_id + "`n" + $Identity.agent_id + "`n" + $Identity.installation_id + "`nAIDR.Response.v1")
    $policy = Get-AidrResponseHash ((@($Addresses | ForEach-Object Address | Sort-Object) -join '\n'))
    $group = 'AIDR.Response.' + $binding.Substring(0, 24)
    foreach ($direction in @('Inbound', 'Outbound')) {
        foreach ($bits in @(32, 128)) {
            [pscustomobject]@{ Name = "$group.$CommandId.block$bits.$direction"; Group = $group; Description = "AIDR response v1; identity=$binding; command=$CommandId; policy=$policy";
                Direction = $direction; Action = 'Block'; RemoteAddress = @(Get-AidrResponseComplement $Addresses $bits) }
        }
        [pscustomobject]@{ Name = "$group.$CommandId.recovery.$direction"; Group = $group; Description = "AIDR response v1; identity=$binding; command=$CommandId; policy=$policy";
            Direction = $direction; Action = 'Allow'; RemoteAddress = @($Addresses | ForEach-Object Address) }
    }
}

function Get-AidrResponseAddressIntervals {
    param([string[]]$Values)
    foreach ($value in $Values) {
        if ($value -eq 'Any') {
            foreach ($bits in @(32, 128)) { [pscustomobject]@{ Bits = $bits; Start = [Numerics.BigInteger]::Zero; End = [Numerics.BigInteger]::Pow(2, $bits) - 1 } }
            continue
        }
        if ($value.Contains('-')) {
            $ends = $value.Split('-')
            if ($ends.Count -ne 2) { throw 'unsupported_firewall_address' }
            $first = Get-AidrResponseIp $ends[0]; $last = Get-AidrResponseIp $ends[1]
            if ($first.Bits -ne $last.Bits -or $first.Number -gt $last.Number) { throw 'unsupported_firewall_address' }
            [pscustomobject]@{ Bits = $first.Bits; Start = $first.Number; End = $last.Number }
        } elseif ($value.Contains('/')) {
            $parts = $value.Split('/')
            if ($parts.Count -ne 2 -or $parts[1] -notmatch '^\d{1,3}$') { throw 'unsupported_firewall_address' }
            $ip = Get-AidrResponseIp $parts[0]; $prefix = [int]$parts[1]
            if ($prefix -gt $ip.Bits) { throw 'unsupported_firewall_address' }
            $size = [Numerics.BigInteger]::Pow(2, $ip.Bits - $prefix)
            $start = [Numerics.BigInteger]::Divide($ip.Number, $size) * $size
            [pscustomobject]@{ Bits = $ip.Bits; Start = $start; End = $start + $size - 1 }
        } else {
            $ip = Get-AidrResponseIp $value
            [pscustomobject]@{ Bits = $ip.Bits; Start = $ip.Number; End = $ip.Number }
        }
    }
}

function Get-AidrResponseAddressSet {
    param([string[]]$Values)
    $merged = [Collections.Generic.List[object]]::new()
    foreach ($interval in @(Get-AidrResponseAddressIntervals $Values | Sort-Object Bits, Start, End)) {
        if ($merged.Count -gt 0 -and $merged[$merged.Count - 1].Bits -eq $interval.Bits -and $interval.Start -le ($merged[$merged.Count - 1].End + 1)) {
            if ($interval.End -gt $merged[$merged.Count - 1].End) { $merged[$merged.Count - 1].End = $interval.End }
        } else { $merged.Add($interval) }
    }
    return (($merged | ForEach-Object { '{0}:{1}:{2}' -f $_.Bits, $_.Start, $_.End }) -join ';')
}

function Assert-AidrResponseFirewallPolicy {
    param([object[]]$Addresses, [object[]]$ActiveRules, [string[]]$OwnedNames)
    if (-not (Test-AidrResponseAdmin)) { throw 'response_requires_administrator' }
    if ((Get-Service -Name MpsSvc -ErrorAction Stop).Status -ne 'Running') { throw 'firewall_service_unavailable' }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -ne 3 -or @($profiles.Name | Sort-Object -Unique).Count -ne 3) { throw 'firewall_profile_unavailable' }
    foreach ($profile in $profiles) {
        if ($profile.Name -notin @('Domain', 'Private', 'Public') -or [string]$profile.Enabled -ne 'True' -or [string]$profile.AllowLocalFirewallRules -eq 'False' -or
            [string]$profile.AllowInboundRules -eq 'False' -or @($profile.DisabledInterfaceAliases | Where-Object { $_ -notin @('', 'NotConfigured') }).Count -gt 0) { throw 'firewall_policy_unsupported' }
    }
    foreach ($rule in $ActiveRules) {
        if ([string]$rule.Enabled -ne 'True' -or $rule.Name -cin $OwnedNames) { continue }
        if ([string]$rule.Action -eq 'Allow') {
            $security = Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            if ([string]$security.OverrideBlockRules -eq 'True') { throw 'firewall_bypass_policy_unsupported' }
        } elseif ([string]$rule.Action -eq 'Block') {
            $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            foreach ($range in @(Get-AidrResponseAddressIntervals @($filter.RemoteAddress))) {
                foreach ($ip in $Addresses) {
                    if ($range.Bits -eq $ip.Bits -and $range.Start -le $ip.Number -and $range.End -ge $ip.Number) { throw 'firewall_recovery_policy_conflict' }
                }
            }
        }
    }
}

function Assert-AidrResponseRule {
    param($Rule, $Expected, [switch]$Effective)
    if ($Rule.Name -cne $Expected.Name -or $Rule.Group -cne $Expected.Group -or $Rule.Description -cne $Expected.Description -or
        [string]$Rule.Enabled -ne 'True' -or [string]$Rule.Direction -ne $Expected.Direction -or [string]$Rule.Action -ne $Expected.Action -or [string]$Rule.Profile -ne 'Any' -or
        [string]$Rule.EdgeTraversalPolicy -ne 'Block' -or -not [string]::IsNullOrEmpty([string]$Rule.Owner) -or
        ($Effective -and [string]$Rule.PolicyStoreSourceType -ne 'Local') -or [string]$Rule.PrimaryStatus -ne 'OK') { throw 'firewall_owned_rule_mismatch' }
    foreach ($field in @('Platform', 'PolicyAppId', 'PackageFamilyName')) {
        $value = Get-AidrProperty $Rule $field
        if ($null -ne $value -and @($value | Where-Object { $_ -notin @('', 'Any') }).Count -gt 0) { throw 'firewall_owned_filter_mismatch' }
    }
    if ($Effective) {
        $statuses = @(Get-AidrProperty $Rule 'EnforcementStatus')
        if ($statuses.Count -eq 0 -or @($statuses | Where-Object { $_ -notin @('Full', 'InactiveProfile') }).Count -gt 0) { throw 'firewall_owned_rule_not_enforced' }
    }
    $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    if ((Get-AidrResponseAddressSet @($address.LocalAddress)) -ne (Get-AidrResponseAddressSet @('Any')) -or
        (Get-AidrResponseAddressSet @($address.RemoteAddress)) -ne (Get-AidrResponseAddressSet @($Expected.RemoteAddress))) { throw 'firewall_owned_filter_mismatch' }
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    if ([string]$port.Protocol -notin @('Any', '256') -or [string]$port.LocalPort -ne 'Any' -or [string]$port.RemotePort -ne 'Any' -or
        @((Get-AidrProperty $port 'DynamicTarget') | Where-Object { $_ -notin @('', 'Any') }).Count -gt 0) { throw 'firewall_owned_filter_mismatch' }
    $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    $service = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    $interface = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    $interfaceType = Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    $security = Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    if ([string]$app.Program -ne 'Any' -or [string]$app.Package -notin @('', 'Any') -or [string]$service.Service -ne 'Any' -or
        [string]$interface.InterfaceAlias -ne 'Any' -or [string]$interfaceType.InterfaceType -ne 'Any' -or [string]$security.Authentication -ne 'NotRequired' -or
        [string]$security.Encryption -ne 'NotRequired' -or [string]$security.OverrideBlockRules -ne 'False' -or
        [string]$security.LocalUser -ne 'Any' -or [string]$security.RemoteUser -ne 'Any' -or [string]$security.RemoteMachine -ne 'Any') { throw 'firewall_owned_filter_mismatch' }
}

function Get-AidrResponseFirewallRules {
    param([string]$Store)
    if ($Store -ceq 'ActiveStore') { return @(Get-NetFirewallRule -All -PolicyStore $Store -TracePolicyStore -ErrorAction Stop) }
    return @(Get-NetFirewallRule -All -PolicyStore $Store -ErrorAction Stop)
}

function Test-AidrResponseRuleSet {
    param([object[]]$Expected, [switch]$Absent)
    foreach ($store in @('PersistentStore', 'ActiveStore')) {
        $rules = @(Get-AidrResponseFirewallRules $store)
        $owned = @($rules | Where-Object Group -CEQ $Expected[0].Group)
        if ($Absent -and $owned.Count -ne 0) { throw 'firewall_release_not_observed' }
        if (-not $Absent -and @($owned | Where-Object { $_.Name -cnotin @($Expected.Name) }).Count -gt 0) { throw 'firewall_unexpected_owned_rule' }
        foreach ($item in $Expected) {
            $matches = @($rules | Where-Object Name -CEQ $item.Name)
            if ($Absent) { if ($matches.Count -ne 0) { throw 'firewall_release_not_observed' }; continue }
            if ($matches.Count -ne 1) { throw 'firewall_isolation_not_observed' }
            Assert-AidrResponseRule $matches[0] $item -Effective:($store -eq 'ActiveStore')
        }
    }
}

function Get-AidrResponseEvidence {
    param($Request, [string]$State, [int]$RuleCount = 0)
    return [pscustomobject]@{ schema_version = 1; tenant_id = $Request.identity.tenant_id; agent_id = $Request.identity.agent_id; installation_id = $Request.identity.installation_id;
        command_id = $Request.command.id; command_type = $Request.command.command_type; rollback_of = $Request.command.rollback_of; state = $State; owned_rule_count = $RuleCount }
}

function Invoke-AidrResponseAction {
    param($Request)
    $script:AidrResponseIntentWritten = $false
    $ips = @(Assert-AidrResponseRequest $Request)
    $root = [IO.Path]::GetFullPath($Request.state_root)
    Assert-AidrResponseStatePath $root
    if ($Request.operation -ceq 'inspect_removal') {
        $binding = Get-AidrResponseHash ($Request.identity.tenant_id + "`n" + $Request.identity.agent_id + "`n" + $Request.identity.installation_id + "`nAIDR.Response.v1")
        $group = 'AIDR.Response.' + $binding.Substring(0, 24)
        $existed = [IO.Directory]::Exists($root)
        $inspectionLock = $null
        if ($existed) {
            Assert-AidrResponsePrivateState $root
            $inspectionLockPath = Join-Path $root 'action.lock'
            Assert-AidrNoReparsePath $inspectionLockPath
            try { $inspectionLock = [IO.FileStream]::new($inspectionLockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 4096, [IO.FileOptions]::DeleteOnClose) }
            catch { throw 'response_action_busy' }
        }
        try {
            if ($existed) {
                if ($null -ne (Read-AidrResponseBarrier (Join-Path $root 'barrier.json') $Request.identity)) { throw 'response_removal_active_pause' }
                foreach ($entry in @(@{ Name = 'pause-state.json'; Type = 'agent_resume' }, @{ Name = 'network-state.json'; Type = 'network_release' })) {
                    $saved = Read-AidrResponseState (Join-Path $root $entry.Name) $Request.identity
                    if ($null -ne $saved -and ($saved.phase -cne 'applied' -or $saved.command.command_type -cne $entry.Type)) { throw 'response_removal_active_state' }
                }
            }
            foreach ($store in @('PersistentStore', 'ActiveStore')) {
                if (@(Get-AidrResponseFirewallRules $store | Where-Object { $_.Group -ceq $group -or $_.Name.StartsWith($group + '.', [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) { throw 'response_removal_owned_rules_present' }
            }
            if (-not $existed -and [IO.Directory]::Exists($root)) { throw 'response_removal_state_changed' }
            return @{ ok = $true; observed = $true; removable = $true; evidence = @{ schema_version = 1; tenant_id = $Request.identity.tenant_id; agent_id = $Request.identity.agent_id; installation_id = $Request.identity.installation_id; state = 'native_inactive'; owned_rule_count = 0 } }
        } finally { if ($null -ne $inspectionLock) { $inspectionLock.Dispose() } }
    }
    $command = $Request.command
    $network = $command.command_type -clike 'network_*'
    if ($Request.operation -ceq 'dry_run') {
        $rules = @()
        if ($network) { $rules = @(Get-AidrResponseRules $Request.identity $(if ($null -eq $command.rollback_of) { $command.id } else { $command.rollback_of }) $ips) }
        return @{ ok = $true; observed = $false; evidence = (Get-AidrResponseEvidence $Request 'planned' $rules.Count) }
    }
    if ($network -and -not (Test-AidrResponseAdmin)) { throw 'response_requires_administrator' }
    if ($Request.operation -ceq 'verify' -and -not [IO.Directory]::Exists($root)) { throw 'response_action_not_observed' }
    if ($Request.operation -ceq 'execute' -and -not [IO.Directory]::Exists($root)) { Initialize-AidrResponseStateRoot $root }
    Assert-AidrResponsePrivateState $root
    $lockPath = Join-Path $root 'action.lock'
    Assert-AidrNoReparsePath $lockPath
    try { $lock = [IO.FileStream]::new($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 4096, [IO.FileOptions]::DeleteOnClose) }
    catch { throw 'response_action_busy' }
    try {
        $statePath = Join-Path $root $(if ($network) { 'network-state.json' } else { 'pause-state.json' })
        $state = Read-AidrResponseState $statePath $Request.identity
        $barrierPath = Join-Path $root 'barrier.json'
        $rollback = $null -ne $command.rollback_of
        if ($Request.operation -ceq 'verify') {
            if ($null -eq $state -or $state.command.id -cne $command.id -or $state.command.command_type -cne $command.command_type -or $state.command.rollback_of -cne $command.rollback_of) { throw 'response_action_not_observed' }
            if ($network) {
                $savedIps = @($state.recovery_addresses | ForEach-Object { Get-AidrResponseIp $_ })
                $rules = @(Get-AidrResponseRules $Request.identity $state.original_command_id $savedIps)
                if (-not $rollback) {
                    if ((@($ips | ForEach-Object Address) -join ',') -cne (@($savedIps | ForEach-Object Address) -join ',')) { throw 'response_policy_mismatch' }
                    $active = @(Get-AidrResponseFirewallRules 'ActiveStore')
                    Assert-AidrResponseFirewallPolicy $savedIps $active @($rules.Name)
                }
                Test-AidrResponseRuleSet $rules -Absent:$rollback
                return @{ ok = $true; observed = $true; evidence = (Get-AidrResponseEvidence $Request $(if ($rollback) { 'owned_rules_absent' } else { 'owned_rules_effective' }) $rules.Count) }
            }
            $barrier = Read-AidrResponseBarrier $barrierPath $Request.identity
            if (($rollback -and $null -ne $barrier) -or (-not $rollback -and ($null -eq $barrier -or $barrier.command_id -cne $command.id))) { throw 'response_action_not_observed' }
            return @{ ok = $true; observed = $true; evidence = (Get-AidrResponseEvidence $Request $(if ($rollback) { 'matching_barrier_absent' } else { 'signed_barrier_present' })) }
        }
        # A retry may observe a completed effect, but must never change its immutable policy.
        if ($null -ne $state -and -not $rollback -and $state.original_command_id -ceq $command.id -and $state.command.id -cne $command.id) { throw 'response_command_replay' }
        if ($null -ne $state -and $state.command.id -ceq $command.id) {
            if ($state.command.command_type -cne $command.command_type -or $state.command.rollback_of -cne $command.rollback_of -or
                ($network -and -not $rollback -and (@($state.recovery_addresses) -join ',') -cne (@($ips | ForEach-Object Address) -join ','))) { throw 'response_command_reuse' }
            # Already holding the action lock: observe directly instead of recursively acquiring it.
            if ($network) {
                $savedIps = @($state.recovery_addresses | ForEach-Object { Get-AidrResponseIp $_ })
                $rules = @(Get-AidrResponseRules $Request.identity $state.original_command_id $savedIps)
                if (-not $rollback) { Assert-AidrResponseFirewallPolicy $savedIps @(Get-AidrResponseFirewallRules 'ActiveStore') @($rules.Name) }
                Test-AidrResponseRuleSet $rules -Absent:$rollback
            } else {
                $barrier = Read-AidrResponseBarrier $barrierPath $Request.identity
                if (($rollback -and $null -ne $barrier) -or (-not $rollback -and ($null -eq $barrier -or $barrier.command_id -cne $command.id))) { throw 'response_action_not_observed' }
            }
            return @{ ok = $true; evidence = (Get-AidrResponseEvidence $Request 'idempotent') }
        }
        if (-not $network) {
            $barrier = Read-AidrResponseBarrier $barrierPath $Request.identity
            if ($rollback) {
                if ($null -eq $barrier -or $barrier.command_id -cne $command.rollback_of -or $null -eq $state -or $state.command.command_type -cne 'agent_pause' -or $state.command.id -cne $command.rollback_of) { throw 'response_rollback_mismatch' }
            } elseif ($null -ne $barrier -or ($null -ne $state -and $state.command.command_type -cne 'agent_resume')) { throw 'response_pause_conflict' }
            $next = New-AidrResponseState $Request $(if ($rollback) { $command.rollback_of } else { $command.id }) @()
            $script:AidrResponseIntentWritten = $true
            Write-AidrResponseState $statePath $next
            if ($rollback) {
                $again = Read-AidrResponseBarrier $barrierPath $Request.identity
                if ($null -eq $again -or ($again | ConvertTo-Json -Depth 20 -Compress) -cne ($barrier | ConvertTo-Json -Depth 20 -Compress)) { throw 'response_barrier_changed' }
                Assert-AidrNoReparsePath $barrierPath
                [IO.File]::Delete($barrierPath)
            } else {
                $value = [pscustomobject]@{ schema_version = 1; tenant_id = $Request.identity.tenant_id; agent_id = $Request.identity.agent_id; installation_id = $Request.identity.installation_id;
                    command_id = $command.id; created_at = $next.created_at; command_signed = $Request.delivery }
                Write-AidrResponseState $barrierPath $value
            }
            $next.phase = 'applied'; Write-AidrResponseState $statePath $next
            return @{ ok = $true; evidence = (Get-AidrResponseEvidence $Request 'applied') }
        }
        if ($rollback) {
            if ($null -eq $state -or $state.command.command_type -cne 'network_isolate' -or $state.command.id -cne $command.rollback_of) { throw 'response_rollback_mismatch' }
            $savedIps = @($state.recovery_addresses | ForEach-Object { Get-AidrResponseIp $_ })
            $rules = @(Get-AidrResponseRules $Request.identity $command.rollback_of $savedIps)
            $persistent = @(Get-AidrResponseFirewallRules 'PersistentStore')
            foreach ($storeRules in @($persistent), @(Get-AidrResponseFirewallRules 'ActiveStore')) {
                foreach ($existing in @($storeRules | Where-Object Group -CEQ $rules[0].Group)) {
                    $match = @($rules | Where-Object Name -CEQ $existing.Name)
                    if ($match.Count -ne 1) { throw 'firewall_unexpected_owned_rule' }
                    Assert-AidrResponseRule $existing $match[0]
                }
            }
            foreach ($expected in $rules) {
                $matches = @($persistent | Where-Object Name -CEQ $expected.Name)
                if ($matches.Count -gt 1) { throw 'firewall_owned_rule_mismatch' }
                if ($matches.Count -eq 1) { Assert-AidrResponseRule $matches[0] $expected }
            }
            $next = New-AidrResponseState $Request $command.rollback_of @($savedIps | ForEach-Object Address)
            $script:AidrResponseIntentWritten = $true
            Write-AidrResponseState $statePath $next
            foreach ($expected in $rules) {
                if (@($persistent | Where-Object Name -CEQ $expected.Name).Count -eq 1) {
                    Remove-NetFirewallRule -Name $expected.Name -PolicyStore PersistentStore -ErrorAction Stop | Out-Null
                }
            }
            Test-AidrResponseRuleSet $rules -Absent
            $next.phase = 'applied'; Write-AidrResponseState $statePath $next
            return @{ ok = $true; evidence = (Get-AidrResponseEvidence $Request 'applied' $rules.Count) }
        }
        if ($null -ne $state -and ($state.command.command_type -cne 'network_release' -or $state.phase -cne 'applied')) { throw 'response_isolation_conflict' }
        $rules = @(Get-AidrResponseRules $Request.identity $command.id $ips)
        $active = @(Get-AidrResponseFirewallRules 'ActiveStore')
        $persistent = @(Get-AidrResponseFirewallRules 'PersistentStore')
        foreach ($existing in @($active) + @($persistent)) {
            if ($existing.Group -ceq $rules[0].Group -or $existing.Name -cin @($rules.Name)) { throw 'firewall_owned_rule_collision' }
        }
        Assert-AidrResponseFirewallPolicy $ips $active @()
        $next = New-AidrResponseState $Request $command.id @($ips | ForEach-Object Address)
        $script:AidrResponseIntentWritten = $true
        Write-AidrResponseState $statePath $next
        $attempted = [Collections.Generic.List[object]]::new()
        try {
            # Recovery Allows do not intersect Blocks. Install them before isolation.
            foreach ($expected in @($rules | Sort-Object Action)) {
                $attempted.Add($expected)
                New-NetFirewallRule -Name $expected.Name -DisplayName $expected.Name -Group $expected.Group -Description $expected.Description -PolicyStore PersistentStore -Enabled True -Profile Any -Direction $expected.Direction -Action $expected.Action -Protocol Any -LocalAddress Any -RemoteAddress $expected.RemoteAddress -LocalPort Any -RemotePort Any -Program Any -Service Any -InterfaceAlias Any -InterfaceType Any -Authentication NotRequired -Encryption NotRequired -OverrideBlockRules $false -ErrorAction Stop | Out-Null
            }
        } catch {
            # Never clear a whole group. Even cleanup checks each exact expected rule.
            foreach ($expected in $attempted) {
                try {
                    $matches = @(Get-AidrResponseFirewallRules 'PersistentStore' | Where-Object Name -CEQ $expected.Name)
                    if ($matches.Count -eq 1) { Assert-AidrResponseRule $matches[0] $expected; Remove-NetFirewallRule -Name $expected.Name -PolicyStore PersistentStore -ErrorAction Stop | Out-Null }
                } catch { throw 'firewall_partial_action_cleanup_failed' }
            }
            throw 'firewall_action_failed'
        }
        $next.phase = 'applied'; Write-AidrResponseState $statePath $next
        return @{ ok = $true; evidence = (Get-AidrResponseEvidence $Request 'applied' $rules.Count) }
    } catch {
        if ($script:AidrResponseIntentWritten) { throw 'native_action_outcome_unknown' }
        throw
    } finally { $lock.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        [Console]::InputEncoding = [Text.UTF8Encoding]::new($false, $true)
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $buffer = [char[]]::new(16385)
        $length = 0
        while ($length -lt $buffer.Length) {
            $read = [Console]::In.Read($buffer, $length, $buffer.Length - $length)
            if ($read -eq 0) { break }
            $length += $read
        }
        if ($length -eq 0 -or $length -gt 16384) { throw 'invalid_response_request' }
        $request = ([string]::new($buffer, 0, $length)) | ConvertFrom-Json -ErrorAction Stop
        $null = Assert-AidrResponseRequest $request
        Assert-AidrResponseStatePath $request.state_root -CurrentUser
        if ($WhatIf -and $request.operation -cne 'inspect_removal') { $request.operation = 'dry_run' }
        $result = Invoke-AidrResponseAction $request
    } catch {
        $code = [string]$_.Exception.Message
        if ($code -cnotmatch '^[a-z][a-z0-9_]{0,63}$') { $code = 'native_response_action_failed' }
        $result = @{ ok = $false; code = $code }
    }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Depth 10 -Compress))
}
