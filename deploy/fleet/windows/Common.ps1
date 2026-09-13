Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-AidrSha256 {
    param([AllowNull()][string]$Value)
    return $null -ne $Value -and $Value -match '^[a-fA-F0-9]{64}$'
}

function Assert-AidrKnownProperties {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string[]]$Allowed, [Parameter(Mandatory)][string]$Label)
    foreach ($name in @($Value.PSObject.Properties.Name)) {
        if ($name -notin $Allowed) { throw "$Label contains an unsupported property" }
    }
}

function Get-AidrSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $digest = $hasher.ComputeHash($stream) } finally { $stream.Dispose(); $hasher.Dispose() }
    return (([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant())
}

function Test-AidrFixedStringEqual {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)
    $leftBytes = [Text.Encoding]::UTF8.GetBytes($Left.ToLowerInvariant())
    $rightBytes = [Text.Encoding]::UTF8.GetBytes($Right.ToLowerInvariant())
    if ($leftBytes.Length -ne $rightBytes.Length) { return $false }
    $difference = 0
    for ($index = 0; $index -lt $leftBytes.Length; $index++) { $difference = $difference -bor ($leftBytes[$index] -bxor $rightBytes[$index]) }
    return $difference -eq 0
}

function Get-AidrSafeChildPath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RelativePath,
        [switch]$MustExist,
        [switch]$Directory
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or [IO.Path]::IsPathRooted($RelativePath) -or $RelativePath.Contains('\')) {
        throw "Fleet manifest contains an unsafe relative path"
    }
    $segments = $RelativePath.Split('/')
    if ($segments | Where-Object { $_ -in @('', '.', '..') }) { throw "Fleet manifest contains an unsafe relative path" }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $candidate = [IO.Path]::GetFullPath((Join-Path $rootFull ($segments -join [IO.Path]::DirectorySeparatorChar)))
    $prefix = "$rootFull$([IO.Path]::DirectorySeparatorChar)"
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Fleet path escapes its package root" }
    if ($MustExist -and -not (Test-Path -LiteralPath $candidate)) { throw "Required fleet package file is missing" }
    if ($MustExist -and $Directory -and -not (Test-Path -LiteralPath $candidate -PathType Container)) { throw "Required fleet directory is missing" }
    if ($MustExist -and -not $Directory -and -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Required fleet file is missing" }
    return $candidate
}

function Get-AidrValidatedTargetHome {
    param([Parameter(Mandatory)][string]$TargetHome)
    if (-not [IO.Path]::IsPathRooted($TargetHome)) { throw "TargetHome must be an explicit absolute path" }
    $resolved = (Resolve-Path -LiteralPath $TargetHome -ErrorAction Stop).Path.TrimEnd('\', '/')
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { throw "TargetHome must be an existing directory" }
    $root = [IO.Path]::GetPathRoot($resolved).TrimEnd('\', '/')
    if ($resolved.Equals($root, [StringComparison]::OrdinalIgnoreCase)) { throw "TargetHome cannot be a filesystem root" }
    $forbidden = @($env:windir, $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') }
    if ($forbidden | Where-Object { $resolved.Equals($_, [StringComparison]::OrdinalIgnoreCase) }) {
        throw "TargetHome cannot be a shared operating-system directory"
    }
    return $resolved
}

function Write-AidrFleetLog {
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9_.-]+$')][string]$Event,
        [ValidateSet('info', 'warning', 'error')][string]$Level = 'info',
        [hashtable]$Fields = @{}
    )
    $safe = [ordered]@{ timestamp = [DateTimeOffset]::UtcNow.ToString('o'); level = $Level; event = $Event }
    foreach ($name in ($Fields.Keys | Sort-Object)) {
        if ($name -notmatch '^(version|operation|result|target_id|artifact_sha256|manifest_sha256)$') { continue }
        $value = [string]$Fields[$name]
        if ($value.Length -gt 128 -or $value -match '(?i)(token|secret|password|api[_-]?key|bearer)') { $value = '[redacted]' }
        $safe[$name] = $value
    }
    $parent = Split-Path -Parent $LogPath
    if ([string]::IsNullOrWhiteSpace($parent)) { throw "LogPath must include a directory" }
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    Add-Content -LiteralPath $LogPath -Value ($safe | ConvertTo-Json -Compress) -Encoding utf8
}

function Get-AidrFleetPaths {
    param([Parameter(Mandatory)][string]$TargetHome, [Parameter(Mandatory)][string]$StateRoot)
    if (-not [IO.Path]::IsPathRooted($StateRoot)) { throw "StateRoot must be an absolute path" }
    $stateRootFull = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\', '/')
    if ($stateRootFull.Equals([IO.Path]::GetPathRoot($stateRootFull).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "StateRoot cannot be a filesystem root"
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $digest = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($TargetHome.ToLowerInvariant())) } finally { $hasher.Dispose() }
    $targetId = ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
    return [pscustomobject]@{
        TargetId = $targetId
        Root = $stateRootFull
        State = Join-Path $stateRootFull "targets/$targetId/state.json"
        Cache = Join-Path $stateRootFull "targets/$targetId/cache"
        DefaultLog = Join-Path $stateRootFull "logs/$targetId.jsonl"
    }
}

function Initialize-AidrFleetStateRoot {
    param([Parameter(Mandatory)][string]$StateRoot)
    $root = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\', '/')
    $defaultRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'SingularityAIDR/Fleet')).TrimEnd('\', '/')
    if (-not $root.Equals($defaultRoot, [StringComparison]::OrdinalIgnoreCase)) { [IO.Directory]::CreateDirectory($root) | Out-Null; return }
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The default machine fleet state requires an elevated MDM or administrator context"
    }
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, $allow))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($administrators, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, $allow))
    Set-Acl -LiteralPath $root -AclObject $acl
    $verifiedAcl = Get-Acl -LiteralPath $root
    $unexpectedAllow = @($verifiedAcl.Access | Where-Object {
        if ($_.AccessControlType -ne $allow) { return $false }
        try { $identitySid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $true }
        return $identitySid -notin @('S-1-5-18', 'S-1-5-32-544')
    })
    if ($unexpectedAllow.Count -ne 0) { throw "Fleet state ACL contains an unexpected allowed principal" }
}

function Read-AidrFleetManifest {
    param([Parameter(Mandatory)][string]$ManifestPath, [Parameter(Mandatory)][string]$ExpectedManifestSha256)
    if (-not (Test-AidrSha256 $ExpectedManifestSha256)) { throw "ExpectedManifestSha256 must contain exactly 64 hexadecimal characters" }
    $resolved = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "ManifestPath must be a file" }
    if ((Get-Item -LiteralPath $resolved).Length -gt 1048576) { throw "Fleet manifest exceeds the 1 MiB limit" }
    $actual = Get-AidrSha256 $resolved
    if (-not (Test-AidrFixedStringEqual $actual $ExpectedManifestSha256)) { throw "Fleet manifest SHA-256 mismatch" }
    try { $manifest = Get-Content -LiteralPath $resolved -Raw -Encoding utf8 | ConvertFrom-Json } catch { throw "Fleet manifest is not valid JSON" }
    Assert-AidrKnownProperties -Value $manifest -Allowed @('schema_version', 'product', 'connector', 'package_version', 'minimum_node_major', 'artifact', 'installer', 'agent_config', 'operations', 'assurance') -Label 'Fleet manifest'
    if ($manifest.schema_version -ne 1 -or $manifest.product -ne 'singularity-aidr') { throw "Unsupported fleet manifest schema or product" }
    if ([string]$manifest.connector -ne 'claude-code') { throw "Unsupported fleet connector" }
    if ([string]$manifest.package_version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid package version" }
    if ([int]$manifest.minimum_node_major -lt 18 -or [int]$manifest.minimum_node_major -gt 99) { throw "Invalid minimum Node.js version" }
    if ($null -eq $manifest.artifact) { throw "Artifact metadata is missing" }
    Assert-AidrKnownProperties -Value $manifest.artifact -Allowed @('path', 'sha256', 'signature_path', 'signature_required', 'allowed_signer_thumbprints', 'require_trusted_chain') -Label 'Artifact metadata'
    if (-not (Test-AidrSha256 ([string]$manifest.artifact.sha256))) { throw "Artifact SHA-256 is missing or invalid" }
    if ($manifest.artifact.signature_required -ne $true) { throw "Fleet artifacts must require a detached CMS signature" }
    if ($null -eq $manifest.artifact.allowed_signer_thumbprints -or @($manifest.artifact.allowed_signer_thumbprints).Count -lt 1) { throw "At least one signer thumbprint is required" }
    foreach ($thumbprint in @($manifest.artifact.allowed_signer_thumbprints)) {
        if ([string]$thumbprint -notmatch '^[a-fA-F0-9]{40,128}$') { throw "Invalid signer certificate thumbprint" }
    }
    if ($null -eq $manifest.installer) { throw "Installer metadata is missing" }
    Assert-AidrKnownProperties -Value $manifest.installer -Allowed @('path', 'sha256', 'package_root') -Label 'Installer metadata'
    if (-not (Test-AidrSha256 ([string]$manifest.installer.sha256)) -or [string]$manifest.installer.package_root -ne 'package') {
        throw "Installer metadata is invalid"
    }
    if ($null -ne $manifest.agent_config) {
        Assert-AidrKnownProperties -Value $manifest.agent_config -Allowed @('path', 'sha256', 'preserve_existing') -Label 'Agent configuration metadata'
        if (-not (Test-AidrSha256 ([string]$manifest.agent_config.sha256)) -or $manifest.agent_config.preserve_existing -ne $true) { throw "Agent configuration metadata is invalid" }
    }
    if ($null -eq $manifest.operations) { throw "Fleet operation metadata is missing" }
    Assert-AidrKnownProperties -Value $manifest.operations -Allowed @('installation_context', 'target_home_required', 'preserve_existing_config', 'retained_rollback_candidates') -Label 'Fleet operation metadata'
    if ([string]$manifest.operations.installation_context -ne 'machine-or-mdm-managed-user' -or $manifest.operations.target_home_required -ne $true -or $manifest.operations.preserve_existing_config -ne $true -or [int]$manifest.operations.retained_rollback_candidates -ne 3) {
        throw "Fleet operation metadata is invalid"
    }
    $base = Split-Path -Parent $resolved
    $null = Get-AidrSafeChildPath -Root $base -RelativePath ([string]$manifest.artifact.path) -MustExist
    $null = Get-AidrSafeChildPath -Root $base -RelativePath ([string]$manifest.artifact.signature_path) -MustExist
    $null = Get-AidrSafeChildPath -Root $base -RelativePath ([string]$manifest.installer.path) -MustExist
    if ($null -ne $manifest.agent_config) { $null = Get-AidrSafeChildPath -Root $base -RelativePath ([string]$manifest.agent_config.path) -MustExist }
    return [pscustomobject]@{ Path = $resolved; Base = $base; Sha256 = $actual; Value = $manifest }
}

function Assert-AidrFileDigest {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedSha256, [Parameter(Mandatory)][string]$Label)
    $actual = Get-AidrSha256 $Path
    if (-not (Test-AidrFixedStringEqual $actual $ExpectedSha256)) { throw "$Label SHA-256 mismatch" }
    return $actual
}

function Assert-AidrDetachedCmsSignature {
    param(
        [Parameter(Mandatory)][string]$ContentPath,
        [Parameter(Mandatory)][string]$SignaturePath,
        [Parameter(Mandatory)][string[]]$AllowedSignerThumbprints,
        [switch]$RequireTrustedChain
    )
    try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop } catch { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    try {
        $contentInfo = [Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($ContentPath))
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $true)
        $cms.Decode([IO.File]::ReadAllBytes($SignaturePath))
        $cms.CheckSignature($true)
    } catch { throw "Artifact CMS signature is invalid" }
    if ($cms.SignerInfos.Count -ne 1 -or $null -eq $cms.SignerInfos[0].Certificate) { throw "Artifact must have exactly one identifiable CMS signer" }
    $actualThumbprint = $cms.SignerInfos[0].Certificate.Thumbprint.Replace(' ', '').ToUpperInvariant()
    $allowed = @($AllowedSignerThumbprints | ForEach-Object { ([string]$_).Replace(' ', '').ToUpperInvariant() })
    if ($actualThumbprint -notin $allowed) { throw "Artifact signer certificate is not allowed" }
    if ($RequireTrustedChain) {
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Offline
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        if (-not $chain.Build($cms.SignerInfos[0].Certificate)) { throw "Artifact signer certificate chain is not trusted" }
    }
    return $actualThumbprint
}

function Assert-AidrManifestPayload {
    param([Parameter(Mandatory)]$ManifestRecord)
    $manifest = $ManifestRecord.Value
    $artifact = Get-AidrSafeChildPath -Root $ManifestRecord.Base -RelativePath ([string]$manifest.artifact.path) -MustExist
    $signature = Get-AidrSafeChildPath -Root $ManifestRecord.Base -RelativePath ([string]$manifest.artifact.signature_path) -MustExist
    $installer = Get-AidrSafeChildPath -Root $ManifestRecord.Base -RelativePath ([string]$manifest.installer.path) -MustExist
    if ((Get-Item -LiteralPath $signature).Length -gt 1048576) { throw "Artifact signature exceeds the 1 MiB limit" }
    if ((Get-Item -LiteralPath $installer).Length -gt 2097152) { throw "Endpoint installer exceeds the 2 MiB limit" }
    $null = Assert-AidrFileDigest -Path $artifact -ExpectedSha256 ([string]$manifest.artifact.sha256) -Label 'Artifact'
    $null = Assert-AidrFileDigest -Path $installer -ExpectedSha256 ([string]$manifest.installer.sha256) -Label 'Installer'
    $thumbprint = Assert-AidrDetachedCmsSignature -ContentPath $artifact -SignaturePath $signature -AllowedSignerThumbprints @($manifest.artifact.allowed_signer_thumbprints) -RequireTrustedChain:([bool]$manifest.artifact.require_trusted_chain)
    $config = $null
    if ($null -ne $manifest.agent_config) {
        $config = Get-AidrSafeChildPath -Root $ManifestRecord.Base -RelativePath ([string]$manifest.agent_config.path) -MustExist
        if ((Get-Item -LiteralPath $config).Length -gt 10485760) { throw "Agent configuration exceeds the 10 MiB limit" }
        $null = Assert-AidrFileDigest -Path $config -ExpectedSha256 ([string]$manifest.agent_config.sha256) -Label 'Agent configuration'
    }
    return [pscustomobject]@{ Artifact = $artifact; Signature = $signature; Installer = $installer; Config = $config; SignerThumbprint = $thumbprint }
}

function Expand-AidrVerifiedArchive {
    param([Parameter(Mandatory)][string]$Archive, [Parameter(Mandatory)][string]$Destination)
    if ((Get-Item -LiteralPath $Archive).Length -gt 536870912) { throw "Artifact archive exceeds the 512 MiB fleet limit" }
    $tar = (Get-Command tar.exe -ErrorAction Stop).Source
    $entries = @(& $tar -tf $Archive 2>$null)
    if ($LASTEXITCODE -ne 0 -or $entries.Count -eq 0 -or $entries.Count -gt 20000) { throw "Artifact archive cannot be safely listed" }
    foreach ($entry in $entries) {
        $name = ([string]$entry).TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ([IO.Path]::IsPathRooted($name) -or $name.Contains('\') -or ($name.Split('/') | Where-Object { $_ -in @('', '.', '..') })) {
            throw "Artifact archive contains an unsafe path"
        }
    }
    $detailedEntries = @(& $tar -tvf $Archive 2>$null)
    if ($LASTEXITCODE -ne 0 -or $detailedEntries.Count -eq 0) { throw "Artifact archive metadata cannot be listed" }
    if ($detailedEntries | Where-Object { [string]$_ -match '^[lh]' }) { throw "Artifact archive contains a symbolic or hard link" }
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    & $tar -xf $Archive -C $Destination 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Artifact archive extraction failed" }
    $reparse = Get-ChildItem -LiteralPath $Destination -Force -Recurse | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } | Select-Object -First 1
    if ($null -ne $reparse) { throw "Artifact archive contains a link or reparse point" }
}

function Read-AidrFleetState {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json } catch { throw "Fleet state is invalid" }
}

function Get-AidrConnectorInventory {
    param([Parameter(Mandatory)][string]$ConnectorPath)
    $root = [IO.Path]::GetFullPath($ConnectorPath).TrimEnd('\', '/')
    $items = @(Get-ChildItem -LiteralPath $root -File -Force -Recurse | Sort-Object FullName)
    if ($items.Count -eq 0 -or $items.Count -gt 20000) { throw "Managed connector inventory is empty or too large" }
    $inventory = @()
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Managed connector contains a reparse point" }
        $full = [IO.Path]::GetFullPath($item.FullName)
        $prefix = "$root$([IO.Path]::DirectorySeparatorChar)"
        if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Managed connector file escapes its root" }
        $relative = $full.Substring($prefix.Length).Replace('\', '/')
        $inventory += [pscustomobject]@{ path = $relative; sha256 = Get-AidrSha256 $full }
    }
    return $inventory
}

function Write-AidrFleetState {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $parent = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $temporary = Join-Path $parent ("state.{0}.tmp" -f [Guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($temporary, (($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $replaceBackup = Join-Path $parent ("state.{0}.replace-backup" -f [Guid]::NewGuid().ToString('N'))
        [IO.File]::Replace($temporary, $Path, $replaceBackup)
        [IO.File]::Delete($replaceBackup)
    } else { [IO.File]::Move($temporary, $Path) }
}

function Copy-AidrManifestPackageToCache {
    param([Parameter(Mandatory)]$ManifestRecord, [Parameter(Mandatory)]$Payload, [Parameter(Mandatory)][string]$CacheRoot)
    $cache = Join-Path $CacheRoot $ManifestRecord.Sha256
    [IO.Directory]::CreateDirectory($cache) | Out-Null
    $items = @(
        @{ Source = $ManifestRecord.Path; Relative = 'manifest.json' },
        @{ Source = $Payload.Artifact; Relative = [string]$ManifestRecord.Value.artifact.path },
        @{ Source = $Payload.Signature; Relative = [string]$ManifestRecord.Value.artifact.signature_path },
        @{ Source = $Payload.Installer; Relative = [string]$ManifestRecord.Value.installer.path }
    )
    if ($null -ne $Payload.Config) { $items += @{ Source = $Payload.Config; Relative = [string]$ManifestRecord.Value.agent_config.path } }
    foreach ($item in $items) {
        $destination = Get-AidrSafeChildPath -Root $cache -RelativePath $item.Relative
        [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
        if (Test-Path -LiteralPath $destination) {
            if (-not (Test-AidrFixedStringEqual (Get-AidrSha256 $destination) (Get-AidrSha256 $item.Source))) { throw "Fleet cache contains conflicting content" }
        } else { Copy-Item -LiteralPath $item.Source -Destination $destination }
    }
    $cachedManifest = Join-Path $cache 'manifest.json'
    $null = Assert-AidrFileDigest -Path $cachedManifest -ExpectedSha256 $ManifestRecord.Sha256 -Label 'Cached manifest'
    return $cachedManifest
}

function Invoke-AidrEndpointInstaller {
    param(
        [Parameter(Mandatory)]$ManifestRecord,
        [Parameter(Mandatory)]$Payload,
        [Parameter(Mandatory)][string]$TargetHome
    )
    $node = (Get-Command node.exe -ErrorAction Stop).Source
    $nodeVersion = (& $node -p 'process.versions.node' 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch '^(\d+)\.') { throw "Node.js version cannot be determined" }
    if ([int]$Matches[1] -lt [int]$ManifestRecord.Value.minimum_node_major) { throw "Node.js does not meet the fleet package minimum version" }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ("aidr-fleet-{0}" -f [Guid]::NewGuid().ToString('N'))
    try {
        Expand-AidrVerifiedArchive -Archive $Payload.Artifact -Destination $temporary
        $packageRoot = Get-AidrSafeChildPath -Root $temporary -RelativePath ([string]$ManifestRecord.Value.installer.package_root) -MustExist -Directory
        $packageJsonPath = Join-Path $packageRoot 'package.json'
        if (-not (Test-Path -LiteralPath $packageJsonPath -PathType Leaf)) { throw "Artifact package.json is missing" }
        try { $packageJson = Get-Content -LiteralPath $packageJsonPath -Raw -Encoding utf8 | ConvertFrom-Json } catch { throw "Artifact package.json is invalid" }
        if ([string]$packageJson.name -ne '@singularityrd/aidr-claude-code' -or [string]$packageJson.version -ne [string]$ManifestRecord.Value.package_version) {
            throw "Artifact package identity does not match the fleet manifest"
        }
        foreach ($required in @('dist/pre-tool-use.cjs', 'dist/post-tool-use.cjs', 'dist/session-start.cjs', 'resources/threats', 'resources/allowlists')) {
            $null = Get-AidrSafeChildPath -Root $packageRoot -RelativePath $required -MustExist -Directory:($required -notmatch '\.cjs$')
        }
        $arguments = @($Payload.Installer, '--package-dir', $packageRoot, '--home', $TargetHome)
        $existingConfig = Join-Path $TargetHome '.singularity-aidr/config.json'
        if ($null -ne $Payload.Config -and -not (Test-Path -LiteralPath $existingConfig)) { $arguments += @('--config', $Payload.Config) }
        $output = @(& $node @arguments 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "Endpoint installer failed without updating fleet state" }
        $receiptPath = Join-Path $TargetHome '.singularity-aidr/installation.json'
        if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { throw "Endpoint installer did not create an installation receipt" }
        try { $receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding utf8 | ConvertFrom-Json } catch { throw "Endpoint installation receipt is invalid" }
        if ([string]$receipt.connector -ne 'claude-code' -or [string]$receipt.local_canary -ne 'deny' -or -not (Test-AidrSha256 ([string]$receipt.artifact_sha256))) {
            throw "Endpoint installation receipt failed validation"
        }
        $connectorRoot = Join-Path $TargetHome '.singularity-aidr/connectors/claude'
        $connectorPath = [IO.Path]::GetFullPath([string]$receipt.path)
        $connectorPrefix = [IO.Path]::GetFullPath($connectorRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if (-not $connectorPath.StartsWith($connectorPrefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $connectorPath -PathType Container)) {
            throw "Endpoint installation receipt points outside the managed connector directory"
        }
        return [pscustomobject]@{ ConnectorPath = $connectorPath; ConnectorDigest = [string]$receipt.artifact_sha256 }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
