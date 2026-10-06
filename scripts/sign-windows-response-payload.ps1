[CmdletBinding()]
param(
    [string]$FleetScriptRoot,
    [string]$ClaudeDist,
    [string]$InputManifestPath,
    [string]$ExpectedThumbprint,
    [string]$TimestampServer,
    [string]$ReceiptPath,
    [switch]$CheckOnly,
    [ValidateSet('CurrentUser/My', 'LocalMachine/My')][string]$CertificateStore = 'CurrentUser/My',
    [string]$SignToolPath
)

$script:AidrSigningFleetFiles = @(
    'Common.ps1', 'Install-Aidr.ps1', 'Install-AidrResponseWorker.ps1',
    'Invoke-AidrRemediation.ps1', 'Invoke-AidrResponseAction.ps1',
    'New-AidrFleetManifest.ps1', 'Rollback-Aidr.ps1', 'Test-AidrDetection.ps1',
    'Test-AidrFleetScriptSignatures.ps1', 'Uninstall-Aidr.ps1',
    'Uninstall-AidrResponseWorker.ps1', 'Update-Aidr.ps1'
)
$script:AidrSigningNativeFiles = @('Common.ps1', 'Invoke-AidrResponseAction.ps1')
$script:AidrSigningSourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../deploy/fleet/windows'))

function Assert-AidrSigningFields($Value, [string[]]$Fields) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'invalid_signing_evidence' }
    $names = @($Value.PSObject.Properties.Name)
    if ($names.Count -ne $Fields.Count) { throw 'invalid_signing_evidence' }
    foreach ($name in $names) { if (-not ($Fields -ccontains $name)) { throw 'invalid_signing_evidence' } }
}

function Get-AidrSigningHash([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose(); $stream.Dispose() }
}

function Get-AidrSigningBytesHash([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function ConvertFrom-AidrSigningJson([string]$Json) {
    $parameters = @{ InputObject = $Json; ErrorAction = 'Stop' }
    # PowerShell 7.5 otherwise converts ISO strings to DateTime objects.
    if ((Get-Command ConvertFrom-Json -CommandType Cmdlet).Parameters.ContainsKey('DateKind')) { $parameters.DateKind = 'String' }
    return ConvertFrom-Json @parameters
}

function Assert-AidrSigningPath([string]$Path, [bool]$Directory, [bool]$AllowMissing = $false) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) { throw 'invalid_signing_path' }
    $absolute = [IO.Path]::GetFullPath($Path)
    if ($absolute.Length -gt ([IO.Path]::GetPathRoot($absolute)).Length) { $absolute = $absolute.TrimEnd([IO.Path]::DirectorySeparatorChar) }
    $cursor = $absolute
    while ($cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            $attributes = [IO.File]::GetAttributes($cursor)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'signing_reparse_path' }
        } elseif ($cursor -ceq $absolute -and -not $AllowMissing) { throw 'missing_signing_path' }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
    if ($Directory -and -not [IO.Directory]::Exists($absolute)) { throw 'missing_signing_directory' }
    if (-not $Directory -and [IO.Directory]::Exists($absolute)) { throw 'invalid_signing_path' }
    if (-not $Directory -and [IO.File]::Exists($absolute)) {
        if (-not ('AidrSigningFileIdentity' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class AidrSigningFileIdentity {
    [StructLayout(LayoutKind.Sequential)]
    private struct Info {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    public static void RequireSingleLink(string path) {
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
            Info info;
            if (!GetFileInformationByHandle(file.SafeFileHandle, out info) || info.Links != 1)
                throw new IOException("signing_hardlink_path");
        }
    }
}
'@ -ErrorAction Stop | Out-Null
        }
        try { [AidrSigningFileIdentity]::RequireSingleLink($absolute) } catch { throw 'signing_hardlink_path' }
    }
    return $absolute
}

function Test-AidrSigningOverlap([string]$Left, [string]$Right) {
    $prefix = $Left.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    return $Right.Equals($Left, [StringComparison]::OrdinalIgnoreCase) -or $Right.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Get-AidrSigningInventory([string]$FleetRoot, [string]$Dist) {
    $nativeRoot = Assert-AidrSigningPath (Join-Path $Dist 'native') $true
    $files = @()
    foreach ($name in $script:AidrSigningFleetFiles) {
        $files += [pscustomobject]@{ logical = 'fleet/' + $name; absolute = (Assert-AidrSigningPath (Join-Path $FleetRoot $name) $false) }
    }
    foreach ($name in $script:AidrSigningNativeFiles) {
        $files += [pscustomobject]@{ logical = 'claude/native/' + $name; absolute = (Assert-AidrSigningPath (Join-Path $nativeRoot $name) $false) }
    }
    foreach ($pair in @(@($FleetRoot, $script:AidrSigningFleetFiles), @($nativeRoot, $script:AidrSigningNativeFiles))) {
        foreach ($file in @(Get-ChildItem -LiteralPath $pair[0] -Force -File -ErrorAction Stop)) {
            if ($file.Extension -ieq '.ps1' -and -not ($pair[1] -ccontains $file.Name)) { throw 'unexpected_signing_script' }
        }
    }
    return $files
}

function Read-AidrSigningInputs([string]$Path, $Files, [byte[]]$Snapshot = $null) {
    try {
        $text = if ($null -ne $Snapshot) { [Text.UTF8Encoding]::new($false, $true).GetString($Snapshot) } else { [IO.File]::ReadAllText($Path) }
        $manifest = ConvertFrom-AidrSigningJson $text
    } catch { throw 'invalid_signing_evidence' }
    Assert-AidrSigningFields $manifest @('schema_version', 'purpose', 'git_sha', 'unsigned_release_sha256', 'files')
    if (($manifest.schema_version -isnot [int] -and $manifest.schema_version -isnot [long]) -or $manifest.schema_version -cne 1 -or
        $manifest.purpose -isnot [string] -or $manifest.purpose -cne 'aidr.windows-authenticode.inputs' -or
        $manifest.git_sha -isnot [string] -or $manifest.git_sha -cnotmatch '^[a-fA-F0-9]{40}$' -or
        $manifest.unsigned_release_sha256 -isnot [string] -or $manifest.unsigned_release_sha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        $manifest.files -isnot [array] -or $manifest.files.Count -ne $Files.Count) { throw 'invalid_signing_evidence' }
    $preimages = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $manifest.files) {
        Assert-AidrSigningFields $entry @('path', 'before_sha256')
        if ($entry.path -isnot [string] -or -not (@($Files.logical) -ccontains $entry.path) -or
            $entry.before_sha256 -isnot [string] -or $entry.before_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $preimages.ContainsKey($entry.path)) { throw 'invalid_signing_evidence' }
        $preimages.Add($entry.path, $entry.before_sha256)
    }
    return $preimages
}

function Test-AidrSigningReleaseMarker($Value) {
    if ($null -eq $Value) { return $false }
    if ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) {
            if ($property.Name -ieq 'release_signed' -and $property.Value -eq $true) { return $true }
            if (Test-AidrSigningReleaseMarker $property.Value) { return $true }
        }
    } elseif ($Value -is [array]) {
        foreach ($entry in $Value) { if (Test-AidrSigningReleaseMarker $entry) { return $true } }
    }
    return $false
}

function Assert-AidrSigningUnsignedStage([string[]]$Roots) {
    foreach ($directory in $Roots) {
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -Force -File -ErrorAction Stop)) {
            if ($file.Extension -ieq '.sig') { throw 'already_release_signed' }
            if ($file.Extension -ieq '.json') {
                $safe = Assert-AidrSigningPath $file.FullName $false
                try { $value = ConvertFrom-AidrSigningJson ([IO.File]::ReadAllText($safe)) } catch { throw 'invalid_signing_evidence' }
                if (Test-AidrSigningReleaseMarker $value) { throw 'already_release_signed' }
            }
        }
    }
}

function Assert-AidrSigningCertificate($Certificate, [string]$Thumbprint, [bool]$ForSigning) {
    if ($null -eq $Certificate -or $Certificate.Thumbprint -isnot [string] -or $Certificate.Thumbprint.ToUpperInvariant() -cne $Thumbprint) { throw 'unexpected_signing_certificate' }
    $codeSigning = $false
    foreach ($extension in @($Certificate.Extensions)) {
        if ($extension.Oid.Value -ceq '2.5.29.37') {
            foreach ($usage in @($extension.EnhancedKeyUsages)) { if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') { $codeSigning = $true } }
        }
    }
    if (-not $codeSigning) { throw 'missing_code_signing_eku' }
    if ($ForSigning) {
        if (-not $Certificate.HasPrivateKey) { throw 'missing_signing_private_key' }
        $now = [DateTime]::UtcNow
        if ($Certificate.NotBefore.ToUniversalTime() -gt $now -or $Certificate.NotAfter.ToUniversalTime() -lt $now) { throw 'expired_signing_certificate' }
    }
}

function Get-AidrSigningCertificate([string]$Store, [string]$Thumbprint) {
    $location = if ($Store -ceq 'LocalMachine/My') { [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine } else { [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser }
    $certStore = [Security.Cryptography.X509Certificates.X509Store]::new('My', $location)
    try {
        $certStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        $matches = @($certStore.Certificates | Where-Object { $_.Thumbprint.ToUpperInvariant() -ceq $Thumbprint })
        if ($matches.Count -ne 1) { throw 'signing_certificate_not_found' }
        return $matches[0]
    } finally { $certStore.Close() }
}

function Assert-AidrSigningSignature([string]$Path, [string]$Thumbprint) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ($signature.Status.ToString() -cne 'Valid' -or $signature.SignatureType.ToString() -cne 'Authenticode') { throw 'invalid_authenticode_signature' }
    Assert-AidrSigningCertificate $signature.SignerCertificate $Thumbprint $false
    if ($null -eq $signature.TimeStamperCertificate) { throw 'missing_authenticode_timestamp' }
}

function Assert-AidrSigningReceipt($Receipt, $Files, $Preimages, [string]$InputHash, [string]$Thumbprint, [string]$Timestamp) {
    Assert-AidrSigningFields $Receipt @('schema_version', 'purpose', 'signer_thumbprint', 'timestamp_server', 'verified_at', 'input_manifest_sha256', 'verified', 'files')
    $verifiedAt = [DateTimeOffset]::MinValue
    if (($Receipt.schema_version -isnot [int] -and $Receipt.schema_version -isnot [long]) -or $Receipt.schema_version -cne 1 -or
        $Receipt.purpose -isnot [string] -or $Receipt.purpose -cne 'aidr.windows-authenticode' -or $Receipt.verified -isnot [bool] -or -not $Receipt.verified -or
        $Receipt.signer_thumbprint -isnot [string] -or $Receipt.signer_thumbprint -cne $Thumbprint -or
        $Receipt.timestamp_server -isnot [string] -or $Receipt.timestamp_server -cne $Timestamp -or
        $Receipt.input_manifest_sha256 -isnot [string] -or $Receipt.input_manifest_sha256 -cne $InputHash -or
        $Receipt.verified_at -isnot [string] -or -not [DateTimeOffset]::TryParse($Receipt.verified_at, [ref]$verifiedAt) -or
        $Receipt.files -isnot [array] -or $Receipt.files.Count -ne $Files.Count) { throw 'invalid_signing_receipt' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $Receipt.files) {
        Assert-AidrSigningFields $entry @('path', 'before_sha256', 'sha256', 'size')
        if ($entry.path -isnot [string] -or -not $seen.Add($entry.path) -or -not $Preimages.ContainsKey($entry.path) -or
            $entry.before_sha256 -isnot [string] -or $entry.before_sha256 -cne $Preimages[$entry.path] -or $entry.sha256 -isnot [string] -or $entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            ($entry.size -isnot [int] -and $entry.size -isnot [long]) -or $entry.size -lt 1) { throw 'invalid_signing_receipt' }
        $file = @($Files | Where-Object logical -CEQ $entry.path)[0]
        if ((Get-AidrSigningHash $file.absolute) -cne $entry.sha256 -or ([IO.FileInfo]::new($file.absolute)).Length -ne $entry.size) { throw 'signing_receipt_hash_mismatch' }
    }
}

function Write-AidrSigningReceipt([string]$Path, $Receipt) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Receipt | ConvertTo-Json -Depth 8) + "`n")
        $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        [IO.File]::Move($temporary, $Path)
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}

function Resolve-AidrSigningTool([string]$ProvidedPath) {
    $tool = $ProvidedPath
    if ([string]::IsNullOrWhiteSpace($tool)) {
        $sdkRoot = Assert-AidrSigningPath (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)) 'Windows Kits/10/bin') $true
        $versions = @(Get-ChildItem -LiteralPath $sdkRoot -Directory -ErrorAction Stop | Where-Object { $_.Name -cmatch '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object { [Version]$_.Name } -Descending)
        foreach ($version in $versions) {
            $candidate = Join-Path $version.FullName 'x64/signtool.exe'
            if ([IO.File]::Exists($candidate)) { $tool = $candidate; break }
        }
    }
    if ([string]::IsNullOrWhiteSpace($tool)) { throw 'signing_tool_not_found' }
    $tool = Assert-AidrSigningPath $tool $false
    if ([IO.Path]::GetFileName($tool) -ine 'signtool.exe') { throw 'invalid_signing_tool' }
    $signature = Get-AuthenticodeSignature -LiteralPath $tool -ErrorAction Stop
    if ($signature.Status.ToString() -cne 'Valid' -or $signature.SignatureType.ToString() -cne 'Authenticode' -or
        $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -cnotmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { throw 'untrusted_signing_tool' }
    Assert-AidrSigningCertificate $signature.SignerCertificate $signature.SignerCertificate.Thumbprint.ToUpperInvariant() $false
    return $tool
}

function Invoke-AidrSigningTool([string]$Tool, [string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Tool
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'authenticode_signing_failed' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) { $process.Kill($true); $process.WaitForExit(); throw 'authenticode_signing_timeout' }
        $stdout.GetAwaiter().GetResult() | Out-Null
        $stderr.GetAwaiter().GetResult() | Out-Null
        if ($process.ExitCode -ne 0) { throw 'authenticode_signing_failed' }
    } finally { $process.Dispose() }
}

function Invoke-AidrWindowsSigning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FleetScriptRoot,
        [Parameter(Mandatory)][string]$ClaudeDist,
        [Parameter(Mandatory)][string]$InputManifestPath,
        [Parameter(Mandatory)][string]$ExpectedThumbprint,
        [Parameter(Mandatory)][string]$TimestampServer,
        [Parameter(Mandatory)][string]$ReceiptPath,
        [switch]$CheckOnly,
        [ValidateSet('CurrentUser/My', 'LocalMachine/My')][string]$CertificateStore = 'CurrentUser/My',
        [string]$SignToolPath
    )
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'windows_signing_required' }
    if (-not $CheckOnly -and $PSVersionTable.PSVersion.Major -lt 7) { throw 'powershell_7_signing_required' }
    $CertificateStore = if ($CertificateStore -ieq 'LocalMachine/My') { 'LocalMachine/My' } else { 'CurrentUser/My' }
    if ($ExpectedThumbprint -cnotmatch '^[a-fA-F0-9]{40}$') { throw 'invalid_signing_thumbprint' }
    $thumbprint = $ExpectedThumbprint.ToUpperInvariant()
    $timestampUri = $null
    if (-not [Uri]::TryCreate($TimestampServer, [UriKind]::Absolute, [ref]$timestampUri) -or
        $timestampUri.Scheme -cne 'https' -or [string]::IsNullOrWhiteSpace($timestampUri.Host) -or
        $timestampUri.UserInfo -or $timestampUri.Fragment -or $timestampUri.Query) { throw 'invalid_timestamp_server' }
    $fleetRoot = Assert-AidrSigningPath $FleetScriptRoot $true
    $dist = Assert-AidrSigningPath $ClaudeDist $true
    $inputPath = Assert-AidrSigningPath $InputManifestPath $false
    $receipt = Assert-AidrSigningPath $ReceiptPath $false (-not $CheckOnly)
    Assert-AidrSigningPath ([IO.Path]::GetDirectoryName($receipt)) $true | Out-Null
    if ($inputPath.Equals($receipt, [StringComparison]::OrdinalIgnoreCase)) { throw 'invalid_signing_path' }
    $files = @(Get-AidrSigningInventory $fleetRoot $dist)
    $inputBytes = [IO.File]::ReadAllBytes($inputPath)
    $preimages = Read-AidrSigningInputs $inputPath $files $inputBytes
    $inputHash = Get-AidrSigningBytesHash $inputBytes
    foreach ($name in $script:AidrSigningNativeFiles) {
        if ($preimages['fleet/' + $name] -cne $preimages['claude/native/' + $name]) { throw 'native_signing_source_mismatch' }
    }
    if ($CheckOnly) {
        try { $evidence = ConvertFrom-AidrSigningJson ([IO.File]::ReadAllText($receipt)) } catch { throw 'invalid_signing_receipt' }
        Assert-AidrSigningReceipt $evidence $files $preimages $inputHash $thumbprint $TimestampServer
        foreach ($file in $files) { Assert-AidrSigningSignature $file.absolute $thumbprint }
        # Observe receipt-bound bytes again after Windows trust verification.
        Assert-AidrSigningReceipt $evidence $files $preimages $inputHash $thumbprint $TimestampServer
        if ((Get-AidrSigningHash $inputPath) -cne $inputHash) { throw 'signing_input_manifest_changed' }
        return $evidence
    }
    if ([IO.File]::Exists($receipt)) { throw 'signing_receipt_already_exists' }
    $stageRoot = [IO.Path]::GetDirectoryName($fleetRoot)
    if ([IO.Path]::GetFileName($fleetRoot) -cne 'fleet' -or [IO.Path]::GetFileName($dist) -cne 'claude' -or
        -not ([IO.Path]::GetDirectoryName($dist)).Equals($stageRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not $inputPath.Equals((Join-Path $stageRoot 'input-manifest.json'), [StringComparison]::OrdinalIgnoreCase) -or
        -not $receipt.Equals((Join-Path $stageRoot 'authenticode-receipt.json'), [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe_signing_stage' }
    foreach ($candidate in @($stageRoot, $fleetRoot, $dist)) {
        if ((Test-AidrSigningOverlap $script:AidrSigningSourceRoot $candidate) -or (Test-AidrSigningOverlap $candidate $script:AidrSigningSourceRoot)) { throw 'deployment_source_signing_forbidden' }
    }
    Assert-AidrSigningUnsignedStage @($stageRoot, $fleetRoot, $dist, (Join-Path $dist 'native'))
    foreach ($file in $files) {
        if ((Get-AidrSigningHash $file.absolute) -cne $preimages[$file.logical]) { throw 'signing_preimage_mismatch' }
    }
    $tool = Resolve-AidrSigningTool $SignToolPath
    $certificate = Get-AidrSigningCertificate $CertificateStore $thumbprint
    Assert-AidrSigningCertificate $certificate $thumbprint $true
    foreach ($file in $files) {
        Assert-AidrSigningPath $file.absolute $false | Out-Null
        if ((Get-AidrSigningHash $file.absolute) -cne $preimages[$file.logical]) { throw 'signing_preimage_mismatch' }
        $arguments = @('sign', '/q', '/fd', 'SHA256', '/tr', $TimestampServer, '/td', 'SHA256', '/sha1', $thumbprint, '/s', 'My')
        if ($CertificateStore -ceq 'LocalMachine/My') { $arguments += '/sm' }
        $arguments += $file.absolute
        Invoke-AidrSigningTool $tool $arguments
    }
    $outputs = @()
    foreach ($file in $files) {
        Assert-AidrSigningPath $file.absolute $false | Out-Null
        $beforeVerification = Get-AidrSigningHash $file.absolute
        Assert-AidrSigningSignature $file.absolute $thumbprint
        $afterVerification = Get-AidrSigningHash $file.absolute
        if ($beforeVerification -cne $afterVerification) { throw 'signing_payload_changed' }
        $outputs += [pscustomobject]@{ path = $file.logical; before_sha256 = $preimages[$file.logical]; sha256 = $afterVerification; size = ([IO.FileInfo]::new($file.absolute)).Length }
    }
    if ((Get-AidrSigningHash $inputPath) -cne $inputHash) { throw 'signing_input_manifest_changed' }
    $evidence = [pscustomobject]@{
        schema_version = 1; purpose = 'aidr.windows-authenticode'; signer_thumbprint = $thumbprint;
        timestamp_server = $TimestampServer; verified_at = [DateTimeOffset]::UtcNow.ToString('o');
        input_manifest_sha256 = $inputHash; verified = $true; files = $outputs
    }
    Assert-AidrSigningPath $receipt $false $true | Out-Null
    Write-AidrSigningReceipt $receipt $evidence
    return $evidence
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    try {
        $result = Invoke-AidrWindowsSigning @PSBoundParameters
        $result | ConvertTo-Json -Depth 8 -Compress
    } catch {
        [Console]::Error.WriteLine('Windows Authenticode verification/signing failed: ' + $_.Exception.Message)
        exit 1
    }
}
