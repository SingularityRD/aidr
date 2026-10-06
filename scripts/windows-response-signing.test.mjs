import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const signer = path.join(root, 'scripts/sign-windows-response-payload.ps1');
const psString = (value) => `'${value.replaceAll("'", "''")}'`;

const harnessSource = String.raw`
$ErrorActionPreference = 'Stop'
. SIGNER_PATH
$script:checks = 0
$script:signCalls = 0
$script:storeCalls = 0
$script:signatureCalls = 0
$script:failure = ''
$script:toolTrusted = $true
$script:privateKey = $true
$script:eku = $true
$script:expired = $false
$script:appearManifest = $false
$script:changeOnParse = $false
$script:machine = $false
$script:thumb = '1234567890ABCDEF1234567890ABCDEF12345678'
$script:signedFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$fixture = FIXTURE_PATH
$script:parseJsonBody = (Get-Command ConvertFrom-AidrSigningJson).ScriptBlock
function ConvertFrom-AidrSigningJson([string]$Json) {
    $parsed = & $script:parseJsonBody $Json
    if ($script:changeOnParse -and $parsed.purpose -ceq 'aidr.windows-authenticode.inputs') {
        $changed = & $script:parseJsonBody $Json
        $changed.files[0].before_sha256 = ('0' * 64)
        [IO.File]::WriteAllText($script:inputToChange, ($changed | ConvertTo-Json -Depth 5))
        $script:changeOnParse = $false
    }
    return $parsed
}
function Check($Value, [string]$Label) { if (-not $Value) { throw ('FAILED: ' + $Label) }; $script:checks++ }
function Fails([scriptblock]$Action, [string]$Code) {
    try { & $Action | Out-Null } catch { Check ($_.Exception.Message -ceq $Code) ($Code + ': ' + $_.Exception.Message); return }
    throw ('Expected failure: ' + $Code)
}
function Fake-Certificate([string]$Thumbprint) {
    $usages = if ($script:eku) { @([pscustomobject]@{ Value = '1.3.6.1.5.5.7.3.3' }) } else { @([pscustomobject]@{ Value = '1.3.6.1.5.5.7.3.1' }) }
    return [pscustomobject]@{ Thumbprint = $Thumbprint; Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, C=US'; HasPrivateKey = $script:privateKey;
        NotBefore = [DateTime]::UtcNow.AddDays(-2); NotAfter = $(if ($script:expired) { [DateTime]::UtcNow.AddDays(-1) } else { [DateTime]::UtcNow.AddDays(2) });
        Extensions = @([pscustomobject]@{ Oid = [pscustomobject]@{ Value = '2.5.29.37' }; EnhancedKeyUsages = $usages }) }
}
function Get-AidrSigningCertificate([string]$Store, [string]$Thumbprint) {
    $script:storeCalls++
    Check ($Store -ceq $(if ($script:machine) { 'LocalMachine/My' } else { 'CurrentUser/My' })) 'closed certificate store'
    return Fake-Certificate $Thumbprint
}
function Get-AuthenticodeSignature {
    [CmdletBinding()]param([string]$LiteralPath)
    $script:signatureCalls++
    $tool = [IO.Path]::GetFileName($LiteralPath) -ieq 'signtool.exe'
    if ($tool) { $status = if ($script:toolTrusted) { 'Valid' } else { 'NotTrusted' } } else {
        $status = if ($script:signedFiles.Contains($LiteralPath)) { 'Valid' } else { 'NotSigned' }
    }
    $certificate = Fake-Certificate $script:thumb
    if (-not $tool -and $script:failure -ceq 'wrong_signer') { $certificate.Thumbprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }
    if ($tool -and $script:failure -ceq 'foreign_tool') { $certificate.Subject = 'CN=Untrusted Software, O=Customer' }
    return [pscustomobject]@{ Status = $status; SignatureType = $(if (-not $tool -and $script:failure -ceq 'catalog') { 'Catalog' } else { 'Authenticode' });
        SignerCertificate = $certificate; TimeStamperCertificate = $(if (-not $tool -and $script:failure -ceq 'timestamp') { $null } else { [pscustomobject]@{ Subject = 'Mock TSA' } }) }
}
function Invoke-AidrSigningTool([string]$Tool, [string[]]$Arguments) {
    $script:signCalls++
    $expected = @('sign', '/q', '/fd', 'SHA256', '/tr', 'https://tsa.example.test', '/td', 'SHA256', '/sha1', $script:thumb, '/s', 'My')
    if ($script:machine) { $expected += '/sm' }
    Check ((($Arguments[0..($Arguments.Count - 2)]) -join '|') -ceq ($expected -join '|')) 'fixed SignTool arguments, HTTPS RFC3161 SHA256 and pinned certificate'
    Check ([IO.Path]::GetFileName($Tool) -ceq 'signtool.exe') 'verified tool passed directly'
    if ($script:failure -ceq 'process' -and $script:signCalls -eq 3) { throw 'authenticode_signing_failed' }
    $file = $Arguments[-1]
    [IO.File]::AppendAllText($file, ([Environment]::NewLine + '# fixture signed bytes' + [Environment]::NewLine))
    $script:signedFiles.Add($file) | Out-Null
    if ($script:appearManifest) { [IO.File]::AppendAllText($script:inputToChange, ' '); $script:appearManifest = $false }
}
function New-Stage([string]$Name) {
    $stage = Join-Path $fixture $Name
    $fleet = Join-Path $stage 'fleet'
    $dist = Join-Path $stage 'claude'
    [IO.Directory]::CreateDirectory($fleet) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $dist 'native')) | Out-Null
    foreach ($file in $script:AidrSigningFleetFiles) { [IO.File]::WriteAllText((Join-Path $fleet $file), ('# fixture ' + $file + [Environment]::NewLine)) }
    foreach ($file in $script:AidrSigningNativeFiles) { [IO.File]::Copy((Join-Path $fleet $file), (Join-Path (Join-Path $dist 'native') $file)) }
    $tool = Join-Path $stage 'signtool.exe'
    [IO.File]::WriteAllText($tool, 'fixture tool never executed')
    $request = @{ FleetScriptRoot = $fleet; ClaudeDist = $dist; InputManifestPath = (Join-Path $stage 'input-manifest.json');
        ExpectedThumbprint = $script:thumb.ToLowerInvariant(); TimestampServer = 'https://tsa.example.test'; ReceiptPath = (Join-Path $stage 'authenticode-receipt.json'); SignToolPath = $tool }
    Save-Inputs $request
    return $request
}
function Save-Inputs($Request) {
    $files = @(Get-AidrSigningInventory $Request.FleetScriptRoot $Request.ClaudeDist)
    $entries = @($files | ForEach-Object { [pscustomobject]@{ path = $_.logical; before_sha256 = (Get-AidrSigningHash $_.absolute) } })
    $manifest = [pscustomobject]@{ schema_version = 1; purpose = 'aidr.windows-authenticode.inputs'; git_sha = ('a' * 40); unsigned_release_sha256 = ('b' * 64); files = $entries }
    [IO.File]::WriteAllText($Request.InputManifestPath, ($manifest | ConvertTo-Json -Depth 5))
}
function Reset-Mocks {
    $script:signCalls = 0; $script:storeCalls = 0; $script:signatureCalls = 0; $script:failure = ''; $script:toolTrusted = $true
    $script:privateKey = $true; $script:eku = $true; $script:expired = $false; $script:appearManifest = $false; $script:changeOnParse = $false; $script:machine = $false
}
function Sign-Stage($Request) { return Invoke-AidrWindowsSigning @Request }
function Check-Stage($Request) { return Invoke-AidrWindowsSigning @Request -CheckOnly }
function No-Sign($Request, [string]$Code) {
    Fails { Sign-Stage $Request } $Code
    Check ($script:signCalls -eq 0 -and $script:storeCalls -eq 0) 'failure occurs before certificate lookup or file mutation'
    Check (-not [IO.File]::Exists($Request.ReceiptPath)) 'no success receipt for rejected input'
}
Check ((Assert-AidrSigningPath ([IO.Path]::GetPathRoot($fixture)) $true) -ceq ([IO.Path]::GetPathRoot($fixture))) 'drive root remains absolute with separator'

if ($PSVersionTable.PSVersion.Major -ge 7) {
    $valid = New-Stage 'valid'
    [IO.File]::WriteAllText((Join-Path $valid.ClaudeDist 'aidr-artifact.manifest.json'), '{"schema_version":1,"files":[]}')
    $result = Sign-Stage $valid
    Check ($script:signCalls -eq 14 -and $result.files.Count -eq 14) 'exact fourteen scripts signed'
    Check ($script:signatureCalls -eq 15) 'independent postflight for each script and tool'
    Check ($result.signer_thumbprint -ceq $script:thumb -and $result.purpose -ceq 'aidr.windows-authenticode' -and $result.verified) 'receipt schema and normalized pinned thumbprint'
    Check ($result.input_manifest_sha256 -ceq (Get-AidrSigningHash $valid.InputManifestPath)) 'receipt binds original manifest bytes'
    Check ([IO.File]::Exists($valid.ReceiptPath)) 'verified receipt written once'
    foreach ($entry in $result.files) { Check ($entry.before_sha256 -cne $entry.sha256 -and $entry.size -gt 0) 'receipt preserves preimage and signed bytes' }
    $script:valid = $valid
    Reset-Mocks
    $old = [IO.File]::ReadAllText($valid.ReceiptPath)
    Fails { Sign-Stage $valid } 'signing_receipt_already_exists'
    Check ($script:signCalls -eq 0 -and [IO.File]::ReadAllText($valid.ReceiptPath) -ceq $old) 'preexisting success receipt never overwritten'

    foreach ($case in @('preimage', 'native', 'marker', 'metadata', 'extra', 'manifest', 'schema_type', 'timestamp_url', 'timestamp_query', 'source', 'source_nested', 'source_ancestor', 'hardlink', 'junction')) {
        Reset-Mocks
        $request = New-Stage $case
        $code = ''
        switch ($case) {
            'preimage' { [IO.File]::AppendAllText((Join-Path $request.FleetScriptRoot 'Common.ps1'), 'tamper'); $code = 'signing_preimage_mismatch' }
            'native' { [IO.File]::AppendAllText((Join-Path $request.ClaudeDist 'native/Common.ps1'), 'tamper'); Save-Inputs $request; $code = 'native_signing_source_mismatch' }
            'marker' { [IO.File]::WriteAllText((Join-Path $request.ClaudeDist 'aidr-artifact.manifest.sig'), '{}'); $code = 'already_release_signed' }
            'metadata' { [IO.File]::WriteAllText((Join-Path $request.ClaudeDist 'release-metadata.json'), '{"nested":{"release_signed":true}}'); $code = 'already_release_signed' }
            'extra' { [IO.File]::WriteAllText((Join-Path $request.FleetScriptRoot 'Unexpected.ps1'), '# extra'); $code = 'unexpected_signing_script' }
            'manifest' { $json = [IO.File]::ReadAllText($request.InputManifestPath) | ConvertFrom-Json; $json.files[1].path = $json.files[0].path; [IO.File]::WriteAllText($request.InputManifestPath, ($json | ConvertTo-Json -Depth 5)); $code = 'invalid_signing_evidence' }
            'schema_type' { $json = ConvertFrom-AidrSigningJson ([IO.File]::ReadAllText($request.InputManifestPath)); $json.schema_version = '1'; [IO.File]::WriteAllText($request.InputManifestPath, ($json | ConvertTo-Json -Depth 5)); $code = 'invalid_signing_evidence' }
            'timestamp_url' { $request.TimestampServer = 'http://tsa.example.test'; $code = 'invalid_timestamp_server' }
            'timestamp_query' { $request.TimestampServer = 'https://tsa.example.test?token=unreviewed'; $code = 'invalid_timestamp_server' }
            'source' { $script:AidrSigningSourceRoot = $request.FleetScriptRoot; $code = 'deployment_source_signing_forbidden' }
            'source_nested' { $script:AidrSigningSourceRoot = $fixture; $code = 'deployment_source_signing_forbidden' }
            'source_ancestor' { $script:AidrSigningSourceRoot = Join-Path $request.FleetScriptRoot 'tracked-source'; $code = 'deployment_source_signing_forbidden' }
            'hardlink' { $target = Join-Path $request.FleetScriptRoot 'Common.ps1'; [IO.File]::Delete($target); New-Item -ItemType HardLink -Path $target -Target (Join-Path $request.ClaudeDist 'native/Common.ps1') | Out-Null; $code = 'signing_hardlink_path' }
            'junction' { $real = Join-Path (Split-Path $request.FleetScriptRoot) 'actual-fleet'; [IO.Directory]::Move($request.FleetScriptRoot, $real); New-Item -ItemType Junction -Path $request.FleetScriptRoot -Target $real | Out-Null; $code = 'signing_reparse_path' }
        }
        No-Sign $request $code
        $script:AidrSigningSourceRoot = ORIGINAL_SOURCE
    }
    foreach ($case in @('private', 'expired', 'eku', 'tool', 'foreign_tool', 'process', 'timestamp', 'wrong_signer', 'catalog', 'manifest_changed', 'manifest_snapshot')) {
        Reset-Mocks
        $request = New-Stage ('sign-fail-' + $case)
        switch ($case) {
            'private' { $script:privateKey = $false; $code = 'missing_signing_private_key' }
            'expired' { $script:expired = $true; $code = 'expired_signing_certificate' }
            'eku' { $script:eku = $false; $code = 'missing_code_signing_eku' }
            'tool' { $script:toolTrusted = $false; $code = 'untrusted_signing_tool' }
            'foreign_tool' { $script:failure = $case; $code = 'untrusted_signing_tool' }
            'process' { $script:failure = $case; $code = 'authenticode_signing_failed' }
            'timestamp' { $script:failure = $case; $code = 'missing_authenticode_timestamp' }
            'wrong_signer' { $script:failure = $case; $code = 'unexpected_signing_certificate' }
            'catalog' { $script:failure = $case; $code = 'invalid_authenticode_signature' }
            'manifest_changed' { $script:appearManifest = $true; $script:inputToChange = $request.InputManifestPath; $code = 'signing_input_manifest_changed' }
            'manifest_snapshot' { $script:changeOnParse = $true; $script:inputToChange = $request.InputManifestPath; $code = 'signing_input_manifest_changed' }
        }
        Fails { Sign-Stage $request } $code
        Check (-not [IO.File]::Exists($request.ReceiptPath)) 'partial or postflight failure cannot create receipt'
        if ($case -in @('private', 'expired', 'eku', 'tool', 'foreign_tool')) { Check ($script:signCalls -eq 0) 'tool and certificate preflight before mutations' }
    }
    Reset-Mocks
    $machineRequest = New-Stage 'machine'
    $machineRequest.CertificateStore = 'localmachine/my'; $script:machine = $true
    Sign-Stage $machineRequest | Out-Null
    Check ($script:signCalls -eq 14) 'machine store uses explicit sm argument'
    Reset-Mocks
    $checkRequest = $script:valid
} else {
    # Produce only test evidence with mocked signature observations, no signing.
    $checkRequest = New-Stage 'readonly-fixture'
    $files = @(Get-AidrSigningInventory $checkRequest.FleetScriptRoot $checkRequest.ClaudeDist)
    $preimages = Read-AidrSigningInputs $checkRequest.InputManifestPath $files
    $entries = @()
    foreach ($file in $files) {
        $script:signedFiles.Add($file.absolute) | Out-Null
        $entries += [pscustomobject]@{ path = $file.logical; before_sha256 = $preimages[$file.logical]; sha256 = (Get-AidrSigningHash $file.absolute); size = ([IO.FileInfo]::new($file.absolute)).Length }
    }
    $evidence = [pscustomobject]@{ schema_version = 1; purpose = 'aidr.windows-authenticode'; signer_thumbprint = $script:thumb; timestamp_server = 'https://tsa.example.test';
        verified_at = [DateTimeOffset]::UtcNow.ToString('o'); input_manifest_sha256 = (Get-AidrSigningHash $checkRequest.InputManifestPath); verified = $true; files = $entries }
    [IO.File]::WriteAllText($checkRequest.ReceiptPath, ($evidence | ConvertTo-Json -Depth 5))
    Fails { Sign-Stage $checkRequest } 'powershell_7_signing_required'
}
Reset-Mocks
$before = [IO.File]::ReadAllText($checkRequest.ReceiptPath)
$script:privateKey = $false; $script:expired = $true
Check ((Check-Stage $checkRequest).verified -eq $true) 'timestamped valid historical signature needs no current private key or unexpired publisher'
Check ($script:storeCalls -eq 0 -and $script:signCalls -eq 0 -and $script:signatureCalls -eq 14) 'CheckOnly never resolves cert store or invokes tool'
Check ([IO.File]::ReadAllText($checkRequest.ReceiptPath) -ceq $before) 'CheckOnly leaves original receipt bytes untouched'
$script:privateKey = $true; $script:expired = $false

# Final package/evidence locations differ from the unsigned staging roots.
$relocated = Join-Path $fixture 'final-package'
[IO.Directory]::CreateDirectory((Join-Path $relocated 'windows-fleet')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $relocated 'dist/native')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $relocated 'evidence')) | Out-Null
foreach ($file in @(Get-AidrSigningInventory $checkRequest.FleetScriptRoot $checkRequest.ClaudeDist)) {
    $newRoot = if ($file.logical.StartsWith('fleet/')) { Join-Path $relocated 'windows-fleet' } else { Join-Path $relocated 'dist/native' }
    $destination = Join-Path $newRoot ([IO.Path]::GetFileName($file.absolute))
    [IO.File]::Copy($file.absolute, $destination)
    $script:signedFiles.Add($destination) | Out-Null
}
$relocatedRequest = @{ FleetScriptRoot = (Join-Path $relocated 'windows-fleet'); ClaudeDist = (Join-Path $relocated 'dist');
    InputManifestPath = (Join-Path $relocated 'evidence/windows-authenticode-input-manifest.json'); ReceiptPath = (Join-Path $relocated 'evidence/windows-authenticode-receipt.json');
    ExpectedThumbprint = $script:thumb; TimestampServer = 'https://tsa.example.test' }
[IO.File]::Copy($checkRequest.InputManifestPath, $relocatedRequest.InputManifestPath)
[IO.File]::Copy($checkRequest.ReceiptPath, $relocatedRequest.ReceiptPath)
[IO.File]::WriteAllText((Join-Path $relocatedRequest.ClaudeDist 'aidr-artifact.manifest.sig'), 'final Ed25519 evidence permitted for read-only inspection')
Check ((Check-Stage $relocatedRequest).verified -eq $true) 'CheckOnly authenticates final Ed25519 packaged independent roots by logical paths'
$receiptBytes = [IO.File]::ReadAllText($relocatedRequest.ReceiptPath)
$inputBytes = [IO.File]::ReadAllText($relocatedRequest.InputManifestPath)
$differentNative = ConvertFrom-AidrSigningJson $inputBytes
$differentNative.files[12].before_sha256 = ('0' * 64)
[IO.File]::WriteAllText($relocatedRequest.InputManifestPath, ($differentNative | ConvertTo-Json -Depth 5))
$differentReceipt = ConvertFrom-AidrSigningJson $receiptBytes
$differentReceipt.files[12].before_sha256 = ('0' * 64)
$differentReceipt.input_manifest_sha256 = Get-AidrSigningHash $relocatedRequest.InputManifestPath
[IO.File]::WriteAllText($relocatedRequest.ReceiptPath, ($differentReceipt | ConvertTo-Json -Depth 5))
Fails { Check-Stage $relocatedRequest } 'native_signing_source_mismatch'
[IO.File]::WriteAllText($relocatedRequest.InputManifestPath, $inputBytes)
[IO.File]::WriteAllText($relocatedRequest.ReceiptPath, $receiptBytes)
foreach ($field in @('schema_version', 'purpose', 'signer_thumbprint', 'timestamp_server', 'input_manifest_sha256', 'before_sha256', 'sha256')) {
    $badType = ConvertFrom-AidrSigningJson $receiptBytes
    if ($field -ceq 'schema_version') { $badType.schema_version = '1' }
    elseif ($field -in @('before_sha256', 'sha256')) { $badType.files[0].$field = @($badType.files[0].$field) }
    else { $badType.$field = @($badType.$field) }
    [IO.File]::WriteAllText($relocatedRequest.ReceiptPath, ($badType | ConvertTo-Json -Depth 5))
    Fails { Check-Stage $relocatedRequest } 'invalid_signing_receipt'
}
[IO.File]::WriteAllText($relocatedRequest.ReceiptPath, $receiptBytes)
$badReceipt = ConvertFrom-AidrSigningJson $receiptBytes
$badReceipt.files[0].before_sha256 = ('0' * 64)
[IO.File]::WriteAllText($relocatedRequest.ReceiptPath, ($badReceipt | ConvertTo-Json -Depth 5))
Fails { Check-Stage $relocatedRequest } 'invalid_signing_receipt'
[IO.File]::WriteAllText($relocatedRequest.ReceiptPath, $receiptBytes)
[IO.File]::AppendAllText($relocatedRequest.InputManifestPath, ' ')
Fails { Check-Stage $relocatedRequest } 'invalid_signing_receipt'
[IO.File]::WriteAllText($relocatedRequest.InputManifestPath, [IO.File]::ReadAllText($checkRequest.InputManifestPath))
$script:failure = 'timestamp'
Fails { Check-Stage $relocatedRequest } 'missing_authenticode_timestamp'
$script:failure = ''
[IO.File]::AppendAllText((Join-Path $relocatedRequest.FleetScriptRoot 'Common.ps1'), 'tamper')
Fails { Check-Stage $relocatedRequest } 'signing_receipt_hash_mismatch'
Check ($script:signCalls -eq 0 -and $script:storeCalls -eq 0) 'failed readonly verification never mutates or accesses store'
[pscustomobject]@{ checks = $script:checks; powershell = $PSVersionTable.PSVersion.ToString(); mocked_signing_only = $true } | ConvertTo-Json -Compress
`;

for (const executable of ['pwsh.exe', 'powershell.exe']) {
  test(`Windows Authenticode staging and read-only receipt verification (${executable}, mocked signing only)`, { skip: process.platform !== 'win32' }, (context) => {
    const fixture = mkdtempSync(path.join(homedir(), '.aidr-response-signing-test-'));
    const harness = path.join(fixture, 'check.ps1');
    const source = harnessSource
      .replace('SIGNER_PATH', psString(signer))
      .replace('FIXTURE_PATH', psString(fixture))
      .replace('ORIGINAL_SOURCE', psString(path.join(root, 'deploy/fleet/windows')));
    try {
      writeFileSync(harness, source, 'utf8');
      const result = spawnSync(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', harness], { encoding: 'utf8', timeout: 90_000 });
      assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}\n${result.error ?? ''}`);
      const evidence = JSON.parse(result.stdout.trim());
      assert.equal(evidence.mocked_signing_only, true);
      assert.ok(evidence.checks >= (executable === 'pwsh.exe' ? 150 : 10), result.stdout);
      context.diagnostic(`${evidence.checks} assertions; PowerShell ${evidence.powershell}; no live signing or certificate-store changes`);
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  });
}
