#Requires -Version 5.1
<#
.SYNOPSIS
  Build the Singularity AIDR Windows installer (MSI) from a release-flavour SEA
  bundle built on Windows and signed with the release key
  (`build-sea.mjs --flavor release`, then `--sign`).

.DESCRIPTION
  1. msi-inputs.mjs verifies the SEA bundle (manifests, digests, release
     flavour, Ed25519 signatures against the release key, win32 build, the
     multi-call aidr.exe) and the release trust key fingerprint.
  2. Signed build (-SignThumbprint): the bundle .exe is Authenticode-signed
     with the certificate already imported into CurrentUser\My (the same custody
     as release-rc.yml's windows-authenticode job), the SEA manifest is rewritten
     over the signed bytes (build-sea.mjs --remanifest, which repeats the
     relocated deny canary), the MSI is built and signed, and both signatures
     are verified with signtool /pa.
  3. Unsigned local build: only with -Unsigned; the file name ends in -UNSIGNED.
  There is no third path: no thumbprint and no -Unsigned is an error.

  Requires WiX Toolset 5 (`dotnet tool install --global wix --version 5.0.2`)
  and, for signing, signtool.exe from the Windows SDK.

.EXAMPLE
  ./deploy/installers/windows/build-msi.ps1 -SeaDir bin\aidr-sea -TrustKey release-public.pem `
    -TrustKeyFingerprint <sha256> -Version 0.6.0 -OutDir out -SignThumbprint <thumbprint>
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$SeaDir,
  [Parameter(Mandatory = $true)][string]$TrustKey,
  [Parameter(Mandatory = $true)][string]$TrustKeyFingerprint,
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$OutDir,
  [string]$SignThumbprint = '',
  [string]$TimestampServer = 'http://timestamp.digicert.com',
  # Optional Ed25519 public key `aidr update` verifies the installer catalog with.
  [string]$CatalogKey = '',
  [switch]$Unsigned
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Resolve-Path (Join-Path $here '..\..\..')
$signing = if ($SignThumbprint) { 'signed' } elseif ($Unsigned) { 'unsigned' } else { '' }
if (-not $signing) { throw 'Pass -SignThumbprint for a release build or -Unsigned for a local build.' }
if ($SignThumbprint -and $Unsigned) { throw '-SignThumbprint and -Unsigned are mutually exclusive.' }

function Invoke-Checked([string]$File, [string[]]$Arguments) {
  & $File @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$File $($Arguments -join ' ') exited with $LASTEXITCODE" }
}

function Find-SignTool {
  $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $found = Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
  if (-not $found) { throw 'signtool.exe was not found (install the Windows SDK).' }
  return $found.FullName
}

$stage = Join-Path ([IO.Path]::GetTempPath()) ("aidr-msi-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
  $bundle = Join-Path $stage 'bundle'
  Copy-Item -Recurse -Path (Resolve-Path $SeaDir) -Destination $bundle

  $catalogArgs = @()
  if ($CatalogKey) { $catalogArgs = @('--catalog-key', $CatalogKey) }
  $inputsJson = & node (Join-Path $here 'msi-inputs.mjs') --sea-dir $bundle --trust-key $TrustKey `
    --trust-key-fingerprint $TrustKeyFingerprint --version $Version --signing $signing @catalogArgs
  if ($LASTEXITCODE -ne 0) { throw 'MSI inputs were rejected (see above).' }
  $inputs = $inputsJson | ConvertFrom-Json

  if ($signing -eq 'signed') {
    $signtool = Find-SignTool
    $exes = Get-ChildItem (Join-Path $bundle 'bin') -Filter *.exe | ForEach-Object { $_.FullName }
    Invoke-Checked $signtool (@('sign', '/sha1', $SignThumbprint, '/fd', 'sha256', '/tr', $TimestampServer, '/td', 'sha256') + $exes)
    Invoke-Checked $signtool (@('verify', '/pa', '/all') + $exes)
    # Signing changed the binary: re-manifest the bundle over the signed bytes (the
    # signed runtime manifest is untouched) and re-run the canary with the release key.
    Invoke-Checked 'node' @((Join-Path $repo 'packages\claude-code\scripts\build-sea.mjs'), '--remanifest', $bundle, '--public-key', (Resolve-Path $TrustKey).Path)
  }

  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  $msi = Join-Path (Resolve-Path $OutDir) $inputs.outputName
  if (Test-Path $msi) { throw "$msi already exists" }
  Invoke-Checked 'wix' @('build', (Join-Path $here 'aidr.wxs'), '-arch', $inputs.arch,
    '-d', "ProductVersion=$($inputs.productVersion)",
    '-d', "UpgradeCode=$($inputs.upgradeCode)",
    '-d', "ActiveSetupId=$($inputs.activeSetupId)",
    '-d', "ActiveSetupVersion=$($inputs.activeSetupVersion)",
    '-d', "BundleDir=$bundle",
    '-d', "TrustKey=$((Resolve-Path $TrustKey).Path)",
    '-d', "HasCatalogKey=$($inputs.hasCatalogKey)",
    '-d', "CatalogKey=$(if ($CatalogKey) { (Resolve-Path $CatalogKey).Path } else { '' })",
    '-o', $msi)

  if ($signing -eq 'signed') {
    Invoke-Checked $signtool @('sign', '/sha1', $SignThumbprint, '/fd', 'sha256', '/tr', $TimestampServer, '/td', 'sha256', '/d', 'Singularity AIDR', $msi)
    Invoke-Checked $signtool @('verify', '/pa', $msi)
  } else {
    Write-Warning "UNSIGNED MSI (local build only, never publish): $msi"
  }
  $hash = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant()
  Write-Output "built $msi"
  Write-Output "sha256 $hash"
} finally {
  Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
