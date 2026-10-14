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
     with the selected signer backend (-Signer, default AIDR_WINDOWS_SIGNER, else
     pfx: the certificate already imported into CurrentUser\My; azure-key-vault
     or jsign: a key that stays in a cloud HSM or token, see
     scripts/windows-authenticode-signer.ps1 and
     docs/operations/windows-code-signing.md). Every signed file must carry the
     pinned -SignThumbprint certificate and a timestamp. The SEA manifest is rewritten
     over the signed bytes (build-sea.mjs --remanifest, which repeats the
     relocated deny canary), the MSI is built and signed, and both signatures
     are verified with signtool /pa.
  3. Unsigned local build: only with -Unsigned; the file name ends in -UNSIGNED.
  There is no third path: no thumbprint and no -Unsigned is an error.

  The install wizard (ui\AidrUI.wxs) is built once per culture (en-US, tr-TR,
  the strings in ui\aidr.<culture>.wxl) with the same ProductCode and payload.
  The English MSI is the package; every other culture is embedded in it as a
  language transform (storage named by its LCID, summary languages
  "1033,1055"), which Windows Installer applies when the user's display
  language matches. One MSI is published; `TRANSFORMS=:1055` forces Turkish.
  The company connection page's custom actions (ca\) are built with dotnet.

  Per-customer build (-CustomerPacket <customer-packet.json> [-CustomerId <id>]):
  the vendor-signed customer packet (docs/operations/customer-builds.md) is
  installed as config\customer-packet.json and, per-machine, as the permanent
  %ProgramData%\Singularity AIDR\customer-packet.json; the product is named
  "Singularity AIDR (CUSTOMER)" and the file SingularityAIDR-CUSTOMER-<version>-<arch>.msi.
  msi-inputs.mjs checks the packet's shape and customer id; its signature is
  checked by scripts/customer-packet-verify.mjs before this script runs
  (customer-installer.yml) and again by `aidr setup` on every endpoint.

  -Bundle also builds a setup EXE (bundle.wxs, WiX Burn) around the signed MSI.
  A signed build signs the detached Burn engine, reattaches it, signs the EXE
  and verifies both with signtool /pa.

  Requires WiX Toolset 5 (`dotnet tool install --global wix --version 5.0.2`;
  this script adds the pinned WixToolset.UI.wixext extension, and
  WixToolset.Bal.wixext for -Bundle), the .NET SDK
  (custom actions, net472) and, for signing, signtool.exe from the Windows SDK.

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
  # Authenticode signer backend: pfx | azure-key-vault | jsign (default: AIDR_WINDOWS_SIGNER, else pfx).
  [string]$Signer = '',
  [string]$TimestampServer = 'http://timestamp.digicert.com',
  # Optional Ed25519 public key `aidr update` verifies the installer catalog with.
  [string]$CatalogKey = '',
  # Optional vendor-signed customer packet (per-customer installer) and the customer it must be for.
  [string]$CustomerPacket = '',
  [string]$CustomerId = '',
  # Also build the setup EXE (WiX Burn bootstrapper) around the MSI.
  [switch]$Bundle,
  [switch]$Unsigned
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Resolve-Path (Join-Path $here '..\..\..')
. (Join-Path $repo 'scripts\windows-authenticode-signer.ps1')
$signing = if ($SignThumbprint) { 'signed' } elseif ($Unsigned) { 'unsigned' } else { '' }
if (-not $signing) { throw 'Pass -SignThumbprint for a release build or -Unsigned for a local build.' }
if ($SignThumbprint -and $Unsigned) { throw '-SignThumbprint and -Unsigned are mutually exclusive.' }
if ($signing -eq 'signed') { $Signer = Resolve-AidrAuthenticodeSigner $Signer }

# The WiX UI extension, pinned to the WiX version the release workflow installs.
$WixUiExtension = 'WixToolset.UI.wixext'
$WixUiExtensionVersion = '5.0.2'
# The Burn bootstrapper extension (-Bundle), same pin.
$WixBalExtension = 'WixToolset.Bal.wixext'
if ($CustomerId -and -not $CustomerPacket) { throw '-CustomerId needs -CustomerPacket.' }

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

function Install-WixExtension([string]$Name) {
  $listed = (& wix extension list -g 2>&1 | Out-String)
  $pattern = "$([regex]::Escape($Name))\s+$([regex]::Escape($WixUiExtensionVersion))"
  if ($listed -notmatch $pattern) {
    Invoke-Checked 'wix' @('extension', 'add', '-g', "$Name/$WixUiExtensionVersion")
  }
}

# Sign with the selected backend (pinned identity checked per file), then signtool /pa.
function Invoke-AuthenticodeSign([string]$SignTool, [string[]]$Files, [string]$Description = 'Singularity AIDR') {
  Invoke-AidrAuthenticodeSign -Signer $Signer -Files $Files -Thumbprint $SignThumbprint -TimestampServer $TimestampServer -Description $Description -SignTool $SignTool
  Invoke-Checked $SignTool (@('verify', '/pa') + $Files)
}

# --- Windows Installer automation (the WiLangId / WiSubStg / WiGenXfm steps) ---
$Call = [Reflection.BindingFlags]::InvokeMethod
$Get = [Reflection.BindingFlags]::GetProperty
$Set = [Reflection.BindingFlags]::SetProperty

function Invoke-Com($Target, [string]$Member, [Reflection.BindingFlags]$Kind, [object[]]$Arguments = @()) {
  return $Target.GetType().InvokeMember($Member, $Kind, $null, $Target, $Arguments)
}

function Close-Com([object[]]$Objects) {
  foreach ($object in $Objects) {
    if ($null -ne $object) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object) }
  }
  [GC]::Collect()
  [GC]::WaitForPendingFinalizers()
}

function Get-MsiProperty($Database, [string]$Name) {
  $view = Invoke-Com $Database 'OpenView' $Call @('SELECT `Value` FROM `Property` WHERE `Property` = ''' + $Name + '''')
  $record = $null
  try {
    [void](Invoke-Com $view 'Execute' $Call)
    $record = Invoke-Com $view 'Fetch' $Call
    if ($null -eq $record) { return $null }
    return [string](Invoke-Com $record 'StringData' $Get @(1))
  } finally {
    [void](Invoke-Com $view 'Close' $Call)
    Close-Com @($record, $view)
  }
}

# Generate the transform base -> localized and embed it in base as storage "<lcid>".
function Add-LanguageTransform([string]$Base, [string]$Localized, [int]$Lcid, [string]$Work) {
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $mst = Join-Path $Work "$Lcid.mst"
  $baseDb = Invoke-Com $installer 'OpenDatabase' $Call @($Base, 0)
  $localizedDb = Invoke-Com $installer 'OpenDatabase' $Call @($Localized, 0)
  try {
    if (-not (Invoke-Com $localizedDb 'GenerateTransform' $Call @($baseDb, $mst))) {
      throw "The $Lcid build does not differ from the base MSI."
    }
    [void](Invoke-Com $localizedDb 'CreateTransformSummaryInfo' $Call @($baseDb, $mst, 0, 0))
  } finally {
    Close-Com @($localizedDb, $baseDb)
  }
  # Only text, dialogs and the language differ between the culture builds; a
  # large transform means the payload differed (a second cabinet), which must
  # not ship.
  $size = (Get-Item -LiteralPath $mst).Length
  if ($size -gt 4MB) { throw "The $Lcid language transform is $size bytes: the culture builds differ in more than their text." }
  $db = Invoke-Com $installer 'OpenDatabase' $Call @($Base, 1)
  $view = $null; $record = $null
  try {
    $view = Invoke-Com $db 'OpenView' $Call @('SELECT `Name`, `Data` FROM `_Storages`')
    $record = Invoke-Com $installer 'CreateRecord' $Call @(2)
    [void](Invoke-Com $record 'StringData' $Set @(1, [string]$Lcid))
    [void](Invoke-Com $record 'SetStream' $Call @(2, $mst))
    [void](Invoke-Com $view 'Execute' $Call)
    [void](Invoke-Com $view 'Modify' $Call @(3, $record))
    [void](Invoke-Com $view 'Close' $Call)
    [void](Invoke-Com $db 'Commit' $Call)
  } finally {
    Close-Com @($record, $view, $db, $installer)
  }
  return $mst
}

# Summary "Template": "<platform>;1033" -> "<platform>;1033,1055".
function Set-PackageLanguages([string]$Msi, [int[]]$Lcids) {
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $db = Invoke-Com $installer 'OpenDatabase' $Call @($Msi, 1)
  $info = $null
  try {
    $info = Invoke-Com $db 'SummaryInformation' $Get @(1)
    $template = [string](Invoke-Com $info 'Property' $Get @(7))
    if ($template -notmatch "^[A-Za-z0-9]+;$($Lcids[0])$") { throw "Unexpected MSI template '$template'." }
    $platform = $template.Split(';')[0]
    [void](Invoke-Com $info 'Property' $Set @(7, "$platform;$($Lcids -join ',')"))
    [void](Invoke-Com $info 'Persist' $Call)
    [void](Invoke-Com $db 'Commit' $Call)
  } finally {
    Close-Com @($info, $db, $installer)
  }
}

# Apply each transform to a copy of the base, as msiexec does for that display
# language, and check it switches the language without changing the product.
function Test-LanguageTransforms([string]$Msi, [string]$BaseCopy, [hashtable]$Transforms, [string]$Work) {
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $db = Invoke-Com $installer 'OpenDatabase' $Call @($Msi, 0)
  $info = $null; $view = $null; $names = @()
  try {
    $info = Invoke-Com $db 'SummaryInformation' $Get @(0)
    $template = [string](Invoke-Com $info 'Property' $Get @(7))
    $identity = @('ProductCode', 'UpgradeCode', 'ProductVersion') | ForEach-Object { Get-MsiProperty $db $_ }
    $view = Invoke-Com $db 'OpenView' $Call @('SELECT `Name` FROM `_Storages`')
    [void](Invoke-Com $view 'Execute' $Call)
    while ($null -ne ($record = Invoke-Com $view 'Fetch' $Call)) {
      $names += [string](Invoke-Com $record 'StringData' $Get @(1))
      Close-Com @($record)
    }
    [void](Invoke-Com $view 'Close' $Call)
  } finally {
    Close-Com @($view, $info, $db)
  }
  $expected = "1033," + (($Transforms.Keys | Sort-Object) -join ',')
  if (-not $template.EndsWith(";$expected")) { throw "MSI languages are '$template', expected '...;$expected'." }
  foreach ($lcid in $Transforms.Keys) {
    if ($names -notcontains [string]$lcid) { throw "The $lcid language transform is not embedded." }
    $copy = Join-Path $Work "verify-$lcid.msi"
    Copy-Item -LiteralPath $BaseCopy -Destination $copy
    $check = Invoke-Com $installer 'OpenDatabase' $Call @($copy, 1)
    try {
      [void](Invoke-Com $check 'ApplyTransform' $Call @($Transforms[$lcid], 0))
      if ((Get-MsiProperty $check 'ProductLanguage') -ne [string]$lcid) { throw "The $lcid transform does not set ProductLanguage=$lcid." }
      $after = @('ProductCode', 'UpgradeCode', 'ProductVersion') | ForEach-Object { Get-MsiProperty $check $_ }
      if (($after -join '|') -cne ($identity -join '|')) { throw "The $lcid transform changes the product identity." }
    } finally {
      Close-Com @($check)
      Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
    }
  }
  Close-Com @($installer)
}

$stage = Join-Path ([IO.Path]::GetTempPath()) ("aidr-msi-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
  $bundle = Join-Path $stage 'bundle'
  Copy-Item -Recurse -Path (Resolve-Path $SeaDir) -Destination $bundle

  $catalogArgs = @()
  if ($CatalogKey) { $catalogArgs = @('--catalog-key', $CatalogKey) }
  # The packet is checked and embedded from the same private stage copy.
  $packetArgs = @()
  $packet = ''
  if ($CustomerPacket) {
    $packet = Join-Path $stage 'customer-packet.json'
    Copy-Item -LiteralPath (Resolve-Path $CustomerPacket).Path -Destination $packet
    $packetArgs = @('--customer-packet', $packet)
    if ($CustomerId) { $packetArgs += @('--customer-id', $CustomerId) }
  }
  $inputsJson = & node (Join-Path $here 'msi-inputs.mjs') --sea-dir $bundle --trust-key $TrustKey `
    --trust-key-fingerprint $TrustKeyFingerprint --version $Version --signing $signing @catalogArgs @packetArgs
  if ($LASTEXITCODE -ne 0) { throw 'MSI inputs were rejected (see above).' }
  $inputs = $inputsJson | ConvertFrom-Json

  # The wizard bitmaps must be the ones the committed SVG sources render to.
  Invoke-Checked 'node' @((Join-Path $here 'ui\render-bitmaps.mjs'), '--check')

  if ($signing -eq 'signed') {
    $signtool = Find-SignTool
    $exes = Get-ChildItem (Join-Path $bundle 'bin') -Filter *.exe | ForEach-Object { $_.FullName }
    Invoke-AidrAuthenticodeSign -Signer $Signer -Files $exes -Thumbprint $SignThumbprint -TimestampServer $TimestampServer -SignTool $signtool
    Invoke-Checked $signtool (@('verify', '/pa', '/all') + $exes)
    # Signing changed the binary: re-manifest the bundle over the signed bytes (the
    # signed runtime manifest is untouched) and re-run the canary with the release key.
    Invoke-Checked 'node' @((Join-Path $repo 'packages\claude-code\scripts\build-sea.mjs'), '--remanifest', $bundle, '--public-key', (Resolve-Path $TrustKey).Path)
  }

  # Per-user cleanup script (kept after removal, run by Active Setup as each user): a staged
  # copy is Authenticode-signed so it also runs where policy demands AllSigned.
  $profileCleanup = Join-Path $stage 'Remove-AidrUserRegistrations.ps1'
  Copy-Item -LiteralPath (Join-Path $here 'Remove-AidrUserRegistrations.ps1') -Destination $profileCleanup
  if ($signing -eq 'signed') {
    Invoke-AidrAuthenticodeSign -Signer $Signer -Files @($profileCleanup) -Thumbprint $SignThumbprint -TimestampServer $TimestampServer -SignTool $signtool
  }

  # Company connection custom actions (embedded as a Binary; the MSI signature covers them).
  $actions = Join-Path $stage 'actions'
  Invoke-Checked 'dotnet' @('build', (Join-Path $here 'ca\AidrInstallerActions.csproj'), '-c', 'Release', '-o', $actions, '--nologo')
  $actionsDll = Join-Path $actions 'AidrInstallerActions.CA.dll'
  if (-not (Test-Path -LiteralPath $actionsDll)) { throw "$actionsDll was not built." }

  Install-WixExtension $WixUiExtension
  if ($Bundle) { Install-WixExtension $WixBalExtension }

  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  $msi = Join-Path (Resolve-Path $OutDir) $inputs.outputName
  if (Test-Path $msi) { throw "$msi already exists" }
  # One cabinet cache for every culture build: the payload (and its cabinet) is identical.
  $cabinets = Join-Path $stage 'cabinets'
  $common = @('-arch', $inputs.arch, '-ext', $WixUiExtension, '-cc', $cabinets,
    '-d', "ProductName=$($inputs.productName)",
    '-d', "ProductVersion=$($inputs.productVersion)",
    '-d', "ProductCode=$($inputs.productCode)",
    '-d', "UpgradeCode=$($inputs.upgradeCode)",
    '-d', "ActiveSetupId=$($inputs.activeSetupId)",
    '-d', "ActiveSetupVersion=$($inputs.activeSetupVersion)",
    '-d', "BundleDir=$bundle",
    '-d', "TrustKey=$((Resolve-Path $TrustKey).Path)",
    '-d', "HasCatalogKey=$($inputs.hasCatalogKey)",
    '-d', "CatalogKey=$(if ($CatalogKey) { (Resolve-Path $CatalogKey).Path } else { '' })",
    '-d', "HasCustomerPacket=$($inputs.hasCustomerPacket)",
    '-d', "CustomerPacket=$packet",
    '-d', "InstallerActionsDll=$actionsDll",
    '-d', "ProfileCleanupScript=$profileCleanup")
  # Customer wizard pages (ui/AidrUI.wxs): defined only when the packet says so.
  if ($inputs.customerServer) { $common += @('-d', "CustomerServer=$($inputs.customerServer)") }
  if ($inputs.customerUpdatesUntil) { $common += @('-d', "CustomerUpdatesUntil=$($inputs.customerUpdatesUntil)") }
  $built = @{}
  foreach ($culture in $inputs.cultures) {
    $out = Join-Path $stage "aidr.$($culture.culture).msi"
    # The customer's name in this culture's code page (msi-inputs.mjs wizardCustomerName).
    $customerName = @()
    if ($culture.customerName) { $customerName = @('-d', "CustomerName=$($culture.customerName)") }
    Invoke-Checked 'wix' (@('build', (Join-Path $here 'aidr.wxs'), (Join-Path $here 'ui\AidrUI.wxs')) + $common + $customerName +
      @('-culture', $culture.culture, '-loc', (Join-Path $here "ui\aidr.$($culture.culture).wxl"),
        '-d', "AidrCulture=$($culture.culture)", '-o', $out))
    $built[$culture.culture] = $out
  }

  $baseCulture = $inputs.cultures[0]
  $package = Join-Path $stage 'package.msi'
  Copy-Item -LiteralPath $built[$baseCulture.culture] -Destination $package
  $transforms = @{}
  foreach ($culture in ($inputs.cultures | Select-Object -Skip 1)) {
    $transforms[[int]$culture.lcid] = Add-LanguageTransform -Base $package -Localized $built[$culture.culture] -Lcid $culture.lcid -Work $stage
  }
  Set-PackageLanguages -Msi $package -Lcids @($inputs.cultures | ForEach-Object { [int]$_.lcid })
  Test-LanguageTransforms -Msi $package -BaseCopy $built[$baseCulture.culture] -Transforms $transforms -Work $stage
  Move-Item -LiteralPath $package -Destination $msi

  if ($signing -eq 'signed') {
    Invoke-AidrAuthenticodeSign -Signer $Signer -Files @($msi) -Thumbprint $SignThumbprint -TimestampServer $TimestampServer -Description 'Singularity AIDR' -SignTool $signtool
    Invoke-Checked $signtool @('verify', '/pa', $msi)
  } else {
    Write-Warning "UNSIGNED MSI (local build only, never publish): $msi"
  }
  $outputs = @($msi)

  if ($Bundle) {
    # The EXE embeds the MSI exactly as signed above.
    $exe = Join-Path (Resolve-Path $OutDir) $inputs.bundleOutputName
    if (Test-Path $exe) { throw "$exe already exists" }
    $stagedExe = Join-Path $stage 'bundle.exe'
    Invoke-Checked 'wix' @('build', (Join-Path $here 'bundle.wxs'), '-arch', $inputs.arch, '-ext', $WixBalExtension,
      '-d', "ProductName=$($inputs.productName)",
      '-d', "ProductVersion=$($inputs.productVersion)",
      '-d', "BundleUpgradeCode=$($inputs.bundleUpgradeCode)",
      '-d', "MsiPath=$msi", '-o', $stagedExe)
    if ($signing -eq 'signed') {
      # Burn: sign the engine first (detach, sign, reattach), then the whole EXE.
      $engine = Join-Path $stage 'burn-engine.exe'
      Invoke-Checked 'wix' @('burn', 'detach', $stagedExe, '-engine', $engine)
      Invoke-AuthenticodeSign $signtool @($engine)
      Invoke-Checked 'wix' @('burn', 'reattach', $stagedExe, '-engine', $engine, '-o', $stagedExe)
      Invoke-AuthenticodeSign $signtool @($stagedExe)
    } else {
      Write-Warning "UNSIGNED EXE (local build only, never publish): $exe"
    }
    Move-Item -LiteralPath $stagedExe -Destination $exe
    $outputs += $exe
  }

  foreach ($file in $outputs) {
    $hash = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLowerInvariant()
    Write-Output "built $file"
    Write-Output "sha256 $hash"
  }
} finally {
  Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
