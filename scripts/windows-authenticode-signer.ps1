<#
.SYNOPSIS
  Authenticode signer backends for AIDR release and customer builds.

.DESCRIPTION
  Dot-source this file. AIDR_WINDOWS_SIGNER (or -Signer) selects the backend
  (docs/operations/windows-code-signing.md):

    pfx              signtool.exe with a certificate in the Windows certificate
                     store. The workflows import an ephemeral PFX; local test
                     builds use a test certificate. Kept for local tests and for
                     certificates that can still be exported.
    azure-key-vault  AzureSignTool (pinned, SHA-256 checked) with an HSM-backed
                     Azure Key Vault or Managed HSM certificate. The access token
                     comes from GitHub OIDC (workload identity federation, no
                     client secret) or from AIDR_AZURE_ACCESS_TOKEN for a manual run.
    jsign            jsign (pinned, SHA-256 checked) against a cloud HSM or signing
                     service (AZUREKEYVAULT, TRUSTEDSIGNING, GOOGLECLOUD, AWS,
                     DIGICERTONE, ESIGNER, HASHICORPVAULT, ...) or a PKCS#11 token
                     (PKCS11, CRYPTOCERTUM, ETOKEN, YUBIKEY, ...) on a runner that
                     holds the token.

  For the cloud backends the private key never leaves the HSM: the signer sends
  the digest and receives the signature. Whatever the backend, every signed file
  is then verified the same way (Assert-AidrAuthenticodeSigned): a valid
  Authenticode signature, signer certificate with the independently pinned SHA-1
  thumbprint and the code-signing EKU, and an RFC 3161 timestamp. A backend that
  signs with any other certificate fails the build.
#>

# No Set-StrictMode here: dot-sourcing would change the caller's mode.

$script:AidrSignerBackends = @('pfx', 'azure-key-vault', 'jsign')
$script:AidrJsignVersion = '7.4'
$script:AidrJsignSha256 = '2abf2ade9ea322acc2d60c24794eadc465ff9380938fca4c932d09e0b25f1c28'
$script:AidrJsignUrl = 'https://github.com/ebourg/jsign/releases/download/7.4/jsign-7.4.jar'
$script:AidrAzureSignToolVersion = '7.0.1'
$script:AidrAzureSignToolSha256 = 'cc5a8b6407e98b4c6d9c57a32d7282c63f54f9cb4562a3712c6cb5d2564097cc'
$script:AidrAzureSignToolUrl = 'https://api.nuget.org/v3-flatcontainer/azuresigntool/7.0.1/azuresigntool.7.0.1.nupkg'
# jsign --storetype values for keys that stay in an HSM, a signing service or a token.
$script:AidrJsignStoreTypes = @(
    'AZUREKEYVAULT', 'TRUSTEDSIGNING', 'GOOGLECLOUD', 'AWS', 'DIGICERTONE', 'ESIGNER',
    'HASHICORPVAULT', 'ORACLECLOUD', 'GARASIGN', 'SIGNSERVER', 'SIGNPATH',
    'PKCS11', 'CRYPTOCERTUM', 'ETOKEN', 'YUBIKEY', 'NITROKEY', 'PIV', 'OPENSC'
)
# Store types whose credential can be an Azure access token obtained through GitHub OIDC.
$script:AidrJsignAzureStoreTypes = @{ 'AZUREKEYVAULT' = 'https://vault.azure.net'; 'TRUSTEDSIGNING' = 'https://codesigning.azure.net' }

function Resolve-AidrAuthenticodeSigner {
    param([string]$Name = '')
    if ([string]::IsNullOrWhiteSpace($Name)) { $Name = $env:AIDR_WINDOWS_SIGNER }
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'pfx' }
    if ($script:AidrSignerBackends -cnotcontains $Name) { throw "unsupported_windows_signer: use one of $($script:AidrSignerBackends -join ', ')" }
    return $Name
}

function Assert-AidrSignerThumbprint([string]$Thumbprint) {
    if ($Thumbprint -cnotmatch '^[0-9A-Fa-f]{40}$') { throw 'invalid_signing_thumbprint' }
    return $Thumbprint.ToUpperInvariant()
}

function Assert-AidrTimestampServer([string]$TimestampServer) {
    $uri = $null
    if (-not [Uri]::TryCreate($TimestampServer, [UriKind]::Absolute, [ref]$uri) -or
        ($uri.Scheme -cne 'https' -and $uri.Scheme -cne 'http') -or [string]::IsNullOrWhiteSpace($uri.Host) -or
        $uri.UserInfo -or $uri.Fragment) { throw 'invalid_timestamp_server' }
}

<#
  Backend settings, validated before any tool runs. Secrets are read from the
  environment and never echoed.
#>
function Get-AidrSignerSettings {
    param([Parameter(Mandatory)][string]$Signer)
    switch ($Signer) {
        'pfx' { return @{} }
        'azure-key-vault' {
            $url = $env:AIDR_AZURE_KEY_VAULT_URL
            $certificate = $env:AIDR_AZURE_KEY_VAULT_CERTIFICATE
            if ($url -cnotmatch '^https://[a-z0-9-]{3,24}\.(vault\.azure\.net|vault\.azure\.cn|vault\.usgovcloudapi\.net|managedhsm\.azure\.net)/?$') { throw 'invalid_azure_key_vault_url' }
            if ($certificate -cnotmatch '^[A-Za-z0-9-]{1,127}$') { throw 'invalid_azure_key_vault_certificate' }
            return @{ Url = $url.TrimEnd('/'); Certificate = $certificate }
        }
        'jsign' {
            $storeType = $env:AIDR_JSIGN_STORETYPE
            if ($script:AidrJsignStoreTypes -cnotcontains $storeType) { throw "unsupported_jsign_storetype: use one of $($script:AidrJsignStoreTypes -join ', ')" }
            $keystore = $env:AIDR_JSIGN_KEYSTORE
            if ([string]::IsNullOrWhiteSpace($keystore) -or $keystore -match '[\r\n]') { throw 'invalid_jsign_keystore' }
            $alias = $env:AIDR_JSIGN_ALIAS
            if ([string]::IsNullOrWhiteSpace($alias) -or $alias -match '[\r\n]') { throw 'invalid_jsign_alias' }
            $certfile = $env:AIDR_JSIGN_CERTFILE
            if (-not [string]::IsNullOrWhiteSpace($certfile) -and -not [IO.File]::Exists($certfile)) { throw 'jsign_certfile_missing' }
            return @{ StoreType = $storeType; Keystore = $keystore; Alias = $alias; Certfile = $certfile }
        }
    }
}

<#
  Azure access token through GitHub OIDC workload identity federation: the job
  needs `permissions: id-token: write`, and the Entra app (AIDR_AZURE_CLIENT_ID in
  AIDR_AZURE_TENANT_ID) a federated credential for this repository's protected
  environment. No client secret exists anywhere.
#>
function Get-AidrAzureAccessToken {
    param([Parameter(Mandatory)][string]$Resource)
    if (-not [string]::IsNullOrWhiteSpace($env:AIDR_AZURE_ACCESS_TOKEN)) { return $env:AIDR_AZURE_ACCESS_TOKEN }
    $tenant = $env:AIDR_AZURE_TENANT_ID
    $client = $env:AIDR_AZURE_CLIENT_ID
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if ($tenant -cnotmatch $guid -or $client -cnotmatch $guid) { throw 'azure_federated_identity_not_configured' }
    if ([string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_URL) -or [string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN)) { throw 'github_oidc_unavailable: the job needs permissions id-token: write' }
    $oidc = Invoke-RestMethod -Method Get -Uri ($env:ACTIONS_ID_TOKEN_REQUEST_URL + '&audience=api://AzureADTokenExchange') `
        -Headers @{ Authorization = 'Bearer ' + $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN }
    $authority = 'https://login.microsoftonline.com'
    if (-not [string]::IsNullOrWhiteSpace($env:AIDR_AZURE_AUTHORITY_HOST)) {
        if ($env:AIDR_AZURE_AUTHORITY_HOST -cnotmatch '^https://login\.(microsoftonline\.com|chinacloudapi\.cn|microsoftonline\.us)$') { throw 'invalid_azure_authority_host' }
        $authority = $env:AIDR_AZURE_AUTHORITY_HOST
    }
    $body = @{
        client_id             = $client
        scope                 = "$Resource/.default"
        grant_type            = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $oidc.value
    }
    $token = Invoke-RestMethod -Method Post -Uri "$authority/$tenant/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded'
    if ([string]::IsNullOrWhiteSpace($token.access_token)) { throw 'azure_token_exchange_failed' }
    return $token.access_token
}

function Get-AidrFileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Save-AidrPinnedDownload([string]$Url, [string]$Path, [string]$Sha256) {
    if (-not [IO.File]::Exists($Path)) {
        $partial = "$Path.partial"
        Invoke-WebRequest -Uri $Url -OutFile $partial -UseBasicParsing
        Move-Item -LiteralPath $partial -Destination $Path -Force
    }
    if ((Get-AidrFileSha256 $Path) -cne $Sha256) {
        Remove-Item -LiteralPath $Path -Force
        throw "pinned_tool_hash_mismatch: $Url"
    }
    return $Path
}

<#
  Install the pinned signer tool into ToolRoot (a private per-run directory) and
  return the path to run. pfx needs no tool besides signtool.exe.
#>
function Install-AidrSignerTool {
    param([Parameter(Mandatory)][string]$Signer, [Parameter(Mandatory)][string]$ToolRoot)
    [IO.Directory]::CreateDirectory($ToolRoot) | Out-Null
    switch ($Signer) {
        'pfx' { return '' }
        'jsign' {
            $jar = $env:AIDR_JSIGN_JAR
            if ([string]::IsNullOrWhiteSpace($jar)) { $jar = Join-Path $ToolRoot "jsign-$($script:AidrJsignVersion).jar" }
            return Save-AidrPinnedDownload $script:AidrJsignUrl $jar $script:AidrJsignSha256
        }
        'azure-key-vault' {
            $feed = Join-Path $ToolRoot 'feed'
            [IO.Directory]::CreateDirectory($feed) | Out-Null
            Save-AidrPinnedDownload $script:AidrAzureSignToolUrl (Join-Path $feed "azuresigntool.$($script:AidrAzureSignToolVersion).nupkg") $script:AidrAzureSignToolSha256 | Out-Null
            # Only the hash-checked local package is a source: nothing else is resolved from a feed.
            $config = Join-Path $ToolRoot 'nuget.config'
            [IO.File]::WriteAllText($config, "<?xml version=`"1.0`" encoding=`"utf-8`"?>`n<configuration><packageSources><clear /><add key=`"aidr-pinned`" value=`"$feed`" /></packageSources></configuration>`n")
            $toolPath = Join-Path $ToolRoot 'azuresigntool'
            if ([IO.File]::Exists((Join-Path $toolPath 'azuresigntool.exe'))) { return (Join-Path $toolPath 'azuresigntool.exe') }
            & dotnet tool install AzureSignTool --version $script:AidrAzureSignToolVersion --tool-path $toolPath --configfile $config
            if ($LASTEXITCODE -ne 0) { throw 'azuresigntool_install_failed' }
            return (Join-Path $toolPath 'azuresigntool.exe')
        }
    }
}

function Find-AidrJava {
    foreach ($candidate in @($env:AIDR_JAVA, $(if ($env:JAVA_HOME_17_X64) { Join-Path $env:JAVA_HOME_17_X64 'bin\java.exe' }), $(if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin\java.exe' }))) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and [IO.File]::Exists($candidate)) { return $candidate }
    }
    $command = Get-Command java -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw 'java_not_found: jsign needs Java 8 or later'
}

function Invoke-AidrSignerProcess([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "authenticode_signing_failed: $([IO.Path]::GetFileName($File)) exited with $LASTEXITCODE" }
}

<#
  The command line for one signing call, without running it (tests read it).
  Secrets are passed by reference where the tool allows it (jsign env:NAME).
#>
function Get-AidrSignerCommand {
    param(
        [Parameter(Mandatory)][string]$Signer,
        [Parameter(Mandatory)][string[]]$Files,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$TimestampServer,
        [string]$Description = '',
        [string]$Tool = '',
        [hashtable]$Settings = @{},
        [ValidateSet('CurrentUser/My', 'LocalMachine/My')][string]$CertificateStore = 'CurrentUser/My'
    )
    switch ($Signer) {
        'pfx' {
            $arguments = @('sign', '/fd', 'SHA256', '/tr', $TimestampServer, '/td', 'SHA256', '/sha1', $Thumbprint, '/s', 'My')
            if ($CertificateStore -ceq 'LocalMachine/My') { $arguments += '/sm' }
            if ($Description) { $arguments += @('/d', $Description) }
            return @{ File = $Tool; Arguments = $arguments + $Files }
        }
        'azure-key-vault' {
            $arguments = @('sign', '-kvu', $Settings.Url, '-kvc', $Settings.Certificate, '-kva', $Settings.AccessToken,
                '-fd', 'sha256', '-tr', $TimestampServer, '-td', 'sha256')
            if ($Description) { $arguments += @('-d', $Description) }
            return @{ File = $Tool; Arguments = $arguments + @('-v') + $Files }
        }
        'jsign' {
            $arguments = @('-jar', $Tool, '--storetype', $Settings.StoreType, '--keystore', $Settings.Keystore, '--alias', $Settings.Alias,
                '--storepass', 'env:AIDR_JSIGN_STOREPASS', '--alg', 'SHA-256', '--tsaurl', $TimestampServer, '--tsmode', 'RFC3161', '--replace')
            if ($Settings.Certfile) { $arguments += @('--certfile', $Settings.Certfile) }
            if ($Description) { $arguments += @('--name', $Description) }
            return @{ File = $Settings.Java; Arguments = $arguments + $Files }
        }
    }
}

<#
  Every signed file: valid Authenticode, the pinned signer, code-signing EKU and an
  RFC 3161 timestamp. Run after every backend, so a backend can never substitute
  another identity.
#>
function Assert-AidrAuthenticodeSigned {
    param([Parameter(Mandatory)][string[]]$Files, [Parameter(Mandatory)][string]$Thumbprint)
    $expected = Assert-AidrSignerThumbprint $Thumbprint
    foreach ($file in $Files) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction Stop
        if ($signature.Status.ToString() -cne 'Valid' -or $signature.SignatureType.ToString() -cne 'Authenticode') { throw "invalid_authenticode_signature: $([IO.Path]::GetFileName($file))" }
        $certificate = $signature.SignerCertificate
        if ($null -eq $certificate -or $certificate.Thumbprint.ToUpperInvariant() -cne $expected) { throw "unexpected_signing_certificate: $([IO.Path]::GetFileName($file))" }
        $codeSigning = $false
        foreach ($extension in @($certificate.Extensions)) {
            if ($extension.Oid.Value -ceq '2.5.29.37') {
                foreach ($usage in @($extension.EnhancedKeyUsages)) { if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') { $codeSigning = $true } }
            }
        }
        if (-not $codeSigning) { throw "missing_code_signing_eku: $([IO.Path]::GetFileName($file))" }
        if ($null -eq $signature.TimeStamperCertificate) { throw "missing_authenticode_timestamp: $([IO.Path]::GetFileName($file))" }
    }
}

<#
  Sign Files with the selected backend, then verify each with the pinned identity.
  -SignTool is signtool.exe (pfx). -ToolRoot is a private directory for the pinned
  HSM signer tools (defaults to RUNNER_TEMP / TEMP).
#>
function Invoke-AidrAuthenticodeSign {
    param(
        [Parameter(Mandatory)][string[]]$Files,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$TimestampServer,
        [string]$Description = '',
        [string]$Signer = '',
        [string]$SignTool = '',
        [string]$ToolRoot = '',
        [ValidateSet('CurrentUser/My', 'LocalMachine/My')][string]$CertificateStore = 'CurrentUser/My'
    )
    $Signer = Resolve-AidrAuthenticodeSigner $Signer
    $pinned = Assert-AidrSignerThumbprint $Thumbprint
    Assert-AidrTimestampServer $TimestampServer
    foreach ($file in $Files) { if (-not [IO.File]::Exists($file)) { throw "signing_input_missing: $file" } }
    if ([string]::IsNullOrWhiteSpace($ToolRoot)) {
        $base = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
        $ToolRoot = Join-Path $base 'aidr-authenticode-tools'
    }
    $settings = Get-AidrSignerSettings $Signer
    $tool = $SignTool
    if ($Signer -cne 'pfx') { $tool = Install-AidrSignerTool -Signer $Signer -ToolRoot $ToolRoot }
    elseif ([string]::IsNullOrWhiteSpace($tool)) { throw 'signtool_required' }
    $restoreStorepass = $null
    try {
        if ($Signer -ceq 'azure-key-vault') {
            $settings.AccessToken = Get-AidrAzureAccessToken -Resource $(if ($settings.Url -match 'managedhsm') { 'https://managedhsm.azure.net' } else { 'https://vault.azure.net' })
        } elseif ($Signer -ceq 'jsign') {
            $settings.Java = Find-AidrJava
            if ([string]::IsNullOrWhiteSpace($env:AIDR_JSIGN_STOREPASS)) {
                if (-not $script:AidrJsignAzureStoreTypes.ContainsKey($settings.StoreType)) { throw 'jsign_storepass_required' }
                # Azure-backed store types take an OIDC access token as the store password.
                $restoreStorepass = ''
                $env:AIDR_JSIGN_STOREPASS = Get-AidrAzureAccessToken -Resource $script:AidrJsignAzureStoreTypes[$settings.StoreType]
            }
        }
        $command = Get-AidrSignerCommand -Signer $Signer -Files $Files -Thumbprint $pinned -TimestampServer $TimestampServer `
            -Description $Description -Tool $tool -Settings $settings -CertificateStore $CertificateStore
        Invoke-AidrSignerProcess $command.File $command.Arguments
    } finally {
        if ($null -ne $restoreStorepass) { Remove-Item Env:AIDR_JSIGN_STOREPASS -ErrorAction SilentlyContinue }
        if ($settings.ContainsKey('AccessToken')) { $settings.AccessToken = $null }
    }
    Assert-AidrAuthenticodeSigned -Files $Files -Thumbprint $pinned
}
