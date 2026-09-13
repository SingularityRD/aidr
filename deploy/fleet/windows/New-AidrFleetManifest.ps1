[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactPath,
    [Parameter(Mandatory)][string]$ArtifactSignaturePath,
    [Parameter(Mandatory)][string]$InstallerPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40,128}$')][string]$PublisherThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$PackageVersion,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string]$AgentConfigPath,
    [ValidateRange(18, 99)][int]$MinimumNodeMajor = 24,
    [switch]$RequireTrustedChain
)

. (Join-Path $PSScriptRoot 'Common.ps1')

try {
    foreach ($path in @($ArtifactPath, $ArtifactSignaturePath, $InstallerPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Every required manifest input must be an existing file" }
    }
    if (Test-Path -LiteralPath $OutputDirectory) {
        if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw "OutputDirectory must be a directory" }
        if (Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1) { throw "OutputDirectory must be empty" }
    } else { [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($OutputDirectory)) | Out-Null }
    $output = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $artifactName = [IO.Path]::GetFileName($ArtifactPath)
    $signatureName = "$artifactName.p7s"
    $installerName = 'endpoint-install.mjs'
    $payload = Join-Path $output 'payload'
    [IO.Directory]::CreateDirectory($payload) | Out-Null
    Copy-Item -LiteralPath $ArtifactPath -Destination (Join-Path $payload $artifactName)
    Copy-Item -LiteralPath $ArtifactSignaturePath -Destination (Join-Path $payload $signatureName)
    Copy-Item -LiteralPath $InstallerPath -Destination (Join-Path $payload $installerName)
    $config = $null
    if (-not [string]::IsNullOrWhiteSpace($AgentConfigPath)) {
        if (-not (Test-Path -LiteralPath $AgentConfigPath -PathType Leaf)) { throw "AgentConfigPath must be an existing file" }
        try { $null = Get-Content -LiteralPath $AgentConfigPath -Raw -Encoding utf8 | ConvertFrom-Json } catch { throw "AgentConfigPath must contain valid JSON" }
        Copy-Item -LiteralPath $AgentConfigPath -Destination (Join-Path $payload 'agent-config.json')
        $config = [ordered]@{ path = 'payload/agent-config.json'; sha256 = Get-AidrSha256 (Join-Path $payload 'agent-config.json'); preserve_existing = $true }
    }
    $stagedArtifact = Join-Path $payload $artifactName
    $stagedSignature = Join-Path $payload $signatureName
    $stagedInstaller = Join-Path $payload $installerName
    $verifiedSigner = Assert-AidrDetachedCmsSignature -ContentPath $stagedArtifact -SignaturePath $stagedSignature -AllowedSignerThumbprints @($PublisherThumbprint) -RequireTrustedChain:$RequireTrustedChain
    $manifest = [ordered]@{
        schema_version = 1
        product = 'singularity-aidr'
        connector = 'claude-code'
        package_version = $PackageVersion
        minimum_node_major = $MinimumNodeMajor
        artifact = [ordered]@{
            path = "payload/$artifactName"
            sha256 = Get-AidrSha256 $stagedArtifact
            signature_path = "payload/$signatureName"
            signature_required = $true
            allowed_signer_thumbprints = @($verifiedSigner)
            require_trusted_chain = [bool]$RequireTrustedChain
        }
        installer = [ordered]@{
            path = "payload/$installerName"
            sha256 = Get-AidrSha256 $stagedInstaller
            package_root = 'package'
        }
        agent_config = $config
        operations = [ordered]@{
            installation_context = 'machine-or-mdm-managed-user'
            target_home_required = $true
            preserve_existing_config = $true
            retained_rollback_candidates = 3
        }
        assurance = 'Package digest and detached CMS signer verified locally. Native host invocation and MDM rollout require separate acceptance.'
    }
    $manifestPath = Join-Path $output 'aidr-fleet-manifest.json'
    [IO.File]::WriteAllText($manifestPath, (($manifest | ConvertTo-Json -Depth 20) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
    $manifestHash = Get-AidrSha256 $manifestPath
    [IO.File]::WriteAllText((Join-Path $output 'aidr-fleet-manifest.sha256'), "$manifestHash  aidr-fleet-manifest.json$([Environment]::NewLine)", [Text.UTF8Encoding]::new($false))
    Write-Output $manifestHash
    exit 0
} catch {
    Write-Error "Fleet manifest generation failed closed: $($_.Exception.Message)"
    exit 1
}
