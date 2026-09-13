# Windows enterprise fleet delivery

These scripts package and manage the Claude Code endpoint connector through
Microsoft Intune, Configuration Manager (SCCM), or another Windows software
distribution system. They provide local package integrity, publisher identity,
install/detect/update/uninstall/rollback behavior, state, and redacted logs.
They do not prove that a specific MDM tenant delivered the package or that the
native AI host invoked the registered hook. Record those as separate customer
acceptance evidence.

## Build the deployment directory

Sign the exact `@singularityrd/aidr-claude-code` npm tarball with the approved
code-signing certificate as a detached CMS/PKCS#7 signature. The release
pipeline or HSM should perform this signing step; private keys must not be put
in the deployment directory. Then run:

```powershell
$thumbprint = 'APPROVED_CERTIFICATE_THUMBPRINT'
$manifestSha = & .\deploy\fleet\windows\New-AidrFleetManifest.ps1 `
  -ArtifactPath .\release-output\singularityrd-aidr-claude-code-0.6.0.tgz `
  -ArtifactSignaturePath .\release-output\singularityrd-aidr-claude-code-0.6.0.tgz.p7s `
  -InstallerPath .\scripts\endpoint-install.mjs `
  -PublisherThumbprint $thumbprint `
  -PackageVersion 0.6.0 `
  -AgentConfigPath .\.aidr-deploy\agent-config.json `
  -OutputDirectory .\aidr-windows-0.6.0 `
  -RequireTrustedChain
```

`New-AidrFleetManifest.ps1` verifies the signature and writes both the manifest
and its SHA-256 sidecar. Put the five management scripts, `Common.ps1`, and the
generated directory into the Win32/SCCM package. Store the manifest SHA-256 in
the MDM command line. The command-line value is the trust anchor that prevents
an attacker from replacing the manifest, payload hash, and signer allowlist
together.

Do not omit `-RequireTrustedChain` for a production package. Offline or isolated
test packages may pin a self-signed certificate without that switch; this is
only a test facility.

## Intune and SCCM commands

Run in 64-bit PowerShell. Machine context is recommended. Always pass the
intended interactive user's existing profile explicitly; the installer refuses
drive roots and shared operating-system directories. Replace the example paths
and manifest digest with values from the immutable deployment package.

Install:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File .\Install-Aidr.ps1 -ManifestPath .\aidr-windows-0.6.0\aidr-fleet-manifest.json -ExpectedManifestSha256 64_HEX_SHA256 -TargetHome C:\Users\TARGET_USER
```

Detection rule (custom detection script; exit `0` means detected and `1` means
missing or inconsistent):

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File .\Test-AidrDetection.ps1 -TargetHome C:\Users\TARGET_USER
```

Update uses the same package and rejects versions that are not newer:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File .\Update-Aidr.ps1 -ManifestPath .\aidr-windows-0.6.1\aidr-fleet-manifest.json -ExpectedManifestSha256 64_HEX_SHA256 -TargetHome C:\Users\TARGET_USER
```

Rollback selects the most recent of three previously verified package manifests
retained under `%ProgramData%\SingularityAIDR\Fleet`. It rechecks the cached
manifest, artifact digest, publisher signature, package identity, and local deny
canary before changing active state:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File .\Rollback-Aidr.ps1 -TargetHome C:\Users\TARGET_USER
```

Uninstall removes only AIDR-managed hook entries and backs up Claude settings.
Agent configuration, connector files, and verified rollback packages remain by
default. `-RemoveAgentConfig` moves the configuration to a timestamped recovery
file rather than deleting it.

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File .\Uninstall-Aidr.ps1 -TargetHome C:\Users\TARGET_USER
```

## Operational behavior

- Every install and detection resolves manifest paths beneath the package root,
  rejects traversal/link entries, verifies exact SHA-256 values, checks one CMS
  signer against pinned certificate thumbprints, and optionally requires an
  offline-trusted certificate chain.
- Existing `.singularity-aidr/config.json` is preserved. A packaged config is
  installed only when no config exists. Existing unrelated Claude hooks remain.
- Settings changes are backed up and written atomically by the endpoint
  installer after a local deny canary passes.
- JSONL logs contain event codes, versions, hashes, and opaque target IDs. The
  logging API does not accept paths, tokens, configuration, or credentials.
- The default machine-state directory disables inherited ACLs and grants write
  access only to Local System and local Administrators. Its initialization
  requires an elevated MDM or administrator context. A custom `-StateRoot` is
  intended for isolated verification and must be protected by its operator.
- Detection checks the protected state, cached manifest and signature, endpoint
  receipt, three managed hook registrations, and installed bundles. It reports
  `host_execution: unverified`; only a native host acceptance run can close it.
- Node.js 24 and Windows `tar.exe` are the supported first-customer baseline.
  The manifest may lower the Node minimum only after connector qualification.

Before broad deployment, run install/update/rollback/uninstall rings on each
supported Windows and Claude Code version, test MDM retry/reboot semantics, and
capture real device and native-host evidence. These scripts are an offline-tested
delivery implementation, not an Intune/SCCM certification claim.
