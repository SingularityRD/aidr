# Windows enterprise fleet delivery

These scripts package and manage the Claude Code endpoint connector through
Microsoft Intune, Configuration Manager (SCCM), or another Windows software
distribution system. They provide local package integrity, publisher identity,
install/detect/update/uninstall/rollback behavior, state, and redacted logs.
They do not prove that a specific MDM tenant delivered the package or that the
native AI host invoked the registered hook. Record those as separate customer
acceptance evidence.

## Authenticode release gate

The Windows management scripts are launched with `-ExecutionPolicy AllSigned`.
The protected RC workflow includes an Authenticode signing job and an operator
signing helper; no release certificate is stored in this repository. The
checked-in PowerShell scripts remain unsigned. That is a release blocker until
the configured publisher signs every
PowerShell script in `deploy/fleet/windows` with the approved code-signing
identity. The verifier includes itself and the manifest-generation utility, as
well as `Common.ps1` and the response worker entrypoints. Sign the verifier before
running it under `AllSigned`; it checks every required script and fails closed
on unsigned, invalid, untrusted, missing, unexpected, or differently signed
files.

Keep the management-script Authenticode thumbprint in protected, immutable
release configuration and provide it explicitly. Do not derive the expected
thumbprint from the files being checked. This identity is separate from the CMS
certificate that signs the npm tarball; reusing one certificate requires an
explicit release-security approval. No certificate or signature is fabricated
by the local verification workflow.

Run this after the release signing step and before creating the Win32/SCCM
package. The verifier itself and all checked scripts must already be signed so
the command can run under the required policy:

```powershell
$managementScriptThumbprint = 'APPROVED_AUTHENTICODE_THUMBPRINT'
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned `
  -File .\.release-evidence\windows-fleet\Test-AidrFleetScriptSignatures.ps1 `
  -ExpectedThumbprint $managementScriptThumbprint
if ($LASTEXITCODE -ne 0) { throw 'Windows fleet signing preflight failed; packaging is blocked.' }
```

The preflight checks the actual `.ps1` files in the verified staging folder. Do not edit,
replace, or add PowerShell scripts after it passes; any content change requires
the release signer to sign again and the preflight to be rerun.

The Claude connector also carries `dist/native/Invoke-AidrResponseAction.ps1`
and `dist/native/Common.ps1`. Sign these exact packaged files with the approved
Authenticode identity **before** creating their Ed25519 artifact/package
manifests and the tarball CMS signature. Editing or signing PowerShell after
those manifests were made invalidates the connector integrity. The worker
respects the host's PowerShell execution policy; it does not use `Bypass`.

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

`New-AidrFleetManifest.ps1` verifies the CMS artifact signature and writes both
the manifest and its SHA-256 sidecar. After the Authenticode preflight passes,
put `Common.ps1`, `Install-Aidr.ps1`, `Update-Aidr.ps1`, `Rollback-Aidr.ps1`,
`Uninstall-Aidr.ps1`, `Test-AidrDetection.ps1`, `Invoke-AidrRemediation.ps1`, and
the generated directory into the Win32/SCCM package. Store the manifest
SHA-256 in the MDM command line. The command-line value is the trust anchor that
prevents an attacker from replacing the manifest, payload hash, and signer
allowlist together; it does not replace Authenticode signing of PowerShell
scripts.

The `windows-authenticode` RC job requires protected environment secrets
`AIDR_WINDOWS_CODE_SIGNING_PFX_B64`, `AIDR_WINDOWS_CODE_SIGNING_PFX_PASSWORD`,
`AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT` (uppercase SHA-1 certificate thumbprint),
and protected variable `AIDR_WINDOWS_TIMESTAMP_SERVER` (approved HTTPS URL).
It imports a single pinned certificate only on an ephemeral GitHub-hosted
Windows runner, removes the private PFX and imported key in `finally`, and
publishes only the staged public scripts and verification receipt. The job
binds the 14 unsigned input hashes to the immutable commit and the independent
unsigned build archive hash. Package signing verifies the Windows job's
independent archive/receipt hashes, then updates the native payload before
generating its Ed25519 manifests. Final Windows acceptance rechecks the actual
packaged Authenticode signatures, Code Signing EKU and timestamp. Missing
certificate material blocks the job; local mocked tests cannot establish a
real publisher signature or customer-machine acceptance.

For an operator-controlled signing station with the approved certificate
already in `CurrentUser\My`, prepare a **new** staging directory using the
independently recorded unsigned build archive SHA-256. Signing uses the
Microsoft Windows SDK SignTool with HTTPS RFC 3161 timestamping and does not
import certificates. Use PowerShell 7 or newer. The helper discovers the installed SDK's `x64/signtool.exe`
or accepts an approved absolute `-SignToolPath`; it checks the tool's Microsoft
Authenticode signature before invoking it. PowerShell's signing cmdlet cannot
provide this HTTPS timestamp ([Microsoft documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature?view=powershell-7.5#-timestampserver)).

```powershell
node .github/scripts/windows-authenticode-inputs.mjs prepare `
  --stage .release-evidence/windows-signing --git-sha REVIEWED_COMMIT_SHA `
  --unsigned-release-sha256 INDEPENDENT_UNSIGNED_ARCHIVE_SHA256
$stage = Join-Path (Get-Location) '.release-evidence/windows-signing'
pwsh -NoProfile -NonInteractive -File scripts/sign-windows-response-payload.ps1 `
  -FleetScriptRoot (Join-Path $stage 'fleet') `
  -ClaudeDist (Join-Path $stage 'claude') `
  -InputManifestPath (Join-Path $stage 'input-manifest.json') `
  -ExpectedThumbprint APPROVED_AUTHENTICODE_THUMBPRINT `
  -TimestampServer https://APPROVED_TIMESTAMP_SERVER `
  -ReceiptPath (Join-Path $stage 'authenticode-receipt.json')
```

Transfer the staged inputs with their independently recorded receipt hash to
the package-signing station and run the helper's `consume` mode with
`--stage`, `--git-sha`, `--unsigned-release-sha256`, `--receipt-sha256`,
`--thumbprint`, and `--timestamp-server` before generating final manifests.
Signed customer kits require this verified staging and the independently
configured `--windows-authenticode-receipt-sha256` and
`--windows-code-signing-thumbprint` inputs (or their matching release environment
variables); they cannot fall back to the unsigned repository scripts.

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

When a managed hook registration is missing, mispointed or duplicated (for
example after a partial package removal), remediation re-runs the receipt check
and the connector's own local deny canary, then repairs only the AIDR-marked hook
registrations. It requires no elevation, leaves policy, allowlists, agent
configuration, connector bytes and the receipt untouched, and refuses to
re-enable a host whose hooks are globally disabled:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File .\Invoke-AidrRemediation.ps1 -TargetHome C:\Users\TARGET_USER
```

Add `-DetectionOnly` for a read-only check (optionally with `-Json` for a
machine-readable result). Neither mode proves host execution or MDM delivery.

## Opt-in signed Windows response worker

Activate the worker only after device enrollment has stored the agent credential
in that Windows user's DPAPI store and a current signed managed entitlement is
available. Provisioning must run as the actual enrolled user, with its real OS
profile. `SYSTEM`, another administrator's profile, and `HOME`/`USERPROFILE`
overrides cannot decrypt that user's credentials. The task uses an interactive
user logon, retries every minute, and preserves its state between restarts.
Commands wait while the user is logged out. Linux and macOS response adapters
are unsupported by this worker.

Create a reviewed public configuration with these exact fields. Replace every
placeholder using the approved deployment and the enrolled device identity;
the configuration contains no bearer or private signing key:

```json
{
  "schema_version": 1,
  "tenant_id": "<TENANT_UUID>",
  "agent_id": "<AGENT_UUID>",
  "installation_id": "<ENROLLED_INSTALLATION_UUID>",
  "trusted_command_keys": { "<APPROVED_SIGNER_ID>": "<ED25519_PUBLIC_KEY_PEM>" },
  "control_plane_addresses": ["<CURRENT_CONTROL_PLANE_IP>"],
  "admin_recovery_addresses": ["<ADMIN_RECOVERY_IP>"],
  "network_support_addresses": ["<DNS_DHCP_GATEWAY_OR_REQUIRED_IP>"]
}
```

Pin signer IDs and public keys independently of command replies. Addresses must
be literal IPv4/IPv6 addresses, with at most 64 unique addresses across the three
lists. Include every current control-plane DNS answer and the tested network
dependencies needed for recovery. No hostname, CIDR, wildcard or automatic DNS
exception is accepted. Isolation blocks the complement of these addresses;
Windows block-rule precedence must not accidentally block the recovery path.

After the ordinary signed fleet installation, run the signed worker installer:

```powershell
$responseConfig = '.\response-worker-config.json'
$responseConfigSha = (Get-FileHash -LiteralPath $responseConfig -Algorithm SHA256).Hash
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned `
  -File .\Install-AidrResponseWorker.ps1 -TargetHome C:\Users\ENROLLED_USER `
  -ResponseWorkerConfigPath $responseConfig `
  -ExpectedResponseWorkerConfigSha256 $responseConfigSha -RunElevated
```

`-RunElevated` requires the same enrolled user to be an administrator and the
installer to run elevated. It enables real firewall actions. Without it the
task supports persistent agent pause/resume; firewall commands return an
explicit privilege failure. The ordinary installer also accepts
`-EnableResponseWorker`, `-ResponseWorkerConfigPath`,
`-ExpectedResponseWorkerConfigSha256` and `-ResponseWorkerRunElevated`.
Upgrades rebind an already configured task; a rollback package without the
response worker is refused before replacing hooks.

The hook's independent required-worker flag and authenticated journal prevent
missing or corrupt state from restoring execution. Pause survives command
expiry and credential rotation; only a signed matching resume can release it.
First activation creates a separate random journal secret in DPAPI. A partial
activation or lost credential reference requires explicit operator repair.
The protection boundary trusts the same OS user and administrator; it does not
claim resistance to an administrator restoring old local files.

Signed release/resume commands remove only the exact owned rules/barrier.
Unobserved or partial effects remain `outcome_unknown`; recovery observes them
without repeating the action. Removal stops the owned task and checks its
authenticated idle state plus the native state under locks; active or ambiguous
effects refuse uninstall and restart the task. Required configuration, vault
and journal are preserved. Qualify this flow on an isolated VM with real signed
inputs, DNS/DHCP, IPv6, existing connections and admin recovery before rollout.

## Operational behavior

- Every install and detection resolves manifest paths beneath the package root,
  rejects traversal/link entries, verifies exact SHA-256 values, checks one CMS
  signer against pinned certificate thumbprints, limits compressed archives to
  512 MiB and total expanded regular-file bytes to 512 MiB before extraction,
  and optionally requires an offline-trusted certificate chain.
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
