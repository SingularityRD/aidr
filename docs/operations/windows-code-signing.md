# Windows code signing with an HSM-held certificate

Since June 2023 a publicly trusted OV or EV code-signing key must be generated,
stored and used in a hardware module (CA/Browser Forum Code Signing Baseline
Requirements 6.2.7.4.2). A CA no longer hands out a `.pfx` file you can paste
into a GitHub secret. This page is the engineering runbook: how the release and
customer-installer workflows sign with a key that stays in an HSM, which
backend to pick, what to buy and what to configure. The purchase research
(prices, Turkish eligibility, documents) is in
[the purchase guide](../sales/code-signing-guide.md).

## What is signed, and where

| Workflow job | Files | Script |
|---|---|---|
| `release-rc.yml` → `windows-authenticode` | Windows fleet PowerShell scripts and the Claude connector's native response scripts | `scripts/sign-windows-response-payload.ps1` |
| `release-rc.yml` → `installers-windows` | the SEA bundle `.exe` files, the desktop MSI | `deploy/installers/windows/build-msi.ps1` |
| `customer-installer.yml` → `windows` | the SEA bundle `.exe` files, the customer MSI, the Burn engine (detached, signed, reattached) and the setup EXE | `deploy/installers/windows/build-msi.ps1 -Bundle` |

All three call one library, `scripts/windows-authenticode-signer.ps1`. Whatever
backend signs, every file is then checked the same way: a valid Authenticode
signature, a signer certificate whose SHA-1 thumbprint equals the independently
pinned `AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT` secret, the code-signing EKU and an
RFC 3161 timestamp. A backend that signs with any other certificate stops the
build; no unsigned or differently signed file is published.

## Backends

Selected with the repository (or `release-candidate` environment) variable
`AIDR_WINDOWS_SIGNER`. Unset means `pfx`.

| `AIDR_WINDOWS_SIGNER` | Key lives in | Tool | Runner |
|---|---|---|---|
| `pfx` | a PFX imported into the ephemeral runner's certificate store and deleted afterwards | `signtool.exe` | GitHub-hosted only (enforced) |
| `azure-key-vault` | Azure Key Vault Premium or Managed HSM (FIPS 140 Level 3 HSM) | AzureSignTool 7.0.1, SHA-256 pinned, installed only from the checked package | GitHub-hosted |
| `jsign` | a cloud HSM or signing service, or a PKCS#11 token | jsign 7.4, SHA-256 pinned | GitHub-hosted for cloud store types; a self-hosted Windows runner for a physical token |

`pfx` stays for local test builds (a self-signed test certificate) and for any
certificate that can still be exported. A purchased OV/EV certificate uses
`azure-key-vault` or `jsign`.

### `azure-key-vault`

No client secret exists anywhere: the job's GitHub OIDC token is exchanged for a
short-lived Azure token (workload identity federation). The jobs have
`id-token: write` for this.

| Name | Kind | Value |
|---|---|---|
| `AIDR_WINDOWS_SIGNER` | variable | `azure-key-vault` |
| `AIDR_AZURE_KEY_VAULT_URL` | variable | `https://<vault>.vault.azure.net` (or `.managedhsm.azure.net`) |
| `AIDR_AZURE_KEY_VAULT_CERTIFICATE` | variable | the certificate's name in the vault |
| `AIDR_AZURE_TENANT_ID` | variable | Entra tenant id |
| `AIDR_AZURE_CLIENT_ID` | variable | the app registration (or user-assigned managed identity) client id |
| `AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT` | secret | the certificate's SHA-1 thumbprint, 40 upper-case hex |
| `AIDR_WINDOWS_TIMESTAMP_SERVER` | variable | the CA's HTTPS RFC 3161 timestamp URL |

Azure setup, once:

1. Create a Key Vault with the **Premium** SKU (HSM-protected keys) or a Managed HSM.
2. Create the certificate in the vault with an **RSA-HSM** key, non-exportable,
   issuer "Unknown" (a CSR is generated in the vault). Send the CSR to the CA;
   merge the issued certificate back into the vault. The private key is created
   in the HSM and never leaves it, which is what the CA needs. Ask the CA or
   reseller first whether it accepts a key generated in Azure Key Vault for this
   product and which key attestation it wants.
3. Create an app registration (or user-assigned managed identity) and give it
   the Key Vault roles **Key Vault Crypto User** and **Key Vault Certificate User**
   on this vault only.
4. Add a federated credential: issuer `https://token.actions.githubusercontent.com`,
   subject `repo:<owner>/<repo>:environment:release-candidate`, audience
   `api://AzureADTokenExchange`. Only jobs in the protected `release-candidate`
   environment can then get a token.

### `jsign`

| Name | Kind | Value |
|---|---|---|
| `AIDR_WINDOWS_SIGNER` | variable | `jsign` |
| `AIDR_JSIGN_STORETYPE` | variable | `ESIGNER`, `DIGICERTONE`, `GOOGLECLOUD`, `AWS`, `AZUREKEYVAULT`, `TRUSTEDSIGNING`, `HASHICORPVAULT`, `ORACLECLOUD`, `GARASIGN`, `SIGNSERVER`, `SIGNPATH`, `PKCS11`, `CRYPTOCERTUM`, `ETOKEN`, `YUBIKEY`, `NITROKEY`, `PIV`, `OPENSC` |
| `AIDR_JSIGN_KEYSTORE` | variable | per store type (jsign documentation): the service URL, project/key-ring path, region, or PKCS#11 configuration file |
| `AIDR_JSIGN_ALIAS` | variable | the key or certificate name in the store |
| `AIDR_JSIGN_STOREPASS` | secret | the API credential or token PIN; passed to jsign as `env:AIDR_JSIGN_STOREPASS`, never on the command line. Leave empty for `AZUREKEYVAULT` / `TRUSTEDSIGNING` with the Azure variables above: the OIDC token is used instead. |
| `AIDR_JSIGN_CERTCHAIN_PEM` | variable | the public certificate chain (PEM), for store types that do not return it (for example `GOOGLECLOUD`, `AWS`) |
| `AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT`, `AIDR_WINDOWS_TIMESTAMP_SERVER` | secret / variable | as above |

jsign signs PE files (`.exe`, the detached Burn engine), `.msi` and PowerShell
scripts, so every artefact in the table at the top is covered.

### Physical token (Certum cryptoCertum card, SafeNet eToken, YubiKey)

A USB token cannot be plugged into a GitHub-hosted runner. Two options:

- A **self-hosted Windows runner** in a locked room with the token attached,
  registered only to the `release-candidate` environment, with jsign
  (`CRYPTOCERTUM`, `ETOKEN`, `YUBIKEY` or `PKCS11`) and the token PIN in
  `AIDR_JSIGN_STOREPASS`. The workflows' `runs-on: windows-2022` must then be
  changed to that runner's label; review that change like any release change.
- **Manual signing** on the release engineer's workstation for a one-off: run
  `build-msi.ps1 -Signer jsign` with the same variables set in the shell.
  Prefer a cloud key for repeatable releases.

## Recommended purchase for the first release

The purchase guide recommends **Certum OV through a Turkish reseller** for a
registered company. What matters for this pipeline is *where the key lives*, so
order it with one of these key options, in this order of preference:

1. **Cloud signing at the CA, supported by jsign**: SSL.com eSigner (`ESIGNER`)
   or DigiCert KeyLocker / ONE (`DIGICERTONE`). Works on hosted runners with an
   API credential in `AIDR_JSIGN_STOREPASS`.
2. **Your own cloud HSM**: Azure Key Vault Premium / Managed HSM
   (`azure-key-vault`, no stored secret) or Google Cloud KMS HSM / AWS KMS
   (`jsign`). Only if the CA accepts a CSR from that HSM with its key
   attestation; ask the reseller in writing before paying.
3. **The CA's physical token** (Certum's default for OV is the cryptoCertum
   card): works, but needs the self-hosted runner above.

### Buying Certum OV through a Turkish reseller — steps

1. Company documents ready: Ticaret Sicili Gazetesi, vergi levhası, imza
   sirküleri, a landline or a phone number listed in a public directory, and a
   domain e-mail address (purchase guide §5.3–5.4).
2. Ask two Turkish Certum resellers for a written quote for "Certum Code Signing
   (Standard/OV), 1 year" and for the key options above (card + reader shipped
   within Turkey, SimplySign cloud, or own-HSM CSR). Ask explicitly whether the
   certificate can be issued for a CSR from Azure Key Vault or another HSM.
3. Order, pay in TRY (e-fatura), complete Certum's organisation validation
   (documents upload, the verification call).
4. Generate the key where the chosen option says (vault, cloud service or
   token) and submit the CSR or activate the cloud account. Never generate it
   on a laptop.
5. When the certificate is issued, record its SHA-1 thumbprint (40 upper-case
   hex) in the `AIDR_WINDOWS_CODE_SIGNING_THUMBPRINT` secret of the
   `release-candidate` environment, set the backend variables above and the
   CA's HTTPS timestamp URL in `AIDR_WINDOWS_TIMESTAMP_SERVER`.
6. Delete the `AIDR_WINDOWS_CODE_SIGNING_PFX_B64` and
   `AIDR_WINDOWS_CODE_SIGNING_PFX_PASSWORD` secrets if a test PFX was ever set.
7. Dry run: build a release candidate for a throwaway `vX.Y.Z-rc.N` and check
   the `windows-authenticode` and `installers-windows` jobs, then run
   `Get-AuthenticodeSignature` on the downloaded MSI on a clean Windows machine.
8. Calendar the renewal: certificates are limited to 460 days (CSBR 6.3.2). The
   new certificate has a new thumbprint; update the secret, the fleet README's
   expected thumbprint and the customer-facing verification instructions in the
   same change.

## Local test builds

```powershell
# self-signed test certificate in CurrentUser\My, pfx backend (default)
./deploy/installers/windows/build-msi.ps1 -SeaDir bin\aidr-sea -TrustKey release-public.pem `
  -TrustKeyFingerprint <sha256> -Version 1.0.0 -OutDir out -SignThumbprint <test thumbprint> `
  -TimestampServer https://timestamp.digicert.com
```

A test certificate is not trusted on other machines; `Get-AuthenticodeSignature`
there reports `NotTrusted`, which is why release builds never use one.

## Needs a human

- Buying the certificate and passing the CA's organisation validation.
- Creating the vault, app registration and federated credential (or the cloud
  signing account) and setting the variables and secrets listed above.
- The first signed release candidate and the check on a clean Windows machine.
