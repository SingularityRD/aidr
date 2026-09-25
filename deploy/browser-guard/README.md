# Deploying Singularity AIDR Browser Guard

This folder has example policies for installing Browser Guard on managed
machines and setting its configuration centrally. The managed configuration
reaches the extension through `chrome.storage.managed` (Chrome, Edge) or
`browser.storage.managed` (Firefox), and every key set here is locked in the
extension's UI.

| File | Use |
|---|---|
| [`chrome-managed-policy.example.json`](chrome-managed-policy.example.json) | Chrome on Linux (`/etc/opt/chrome/policies/managed/`), and the reference copy of the managed values |
| [`windows-registry.example.reg`](windows-registry.example.reg) | Chrome and Edge on Windows: GPO preference, `reg import`, or any tool that writes HKLM |
| [`edge-intune.example.json`](edge-intune.example.json) | Edge on Windows through Microsoft Intune |
| [`firefox-policies.example.json`](firefox-policies.example.json) | Firefox `policies.json` (Windows, macOS, Linux) |
| [`macos-jamf.example.mobileconfig`](macos-jamf.example.mobileconfig) | Chrome and Edge on macOS through Jamf Pro (or any MDM) |

All five files carry the **same** managed values; the automated test
`packages/browser-guard/src/__tests__/build-tools.test.ts` fails if they drift
apart or use a key the extension does not accept.

## Before you start

1. **Get the extension IDs.** Replace every `REPLACE_WITH_CHROME_EXTENSION_ID`
   and `REPLACE_WITH_EDGE_EXTENSION_ID` placeholder:
   - Chrome Web Store / Edge Add-ons: the ID shown on the listing (32 letters
     `a`-`p`). The store update URLs are already in the examples.
   - Self-hosted Chromium build: pack `dist/chrome` with your own key
     (`chrome --pack-extension=dist/chrome --pack-extension-key=browser-guard.pem`),
     host the `.crx` with an `update.xml`, and use that URL instead of the store
     URL. The ID is derived from the key. Chrome and Edge only install off-store
     extensions when they are force-installed by policy on managed machines.
   - Firefox always uses `browser-guard@singularityrd.com`. The XPI must be
     signed by Mozilla (listed on addons.mozilla.org, or signed as unlisted and
     self-hosted); replace the example `install_url`.
2. **Replace the example values.** `policyId`, `literals`, the example
   `exactData` set (its key is published in this repository, so it must never be
   deployed), `telemetry.controlPlaneUrl` and `telemetry.apiKey`. Remove
   `telemetry` entirely if you do not want counts sent to your control plane.
3. **Pilot first.** Roll out to a test group in `monitor` mode, check the
   popup statistics and control-plane counts, then switch to `auto` or
   `confirm`.

## Managed keys

| Key | Type | Notes |
|---|---|---|
| `mode` | string | `auto`, `confirm`, `block`, `monitor` |
| `enabledEntities` | array of entity types | e.g. `EMAIL`, `PHONE`, `TC_KIMLIK`, `IBAN`, `CREDIT_CARD`, `SECRET`, `PRIVATE_KEY` |
| `neverRestore` | array of entity types | masked in prompts and kept masked in responses |
| `literals` | array of `{ "value", "type" }` | organisation terms; up to 1024, each 2-256 characters |
| `exactData` | array of `{ "datasetId", "keyB64", "fingerprints", "type" }` | up to 16 datasets, 100 000 fingerprints in total; build with `fingerprint-dataset.mjs` |
| `detectSignals` | boolean | prompt-injection and source-code signals |
| `signalAction` | string | `off`, `warn`, `block` |
| `blockedSites` | array of site ids | the page is blocked from loading; `chatgpt`, `gemini`, `claude`, `copilot`, `perplexity`, `deepseek`, `mistral`, `grok` |
| `disabledSites` | array of site ids | the guard only monitors on these sites (`custom` = every configured internal site) |
| `customSites` | array of `{ "id", "label", "hosts", "editorSelectors", "sendButtonSelectors", "responseSelectors" }` | company-internal AI portals to protect; up to 20 sites, 1-10 exact HTTPS hosts each (no port, path, wildcard, IP or built-in AI host), up to 20 CSS selectors per list. Each user allows access to the hosts once on the options page (**AI services** > **Allow access**); only then is the content script registered there |
| `shadowAi` | `{ "mode", "sanctioned", "blocked" }` | Shadow AI discovery and control: `mode` `off` (default), `monitor` (count visits per catalogued AI service and day) or `block-unsanctioned` (also block every catalogued service not in `sanctioned`); ids in `blocked` are blocked in every mode. Ids are the catalog ids in `src/sites/catalog.ts`. Counting and blocking need each user's one-time **Allow access** on the options page; until then the page reports access as missing |
| `allowUserPause` | boolean | users may pause protection for up to 60 minutes |
| `allowSendAnyway` | boolean | users may send unmasked after a warning |
| `maskPaste` | boolean | mask sensitive data as it is pasted |
| `fileHandling` | string | `scan`, `block`, `allow` |
| `documentHandling` | string | `mask` (default), `block`, `allow`: Office/PDF uploads when `fileHandling` is `scan`; optional, not set in the examples below |
| `maxFileBytes` | integer | at most 52428800 (50 MiB) |
| `restoreResponses` | boolean | restore original values in responses locally |
| `useNativeHost` | boolean | use the AIDR Privacy native host for NER (install it separately) |
| `telemetry` | `{ "controlPlaneUrl", "apiKey" }` | counts-only telemetry; `https://` required (plain `http://` only for `localhost`/`127.0.0.1`) |
| `language` | string | `auto`, `en`, `tr` |
| `policyId` | string | reported with telemetry; `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` |
| `allowUserOverrides` | boolean | default `false`; see below |

The Chrome/Edge schema is `static/managed_schema.json` in the extension.

**User settings under a managed policy.** Every key you set is locked. In
addition, as soon as *any* managed policy is present, the settings a user could
use to weaken protection - `mode`, `enabledEntities`, `literals`, `maskPaste`,
`restoreResponses` and `disabledSites` - are locked too: keys you leave out take
the built-in default (for example `auto` mode, every entity type except
`USERNAME`/`LOCATION`) and the extension rejects user changes to them
(`SET_USER_SETTINGS` answers `LOCKED_KEYS`; the options page shows them
read-only). A managed policy that fails validation still locks them. Set
`allowUserOverrides: true` to let users keep changing the protection keys you
do not set (a managed `mode` then still locks `disabledSites`). `language` and a
user's own `telemetry` target are never locked unless you set them.

## Chrome and Edge on Windows (Group Policy)

**Install.** Either import the Google Chrome / Microsoft Edge ADMX templates and
set *Extensions > Configure the list of force-installed apps and extensions*
(`ExtensionInstallForcelist`) to `<id>;<update URL>`, or set
*Extension management settings* (`ExtensionSettings`) to a JSON value such as:

```json
{ "<id>": { "installation_mode": "force_installed",
            "update_url": "https://clients2.google.com/service/update2/crx",
            "toolbar_pin": "force_pinned" } }
```

(Edge: update URL `https://edge.microsoft.com/extensionwebstorebase/v1/crx`,
`"toolbar_state": "force_shown"`.)

**Configure.** Extension policy is not in the ADMX templates. Write it under

```
HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<id>\policy
HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<id>\policy
```

with a GPO *Registry* preference item per value, or import
`windows-registry.example.reg`. Strings are `REG_SZ`, booleans and integers are
`REG_DWORD`, and arrays/objects (`enabledEntities`, `literals`, `exactData`,
`telemetry`...) are `REG_SZ` holding the JSON text. Browsers read the values at
start-up and on the policy refresh interval; check them at `chrome://policy` or
`edge://policy` under the extension's ID.

## Edge with Microsoft Intune

`edge-intune.example.json` describes a complete configuration:

1. **Install:** a *Settings catalog* profile with Microsoft Edge >
   Extensions > *Control which extensions are installed silently*
   (`ExtensionInstallForcelist`) and, optionally, *Configure extension
   management settings* (`ExtensionSettings`). The same file shows the
   equivalent custom OMA-URI for tenants that ingest the Edge ADMX.
2. **Configure:** Intune has no catalog entry for per-extension policy, so
   deploy the `managedConfiguration.values` under the listed registry key with
   a PowerShell platform script, a Remediation, or a Win32 app, for example:

   ```powershell
   $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<id>\policy'
   New-Item -Path $key -Force | Out-Null
   New-ItemProperty -Path $key -Name mode -PropertyType String -Value 'auto' -Force | Out-Null
   New-ItemProperty -Path $key -Name allowUserPause -PropertyType DWord -Value 0 -Force | Out-Null
   New-ItemProperty -Path $key -Name neverRestore -PropertyType String -Value '["SECRET","PRIVATE_KEY"]' -Force | Out-Null
   ```

Chrome under Intune works the same way with the Chrome ADMX/Settings catalog
entries and `HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\...`.

## Firefox

Copy `firefox-policies.example.json` to `policies.json` in the `distribution`
folder of the Firefox installation (Windows: `C:\Program Files\Mozilla
Firefox\distribution\`; macOS: `Firefox.app/Contents/Resources/distribution/`;
Linux: `/etc/firefox/policies/` or the install directory's `distribution/`).
On Windows you can use the Firefox ADMX templates instead; on macOS, the
`org.mozilla.firefox` preference domain with `EnterprisePoliciesEnabled`.

- `ExtensionSettings` force-installs the add-on from `install_url`.
- `3rdparty.Extensions["browser-guard@singularityrd.com"]` holds the managed
  values as plain JSON.

Check them at `about:policies`.

## macOS with Jamf Pro

Upload `macos-jamf.example.mobileconfig` as a configuration profile
(*Computers > Configuration Profiles > Upload*), or recreate its payloads in
*Application & Custom Settings*:

| Preference domain | Content |
|---|---|
| `com.google.Chrome` | `ExtensionInstallForcelist`, `ExtensionSettings` |
| `com.google.Chrome.extensions.<id>` | the managed values |
| `com.microsoft.Edge` | `ExtensionInstallForcelist` |
| `com.microsoft.Edge.extensions.<id>` | the managed values |

Arrays and dictionaries are native plist types here (no JSON strings). Scope
the profile to computers, not users. Replace the placeholder IDs in both the
payload types and the forcelist entries before uploading; the profile is not
signed, so Jamf will sign it on upload.

## Chrome on Linux

Copy `chrome-managed-policy.example.json` to
`/etc/opt/chrome/policies/managed/aidr-browser-guard.json` (Chromium:
`/etc/chromium/policies/managed/`). The top-level keys install the extension and
`3rdparty.extensions.<id>` holds the managed values.

## Exact data sets

```bash
node packages/browser-guard/scripts/fingerprint-dataset.mjs \
  --in customers.csv --header --columns full_name \
  --dataset-id crm-customers --type PERSON \
  --key-file crm.key.b64 --out crm-customers.json
```

Put the JSON object into the `exactData` array. Keep `crm.key.b64` (or let the
tool generate a key on first run and save `keyB64` from the output) so later
regenerations keep the same fingerprints. The dataset contains the HMAC key, so
anyone with the dataset can test guessed values against it: deliver it only
through managed policy and restrict who can read the policy files. The
normalisation and fingerprint algorithm are documented in
`packages/browser-guard/README.md`.

## Verifying a rollout

1. `chrome://policy` / `edge://policy` / `about:policies` shows the extension
   policy with status OK.
2. The extension popup shows the mode with a lock icon and "Managed by your
   organization".
3. On a supported AI site, type a test value such as an example email address
   (`jane.doe@example.com`) and send it: in `auto` mode the site receives
   `[EMAIL_1]`.
4. With telemetry configured, `privacy_scan` counts appear in the control plane
   within about a minute.
5. With `customSites` or `shadowAi` set, the options page has an **AI services**
   section. After **Allow access**, a custom site shows **Protected** (reload tabs
   that were already open) and Shadow AI shows "Access granted"; opening an
   unsanctioned catalogued service (in `block-unsanctioned` mode) shows the blocked
   page, and `shadow_ai_usage` counts reach the dashboard's **Shadow AI** panel.
