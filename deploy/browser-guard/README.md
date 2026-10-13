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
| [`chrome-self-hosted-policy.example.json`](chrome-self-hosted-policy.example.json) | Self-hosted package, Chrome (and Edge) on Linux: installs and updates from your own `update.xml` |
| [`windows-self-hosted-registry.example.reg`](windows-self-hosted-registry.example.reg) | Self-hosted package, Chrome and Edge on Windows |

All seven files carry the **same** managed values and the same browser
hardening policies (see [Hardening the browser](#hardening-the-browser)); the
automated test `packages/browser-guard/src/__tests__/build-tools.test.ts` fails
if they drift apart, drop a hardening policy, or use a key the extension does not
accept. The store files use only the store IDs and update URLs, the self-hosted
files only `<SELF_HOSTED_EXTENSION_ID>` and your internal update URL.

## Before you start

1. **Put in the store IDs.** The examples install Browser Guard from the stores by
   store ID. Replace every placeholder (search for the angle brackets; in the
   `.mobileconfig` they are written `&lt;...&gt;`):
   - `<CHROME_WEB_STORE_ID>`: the 32-letter (`a`-`p`) ID of the Chrome Web Store
     listing, the last part of its URL. Update URL
     `https://clients2.google.com/service/update2/crx` (already in the examples).
   - `<EDGE_ADDONS_ID>`: the ID of the Microsoft Edge Add-ons listing (it differs
     from the Chrome Web Store ID). Update URL
     `https://edge.microsoft.com/extensionwebstorebase/v1/crx`. Edge can also
     force-install the Chrome Web Store item (`<CHROME_WEB_STORE_ID>` with the Google
     update URL); then put that ID in the Edge `3rdparty` policy key as well, because
     managed configuration is looked up by the installed extension's ID.
   - Firefox: the add-on ID is always `browser-guard@singularityrd.com` (the
     addons.mozilla.org ID). Replace `<FIREFOX_XPI_HOST>` in `install_url` with
     the HTTPS location of the Mozilla-signed XPI (unlisted, self-distributed), or
     use `https://addons.mozilla.org/firefox/downloads/latest/<AMO_SLUG>/latest.xpi`
     if the add-on is listed on addons.mozilla.org.
   - Self-hosted package instead of the stores (isolated networks, updates from your
     own server): use the `*-self-hosted-*` files. `<SELF_HOSTED_EXTENSION_ID>` is the
     ID of the Singularity-signed CRX (it differs from the store IDs; your contact
     gives it), and `<INTERNAL_HOST>` the HTTPS server that hosts the feed built by
     `packages/browser-guard/scripts/update-feed.mjs`. `"override_update_url": true`
     makes the browser take updates from that server. Chrome and Edge only install
     off-store extensions when they are force-installed by policy on managed
     machines. See ["Hosting Browser Guard updates internally"](../../docs/installation/browser-guard-enterprise.md#10-hosting-browser-guard-updates-internally).

   Step-by-step guides for Intune, the Google Admin console, Jamf, Group Policy and
   Firefox, with verification and rollback, are in
   [`docs/installation/browser-guard-enterprise.md`](../../docs/installation/browser-guard-enterprise.md).
2. **Replace the example values.** `policyId`, `literals`, the example
   `exactData` set (its `fingerprints` are a `REPLACE_WITH_...` placeholder and it
   carries no key: build the real dataset with `fingerprint-dataset.mjs`, see
   [Exact data sets](#exact-data-sets). The extension refuses a policy that still
   carries the placeholder and reports it in its policy warnings), `telemetry.controlPlaneUrl` and `telemetry.apiKey`. Remove
   `telemetry` entirely if you do not want counts sent to your control plane.
3. **Pilot first.** Roll out to a test group in `monitor` mode, check the
   popup statistics and control-plane counts, then switch to `auto` or
   `confirm`.
4. **Expect the "Block content on any page" permission warning.** The
   extension requests the `declarativeNetRequest` permission, which Chrome,
   Edge and Firefox describe as "Block content on any page" on the install
   and permission screens. It is used only to install `block` rules for the
   sites you list in `blockedSites` and the services Shadow AI control blocks
   (`shadowAi`); no redirect or header-modifying rule is ever installed. The
   extension deliberately does not use the quieter
   `declarativeNetRequestWithHostAccess` variant: under it a block applies
   only where the user has granted host access to both the blocked site and
   the page that started the navigation, so a user could escape your block by
   declining or revoking that access or by following a link from another
   site. With `declarativeNetRequest` your block never depends on the policed
   user's grant. Tell users about the warning before a user-installed rollout;
   force-installed copies are installed without a prompt.

## Managed keys

| Key | Type | Notes |
|---|---|---|
| `mode` | string | `auto`, `confirm`, `block`, `monitor` |
| `enabledEntities` | array of entity types | e.g. `EMAIL`, `PHONE`, `TC_KIMLIK`, `IBAN`, `CREDIT_CARD`, `SECRET`, `PRIVATE_KEY` |
| `neverRestore` | array of entity types | masked in prompts and kept masked in responses |
| `literals` | array of `{ "value", "type" }` | organisation terms; up to 1024, each 2-256 characters |
| `exactData` | array of `{ "datasetId", "keySource": "native-host", "minEntropyBits", "fingerprints", "type" }` | up to 16 datasets, 100 000 fingerprints in total; build with `fingerprint-dataset.mjs`; no key in policy (the native host derives it); `minEntropyBits` at least 64 |
| `detectSignals` | boolean | prompt-injection and source-code signals |
| `signalAction` | string | `off`, `warn`, `block` |
| `blockedSites` | array of site ids | the page is blocked from loading; `chatgpt`, `gemini`, `claude`, `copilot`, `perplexity`, `deepseek`, `mistral`, `grok` |
| `disabledSites` | array of site ids | the guard only monitors on these sites (`custom` = every configured internal site) |
| `customSites` | array of `{ "id", "label", "hosts", "editorSelectors", "sendButtonSelectors", "responseSelectors" }` | company-internal AI portals to protect; up to 20 sites, 1-10 exact HTTPS hosts each (no port, path, wildcard, IP or built-in AI host), up to 20 CSS selectors per list. Each user allows access to the hosts once on the options page (**AI services** > **Allow access**); only then is the content script registered there |
| `shadowAi` | `{ "mode", "sanctioned", "blocked" }` | Shadow AI discovery and control: `mode` `off` (default), `monitor` (count visits per catalogued AI service and day) or `block-unsanctioned` (also block every catalogued service not in `sanctioned`); ids in `blocked` are blocked in every mode. Ids are the catalog ids in `src/sites/catalog.ts`. Blocking applies without any user grant. Counting visits, and showing the Browser Guard blocked page instead of the browser's own, need each user's one-time **Allow access** on the options page; until then the page reports access as missing |
| `allowUserPause` | boolean | users may pause protection for up to 60 minutes. **`false` under any managed policy unless you set it to `true`** (the built-in `true` applies only to unmanaged installs). Sends during a pause are reported with `reason: "paused"` |
| `allowSendAnyway` | boolean | users may send the original (unmasked) text after a warning. **`false` under any managed policy unless you set it to `true`** |
| `maskPaste` | boolean | mask sensitive data as it is pasted |
| `fileHandling` | string | `scan`, `block`, `allow` |
| `documentHandling` | string | `mask` (default), `block`, `allow`: Office/PDF uploads when `fileHandling` is `scan`; optional, not set in the examples below |
| `maxFileBytes` | integer | at most 52428800 (50 MiB) |
| `restoreResponses` | boolean | restore original values in responses locally |
| `useNativeHost` | boolean | use the AIDR Privacy native host for NER (install it separately) |
| `requireNativeNer` | boolean | default `false` (as in the examples). `true` makes native NER mandatory: a send, paste or upload the native host could not check for names, addresses and places is **blocked**; forces and locks `useNativeHost`. Needs the native host on every machine. See [Requiring native NER](#requiring-native-ner) |
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
`allowUserPause` and `allowSendAnyway` are not user settings: under any managed
policy (and when the browser cannot read the managed policy at all) both are
`false` unless you set them, whatever `allowUserOverrides` says.

**Invalid values fail safe.** A managed value of the wrong type or with an unknown
entry (a typo in a site id, `"false"` as a `REG_SZ` where a `REG_DWORD` is
expected, `"Block"` instead of `"block"`) never falls back to the permissive
built-in default:

- a list keeps its valid entries and drops only the bad ones (`blockedSites`,
  `disabledSites`, `literals`, `exactData`, `customSites`, the `shadowAi` id lists);
  `enabledEntities` and `neverRestore` become every entity type;
- any other protection key takes its strictest value: `mode` `block`,
  `allowUserPause`/`allowSendAnyway` `false`, `requireNativeNer` `true`,
  `maskPaste`/`detectSignals` `true`, `restoreResponses` `false`, `fileHandling`
  and `documentHandling` `block`, `signalAction` `block`, `useNativeHost` `true`,
  an unknown `shadowAi.mode` `block-unsanctioned`;
- `telemetry`, `language`, `policyId`, `maxFileBytes`, `acceptableUse` and
  `dashboardPolicy` have no safe value to invent and keep the built-in one.

Each such key is locked and reported: the popup and the options page show "Your
organization's policy has N invalid setting(s)", and every `privacy_scan` event
carries `policy_errors: N`. Chrome and Edge also validate against the schema
themselves and drop a value that does not match before the extension sees it
(shown as an error at `chrome://policy` / `edge://policy`); the extension then
treats the key as unset, which under a managed policy is still the locked
built-in value (and `false` for pause and send-original).

## Requiring native NER

`requireNativeNer: true` turns the optional native host
([`packages/browser-guard/docs/native-host.md`](../../packages/browser-guard/docs/native-host.md))
into a requirement. While `PERSON`, `ADDRESS` or `LOCATION` is in `enabledEntities`:

- **What it blocks.** A prompt send, text paste or file upload whose text the host did
  not check with NER is blocked instead of going out after the built-in rules only:
  host not installed or `nativeMessaging` not granted, host crashed, backed off or
  slower than the 2.5 s page timeout, a rules-only host (no approved `ner` block in its
  config), a malformed reply, or text over the host's 200,000-character limit. A
  prompt with no findings is blocked too: "nothing found without NER" is not a clean
  check. `monitor` mode (and sites in `disabledSites`) never block; the check is
  recorded instead, and every `privacy_scan` event carries `native_ner: "used"` or
  `"unavailable"`.
- **It needs the native host.** It forces and locks `useNativeHost` on. Install the
  host (with an approved NER model) on every machine and make sure each user has
  granted the optional `nativeMessaging` permission *before* you set it, or every send
  on those machines is blocked. Roll it out in `monitor` mode first and check that the
  control plane shows `native_ner: "used"`, not `"unavailable"`.
- **Large uploads are slower.** Every text part of an uploaded file is NER-checked: a
  large document is scanned in several windows, each waiting for its own host answer
  (the host starts a process per scan, up to 2.5 s each), so big uploads can take
  noticeably longer than with rules only, and one failed window blocks the whole
  upload. Measure on your target hardware with your largest typical files.

The same requirement can be switched on from the dashboard (Browser Privacy Guard →
**Require native NER**, owners and administrators, multi-factor verification,
audited). It reaches browsers in the signed dashboard policy, so they also need
`telemetry` and the managed `dashboardPolicy` trust anchor (see "Allow / block from
the dashboard" in [`packages/browser-guard/README.md`](../../packages/browser-guard/README.md)).
Browser Guard takes the stricter value: the
dashboard can switch the requirement on, but never off where this managed key is
`true`. While four-eyes change control is on, switching it off in the dashboard is
refused until four-eyes is turned off (which a second owner or administrator must
approve).

## Hardening the browser

Browser Guard protects the browser profiles it runs in. Every example also sets
the browser policies that close the obvious ways around it. They affect the whole
browser, not only AI sites, so review each one before you roll it out:

| Policy | Value | Why | Trade-off |
|---|---|---|---|
| Chrome `IncognitoModeAvailability` | `1` (disabled) | the extension is `incognito: "not_allowed"`: a private window has no protection | users lose private windows |
| Edge `InPrivateModeAvailability` | `1` (disabled) | same for InPrivate | users lose InPrivate |
| Firefox `DisablePrivateBrowsing` | `true` | same for private windows | users lose private windows |
| Chrome/Edge `BrowserGuestModeEnabled` | `false` | a Guest profile runs without force-installed extensions | no Guest browsing |
| Chrome/Edge `DeveloperToolsAvailability` | `2` (blocked everywhere) | the page console can call the AI site's API directly, past the guard; DevTools on the extension can also change its local state | developers lose DevTools; for developer groups use `1` (blocked only on policy-installed extensions) and accept the console path |
| Firefox `DisableDeveloperTools` | `true` | same | same |
| Chrome/Edge `ExtensionInstallBlocklist` `["*"]` + `ExtensionInstallAllowlist` | the Browser Guard id | another extension can read the page or call the AI API with the user's session | add every extension your organization approves to the allowlist (force-installed ones are always allowed) |
| Firefox `ExtensionSettings["*"]` | `installation_mode: "blocked"` | same | list approved add-ons in `ExtensionSettings` as `allowed` or `force_installed` |

Two gaps are outside any browser policy: other browsers on the machine (block or
manage them with your endpoint tooling) and other operating-system user profiles.

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

- `ExtensionSettings` force-installs the add-on from `install_url` and blocks
  every other add-on (`"*": { "installation_mode": "blocked" }`).
- `DisablePrivateBrowsing` and `DisableDeveloperTools` close private windows and
  the page console (see [Hardening the browser](#hardening-the-browser)).
- `3rdparty.Extensions["browser-guard@singularityrd.com"]` holds the managed
  values as plain JSON.

Check them at `about:policies`.

## macOS with Jamf Pro

Upload `macos-jamf.example.mobileconfig` as a configuration profile
(*Computers > Configuration Profiles > Upload*), or recreate its payloads in
*Application & Custom Settings*:

| Preference domain | Content |
|---|---|
| `com.google.Chrome` | `ExtensionInstallForcelist`, `ExtensionSettings`, and the hardening keys `IncognitoModeAvailability`, `BrowserGuestModeEnabled`, `DeveloperToolsAvailability`, `ExtensionInstallBlocklist`, `ExtensionInstallAllowlist` |
| `com.google.Chrome.extensions.<id>` | the managed values |
| `com.microsoft.Edge` | `ExtensionInstallForcelist`, and the hardening keys `InPrivateModeAvailability`, `BrowserGuestModeEnabled`, `DeveloperToolsAvailability`, `ExtensionInstallBlocklist`, `ExtensionInstallAllowlist` |
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
node packages/browser-guard/scripts/fingerprint-dataset.mjs --new-secret edm-secret.b64
node packages/browser-guard/scripts/fingerprint-dataset.mjs \
  --in customers.csv --header --columns full_name,account_no --composite \
  --dataset-id crm-customers --type PERSON \
  --secret-file edm-secret.b64 --out crm-customers.json
```

Managed policy is readable by every user of the endpoint (`chrome://policy`, the
registry, `policies.json`), so a dataset carries no key. Install `edm-secret.b64` with
the AIDR Privacy native host (`"exactData": {"secretFile": ...}` in its config; see
`packages/browser-guard/docs/native-host.md`); the host derives each dataset's key from
it. Datasets need the native host: without it (or on Firefox) their scans are reported
incomplete. The tool refuses datasets whose values could be enumerated (below 64 bits
of estimated entropy, for example names or customer numbers on their own): combine
columns with `--composite`. Older datasets that carry `keyB64` are refused with a
warning; rebuild them.

Put the JSON object into the `exactData` array, replacing the example entry whose
fingerprints are `REPLACE_WITH_FINGERPRINTS_FROM_FINGERPRINT_DATASET`. While any
dataset still carries a `REPLACE_WITH_` placeholder, the extension ignores the
whole managed `exactData` value and warns
(`managed: "exactData" still holds the example placeholder key`). Earlier
versions of these examples shipped a real 32-byte example key; it was retired as
compromised (see `docs/production-readiness/secret-history-triage-2026-10-11.md`).
Keep `edm-secret.b64` outside the repository and restrict who can read it; the same
secret and dataset id reproduce the same fingerprints. The normalisation and
fingerprint algorithm are documented in `packages/browser-guard/README.md`.

## Verifying a rollout

1. `chrome://policy` / `edge://policy` / `about:policies` shows the extension
   policy with status OK.
2. The extension popup shows the mode with a lock icon and "Managed by your
   organization", and no "invalid setting(s)" policy error. AI tabs that were
   open when the extension was installed are protected without a reload (the
   extension injects into them); a tab it could not reach shows **Not
   protected — reload this tab**.
3. On a supported AI site, type a test value such as an example email address
   (`jane.doe@example.com`) and send it: in `auto` mode the site receives
   `[EMAIL_1]`.
4. With telemetry configured, `privacy_scan` counts appear in the control plane
   within about a minute.
5. With `customSites` or `shadowAi` set, the options page has an **AI services**
   section. After **Allow access**, a custom site shows **Protected** (tabs that
   were already open are injected at once) and Shadow AI shows "Access granted"; opening an
   unsanctioned catalogued service (in `block-unsanctioned` mode) shows the blocked
   page, and `shadow_ai_usage` counts reach the dashboard's **Shadow AI** panel.
