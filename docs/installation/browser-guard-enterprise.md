# Deploying Browser Guard in an organisation

[Türkçe](browser-guard-enterprise.tr.md)

This guide installs Singularity AIDR Browser Guard on managed computers from the
browser stores, locks its settings, and shows how to check and roll back a rollout.
The policy files it refers to are in [`deploy/browser-guard/`](../../deploy/browser-guard/README.md);
the meaning of every managed setting is in the
["Managed keys"](../../deploy/browser-guard/README.md#managed-keys) table there.
For a single user's own install see [browser-guard.md](browser-guard.md).

## 1. What you deploy

| Browser | Source | Extension ID | Update URL |
|---|---|---|---|
| Google Chrome | Chrome Web Store (unlisted listing) | `<CHROME_WEB_STORE_ID>` | `https://clients2.google.com/service/update2/crx` |
| Microsoft Edge | Microsoft Edge Add-ons (unlisted listing) | `<EDGE_ADDONS_ID>` | `https://edge.microsoft.com/extensionwebstorebase/v1/crx` |
| Mozilla Firefox 140+ | Mozilla-signed XPI (addons.mozilla.org, unlisted, self-hosted) | `browser-guard@singularityrd.com` | the publisher's `updates.json` built into the XPI (see section 10) |
| Chrome and Edge, internal hosting | CRX signed by Singularity, served from your own HTTPS server | `<SELF_HOSTED_EXTENSION_ID>` (differs from the store IDs) | `https://<INTERNAL_HOST>/browser-guard/update.xml` |

The last row is for networks that cannot reach the stores, or that want every update to
come from their own server: see
[section 10, "Hosting Browser Guard updates internally"](#10-hosting-browser-guard-updates-internally).

`<CHROME_WEB_STORE_ID>` and `<EDGE_ADDONS_ID>` are the IDs of the published store
listings (32 letters `a`-`p`; the last part of the listing URL). Your Singularity
contact or the listing link gives them. Every example file uses exactly these
placeholders: replace them before deploying. An unreplaced placeholder is not a
valid extension ID, so the browser installs nothing (it fails safe, not open).

An unlisted listing is not shown in store search; it installs from its link or by
policy, and policy installation works exactly as for a public listing.

Two parts are deployed everywhere:

1. **Install policy**: force-install the extension and pin it to the toolbar
   (`ExtensionInstallForcelist` / `ExtensionSettings`, Firefox `ExtensionSettings`).
2. **Managed configuration**: the Browser Guard settings, read by the extension
   through `chrome.storage.managed` (the `3rdparty` policy branch). Keys you set are
   locked for the user. The schema is `static/managed_schema.json` in the extension.

Every example also carries the recommended browser hardening (no private/InPrivate
windows, no Guest profile, no developer tools, no other extensions). Read
["Hardening the browser"](../../deploy/browser-guard/README.md#hardening-the-browser)
before rolling those out: they affect the whole browser.

## 2. Before you start

1. Replace the store IDs as above, and the example values (`policyId`, `literals`,
   the `exactData` placeholder, `telemetry.controlPlaneUrl`, `telemetry.apiKey`).
   Remove `telemetry` if you do not report to an AIDR control plane.
2. Pilot with a small group in `"mode": "monitor"`: nothing is masked or blocked,
   but every check is counted, so you can see what would happen.
3. Tell users that Chrome, Edge and Firefox describe the `declarativeNetRequest`
   permission as "Block content on any page". It is used only for the AI sites you
   block. Force-installed copies install without a prompt.

## 3. Microsoft Intune (Windows)

**Edge.** Use [`edge-intune.example.json`](../../deploy/browser-guard/edge-intune.example.json):

1. **Devices > Configuration > Create > New policy**, platform *Windows 10 and later*,
   profile type *Settings catalog*.
2. Add **Microsoft Edge > Extensions > Control which extensions are installed
   silently** with the value `<EDGE_ADDONS_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx`,
   and optionally **Configure extension management settings** with the
   `ExtensionSettings` JSON from the example (pins the toolbar button).
3. Add the hardening settings listed in `settingsCatalog` of the example, then
   assign the profile to a device group (pilot group first).
4. Managed configuration: Intune has no catalog entry for per-extension policy.
   Deploy the registry values of `managedConfiguration` with a **Devices > Scripts
   and remediations > Platform scripts** PowerShell script (run as system, 64-bit):

   ```powershell
   $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<EDGE_ADDONS_ID>\policy'
   New-Item -Path $key -Force | Out-Null
   New-ItemProperty -Path $key -Name mode -PropertyType String -Value 'auto' -Force | Out-Null
   New-ItemProperty -Path $key -Name allowUserPause -PropertyType DWord -Value 0 -Force | Out-Null
   New-ItemProperty -Path $key -Name neverRestore -PropertyType String -Value '["SECRET","PRIVATE_KEY"]' -Force | Out-Null
   # ...one line per value in managedConfiguration.values (strings REG_SZ, booleans/integers DWord,
   # lists and objects as JSON text in REG_SZ)
   ```

   Alternatively import [`windows-registry.example.reg`](../../deploy/browser-guard/windows-registry.example.reg)
   (Chrome and Edge) from a Win32 app with `reg import`.

**Chrome.** The same, with the Google Chrome entries of the Settings catalog
(**Google > Google Chrome > Extensions**) or the Chrome ADMX ingested as a custom
profile, the ID `<CHROME_WEB_STORE_ID>` with the Google update URL, and the
registry key `HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<CHROME_WEB_STORE_ID>\policy`.

## 4. Google Admin console (Chrome Enterprise Core)

For browsers enrolled in Chrome Enterprise Core (formerly Chrome Browser Cloud
Management) or signed in with managed Google accounts:

1. **Devices > Chrome > Apps & extensions > Users & browsers**, select the
   organisational unit (pilot OU first).
2. **+ > Add Chrome app or extension by ID**, enter `<CHROME_WEB_STORE_ID>`, source
   *From the Chrome Web Store*.
3. Set **Installation policy** to *Force install + pin to browser toolbar*.
4. **Policy for extensions**: paste the managed configuration as JSON. The console
   expects each value wrapped as `{"Value": ...}`. Convert the reference copy with:

   ```bash
   node -e 'const p=require("./deploy/browser-guard/chrome-managed-policy.example.json")["3rdparty"].extensions["<CHROME_WEB_STORE_ID>"];console.log(JSON.stringify(Object.fromEntries(Object.entries(p).map(([k,v])=>[k,{Value:v}])),null,2))'
   ```

5. Hardening under **Devices > Chrome > Settings > Users & browsers**: *Incognito
   mode* disallowed, *Browser guest mode* disabled, *Developer tools* never allowed,
   and under **Apps & extensions > Additional settings** block all other extensions
   (allowlist only what you approve).
6. **Save**. Browsers pick the change up at their next policy refresh (or
   `chrome://policy` > *Reload policies*).

## 5. Jamf Pro (macOS)

1. Open [`macos-jamf.example.mobileconfig`](../../deploy/browser-guard/macos-jamf.example.mobileconfig)
   in a text editor. Replace `&lt;CHROME_WEB_STORE_ID&gt;` and `&lt;EDGE_ADDONS_ID&gt;`
   (XML-escaped placeholders) with the store IDs, in the payload types and in the
   forcelist entries, and the example values.
2. **Computers > Configuration Profiles > Upload**, select the file. Jamf signs the
   profile on upload.
3. Scope it to computers (not users), pilot group first.
4. The profile has four payloads: `com.google.Chrome` and `com.microsoft.Edge` (install
   and hardening) and `com.google.Chrome.extensions.<id>` /
   `com.microsoft.Edge.extensions.<id>` (managed configuration, native plist types).

Firefox on macOS: use the `org.mozilla.firefox` preference domain with
`EnterprisePoliciesEnabled` and the same content as `policies.json` (section 7), or
place `policies.json` in `Firefox.app/Contents/Resources/distribution/`.

## 6. Group Policy (Windows, Active Directory)

1. Import the Google Chrome and Microsoft Edge ADMX templates into the Central Store.
2. In a GPO linked to the computers' OU: **Computer Configuration > Policies >
   Administrative Templates > Google > Google Chrome > Extensions > Configure the list
   of force-installed apps and extensions**: add
   `<CHROME_WEB_STORE_ID>;https://clients2.google.com/service/update2/crx`. Edge:
   **Microsoft Edge > Extensions > Control which extensions are installed silently**:
   `<EDGE_ADDONS_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx`.
3. Set the hardening policies (*Incognito mode availability*, *InPrivate mode
   availability*, *Enable guest mode*, *Control where developer tools can be used*,
   the extension block/allow lists).
4. Managed configuration is not in the ADMX templates: add **Computer Configuration >
   Preferences > Windows Settings > Registry** items under
   `HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<CHROME_WEB_STORE_ID>\policy`
   and `HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<EDGE_ADDONS_ID>\policy`
   (types as in `windows-registry.example.reg`), or run `reg import` of that file from
   a startup script.
5. `gpupdate /force` on a pilot machine, then check section 8.

## 7. Firefox (`policies.json`, Windows, macOS and Linux)

1. Get the Mozilla-signed XPI of the release (signed as an unlisted add-on on
   addons.mozilla.org; the publisher downloads it from the AMO Developer Hub after
   signing, your Singularity contact provides it) and host it on an HTTPS server your
   computers can reach. Firefox refuses unsigned add-ons.
2. Edit [`firefox-policies.example.json`](../../deploy/browser-guard/firefox-policies.example.json):
   set `install_url` to that file (replace `<FIREFOX_XPI_HOST>`), and the example
   values in `3rdparty.Extensions["browser-guard@singularityrd.com"]`.
3. Save it as `policies.json` in the `distribution` folder of the Firefox installation
   (Windows `C:\Program Files\Mozilla Firefox\distribution\`; macOS
   `Firefox.app/Contents/Resources/distribution/`; Linux `/etc/firefox/policies/`), or
   use the Firefox ADMX templates (Windows) or the `org.mozilla.firefox` domain (macOS).

**Updates.** The self-distributed XPI carries the address of the publisher's update
manifest (`updates.json`), and Mozilla's signature covers it. Firefox checks that
address on its regular add-on update check and installs a newer signed version by
itself; your computers only need HTTPS access to that host. If they cannot reach it
(an isolated network), Firefox does not update the add-on by itself: roll out a new
version by publishing the new signed XPI under a new file name and changing
`install_url`; Firefox installs from the new URL when it next reads the policy. Check
this on a pilot machine (`about:addons` shows the version) before widening. See
[section 10](#10-hosting-browser-guard-updates-internally).

## 8. Verifying the deployment

On a pilot computer, after the browser restarted or reloaded its policies:

1. `chrome://policy`, `edge://policy` or `about:policies`: `ExtensionInstallForcelist`
   (Firefox: `ExtensionSettings`) is listed with status OK, and the extension's own
   policy appears under its ID without errors.
2. `chrome://extensions` / `edge://extensions` / `about:addons`: Browser Guard is
   installed, enabled and marked as installed by your organisation (it cannot be
   removed by the user).
3. The toolbar popup shows the mode with a lock and "Managed by your organization",
   and no "invalid setting(s)" warning. A policy error count there means a value did
   not validate; it then runs at its strictest value (see
   ["Invalid values fail safe"](../../deploy/browser-guard/README.md#managed-keys)).
4. On a supported AI site, type a test address such as `jane.doe@example.com` and
   send: in `auto` mode the site receives `[EMAIL_1_xxxx]`.
5. With telemetry: `privacy_scan` counts appear in the AIDR dashboard within about a
   minute.

From a command line: Windows `reg query "HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"`;
macOS `sudo profiles show -type configuration | grep -i browser-guard`; Linux
`cat /etc/opt/chrome/policies/managed/*.json`.

## 9. Pinning, staged rollout and rollback

- **The stores serve only the latest published version.** Chrome and Edge update a
  store-installed extension automatically and cannot be held at an older store
  version by policy. Stage changes with your own rings instead: assign the install
  policy to a pilot group first, then widen it.
- **Configuration rollback** is immediate: change or remove the managed values and
  let the browsers refresh their policy. Under any managed policy, settings you remove
  fall back to the locked built-in values, not to the user's.
- **Extension rollback** is done by the publisher: the previous code is published
  again under a new, higher version number (the stores reject a lower one). Each
  release is reproducible from its signed tag (see the release workflow).
- **Emergency stop:** remove the ID from the force-install policy (the browser
  uninstalls it) or add it to `ExtensionInstallBlocklist`. Note that this removes the
  protection too.
- **Pinning an exact version** is possible only with self-hosting: the self-hosted
  Chrome/Edge package served from your own `update.xml`, which you advance only when
  you choose (section 10; a different extension ID, so the managed configuration moves
  to that ID), or a specific signed Firefox XPI at a fixed `install_url`.

## 10. Hosting Browser Guard updates internally

Store installs update themselves from the Chrome Web Store and Edge Add-ons. When your
computers cannot reach the stores (an isolated network, a proxy that blocks them), or
you want every update to come from your own server, use the self-hosted package
instead. The browser then checks your server on its regular extension update check and
installs a newer version by itself, with no action from the user.

**What you receive for each release** (from your Singularity contact or the GitHub
release, with `SHA256SUMS` and a build-provenance attestation):

| File | What it is |
|---|---|
| `aidr-browser-guard-<version>.crx` | Chrome and Edge package, signed by Singularity (CRX3) |
| `aidr-browser-guard-firefox-selfhosted-<version>.zip` | the Firefox build Mozilla signs; the signed XPI comes from your contact |

**The self-hosted extension ID.** The self-hosted package has its own extension ID,
`<SELF_HOSTED_EXTENSION_ID>`, which differs from the store IDs. It is fixed by
Singularity's signing key, so it is the same for Chrome and Edge and stays the same for
every release; your contact gives it to you. Pin it: every policy below uses it, and
the feed tool refuses a package signed for any other ID. Moving from a store install
to the self-hosted package is a new extension for the browser: move the managed
configuration to the new ID and remove the store ID from the force-install list.

### Chrome and Edge

1. **Check the download.** `sha256sum --check --ignore-missing SHA256SUMS`, and with
   the GitHub CLI `gh attestation verify aidr-browser-guard-<version>.crx --repo SingularityRD/aidr`.
2. **Build the update feed for your server.** With the Browser Guard sources (or the
   `packages/browser-guard/scripts` folder):

   ```bash
   node packages/browser-guard/scripts/update-feed.mjs \
     --base-url https://<INTERNAL_HOST>/browser-guard \
     --out browser-guard-feed \
     --chrome-crx aidr-browser-guard-<version>.crx \
     --extension-id <SELF_HOSTED_EXTENSION_ID> \
     --previous <the feed you host now>   # leave out the first time
   ```

   It needs no key. It checks the CRX signature and that the package is for the pinned
   ID, refuses a version that is not higher than the one you host (a feed never goes
   backwards), keeps the older packages, and writes `update.xml`, `packages/` and
   `SHA256SUMS`. It writes nothing unless every check passes.

   Without the tool, `update.xml` is four values (the CRX's SHA-256 from
   `sha256sum`):

   ```xml
   <?xml version='1.0' encoding='UTF-8'?>
   <gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
     <app appid='<SELF_HOSTED_EXTENSION_ID>'>
       <updatecheck codebase='https://<INTERNAL_HOST>/browser-guard/packages/aidr-browser-guard-<version>.crx' version='<version>' hash_sha256='<sha256 of the crx>' />
     </app>
   </gupdate>
   ```

3. **Upload the folder** to `https://<INTERNAL_HOST>/browser-guard/` on any static
   HTTPS server whose certificate your computers trust. Serve `.crx` as
   `application/x-chrome-extension` and `update.xml` as `text/xml`. Upload the
   packages first and `update.xml` last, so a browser never sees a manifest for a
   package that is not there yet.
4. **Set the policy.** Use
   [`chrome-self-hosted-policy.example.json`](../../deploy/browser-guard/chrome-self-hosted-policy.example.json)
   (Chrome on Linux; Edge on Linux reads the same file from `/etc/opt/edge/policies/managed/`)
   or [`windows-self-hosted-registry.example.reg`](../../deploy/browser-guard/windows-self-hosted-registry.example.reg)
   (Chrome and Edge on Windows; with Intune or Group Policy set the same
   `ExtensionInstallForcelist` and `ExtensionSettings` values). Replace
   `<SELF_HOSTED_EXTENSION_ID>`, `<INTERNAL_HOST>` and the example values. Keep
   `"override_update_url": true`: the package names the publisher's update address, and
   this setting makes the browser ask your server instead. Chrome and Edge install a
   package from outside the stores only when it is force-installed by policy like this.
5. **Verify** as in section 8; `chrome://policy` shows `ExtensionSettings` with your
   `update_url`.

**Each release:** run step 2 with `--previous` pointing at the feed you host, then
upload. Browsers pick the new version up on their next update check.
**Pinning and rollback:** browsers install what `update.xml` names, so to hold a
version, do not publish the newer one. A browser never installs a lower version over a
higher one: to roll back, Singularity publishes the previous code under a higher
version number, which you add like any release.

### Firefox

Firefox has no policy that changes an add-on's update address, and Mozilla's signature
covers the address built into the XPI. The self-distributed XPI therefore updates from
the publisher's `updates.json` (the address is in its `manifest.json`,
`browser_specific_settings.gecko.update_url`): allow HTTPS access to that host and
Firefox updates the add-on by itself, each package checked against the `update_hash`
in `updates.json` and against Mozilla's signature. On a network without that access,
update by changing `install_url` as described in section 7.
