# Singularity AIDR Browser Guard

Browser Guard is a Manifest V3 extension for Chrome, Edge and Firefox. It checks
prompts, pastes and uploaded files for sensitive data before they reach AI chat
products. Detected values are replaced with reversible placeholders such as
`[EMAIL_1]` or `[TCKN_1]`, and the originals are restored locally, in your
browser only, when the placeholders appear in the answer.

Detection reuses the AIDR Privacy rule layer (`packages/privacy`): the same
validated detectors, including Turkish identifiers, run in the page with no
network access.

| | |
|---|---|
| Browsers | Chrome 120+, Edge 120+ (Chromium), Firefox 140+ (ESR) |
| Sites | ChatGPT (`chatgpt.com`, `chat.openai.com`), Gemini (`gemini.google.com`), Claude (`claude.ai`), Microsoft Copilot (`copilot.microsoft.com`), Perplexity (`www.perplexity.ai`, `perplexity.ai`), DeepSeek (`chat.deepseek.com`), Mistral Le Chat (`chat.mistral.ai`), Grok (`grok.com`) |
| Languages | English, Turkish |
| Data sent anywhere | Nothing by default. When an administrator connects a control plane, only counts per entity type are sent (see [Privacy](#privacy)). |

Module contracts are in [`src/types.ts`](src/types.ts). The telemetry wire format is fixed by
[`docs/contracts/privacy-telemetry.md`](../../docs/contracts/privacy-telemetry.md).
Admin deployment is covered in [`deploy/browser-guard/`](../../deploy/browser-guard/README.md), and the
administrator and end-user guide is [`docs/platform-guides/browser-guard.md`](../../docs/platform-guides/browser-guard.md).

## What it does

1. **Intercepts the send.** On a supported site the content script watches the
   prompt editor (textarea, ProseMirror, Quill or contenteditable) and the send
   button/Enter key. Before the site gets the text, the text is scanned.
2. **Detects.** Rule detectors with checksums (Luhn, IBAN mod-97, TC Kimlik No,
   and others), organisation literals, exact-data fingerprints and, when the
   optional native host is installed, NER for names and addresses. Risk signals
   such as prompt-injection phrasing are reported by code.
3. **Acts according to the mode.**

   | Mode | Behaviour |
   |---|---|
   | `auto` (default) | Replaces findings with placeholders and sends. |
   | `confirm` | Shows the findings and asks: send masked, edit, or (if allowed) send anyway. |
   | `block` | Stops the send while sensitive data is present. |
   | `monitor` | Sends the original text and only counts what it found. |

4. **Restores locally.** Placeholders in responses and in your own sent messages
   are replaced with the originals in the page. Types listed in `neverRestore`
   (by default `SECRET` and `PRIVATE_KEY`) stay masked. The mapping lives in
   memory (`chrome.storage.session`) and is never written to disk or sent over
   the network.
5. **Pastes and files.** Pasted text is masked as it is pasted (`maskPaste`).
   Uploaded text files (CSV, TXT, JSON and similar) are scanned and replaced with
   a sanitised copy, blocked, or allowed according to `fileHandling` and
   `maxFileBytes`.

If a scan cannot finish (input over the size limit, or the time budget runs out)
the result is marked incomplete and the guard does not report it as clean: the
send is handled as policy requires rather than silently passed through.

## Building

Requires Node.js 22.12+ and pnpm (repository root: `pnpm install`).

```bash
pnpm build:browser-guard            # development build (inline source maps)
pnpm package:browser-guard          # release build + store zips + SHA256SUMS

# or inside packages/browser-guard
pnpm build                          # node scripts/build.mjs
pnpm build:release                  # node scripts/build.mjs --release --zip
pnpm check                          # tsc --noEmit
pnpm test:e2e                       # build, then real-browser E2E (see e2e/README.md)
```

Output:

```
dist/chrome/                               unpacked Chrome/Edge extension
dist/firefox/                              unpacked Firefox extension
dist/aidr-browser-guard-chrome-<ver>.zip   upload to the Chrome Web Store / Edge Add-ons
dist/aidr-browser-guard-firefox-<ver>.zip  upload to addons.mozilla.org
dist/SHA256SUMS                            sha256sum -c compatible
```

`scripts/build.mjs` bundles four entry points with esbuild into classic IIFE
scripts (`background.js`, `content.js`, `popup.js`, `options.js`) targeting
`chrome120` and `firefox140`, copies `static/*.html`, `static/*.css`,
`static/managed_schema.json` (Chrome only), `static/icons/` and `_locales/`, and
writes a manifest per target. `--release` minifies and drops source maps. The
zips are deterministic: sorted entries, fixed timestamps and permissions, so the
same sources always give the same SHA-256.

The build fails, naming the file, when:

- an entry point, static page, icon or `_locales/en/messages.json` is missing;
- a locale lacks `extName`/`extDescription`, or they exceed the store limits;
- a bundle contains `eval`, `new Function`, string timers, `importScripts`,
  dynamic `import()` or `document.write`;
- a bundle or page references a remote origin other than the supported AI
  sites, loopback, or reserved example domains;
- an extension page has an inline script, inline style or event handler, or
  loads anything that is not a packaged file.

Options: `--root <dir>` (package root with `package.json`, `static/`,
`_locales/`), `--entries-root <dir>` (where `src/` entry points are resolved; used
by tests), `--out <dir>`.

The host list in the manifest is read at build time from `MATCH_PATTERNS` in
[`src/sites/index.ts`](src/sites/index.ts), so it cannot drift from the site
adapters.

### Loading an unpacked build

- **Chrome/Edge:** `chrome://extensions` (or `edge://extensions`), enable
  Developer mode, *Load unpacked*, select `dist/chrome`.
- **Firefox:** `about:debugging#/runtime/this-firefox`, *Load Temporary Add-on*,
  select `dist/firefox/manifest.json`.

### Icons

`static/icons/icon-{16,32,48,128}.png` are generated from the brand master
`images/aidr-icon.png` by a dependency-free PNG resampler:

```bash
node scripts/icons.mjs           # regenerate
node scripts/icons.mjs --check   # exit 1 if the committed icons are stale
```

## Manifest and permissions

| Key | Value | Why |
|---|---|---|
| `permissions` | `storage`, `alarms`, `declarativeNetRequestWithHostAccess` | settings and the in-memory vault; telemetry batching; blocking sites an admin lists in `blockedSites` |
| `host_permissions` | the ten HTTPS hosts above | content script injection on supported sites only |
| `optional_permissions` | `nativeMessaging` | requested only when the optional native NER host is turned on |
| `optional_host_permissions` | `https://*/*` | never requested at install; available for an admin-approved generic site |
| `content_scripts` | `run_at: document_start`, `all_frames: false` | intercept before the page's own handlers; top frame only |
| `web_accessible_resources` | `blocked.html` for `http(s)://*/*` | the page a site listed in `blockedSites` is redirected to; a redirect from a web page to an extension page only loads if the page is web accessible. It is static and cannot be framed. Its `ui.css` and `popup.js` are requested by the extension page itself and are deliberately not exposed to web origins (verified by the `blocked-site` E2E scenario) |
| `incognito` | `not_allowed` | the extension does not run in private windows |
| CSP (`extension_pages`) | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https: http://localhost:* http://127.0.0.1:*; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` | no remote code; `connect-src 'self'` so the options page can load the packaged `_locales` for the language override; `https:` because the control-plane URL is configurable per tenant; loopback HTTP for local development |

Chrome/Edge use a service worker (`background.service_worker`),
`options_page` and `storage.managed_schema`. Firefox uses an event page
(`background.scripts`), `options_ui`, and
`browser_specific_settings.gecko.id = browser-guard@singularityrd.com` with
`strict_min_version: 140.0` (Firefox for Android 142.0, the first releases
with `data_collection_permissions`). The version comes from `package.json`; a
pre-release suffix (`1.2.0-rc.1`) goes to Chrome's `version_name`.

## Configuration

User settings (options page) are stored in `chrome.storage.local`. Managed
policy (`chrome.storage.managed`) always wins, and managed keys are shown
read-only with "Managed by your organization".

| Managed key | Type | Default |
|---|---|---|
| `mode` | `auto` \| `confirm` \| `block` \| `monitor` | `auto` |
| `enabledEntities` | entity types | all except `USERNAME`, `LOCATION` |
| `neverRestore` | entity types | `SECRET`, `PRIVATE_KEY` |
| `literals` | `[{ value, type }]`, up to 1024, 2-256 chars each | none |
| `exactData` | up to 16 `ExactDataSet`s | none |
| `detectSignals` / `signalAction` | boolean / `off` \| `warn` \| `block` | `true` / `warn` |
| `blockedSites` / `disabledSites` | site ids | none |
| `allowUserPause` / `allowSendAnyway` | boolean | `true` / `true` |
| `maskPaste` | boolean | `true` |
| `fileHandling` / `maxFileBytes` | `scan` \| `block` \| `allow` / bytes (max 50 MiB) | `scan` / 5 MiB |
| `restoreResponses` | boolean | `true` |
| `useNativeHost` | boolean | `false` |
| `telemetry` | `{ controlPlaneUrl, apiKey }` | none (no telemetry) |
| `language` | `auto` \| `en` \| `tr` | `auto` |
| `policyId` | string reported with telemetry | `aidr-browser-guard-default` |

The authoritative schema is [`static/managed_schema.json`](static/managed_schema.json);
managed values are validated strictly in `src/background/policy.ts` before use.
Chrome compiles the schema's `pattern`s with RE2 when the extension loads and
refuses to load the whole extension if one does not compile (repetition counts,
nested ones multiplied, are capped at 1000; no lookaround or backreferences), so
the build rejects such a schema (`managedSchemaProblems` in `scripts/build.mjs`).

### Exact data match

`exactData` lets an organisation flag its own records (customer names, account
numbers, project code names) without shipping the values. Build a dataset from
a CSV:

```bash
node scripts/fingerprint-dataset.mjs --in customers.csv --header --columns full_name \
  --dataset-id crm-customers --type PERSON --key-file crm.key.b64 --out crm-customers.json
```

Algorithm (identical in the tool and in `src/engine/exact-data.ts`):

1. `value.normalize("NFKC").toLowerCase()`
2. remove U+200B-U+200F, U+2060, U+FEFF
3. fold Turkish `ı` (U+0131) and `i̇` (`i` + U+0307, what `İ` lowercases to) to `i`
4. tokens = every match of `/[\p{L}\p{N}]+/gu`; a value must give 1-16 tokens and at least 3 characters
5. fingerprint = lowercase hex `HMAC-SHA256(key, UTF-8(JSON.stringify(tokens)))`

In the page, the same normalisation is applied to the prompt and every window
of up to 16 consecutive tokens is fingerprinted with WebCrypto and compared with
the dataset. Only fingerprints and the HMAC key are in the dataset; the source
values are never written or logged. Anyone holding the dataset can test guesses
against it, so treat it as confidential and distribute it only through managed
policy. Without `--key-file`/`--key-b64` a fresh 32-byte key is generated; keep it
to regenerate the dataset with stable fingerprints.

## Privacy

- Detection, masking and restoring run entirely in the browser.
- The placeholder-to-value mapping is held in memory and cleared when the
  browser session ends; it is never sent anywhere.
- With no `telemetry` configured, the extension makes no network requests of
  its own.
- With `telemetry` configured (by an administrator, or by the user in the
  options page), the extension sends batched `privacy_scan` events to
  `{controlPlaneUrl}/functions/v1/ingest`: site id, action, channel, counts per
  entity type, total findings and `policyId`. Never prompt text, masked text,
  values, file names or URLs.
- The optional native host (`useNativeHost`) runs on the same machine and is
  reached through native messaging; see [`docs/native-host.md`](docs/native-host.md).

## Limitations

- Only the listed sites are protected out of the box. Other AI tools, desktop
  apps and API clients are not covered by this extension.
- Site adapters depend on each product's DOM. A site redesign can break
  interception until the adapter is updated; the real-browser suite in `e2e/`
  guards against regressions on recorded page structures.
- Free-form names and addresses without a label ("Name:", "Adres:") need the
  optional native host (NER). Without it, rule detection covers structured
  identifiers, labelled fields, organisation literals and exact-data sets.
- Images and PDFs are not OCR'd in the browser. Set `fileHandling: block` if
  such uploads must not reach AI sites at all.
- Restoring works on text the site renders in the page. Content the site
  exports, copies to the clipboard itself, or shares by link contains the
  placeholders, not the originals.
- A user with local administrator rights can remove a force-installed
  extension's policy or use another browser. Pair the extension with browser
  management (force-install, block other profiles/browsers) where that matters.

## Tests

```bash
AIDR_TEST_NO_BUILD=1 pnpm exec vitest run packages/browser-guard/src/__tests__
```

`build.test.ts` builds a stub package in a temporary directory and checks both
manifests, the CSP, permissions, locale copying, zips and `SHA256SUMS`,
reproducibility, and every fail-closed path. `build-tools.test.ts` covers the
fingerprint tool (against WebCrypto), the zip writer, the icons, and checks that
all deployment examples carry the same valid policy.
