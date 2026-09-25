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
   optional native host is enabled (`useNativeHost`) and reachable, its NER
   findings for names, addresses and places, requested in parallel and merged
   before masking. If the host does not answer, the scan is rules-only and the
   in-page message says so ([`docs/native-host.md`](docs/native-host.md)). Risk
   signals such as prompt-injection phrasing are reported by code.
3. **Acts according to the mode.**

   | Mode | Behaviour |
   |---|---|
   | `auto` (default) | Replaces findings with placeholders and sends. |
   | `confirm` | Shows the findings and asks: send masked, edit, or (if allowed) send anyway. |
   | `block` | Stops the send while sensitive data is present. |
   | `monitor` | Sends the original text and only counts what it found. |

   A site in `disabledSites` (or any site while the user has paused protection)
   behaves as `monitor`: nothing is masked or held back, but sends, pastes and
   files are still scanned and recorded as `allowed` with their counts. Site blocks
   (`blockedSites`) and `fileHandling: "block"` still apply there.

4. **Restores locally.** Placeholders in responses and in your own sent messages
   are replaced with the originals in the page. Types listed in `neverRestore`
   (by default `SECRET` and `PRIVATE_KEY`) stay masked. The mapping lives in the
   content script's memory; a copy is kept by the background worker in
   `chrome.storage.session` (memory-backed, `TRUSTED_CONTEXTS` only) under the tab
   id and page origin, so a reload of the tab keeps restoring answers. The copy
   holds no `neverRestore` values and is deleted when the tab closes, after 4 hours
   without a save, or when the browser exits. Nothing is written to disk or
   `storage.local`, or sent over the network. The AI site must not be able to read
   a restored value back, so:
   - the value is shown from a closed shadow root as CSS generated content (not a
     text node, so `window.find()`, selection and `innerText` never see it), with
     every inherited style reset, generic system fonts only (page `@font-face`
     rules cannot load per-character fonts for it) and a fixed-width box ending in
     an ellipsis (its size does not reveal the value's length);
   - only placeholders that were in a prompt you actually sent from this tab (or in
     a masked file attached to it) are restored, and only in messages that appeared
     after that send; a page script that plants a placeholder elsewhere gets the
     placeholder back, not the value. The set of sent placeholders is persisted
     with the vault: after a reload, exactly those are restorable again (anywhere
     in the re-rendered conversation), and nothing else.
   The `restore-side-channels` E2E scenario attacks all of this from the page;
   `reload-restore` covers the reload, per-tab isolation and cleanup.
5. **Pastes and files.** Pasted text is masked as it is pasted (`maskPaste`).
   Uploaded text files (CSV, TXT, JSON and similar) are scanned and replaced with
   a sanitised copy, blocked, or allowed according to `fileHandling` and
   `maxFileBytes`. Text files that are not UTF-8 (Excel's default ANSI CSV) are
   decoded as windows-1254, or windows-1252 when that fits better, scanned, and a
   masked copy is written as UTF-8 (CSV/TSV with a BOM). A text-named file that
   contains NUL bytes cannot be decoded safely and is blocked
   (`TEXT_FILE_NOT_DECODABLE`) in every mode except `monitor`.
6. **Office documents and PDFs** (`documentHandling`, default `mask`). Everything
   runs in the content script: a small ZIP reader/writer on the browser's
   `DecompressionStream`/`CompressionStream`, a strict XML scanner and a PDF text
   extractor - no remote code, no WebAssembly, no new dependencies.
   - **DOCX / XLSX / PPTX** (and `docm`/`xlsm`/`pptm`, templates, shows) are opened,
     their text is masked in place and the package is re-zipped under the same
     name and type (`mask`, reason `SENSITIVE_DATA`). Word paragraphs are scanned
     as a whole, so an e-mail or TCKN split across differently formatted runs is
     found; the placeholder goes into the first run and the rest of the value is
     removed from the others, so only the runs that held it change. Covered: body,
     headers, footers, footnotes/endnotes, comments and their authors, tracked
     changes, field codes, text boxes, tables; Excel shared strings (rich text),
     inline strings, formula string results and numeric/date cells (a masked
     number becomes a text cell; a formula keeps its formula), comments, pivot
     cache strings, header/footer text, with sensitive column headers masking the
     whole column as for CSV; PowerPoint slides, notes, layouts, masters and
     comments; charts/diagrams/drawings, document properties and `mailto:` and
     other external hyperlink targets in every format. Other parts (styles, media,
     fonts...) are copied byte for byte.
   - Blocked with a reason (recorded only in `monitor` mode): macros or ActiveX
     (`DOCUMENT_MACROS`), password protection (`DOCUMENT_ENCRYPTED`), external
     workbook links, data connections, remote templates or linked objects
     (`DOCUMENT_EXTERNAL_LINKS`), embedded objects that are not themselves
     DOCX/XLSX/PPTX (`DOCUMENT_EMBEDDED_OBJECT`; embedded workbooks such as chart
     data are sanitised recursively), malformed XML or DOCTYPE declarations
     (`DOCUMENT_MALFORMED`) and unsafe archives (`ARCHIVE_*`: ZIP64, more than 4096
     entries, declared compression ratio over 200:1 for entries above 1 MiB, more
     than 48 MiB per entry or 64 MiB inflated in total, path traversal, duplicate or
     overlapping entries, CRC mismatch).
   - **PDF** text is extracted (object and cross-reference streams, Flate/LZW/
     ASCIIHex/ASCII85/RunLength, WinAnsi/MacRoman/Standard encodings with
     `/Differences`, ToUnicode CMaps for Identity-H fonts, Form XObjects,
     annotations, form fields, document info) and scanned. PDFs are not rewritten:
     one with findings is blocked (`SENSITIVE_DATA_IN_PDF`) and the user is told to
     paste the text instead, where it is masked; `monitor` records it. A PDF
     without extractable text (scanned), with image-only pages or undecodable
     parts (`PDF_NO_TEXT`, `PDF_PARTIAL`), encrypted (`PDF_ENCRYPTED`) or
     unparseable (`PDF_UNPARSEABLE`) is treated like other binaries: uploaded with
     an "unscanned" warning, blocked in `block` mode. Findings in the readable
     part still block.
   - `documentHandling: block` rejects every Office/PDF upload in every mode;
     `allow` skips document parsing (the previous behaviour: unscanned warning,
     blocked in `block` mode). A document whose scan exceeds 30 s is blocked
     (`SCAN_INCOMPLETE`).

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
| `optional_permissions` | `nativeMessaging` | requested on the options page (from the click that turns the native NER host on, or the **Grant permission** button when an administrator enabled it); never at install |
| `optional_host_permissions` | `https://*/*` | never requested at install; available for an admin-approved generic site |
| `content_scripts` | `run_at: document_start`, `all_frames: false` | intercept before the page's own handlers; top frame only |
| `web_accessible_resources` | none | nothing is exposed to web pages, so a page cannot fingerprint the extension by probing its resources. A site listed in `blockedSites` is refused by a declarativeNetRequest rule and the background worker then opens `blocked.html` in that tab itself (`tabs.update`, an extension-initiated navigation). A DNR redirect would need the page to be web accessible, and Chrome refuses DNR redirects to `use_dynamic_url` resources (verified by the `blocked-site` E2E scenario) |
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
read-only with "Managed by your organization". When any managed policy is
present, the settings a user could weaken protection with (`mode`,
`enabledEntities`, `literals`, `maskPaste`, `restoreResponses`,
`disabledSites`) are locked as well, at the managed or built-in value, unless
the policy sets `allowUserOverrides: true` (see `deploy/browser-guard/README.md`).

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
| `documentHandling` | `mask` \| `block` \| `allow` (managed only; Office/PDF when `fileHandling` is `scan`) | `mask` |
| `restoreResponses` | boolean | `true` |
| `useNativeHost` | boolean | `false` (also a user setting unless managed) |
| `telemetry` | `{ controlPlaneUrl, apiKey }` | none (no telemetry) |
| `language` | `auto` \| `en` \| `tr` | `auto` |
| `policyId` | string reported with telemetry | `aidr-browser-guard-default` |
| `allowUserOverrides` | boolean (managed only) | `false`: a managed policy locks the protection settings above |

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
- The placeholder-to-value mapping is held in memory (the page, plus a per-tab
  copy in `chrome.storage.session`) and cleared when the tab closes or the
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
  optional native host (NER), which ships without model weights or accuracy
  evidence. Without it, rule detection covers structured identifiers, labelled
  fields, organisation literals and exact-data sets. NER is applied to prompts
  and pastes, not to uploaded files.
- The restore mapping survives a reload of the same tab, but not a browser
  restart, another tab, or 4 hours without a save; if the worker does not answer
  within 1.5 s while the page loads, earlier placeholders stay placeholders.
- Images are not OCR'd in the browser: pictures inside Office documents, scanned
  PDFs and image-only PDF pages are not inspected (scanned PDFs are reported as
  unscanned, not as clean). Set `fileHandling: block` or
  `documentHandling: block` if such uploads must not reach AI sites at all.
- PDFs are scanned but never rewritten, so a PDF with findings is blocked rather
  than masked. PDF text extraction does not decrypt encrypted files, does not
  handle Type0 fonts without a ToUnicode map or predefined CJK CMaps, and uses
  glyph positions to rebuild word and line breaks, which can differ from the
  visual reading order in multi-column layouts.
- Office masking covers text; sheet names, defined names, table column names and
  numeric pivot-cache values are not rewritten (a masked header cell can make
  Excel repair a table's column name).
  Legacy binary formats (`.doc`, `.xls`, `.ppt`) and OpenDocument files are not
  parsed and follow the binary-file rule.
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
`files-office.test.ts`, `files-office-zip.test.ts` and `files-pdf.test.ts` build
DOCX/XLSX/PPTX packages and PDFs in memory (no binary fixtures), sanitise them with
the real detection engine and vault, and re-open the output to check that
placeholders are present and originals are gone; they also cover macro, encryption
and external-link refusals, zip-bomb, ZIP64 and path-traversal refusals, PDF font
encodings and filters, and time bounds. The `file-upload-docx` and
`file-upload-pdf-blocked` E2E scenarios upload a DOCX and a PDF on the ChatGPT
fixture in a real browser.
