# Singularity AIDR Browser Guard

Browser Guard is a Manifest V3 extension for Chrome, Edge and Firefox. It checks
prompts, pastes and uploaded files for sensitive data before they reach AI chat
products. Detected values are replaced with reversible placeholders such as
`[EMAIL_1_k3f9]` or `[TCKN_1_k3f9]` (type, number, per-page random tag), and the originals are restored locally, in your
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
     in the re-rendered conversation), and nothing else;
   - placeholders carry a random tag per page life (`[EMAIL_1_k3f9]`). Numbering
     restarts in every tab and after every reload, so without the tag a placeholder
     from another conversation or tab that is rendered after a send (for example
     after an in-app navigation) could be restored with this tab's value. A foreign
     placeholder now matches only if its tag collides (one in 36^4). Untagged
     placeholders from a vault saved by an earlier version are still restored.
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
6. **Office documents, OpenDocument and PDFs** (`documentHandling`, default `mask`). Everything
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
   - **ODT / ODS / ODP / ODG** (and templates) go through the same ZIP reader/writer,
     XML scanner and limits and are masked in place the same way: paragraphs are
     scanned over their spans, links and fields; notes, annotations and text boxes;
     headers/footers (`styles.xml`), document metadata, hyperlink targets, and cell
     values and formulas. Tables use their first row as column headers (a sensitive
     header masks the column); a cell is masked as a unit, and a masked numeric/date
     cell becomes a text cell. Embedded objects (`Object 1/`) are masked in place.
     Refused as for OOXML: encryption, Basic/script libraries and script event
     listeners, DDE and linked sections/sheets/objects, plugins/applets/frames, OLE
     objects and other binary entries such as embedded media.
   - **Legacy `.doc` / `.xls` / `.ppt`** (and `.dot`/`.xlt`/`.xla`/`.pps`/`.pot`/`.ppa`;
     OLE compound files, also recognised by content or MIME type) are read by a
     bounded, dependency-free compound-file reader (`src/engine/legacy/`) and their
     text is scanned, but never rewritten: Word text from the piece table
     (8-bit and UTF-16 pieces: body, headers/footers, footnotes, comments, text
     boxes, field codes); Excel BIFF8 shared strings, string/number/formula cells
     (first row as column headers, as for XLSX), sheet names, headers/footers,
     comments and their authors, hyperlink targets and external-workbook paths;
     PowerPoint text atoms and strings (slides, notes, masters, comments,
     hyperlinks); document properties; and embedded Word/Excel/PowerPoint objects
     (Word `ObjectPool`, Excel `MBD...` storages, PowerPoint `ExOleObjStg`, zlib
     included), up to 3 levels. A file with findings is blocked
     (`SENSITIVE_DATA_IN_LEGACY_OFFICE`) and the user is told to save it as
     .docx/.xlsx/.pptx, which AIDR masks; `monitor` records it. A completely read,
     clean file is allowed (pictures add `DOCUMENT_IMAGES_NOT_INSPECTED`). A file
     that may not have been read completely - Word 6/95 or Excel 5/95
     (`LEGACY_OFFICE_UNSUPPORTED`), a record or piece table that does not fit,
     pivot caches, the 8M-character budget (`LEGACY_OFFICE_PARTIAL`), or one that
     is not a compound file at all (`DOCUMENT_UNPARSEABLE`, e.g. RTF saved as
     `.doc`) - is treated like other binaries with `LEGACY_OFFICE_FORMAT`:
     uploaded with a "could not be fully checked, save as .docx/.xlsx/.pptx"
     warning, blocked in `block` mode; findings in the readable part still block.
     Refused like OOXML (recorded only in `monitor` mode): password protection
     (`DOCUMENT_ENCRYPTED`), VBA projects and Excel 4.0 macro sheets
     (`DOCUMENT_MACROS`), embedded objects that are not Word/Excel/PowerPoint
     (`DOCUMENT_EMBEDDED_OBJECT`), a corrupt or adversarial container (cyclic
     FAT/DIFAT/directory, sectors outside the file, truncation:
     `DOCUMENT_MALFORMED`) and one over the reader's limits (64 MiB file, 48 MiB
     stream, 16,384 directory entries: `DOCUMENT_LIMIT_EXCEEDED`). An OOXML
     package saved under a legacy name is masked as OOXML. `documentHandling:
     block` rejects legacy files with the other documents.
   - **Pictures inside Office/OpenDocument files.** A document's first-page
     thumbnail (`docProps/thumbnail.*`, `Thumbnails/thumbnail.png`) shows the text
     before masking, so a rewritten package gets a blank PNG/JPEG thumbnail. With
     the native host's OCR (below) PNG/JPEG/WebP pictures are inspected: sensitive
     text blocks the upload (`SENSITIVE_DATA_IN_IMAGE`); otherwise, and for formats
     OCR cannot read (EMF/WMF/GIF/SVG...), more than 16 pictures or a 90 s OCR
     budget, the decision carries `DOCUMENT_IMAGES_NOT_INSPECTED` and the user is
     warned that the pictures were not inspected.
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
   - **Screenshots and photos** (PNG/JPEG/WebP): with `useNativeHost` and a host
     configured with OCR, the image is sent to the local host (`image-scan`, counts
     only; the host never returns pixels or text) and blocked when its text holds
     sensitive data (`SENSITIVE_DATA_IN_IMAGE`; pixels are not masked). A clean OCR
     result lets it through. Without the host, without OCR on it, or when OCR could
     not read the image fully (no text, uncertain words, barcodes, limits), the
     image is reported as not inspected (`IMAGE_NOT_INSPECTED`): uploaded with a
     warning, blocked in `block` mode, never treated as clean.
   - `documentHandling: block` rejects every Office/OpenDocument/PDF upload in every mode;
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
| `permissions` | `storage`, `alarms`, `declarativeNetRequest`, `scripting` | settings and the in-memory vault; telemetry batching; blocking sites an admin lists in `blockedSites` or blocks with `shadowAi` (block rules only; `declarativeNetRequest` applies them without host permissions, so an administrator's block never depends on the user's host-access grant; install warning "Block content on any page"); registering the content script for administrator-configured `customSites` (no install warning, and no access by itself: injection still needs host access to the page) |
| `host_permissions` | the ten HTTPS hosts above | content script injection on supported sites only |
| `optional_permissions` | `nativeMessaging` | requested on the options page (from the click that turns the native NER host on, or the **Grant permission** button when an administrator enabled it); never at install |
| `optional_host_permissions` | `https://*/*` | never requested at install. The options page requests exact `https://<host>/*` origins, from a click, only for what the managed policy configures: the hosts of `customSites`, and the Shadow AI catalog origins when `shadowAi` is on (or the origins of explicitly blocked services). No `tabs`, `webNavigation`, `history` or `<all_urls>` permission is requested: the extension sees a tab's URL only on origins it was granted |
| `content_scripts` | `content.js` and `content-main.js` (`world: "MAIN"`), both `run_at: document_start`, `all_frames: false` | intercept before the page's own handlers; top frame only. `content-main.js` runs in the page's JavaScript world with no extension APIs and no data: it only hooks `<input type=file>` (`click`, `showPicker`, the `files` getter) so detached and shadow-DOM file inputs are handed to `content.js` for checking (see [Limitations](#limitations)). Custom sites get both scripts |
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
| `customSites` | up to 20 `{ id, label, hosts, editorSelectors, sendButtonSelectors, responseSelectors }` (managed only) | none |
| `shadowAi` | `{ mode: off \| monitor \| block-unsanctioned, sanctioned: [ids], blocked: [ids] }` (managed only) | `off` |
| `allowUserPause` / `allowSendAnyway` | boolean | `true` / `true` |
| `maskPaste` | boolean | `true` |
| `fileHandling` / `maxFileBytes` | `scan` \| `block` \| `allow` / bytes (max 50 MiB) | `scan` / 5 MiB |
| `documentHandling` | `mask` \| `block` \| `allow` (managed only; Office/OpenDocument/legacy Office/PDF when `fileHandling` is `scan`) | `mask` |
| `restoreResponses` | boolean | `true` |
| `useNativeHost` | boolean | `false` (also a user setting unless managed) |
| `telemetry` | `{ controlPlaneUrl, apiKey }` | none (no telemetry) |
| `language` | `auto` \| `en` \| `tr` | `auto` |
| `policyId` | string reported with telemetry | `aidr-browser-guard-default` |
| `dashboardPolicy` | `{ publicKeysPem: [1-4 Ed25519 SPKI PEM], tenantId? }` (managed only) | none: dashboard Shadow AI decisions are not applied |
| `allowUserOverrides` | boolean (managed only) | `false`: a managed policy locks the protection settings above |

The authoritative schema is [`static/managed_schema.json`](static/managed_schema.json);
managed values are validated strictly in `src/background/policy.ts` before use.
Chrome compiles the schema's `pattern`s with RE2 when the extension loads and
refuses to load the whole extension if one does not compile (repetition counts,
nested ones multiplied, are capped at 1000; no lookaround or backreferences), so
the build rejects such a schema (`managedSchemaProblems` in `scripts/build.mjs`).

### Custom internal AI sites

`customSites` extends masking to company-internal LLM portals. Each entry has a
stable `id` (`^[a-z0-9][a-z0-9-]{0,31}$`), a `label`, 1-10 exact HTTPS `hosts`
(bare hostname or `https://host`; no port, path, wildcard, IP address or built-in
AI host) and up to 20 CSS selectors each for the prompt editor, the send button
and the assistant responses (no `{ } ; <`, 256 characters max; selectors the page's
parser rejects are dropped in the page). Generic fallbacks (`textarea`,
`[contenteditable]`, `button[type=submit]`, ...) are always appended. An invalid
entry rejects the whole key (a policy warning, the rest of the policy applies).

A managed policy cannot grant host access, and browsers only show the permission
prompt from a user gesture, so each user clicks **Allow access** once on the options
page (**AI services** section). The worker then registers the same `content.js` for
exactly the granted hosts (`chrome.scripting.registerContentScripts`, id
`aidr-custom-sites`, top frame, `document_start`), re-syncs on every policy change
and grant/revocation, and accepts messages from those hosts as site `custom`.
Tabs that were already open need a reload. Until access is granted the options page
shows the site as **Needs access** and nothing runs there.

### Shadow AI discovery and control

`shadowAi` covers the ~75 generative-AI services in
[`src/sites/catalog.ts`](src/sites/catalog.ts) (chat, coding, image/video/voice,
meeting, writing, search, agent), identified by stable catalog ids.

| Mode | Behaviour |
|---|---|
| `off` (default) | nothing is counted; ids in `blocked` are still blocked |
| `monitor` | a visit (a tab entering a service) is counted per service and UTC day |
| `block-unsanctioned` | counted, and every catalogued service not in `sanctioned` is blocked |

A service in both `sanctioned` and `blocked` is blocked. Blocking uses one
declarativeNetRequest rule per service (`main_frame` + `sub_frame`, ids 7401+). The
block needs no host access (`declarativeNetRequest` applies block rules everywhere), so
it holds whether or not the user granted anything; with access to the service's origin
the worker also shows `blocked.html?service=<id>` in the tab, without it the user sees
the browser's own blocked page. Visibility uses `tabs.onUpdated`, which reports a URL
only for origins the extension holds host access to, so the options page asks each user
once to allow access to the catalog origins; until then the page (and the
`missingOrigins` list of `GET_SITE_ACCESS`) says visits are not counted and blocks are
not explained - it is never shown as "no usage".
Only the catalog id is kept: counts live in `chrome.storage.local`
(`shadowAiUsage`, 30 days, no URL, host, path or title) and, with telemetry on, are
sent as aggregated `shadow_ai_usage` events at each flush
([contract](../../docs/contracts/privacy-telemetry.md)). The trade-off is explicit:
the `tabs` permission would give visibility without a grant, but it exposes every
URL the user visits and shows a "Read your browsing history" warning, so it is not
used. Services on a path of a general-purpose host (Notion AI, GitHub Copilot, Bing)
are not in the catalog; blocking them by host would break the host product.

#### Allow / block from the dashboard

Owners and administrators can also allow or block a detected service from the
dashboard (Browser Privacy Guard → Shadow AI; AAL2, audited). The decision is an AI
governance register entry (`ai_site`, catalog id; `approved` or `banned`) and reaches
enrolled browsers as a **signed** document from
`GET {controlPlaneUrl}/functions/v1/browser-guard-policy`, authenticated with the
telemetry key ([`src/background/dashboard-policy.ts`](src/background/dashboard-policy.ts)).
The extension applies it only when the managed `dashboardPolicy` key pins the
control plane's Ed25519 policy signing key(s): the signature must verify, the
`policy_sha256` digest must match the document and the signed envelope, the tenant
must match a pinned `tenantId`, and the sequence must not be lower than the last
accepted one. An unsigned, tampered, foreign-key or replayed document is ignored and
the last verified one stays in force. Refresh: startup, every managed-policy change and
every 15 minutes (`aidr-dashboard-policy` alarm).

Precedence is **most restrictive wins**: a dashboard block applies in every mode; a
dashboard allow only marks a service sanctioned when the managed `shadowAi` does not
block it (an MDM `blocked` id, or an unsanctioned service under MDM
`block-unsanctioned`, stays blocked); the dashboard never changes `mode`. When the
signed document expires (24 h by default) without a successful refresh, its blocks
stay and its sanctions are dropped. Deploy `telemetry` through managed policy as well,
so a user cannot disconnect the refresh. The GPO/MDM `shadowAi` snippet remains the
alternative for fleets without a control plane.

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
  values, file names or URLs. With `shadowAi` on it also sends aggregated
  `shadow_ai_usage` events: catalog service id, visited/blocked, count and whether
  the service is sanctioned. Never the URL, host, path or page title.
- With `telemetry` and the managed `dashboardPolicy` set, it also fetches the signed
  dashboard policy (`GET /functions/v1/browser-guard-policy`, telemetry key only, no
  body, no browsing data).
- The optional native host (`useNativeHost`) runs on the same machine and is
  reached through native messaging; see [`docs/native-host.md`](docs/native-host.md).

## Limitations

- Only the listed sites are protected out of the box; internal portals need a
  `customSites` entry and each user's host-access grant. Other AI tools, desktop
  apps and API clients are not covered by this extension.
- Shadow AI counting, and the `blocked.html` explanation page, act only on origins
  the user granted; the block itself applies without a grant (the user then sees the
  browser's own "blocked by an extension" page). Tab state is kept in memory, so a
  worker restart can count one visit twice.
- Site adapters depend on each product's DOM. A site redesign can break
  interception until the adapter is updated; the real-browser suite in `e2e/`
  guards against regressions on recorded page structures.
- Free-form names and addresses without a label ("Name:", "Adres:") need the
  optional native host (NER), which ships without model weights or accuracy
  evidence. Without it, rule detection covers structured identifiers, labelled
  fields, organisation literals and exact-data sets. Usernames, health/insurance
  numbers and places are found only after a label (`Kullanıcı adı:`, `SGK sicil
  no:`, `NHS number:`, `Konum:`, `City:`...); licence plates as validated Turkish
  plates (`34 ABC 123`) or after a plate label. NER is applied to prompts
  and pastes, not to uploaded files.
- The restore mapping survives a reload of the same tab, but not a browser
  restart, another tab, or 4 hours without a save; if the worker does not answer
  within 1.5 s while the page loads, earlier placeholders stay placeholders.
- Images are not OCR'd in the browser itself. Uploaded images and pictures inside
  Office/OpenDocument files are OCR'd only through the optional native host with OCR
  configured, and blocked (never masked) when they show sensitive data; without it
  they are reported as not inspected, not as clean. Scanned PDFs and image-only PDF
  pages are not OCR'd (reported as unscanned). Set `fileHandling: block` or
  `documentHandling: block` if such uploads must not reach AI sites at all.
- PDFs are scanned but never rewritten, so a PDF with findings is blocked rather
  than masked. PDF text extraction does not decrypt encrypted files, does not
  handle Type0 fonts without a ToUnicode map or predefined CJK CMaps, and uses
  glyph positions to rebuild word and line breaks, which can differ from the
  visual reading order in multi-column layouts.
- Office masking covers text; sheet names, defined names, table column names and
  numeric pivot-cache values are not rewritten (a masked header cell can make
  Excel repair a table's column name).
  OpenDocument masking has the same scope (sheet and table names, named ranges
  and chart caches are not rewritten). Legacy binary formats (`.doc`, `.xls`,
  `.ppt`) are scanned but never masked: a file with findings is blocked, and the
  user has to save it as .docx/.xlsx/.pptx to upload a masked copy. Pictures in
  legacy files are not OCR'd; Word revision/comment author tables and Excel
  defined names and data-validation lists are not read; pivot caches are not
  parsed (they mark the file as partly read).
- File inputs: inputs in the page's document are intercepted by the content script.
  Inputs created without being attached (`createElement("input")` + `click()`) and
  inputs inside shadow roots are covered by a small page-world script
  (`content-main.js`) that holds their selection back (empty `files`, stopped
  `input`/`change` events) until the content script has checked it, and clears it
  when the check fails or does not answer. Limits: a page that submits such an input
  through a native form submission or `new FormData(form)` reads the files without
  that hook; a page script can remove or bypass a page-world hook (it runs in the
  page's own JavaScript world), so this protects against upload code the guard
  cannot see, not against a site that deliberately evades it; and an input in an
  open shadow root without the page-world script is blocked (with a notice) rather
  than checked, while one in a closed shadow root cannot be seen at all. The
  Chromium and Firefox page-world relay is covered by unit tests (jsdom), not yet by
  the real-browser E2E suite. `window.showOpenFilePicker()` (File System Access API)
  is not intercepted.
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
`files-office.test.ts`, `files-office-zip.test.ts`, `files-odf.test.ts`,
`files-images.test.ts`, `files-pdf.test.ts` and `files-legacy-office.test.ts` build
DOCX/XLSX/PPTX, ODT/ODS/ODP packages, images, PDFs and synthetic .doc/.xls/.ppt
compound files (including cyclic-FAT, truncated and oversized ones) in memory (no
binary fixtures), sanitise them with
the real detection engine and vault, and re-open the output to check that
placeholders are present and originals are gone; they also cover macro, encryption
and external-link refusals, zip-bomb, ZIP64 and path-traversal refusals, PDF font
encodings and filters, legacy-format and OCR decisions, and time bounds. The
`file-upload-docx`, `file-upload-odt`, `file-upload-pptx-thumbnail`,
`file-upload-legacy-doc`, `file-upload-legacy-doc-blocked` and
`file-upload-pdf-blocked` E2E scenarios upload those
files on the ChatGPT fixture in a real browser (the blank thumbnails are decoded by
Chromium itself).
