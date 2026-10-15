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
| Sites | ChatGPT (`chatgpt.com`, `chat.openai.com`), Gemini (`gemini.google.com`), Claude (`claude.ai`), Microsoft Copilot (`copilot.microsoft.com`) and Microsoft 365 Copilot Chat (`m365.cloud.microsoft`, `copilot.cloud.microsoft`; same site id `copilot`; also as a subframe, the Copilot pane of the Office web apps, see [Limitations](#limitations)), Perplexity (`www.perplexity.ai`, `perplexity.ai`), DeepSeek (`chat.deepseek.com`), Mistral Le Chat (`chat.mistral.ai`), Grok (`grok.com`) |
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
   in-page message says so ([`docs/native-host.md`](docs/native-host.md)); with the
   managed `requireNativeNer` the send, paste or upload is blocked instead. Risk
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
     number becomes a text cell; a clean formula keeps its formula), formulas
     themselves (a cell whose formula holds sensitive data - and every dependent of
     such a shared formula - loses the formula and becomes a masked constant, so a
     recalculation cannot bring the value back), conditional-format and
     data-validation formulas, defined names, comments, pivot cache strings,
     header/footer text, with sensitive column headers masking the whole column as
     for CSV; PowerPoint slides, notes, layouts, masters and
     comments; charts/diagrams/drawings, document properties and `mailto:` and
     other external hyperlink targets in every format. Other parts (styles, media,
     fonts...) are copied byte for byte. XML names are matched by namespace URI and
     local name, never by the prefix a file happens to use (`x:p` bound to the
     WordprocessingML namespace, or a default namespace, is still a paragraph); a
     part that uses an undeclared prefix is refused (`DOCUMENT_MALFORMED`). The
     same applies to OpenDocument text and its macro / OLE / external-link checks.
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
     annotations, form fields, document info, XMP metadata, and embedded files /
     file attachments whose content is plain UTF-8/UTF-16 text) and scanned. An
     embedded file that is not plain text (nested PDF, Office document, image,
     archive...), cannot be decoded or is missing adds
     `PDF_EMBEDDED_FILES_NOT_INSPECTED`, so such a PDF is never reported as clean.
     A PDF (or OOXML/ODF/OLE document) is recognised by its content first, so
     renaming it `report.txt` or sending it as `text/plain` changes neither the scan
     nor `documentHandling`. PDFs are not rewritten:
     one with findings is blocked (`SENSITIVE_DATA_IN_PDF`) and the user is told to
     paste the text instead, where it is masked; `monitor` records it. A PDF
     without extractable text (scanned), with image-only pages or undecodable
     parts (`PDF_NO_TEXT`, `PDF_PARTIAL`), encrypted (`PDF_ENCRYPTED`) or
     unparseable (`PDF_UNPARSEABLE`) is treated like other binaries: uploaded with
     an "unscanned" warning, blocked in `block` mode. Findings in the readable
     part still block.
   - **Images inside PDFs** (`src/engine/pdf/images.ts`): images drawn by a page or
     Form XObject, inline images and image XObjects referenced elsewhere (soft masks
     excluded) are OCR'd through the same native-host path as screenshots. JPEG
     (`DCTDecode`) is sent as is; Flate/LZW/RunLength/ASCII images in Gray, RGB, CMYK,
     ICCBased, Indexed or Separation colour spaces (1-16 bit, PNG predictors) are
     re-encoded as PNG in the browser (no canvas). Sensitive text blocks the PDF
     (`SENSITIVE_DATA_IN_IMAGE`). Any image of 8x8 px or more that is not read to a
     verdict makes the PDF an uninspected image: `PDF_IMAGES_NOT_INSPECTED` plus
     `PDF_IMAGE_OCR_UNAVAILABLE`, `PDF_IMAGE_UNSUPPORTED` (JPEG 2000, JBIG2, CCITT,
     DeviceN, Lab, TIFF predictor), `PDF_IMAGE_UNDECODABLE`, `PDF_IMAGE_LIMIT` (more
     than 16 images, 12 Mpx, 8192 px per side, 8 MiB, 90 s OCR budget) or
     `PDF_IMAGE_OCR_INCOMPLETE` + the host's code (a picture without text comes back
     as `IMAGE_NO_TEXT`); uploaded with a warning, blocked in `block` mode, never
     clean. A PDF whose text and images are clean is allowed (`PDF_IMAGES_OCR_CLEAN`),
     scanned PDFs included.
   - **Screenshots and photos** (PNG/JPEG/WebP): with `useNativeHost` and a host
     configured with OCR, the image is sent to the local host (`image-scan`, counts
     only; the host never returns pixels or text) and blocked when its text holds
     sensitive data (`SENSITIVE_DATA_IN_IMAGE`; pixels are not masked). A clean OCR
     result lets it through. Without the host, without OCR on it, or when OCR could
     not read the image fully (no text, uncertain words, barcodes, limits), the
     image is reported as not inspected (`IMAGE_NOT_INSPECTED`): uploaded with a
     warning, blocked in `block` mode, never treated as clean.
   - `documentHandling: block` rejects every Office/OpenDocument/PDF upload in every mode,
     recognised by content as well as name (in `monitor` mode an upload is held until
     its first bytes were sniffed, so a PDF renamed to `.txt` is refused too);
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
pnpm package:browser-guard          # release build + store zips + AMO source zip + SHA256SUMS + store validation

# or inside packages/browser-guard
pnpm build                          # node scripts/build.mjs
pnpm build:release                  # build.mjs --release --zip, source-archive.mjs, validate-store.mjs
pnpm store:validate                 # offline store checks of dist/ zips and store/ (scripts/validate-store.mjs)
pnpm store:assets                   # regenerate store/images/ from the E2E fixtures (scripts/store-assets.mjs)
pnpm check                          # tsc --noEmit
pnpm test:e2e                       # build, then real-browser E2E (see e2e/README.md)
```

Output:

```
dist/chrome/                               unpacked Chrome/Edge extension
dist/firefox/                              unpacked Firefox extension
dist/aidr-browser-guard-chrome-<ver>.zip   upload to the Chrome Web Store / Edge Add-ons
dist/aidr-browser-guard-firefox-<ver>.zip  upload to addons.mozilla.org
dist/aidr-browser-guard-source-<ver>.zip   source code for the AMO review (scripts/source-archive.mjs)
dist/SHA256SUMS                            sha256sum -c compatible
```

Self-hosted channel (browsers update from an HTTPS feed instead of a store): with
`BROWSER_GUARD_UPDATE_BASE_URL=https://<host>/browser-guard` the release build also
writes `dist/aidr-browser-guard-{chrome,firefox}-selfhosted-<ver>.zip` (the store
packages plus the update URL), and `node scripts/update-feed.mjs` signs the Chrome/Edge
one as a CRX3 with the owner key (`BROWSER_GUARD_CRX_KEY_PEM`; nothing is produced
without it) and writes the feed (`update.xml`, `updates.json`, `packages/`,
`SHA256SUMS`). See [`store/README.md`](store/README.md) and
["Hosting Browser Guard updates internally"](../../docs/installation/browser-guard-enterprise.md#10-hosting-browser-guard-updates-internally).

The listing kit (descriptions EN/TR, single-purpose statement, permission
justifications, data-usage answers, privacy policy pages, screenshots and promo
tiles) and the owner's publishing steps are in [`store/`](store/README.md).
`scripts/validate-store.mjs` checks the uploaded zips themselves and the kit against
the store rules that can be checked offline (manifest fields and limits, version,
icons, no `key`, justified minimum permissions, CSP, no remote code, no source maps)
and fails the release build on a violation. The source zip is built from esbuild's
own list of bundle inputs; unpacking it and following its `AMO-REVIEWER-NOTES.md`
reproduces the Firefox package byte for byte.

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

### Native host registration (per user, no admin)

`scripts/native-host.mjs` registers the optional AIDR Privacy native host for Chrome and Edge
for the current user (Windows: `HKCU\Software\{Google\Chrome,Microsoft\Edge}\NativeMessagingHosts`;
macOS/Linux: the user's `NativeMessagingHosts` directories). The desktop app imports it as
`@singularityrd/aidr-browser-guard/native-host` (`registerNativeHost`, `unregisterNativeHost`,
`nativeHostStatus`, `unpackedExtensionId`; types in `scripts/native-host.d.mts`) or runs the
CLI with `--json`:

```bash
node scripts/native-host.mjs register --host <abs launcher> --extension-id <id> [--browser chrome,edge] --json
node scripts/native-host.mjs status --json
node scripts/native-host.mjs unregister --json
```

Interface, exit codes, error codes and what was verified: [`docs/native-host.md`](docs/native-host.md#per-user-registration-scriptsnative-hostmjs).

### Customer demo

`pnpm demo:package` builds the release and `dist/demo/aidr-browser-guard-demo-<ver>.zip` (a
`Load unpacked` folder plus Turkish install steps); `pnpm demo:live` opens the extension on the
hermetic site fixtures for an offline demo; `pnpm demo:record` regenerates the evidence in
[`docs/screenshots/`](docs/screenshots/). Presenter guide (Turkish), including what was and was
not verified: [`docs/demo/browser-guard-demo.tr.md`](docs/demo/browser-guard-demo.tr.md).

### Loading an unpacked build

- **Chrome/Edge:** `chrome://extensions` (or `edge://extensions`), enable
  Developer mode, *Load unpacked*, select `dist/chrome`.
- **Firefox:** `about:debugging#/runtime/this-firefox`, *Load Temporary Add-on*,
  select `dist/firefox/manifest.json`.

### Icons

The icons and the logo in the popup, options and blocked pages are generated from the
round Singularity product mark [`branding/singularity-mark.svg`](../../branding/singularity-mark.svg)
by `scripts/icons.mjs`, without dependencies:

1. the SVG is parsed (only the subset the mark uses: a circle clip path and polygons; anything
   else, such as `<path>` or gradients, is refused with `SVG_UNSUPPORTED_ELEMENT`) and
   rasterised by a scanline renderer into the master `images/icon-master.png` (1024 px, the
   accent `#3862E8`, legible on light and dark toolbars);
2. the master is box-resampled to `static/icons/icon-{16,32,48,128}.png`;
3. `static/ui.css` `--logo` is set to the same SVG as a data URL, used as a CSS mask, so the
   UI logo takes the theme's `--accent` (as the SVG's `currentColor` intends).

```bash
pnpm icons                # node scripts/icons.mjs: regenerate master, icons and --logo
pnpm icons:check          # exit 1 if any of them is stale (also asserted by build-tools.test.ts)
pnpm store:assets         # then refresh the store screenshots and promo tiles (they show the logo)
```

The output is deterministic, so the committed files change only when the mark changes. When
the designer's master file replaces the SVG (same file name, see `branding/README.md`), run
`pnpm icons` and `pnpm store:assets` and commit the result.

## Manifest and permissions

| Key | Value | Why |
|---|---|---|
| `permissions` | `storage`, `alarms`, `declarativeNetRequest`, `scripting` | settings and the in-memory vault; telemetry batching; blocking sites an admin lists in `blockedSites` or blocks with `shadowAi` (block rules only; `declarativeNetRequest` applies them without host permissions, so an administrator's block never depends on the user's host-access grant; install warning "Block content on any page"); registering the content script for administrator-configured `customSites`, and injecting it into AI tabs that were already open when the extension started (no install warning, and no access by itself: injection still needs host access to the page) |
| `host_permissions` | the twelve HTTPS hosts above | content script injection on supported sites only |
| `optional_permissions` | `nativeMessaging` | requested on the options page (from the click that turns the native NER host on, or the **Grant permission** button when an administrator enabled it); never at install |
| `optional_host_permissions` | `https://*/*` | never requested at install. The options page requests exact `https://<host>/*` origins, from a click, only for what the managed policy configures: the hosts of `customSites`, and the Shadow AI catalog origins when `shadowAi` is on (or the origins of explicitly blocked services). No `tabs`, `webNavigation`, `history` or `<all_urls>` permission is requested: the extension sees a tab's URL only on origins it was granted |
| `content_scripts` | `content.js` and `content-main.js` (`world: "MAIN"`), both `run_at: document_start`: `all_frames: false` for every site host except the two Microsoft 365 Copilot hosts (`m365.cloud.microsoft`, `copilot.cloud.microsoft`), which get the same two scripts with `all_frames: true` (disjoint `matches`, so no frame gets a script twice) | intercept before the page's own handlers; top frame only, except that on the Microsoft 365 Copilot hosts the scripts also run when that host is loaded as a subframe, which is how the Office web apps embed the Copilot pane (see [Limitations](#limitations)). No host permission is added for this: the frame hosts are already site hosts, and the Office pages that embed them get no script. `content-main.js` runs in the page's JavaScript world with no extension APIs and no data: it only hooks `<input type=file>` (`click`, `showPicker`, the `files` getter) so detached and shadow-DOM file inputs are handed to `content.js` for checking (see [Limitations](#limitations)). Custom sites get both scripts |
| `web_accessible_resources` | none | no extension resource is exposed to web pages, so a page cannot detect the extension by probing its resources. That does not make the extension invisible: the page-world hook in `content-main.js` is observable to a page that looks for it (the patched `HTMLInputElement` `files` getter, `click` and `showPicker`, and the `aidr-file-*` relay events). It sets no global name or flag on `window`; see [Limitations](#limitations). A site listed in `blockedSites` is refused by a declarativeNetRequest rule and the background worker then opens `blocked.html` in that tab itself (`tabs.update`, an extension-initiated navigation). A DNR redirect would need the page to be web accessible, and Chrome refuses DNR redirects to `use_dynamic_url` resources (verified by the `blocked-site` E2E scenario) |
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
| `exactData` | up to 16 `ExactDataSet`s (`{ datasetId, keySource: "native-host", minEntropyBits >= 64, fingerprints, type }`, no key; see [Exact data match](#exact-data-match)); forces `useNativeHost` on | none |
| `detectSignals` / `signalAction` | boolean / `off` \| `warn` \| `block` | `true` / `warn` |
| `blockedSites` / `disabledSites` | site ids | none |
| `customSites` | up to 20 `{ id, label, hosts, editorSelectors, sendButtonSelectors, responseSelectors }` (managed only) | none |
| `shadowAi` | `{ mode: off \| monitor \| block-unsanctioned, sanctioned: [ids], blocked: [ids] }` (managed only) | `off` |
| `allowUserPause` / `allowSendAnyway` | boolean (managed only) | `true` / `true` without a managed policy; `false` / `false` under any managed policy unless it sets them |
| `maskPaste` | boolean | `true` |
| `fileHandling` / `maxFileBytes` | `scan` \| `block` \| `allow` / bytes (max 50 MiB) | `scan` / 5 MiB |
| `documentHandling` | `mask` \| `block` \| `allow` (managed only; Office/OpenDocument/legacy Office/PDF when `fileHandling` is `scan`) | `mask` |
| `restoreResponses` | boolean | `true` |
| `useNativeHost` | boolean | `false` (also a user setting unless managed; forced on by `requireNativeNer` or `exactData`) |
| `uninspectedImages` | `"warn"` \| `"block"`: an uploaded picture that could not be inspected (no AIDR Privacy companion, not enabled or permitted, or the host could not read it): `block` = not uploaded, with install/enable guidance (recorded only in monitor mode); `warn` = uploaded with that guidance. Also a user setting (Options) unless managed; locked under a managed policy unless `allowUserOverrides` | `"block"` under any managed policy, else `"warn"` |
| `requireNativeNer` | boolean (managed only; the signed dashboard policy can also switch it on, `true` wins): native NER is mandatory; a prompt, paste or upload the host could not NER-check (missing, crashed, timed out, rules-only, over the limit) is blocked, recorded as `native_ner: unavailable` in monitor mode; forces `useNativeHost` on | `false` |
| `workAccounts` | `{ action: warn \| block \| mask-only, unverified?: enforce \| allow, sites: { chatgpt?, claude?, gemini?, copilot?: { workspaceIds?, emailDomains? } } }` (managed only; see [Personal vs company AI accounts](#personal-vs-company-ai-accounts)) | none (no account check) |
| `telemetry` | `{ controlPlaneUrl, apiKey }` | none (no telemetry) |
| `language` | `auto` \| `en` \| `tr` | `auto` |
| `policyId` | string reported with telemetry | `aidr-browser-guard-default` |
| `dashboardPolicy` | `{ publicKeysPem: [1-4 Ed25519 SPKI PEM], tenantId? }` (managed only) | none: dashboard Shadow AI decisions and the dashboard's "Require native NER" are not applied |
| `allowUserOverrides` | boolean (managed only) | `false`: a managed policy locks the protection settings above |

The authoritative schema is [`static/managed_schema.json`](static/managed_schema.json);
managed values are validated strictly in `src/background/policy.ts` before use. An
invalid managed value fails safe instead of falling back to the default: a list keeps
its valid entries, any other protection key takes its strictest value (`FAIL_SAFE`:
`mode` `block`, pause and send-original off, `requireNativeNer` on, ...), the key is
locked and listed in `policy.policyErrors`, the popup and options page show a policy
error, and `privacy_scan` telemetry carries `policy_errors` (the count). A managed
storage read failure is treated the same way (whole-policy error `*`). Details in
[`deploy/browser-guard/README.md`](../../deploy/browser-guard/README.md#managed-keys).
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
entry is dropped (a policy warning and a policy error); the valid sites stay.

A managed policy cannot grant host access, and browsers only show the permission
prompt from a user gesture, so each user clicks **Allow access** once on the options
page (**AI services** section). The worker then registers the same `content.js` for
exactly the granted hosts (`chrome.scripting.registerContentScripts`, id
`aidr-custom-sites`, top frame, `document_start`), re-syncs on every policy change
and grant/revocation, and accepts messages from those hosts as site `custom`.
Tabs that were already open are injected as soon as access is granted
(`chrome.scripting.executeScript`). Until access is granted the options page
shows the site as **Needs access** and nothing runs there. The script runs in the top
frame only: a portal whose chat editor lives in an iframe (an embedded assistant widget
served from another page or host) is not protected, and the policy cannot detect that.
Configure the host and selectors of the page that contains the editor itself, and try
the portal before rolling the policy out.

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
declarativeNetRequest rule per service (`main_frame` + `sub_frame`, ids 7401+) and a
second one (ids 7701+) that refuses the fetch/XHR and WebSocket requests made by pages
of the service (`initiatorDomains`), so a tab that was already open when the block
arrived stops working at once. When a block is applied the worker also sends every
open tab it can see on a blocked site or service to `blocked.html`. The
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
are not in the catalog; blocking them by host would break the host product. The one
path-scoped entry is Microsoft 365 Copilot Chat (`m365-copilot`): its own host
`copilot.cloud.microsoft` plus only `/chat` (and below) on the shared
`m365.cloud.microsoft` host are counted and blocked (a `regexFilter` rule), never the
rest of Microsoft 365. It is a separate service from consumer Copilot (`copilot`), so the
work-account Copilot can be sanctioned while the consumer one is blocked.

#### Allow / block from the dashboard

Owners and administrators can also allow or block a detected service from the
dashboard (Browser Guard → Shadow AI; AAL2, audited). The decision is an AI
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

The same signed document carries the tenant's **Require native NER** setting
(Browser Guard → Require native NER; owners/admins, AAL2, audited; switching
it off is refused while four-eyes change control is on) as
`browser_guard.require_native_ner: true`; the key is omitted when the setting is off,
so documents of tenants that do not use it stay acceptable to extension versions that
predate it (those versions refuse a document carrying the key and keep their last
verified one). The flag is covered by `policy_sha256` like the lists. It has the
meaning of the managed `requireNativeNer` key and is merged with it the same way as
blocks: `true` from either side wins (the dashboard can switch the requirement on, never
off), it forces and locks `useNativeHost`, and it stays in force after the document
expires.

Precedence is **most restrictive wins**: a dashboard block applies in every mode; a
dashboard allow only marks a service sanctioned when the managed `shadowAi` does not
block it (an MDM `blocked` id, or an unsanctioned service under MDM
`block-unsanctioned`, stays blocked); the dashboard never changes `mode`. When the
signed document expires (24 h by default) without a successful refresh, its blocks
stay and its sanctions are dropped. Deploy `telemetry` through managed policy as well,
so a user cannot disconnect the refresh. The GPO/MDM `shadowAi` snippet remains the
alternative for fleets without a control plane.

### Personal vs company AI accounts

`workAccounts` (managed only) checks, on ChatGPT, Claude, Gemini and Copilot, whether the
user is signed in with the organisation's account: a listed ChatGPT workspace id or Claude
organisation UUID, an account email in a listed domain (Gemini, Microsoft 365 Copilot Chat),
or the Microsoft 365 host itself. Any other account gets the configured action: `warn`
(the first send asks Continue / Cancel), `block` (sends and uploads refused) or `mask-only`
(always masked: no monitor mode, pause or **Send original** on that account). An account the
page does not identify is treated like a personal one unless `unverified: "allow"`. Signals
are read from the page's URL, non-HttpOnly cookies and DOM only; ids and domains never leave
the content script, and telemetry carries only an `account_type` enum. What each site
exposes, what cannot be detected (desktop apps, Safari, other browsers) and the recommended
proxy and identity-provider controls are in [`docs/work-accounts.md`](docs/work-accounts.md).

### Exact data match

`exactData` lets an organisation flag its own records (customer records, account
numbers combined with names, project code names) without shipping the values or
the key. Create the organisation's EDM secret once, install it in the native host
configuration (`"exactData": {"secretFile": "/etc/aidr/edm-secret.b64"}`, see
[`docs/native-host.md`](docs/native-host.md#exact-data-keys-exactdata)), then build each
dataset from a CSV with the same secret:

```bash
node scripts/fingerprint-dataset.mjs --new-secret edm-secret.b64
node scripts/fingerprint-dataset.mjs --in customers.csv --header \
  --columns full_name,account_no --composite \
  --dataset-id crm-customers --type PERSON --secret-file edm-secret.b64 --out crm-customers.json
```

Algorithm (identical in the tool, the native host and `src/engine/exact-data.ts`):

1. `value.normalize("NFKC").toLowerCase()`
2. remove U+200B-U+200F, U+2060, U+FEFF
3. fold Turkish `ı` (U+0131) and `i̇` (`i` + U+0307, what `İ` lowercases to) to `i`
4. tokens = every match of `/[\p{L}\p{N}]+/gu`; a value must give 1-16 tokens and at least 3 characters
5. datasetKey = `HMAC-SHA256(secret, UTF-8("aidr-edm-v2" 0x00 datasetId))`
6. fingerprint = lowercase hex `HMAC-SHA256(datasetKey, UTF-8(JSON.stringify(tokens)))`

The dataset is `{ datasetId, keySource: "native-host", minEntropyBits, fingerprints,
type }`: no key. Managed policy is readable by every user of the endpoint
(`chrome://policy`, the policy registry keys, `policies.json`), so the extension
refuses a dataset that carries `keyB64`. When the policy has datasets the worker
forces `useNativeHost` on, asks the host for the dataset keys (`edm-keys`), keeps them
in memory and hands them to the content scripts only. Until a dataset's key has
arrived (no host, an older host, no secret configured, Firefox), every scan with that
dataset is incomplete, which the guard treats as not checked (fail closed). In the
page, the same normalisation is applied to the prompt and every window of up to 16
consecutive tokens is fingerprinted with WebCrypto and compared with the dataset.

Guessable values are refused. A keyed hash protects only values that cannot be
enumerated by whoever holds the key, and the host runs as the signed-in user, so a
user who reads its secret file (or attaches a debugger to the browser) can obtain the
dataset keys. The tool therefore estimates each value's entropy (digits at log2 10 bits
each; letter runs as dictionary words, 2 bits per letter up to 16 bits; structured
identifiers capped: TCKN, card and phone numbers 30 bits, date of birth 16, IBAN 56)
and refuses the dataset (`LOW_ENTROPY`) when any value is below 64 bits. The policy
refuses a dataset whose `minEntropyBits` is below 64. Names, short account numbers,
phone numbers and national ids alone fall below the floor: combine columns with
`--composite` (one value per row, in column order; it then matches only when the parts
appear together in that order), or leave weak values out with `--drop-low-entropy`.
The estimate is conservative but not a proof: a column that looks random but is
sequential is weaker than estimated. `--key-b64` / `--key-file` are refused. Keep the
secret: the same secret and dataset id reproduce the same fingerprints.

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
- Tabs open before the extension started (install, update, re-enable): the worker
  injects the content scripts into every open, loaded tab of a protected site once per
  extension start, and the popup shows **Not protected — reload this tab** for a
  protected site whose tab has no live content script (a discarded tab, an injection
  the browser refused).
- Shadow AI counting, and the `blocked.html` explanation page, act only on origins
  the user granted; the block itself applies without a grant (the user then sees the
  browser's own "blocked by an extension" page). Tab state is kept in memory, so a
  worker restart can count one visit twice.
- Site adapters depend on each product's DOM. A site redesign can break
  interception until the adapter is updated; the real-browser suite in `e2e/`
  guards against regressions on recorded page structures.
- Microsoft 365 Copilot Chat (`m365.cloud.microsoft/chat`, `copilot.cloud.microsoft`)
  shares the site id `copilot` with consumer Copilot, so `disabledSites` and
  `blockedSites` act on both (a `blockedSites` entry blocks only `/chat` of the shared
  Microsoft 365 host); use the Shadow AI ids `copilot` / `m365-copilot` to treat them
  differently. The guard runs on the whole `m365.cloud.microsoft` host, because the
  Microsoft 365 home enters `/chat` without a page load. Its selectors are covered by
  unit tests against representative markup, not by the real-browser suite or a live
  tenant.
- The Copilot pane inside the Office web apps (Word, Excel, PowerPoint, Outlook on the
  web) is a cross-origin iframe. On the Microsoft 365 Copilot hosts (`m365.cloud.microsoft`,
  `copilot.cloud.microsoft`; list in [`src/sites/frames.ts`](src/sites/frames.ts)) the
  content scripts also run in subframes, so a pane served from one of those hosts is
  guarded like the top-level page: masking on send and paste, file checks, local restore,
  fail-closed until a policy arrives, counts reported as site `copilot` (the worker takes
  the site from the frame's own URL, not from the Office page). The pane keeps its own
  vault record (`vault:<tab>:frame:<origin>`), so it never overwrites a top-frame guard's
  in the same tab, and each send is counted once by the frame that sent it. Policy changes
  reach the pane although its tab's page is not a protected site (the worker registers
  the frame when it boots). The Office pages themselves (`*.officeapps.live.com`,
  `*.office.com`, Outlook) get no script, no host permission and no block: a
  `blockedSites: ["copilot"]` or Shadow AI `m365-copilot` block stops the pane's own frame
  request (the frame rule covers the Copilot hosts, and on `m365.cloud.microsoft` only
  `/chat`), never the Office app, and the Office tab is never redirected to
  `blocked.html`. **Unverified against a live tenant (BG-LIVE):** which origin serves the
  in-app pane, and its markup, could not be checked; a pane served from another host is
  not covered (add the host to `src/sites/frames.ts` and the adapter), and the selectors
  are those of Microsoft 365 Copilot Chat. The pane in a tab that was already open when
  the extension started is guarded after a reload (open-tab injection is top-frame only),
  and Shadow AI visit counts see top-level tab URLs only, so the pane is not counted as a
  visit. The real-browser `frame-copilot-office` scenario covers the frame against a
  fixture, not against Microsoft 365.
- Free-form names and addresses without a label ("Name:", "Adres:") need the
  optional native host (NER), which ships without model weights or accuracy
  evidence. Without it, rule detection covers structured identifiers, labelled
  fields, organisation literals and exact-data sets (the latter need the native host
  for their keys). Usernames, health/insurance
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
  they are reported as not inspected, not as clean. Images inside PDFs (scanned pages
  included) are extracted in the browser and OCR'd the same way; without the host a PDF
  with images is reported as not inspected. OCR accuracy is unmeasured (no evaluation
  on real documents or images). Set `fileHandling: block` or
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
  is not intercepted. The hook is not hidden from the page: it defines no global
  name, flag or symbol on `window` (its state is kept in a closure), but a page can
  still tell that `HTMLInputElement.prototype.files`, `click` and `showPicker` are not
  the browser's own functions and can listen for the `aidr-file-hook-ping`,
  `aidr-file-scan` and `aidr-file-result` events, so a site can detect that Browser
  Guard is installed.
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

`store.test.ts` runs the store validator on a release build and the committed
listing kit, and checks that each store violation it covers is rejected.
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
