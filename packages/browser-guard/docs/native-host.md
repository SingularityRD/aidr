# Browser Guard native host (optional NER and OCR)

Browser Guard does all of its detection inside the browser with the AIDR Privacy rule
layer. An administrator can also connect it to the **AIDR Privacy native host**
(`com.singularity.aidr_privacy`, shipped by `packages/privacy`). The host runs on the
endpoint and adds learned named-entity recognition (NER) and, when configured with a
`visual` backend, OCR of images. Browser Guard sends it the prompt text and gets back
extra spans, and sends it uploaded images and gets back a counts-only verdict.

The host is optional. Without it, every prompt is still scanned, masked and
restored locally. The bridge (`src/background/native.ts`) returns `null` and callers
keep their local findings.

## How prompts and pastes use it

When the effective policy has `useNativeHost: true`, the content guard
(`src/content/guard.ts`) sends every prompt and paste it scans to the worker as a
`NATIVE_SCAN` message, in parallel with the in-page rule engine:

- Only text up to 200,000 characters (the rule engine's own limit) is sent, and the
  page waits at most 2.5 s for the answer (the bridge's 2 s budget plus messaging).
- Only `PERSON`, `ADDRESS` and `LOCATION` spans of types enabled in `enabledEntities`
  are taken, and only when their offsets lie inside the text. A span a rule finding
  already covers is dropped; overlapping spans are merged by the vault into one
  masked span. The merged findings are then masked, confirmed or blocked by mode
  exactly like rule findings, and counted by type.
- When the worker answers `findings: null` (host unavailable, timed out, blocked by
  its own policy, or output that cannot be mapped) or does not answer in time, the
  scan continues **rules-only**. The user is told: the masked/pasted toast and the
  confirm or block bubble add "Advanced name and address detection (native host) is
  unavailable: checked with built-in rules only.", and a clean prompt shows that
  notice once per page until the host works again. The `NATIVE_SCAN` reply also
  carries the bridge `status`.
- Uploaded text files and documents are not sent to the host for NER (rules only)
  unless `requireNativeNer` is set (next section). Images are, for OCR (section after).

## Required NER (`requireNativeNer`, managed only)

An administrator can make native NER mandatory with the managed key
`requireNativeNer: true` (default `false`: everything above stays as it is). It forces
and locks `useNativeHost` on. While `PERSON`, `ADDRESS` or `LOCATION` is enabled:

- A prompt send or text paste whose native scan is anything but a NER answer is
  **blocked** with "Your organisation requires advanced name and address detection
  ... Nothing was sent." That covers: host not installed or `nativeMessaging` not
  granted, a crashed or backed-off host, the 2.5 s timeout, text over 200,000
  characters (not sent to the host), a malformed or `ok: false` reply, a host policy
  block or unmappable output, and a **rules-only host**: with the requirement the
  worker asks the bridge for NER coverage (`scanText(text, { requireNer: true })`), and
  a commit whose `coverage` is not `rules-and-ner` counts as no answer (without
  counting towards the backoff). A clean prompt is blocked too: no findings without
  NER is not a clean check. Such a result is never cached, so the next send asks the
  host again.
- Uploads: every text scan of the file sanitiser (plain text, CSV/JSON cells, Office,
  OpenDocument, PDF and legacy Office text) also goes through native NER, and its
  `PERSON`/`ADDRESS`/`LOCATION` findings are masked (or, for PDFs and legacy Office,
  block) like rule findings. Text over the host limit is retried in the sanitiser's
  smaller windows, each NER-checked. If the host gives no NER answer for any part of
  the file (or cannot OCR one of its images, or OCRs it without NER coverage: such a
  clean verdict is reported `incomplete` / `NATIVE_NER_UNAVAILABLE`), the upload is
  blocked with `NATIVE_NER_UNAVAILABLE` and a hint. After one failure the rest of
  that upload is refused at once instead of waiting for the timeout again. Text
  pasted together with files is held to the same rule.
- `monitor` mode (and sites the user disabled) never block: the check is recorded
  instead.
- Every `RECORD` (and so every `privacy_scan` telemetry event) carries the outcome as a
  status only: `native_ner: "used"` or `"unavailable"` (absent when NER was off), so a
  check that ran without the required NER is never counted as a clean one
  ([`docs/contracts/privacy-telemetry.md`](../../../docs/contracts/privacy-telemetry.md)).
- The options page shows that the requirement is in force.

## How uploads use it (OCR)

With `useNativeHost: true` and a host whose `hello` reports `ocr: true` (a `visual`
block in the host config: local Tesseract with the Turkish and English data, or on Windows
the built-in Windows OCR that the AIDR Privacy companion installer configures, see
[Installing the companion](#installing-the-companion-windows-per-user)):

- An uploaded PNG, JPEG or WebP image (recognised by content, at most 8 MiB), and the
  PNG/JPEG/WebP pictures inside an uploaded DOCX/XLSX/PPTX or ODT/ODS/ODP (at most 16
  per document, within a 90 s OCR budget), are sent to the worker as
  `NATIVE_IMAGE_SCAN` and on to the host as an `image-scan` session. The page waits at
  most 65 s per image (the bridge's own limit is 60 s).
- The host OCRs the image and runs its text engine over the words. It returns only a
  decision and per-type counts: never pixels, OCR text or positions.
  `allow` → clean, `block` → sensitive, `review` → not fully inspected (no text read,
  uncertain words, an undecoded barcode, limits, timeouts, OCR failures).
- A sensitive image blocks the upload (`SENSITIVE_DATA_IN_IMAGE`, recorded only in
  `monitor` mode); the user is told to crop or redact it. Pixels are never masked.
- An image that was not fully inspected, or any image when the host, its OCR or the
  permission is missing, is reported as not inspected (`IMAGE_NOT_INSPECTED`, or
  `DOCUMENT_IMAGES_NOT_INSPECTED` for pictures in a document), never treated as clean.
  A standalone picture follows `uninspectedImages`:
  - `"block"` (the default under any managed policy; locked unless `allowUserOverrides`):
    not uploaded (only recorded in `monitor` mode). When no host answered, the bubble says
    the picture "was not uploaded because the picture could not be inspected" and how to
    install the companion (Singularity AIDR desktop app or the `install-companion` script)
    and turn on **Use the AIDR Privacy helper app** in Options. When the host answered but
    could not read the picture (uncertain OCR, no text, limits), it says that instead.
  - `"warn"` (the default without a managed policy; a user setting on the options page):
    uploaded with a warning carrying the same install guidance; still blocked in `block` mode.
  - An endpoint without a barcode decoder (the companion on a machine without the Visual
    C++ 2013 runtime pyzbar needs) reports clean text as `IMAGE_BARCODE_NOT_CHECKED`: the
    text was inspected, so the picture is uploaded with a "QR codes and barcodes cannot be
    checked on this computer" note under either value (blocked only in `block` mode).
    Sensitive text is blocked regardless.
- Images inside PDFs are extracted in the browser (JPEG as is, other raster images
  re-encoded as PNG) and sent the same way, one `image-scan` session per image. A PDF
  with an image that was not read to a verdict, or that could not be extracted, is
  reported as `PDF_IMAGES_NOT_INSPECTED` with a `PDF_IMAGE_*` detail code and handled
  like an uninspected image.

## What it adds

The in-browser rule layer is good at identifiers with a fixed shape or checksum: email,
phone, IBAN, TC Kimlik, card numbers, keys and secrets, IP/MAC, and similar. It cannot
reliably find things that have no fixed shape:

| Entity | Rule layer alone | With a host NER model |
|---|---|---|
| `PERSON` (a name in running text) | Only with context words or administrator literals | Detected from the model |
| `ADDRESS` | Only with address cue words (e.g. "Adresim") | Street/building phrases without a cue |
| `LOCATION` | After a location label (`Konum:`, `Şehir:`, `Location:`, `City:`...), or an address label while `ADDRESS` is disabled; administrator literals | Detected from the model |

How much this helps depends entirely on the NER model the administrator installs.
`packages/privacy` ships the host and the `LocalNerProcess` protocol, but **no model
weights and no quality evidence**. Measure precision and recall on your own data
before you depend on it. The host's own rule layer also runs, so a host result can
repeat a span Browser Guard already found locally. Callers merge the two sets. Every
host span has `source: "native-ner"` and a fixed score of `0.9`, because the host
applies policy decisions and does not export per-span scores.

## Installing the companion (Windows, per user)

The **AIDR Privacy companion** is the complete per-user install of the host with OCR:
`@singularityrd/aidr-privacy/companion` (CLI `aidr-privacy-companion`, wrappers
`packages/privacy/native/windows/install-companion.ps1` / `uninstall-companion.ps1`). It
finds the Browser Guard extension ids in the Chrome/Edge profiles (reading Preferences only),
stages the host under `%LOCALAPPDATA%\SingularityAIDR\PrivacyCompanion`, sets up OCR with the
Windows built-in recognizer (no OCR model download; Pillow/pyzbar from the hash lock), builds
the launcher and writes the same HKCU keys as the registration below. Status, sources and
tests: [`packages/privacy/README.md`](../../privacy/README.md#status) (implementation in `packages/privacy/src/companion/`).
`scripts/native-host.mjs` (next section) only registers a launcher you already have.

After installing, each user still turns on **Use the AIDR Privacy helper app** in Browser Guard
Options and accepts the browser's permission prompt (or the administrator sets
`useNativeHost: true`; the permission prompt is still the user's).

## Per-user registration (`scripts/native-host.mjs`)

Registration tells Chrome/Edge where the host's manifest is. `scripts/native-host.mjs`
does it for the **current user only, without administrator rights**, and is meant to be
called by the desktop app (`packages/desktop`) or an installer after the host launcher is
in place. It does not build or sign the launcher (see the next section) and cannot grant
the extension's optional `nativeMessaging` permission (the user does that once, on the
options page).

| Platform | Where | What |
|---|---|---|
| Windows | `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.singularity.aidr_privacy`, `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.singularity.aidr_privacy` (`chromium`: `HKCU\Software\Chromium\...`) | default value = absolute path of the manifest, written to `%LOCALAPPDATA%\SingularityAIDR\NativeMessagingHosts\com.singularity.aidr_privacy.json` unless `manifestDir` is given. Never HKLM. |
| macOS | `~/Library/Application Support/{Google/Chrome,Microsoft Edge,Chromium}/NativeMessagingHosts/` | the manifest file itself |
| Linux | `~/.config/{google-chrome,microsoft-edge,chromium}/NativeMessagingHosts/` | the manifest file itself |

The manifest is `{ name: "com.singularity.aidr_privacy", path: <absolute launcher>, type:
"stdio", allowed_origins: ["chrome-extension://<id>/", ...] }`. The host's own config must
list the same ids in `allowedExtensionIds` (the host checks the caller too).

**CLI** (`pnpm --filter @singularityrd/aidr-browser-guard native-host <command>`, or
`node packages/browser-guard/scripts/native-host.mjs <command>`):

```text
register        --host <abs launcher> --extension-id <id> [--extension-id <id>] [--browser chrome,edge] [--manifest-dir <dir>]
unregister      [--browser chrome,edge]
status          [--browser chrome,edge]
create-launcher --config <abs host config.json> --out <abs dir> [--node <abs node.exe>]   (Windows development/demo only)
extension-id    <unpacked extension dir>       (the id Chrome/Edge give a "Load unpacked" build)
--json          one JSON object on stdout: { ok: true, ... } or { ok: false, error: "<CODE>: detail" }
```

Exit codes: `0` ok, `1` failed (`HOST_NOT_FOUND`, `HOST_PATH_UNSAFE`, `EXTENSION_ID_INVALID`,
`BROWSER_INVALID`, `REGISTRY_WRITE_FAILED`, `REGISTRY_VERIFY_FAILED`, `REGISTRY_DELETE_FAILED`,
`REGISTRY_READ_FAILED`, `BUILD_REQUIRED`, ...), `2` usage error.

**Import** (Node 22+, ESM; types in `scripts/native-host.d.mts`):

```js
import {
  registerNativeHost, unregisterNativeHost, nativeHostStatus, unpackedExtensionId,
} from "@singularityrd/aidr-browser-guard/native-host"; // = packages/browser-guard/scripts/native-host.mjs

const { registrations } = registerNativeHost({
  hostPath: "C:\\Program Files\\Singularity AIDR\\aidr-native-launcher.exe", // absolute, must exist
  extensionIds: ["<store or self-hosted id>", unpackedExtensionId("C:\\demo\\browser-guard")],
  browsers: ["chrome", "edge"],          // default
});
nativeHostStatus().browsers;            // [{ browser, registered, usable, manifestPath, hostPath, allowedOrigins, problem? }]
unregisterNativeHost();                 // removes the HKCU keys and the manifest when nothing else uses it
```

All functions are synchronous and throw `Error("<CODE>: detail")`. On Windows writes go
through `reg.exe` and reads through PowerShell with UTF-8 output, so a profile path with
Turkish characters (for example the profile of a user named `Ömer`) is stored and verified exactly; after writing, the key
is read back and `REGISTRY_VERIFY_FAILED` is raised if it does not hold the manifest path.
Expect about one second per registry read (PowerShell start-up).

Development/demo launcher: on Windows the privacy package's production launcher is a C#
executable that must be compiled and signed (below). For a demo machine
`create-launcher` writes `aidr-native-host.cmd`, which starts
`packages/privacy/dist/native/host.js` with the current Node and the given config; Chrome and
Edge run a non-`.exe` host through `cmd.exe`. Paths containing `" % ^ & | < > !` are
refused. Do not ship the `.cmd` launcher.

Verified on Windows 11 (Chrome for Testing 153): the opt-in E2E scenario
`native-host-connected` (`BG_E2E_NATIVE_HOST=1`) registers the real host for Chromium in
HKCU with this module, the worker reports it `connected`, scans go through it, and the
registration is removed afterwards. Not verified: registration for installed Google Chrome
and Microsoft Edge (same code path, other key), the signed production launcher, macOS.

**Known limitation:** the privacy host's own policy blocks text containing secrets
(`SECRET`/`PRIVATE_KEY` are forced to `block` in `packages/privacy/src/native/host.ts`). A
prompt with an API key therefore gets no host spans: Browser Guard masks it with its rules
as usual, but the page says names and addresses were checked "with built-in rules only:
the AIDR Privacy helper app could not be used", although the host is connected.

## Installing the host (administrators)

Nothing in the extension installs the host. Follow the privacy package
deployment material. It is the authority on this, and it lists its own unverified
acceptance items:

- `packages/privacy/docs/BROWSER.md` §4: preparing the host and registering it per OS.
- `packages/privacy/deployment/README.md`: MDM and policy fragments, and the review requirements.
- `packages/privacy/native/config.text-only.example.json`: a text-only host config
  (no OCR). Add the approved `ner` block (`packages/privacy/ner/local-provider.example.json`)
  to get NER. Without it the host reports `coverage: "rules-only"` and adds little
  over Browser Guard's own rules.

Browser Guard needs three extra steps:

1. **Admit the Browser Guard extension ID.** The host checks which extension called it.
   Add Browser Guard's published extension ID to `allowedExtensionIds` in the host
   config. Run `node native/prepare-host.mjs --config <abs> --out <abs> --extension-id <browser-guard-id>`.
   `prepare-host.mjs` writes only the one ID you pass into `allowed_origins`. If the
   AIDR Privacy extension must use the same host too, add its
   `chrome-extension://<id>/` origin to the generated
   `com.singularity.aidr_privacy.json` by hand, during review.
2. **Grant `nativeMessaging`.** The extension manifest declares `nativeMessaging` as an
   *optional* permission. The bridge checks it with `chrome.permissions.contains` and
   never launches the host until it has been granted. Browsers only grant an optional
   permission after the user accepts a prompt raised from a user gesture, and policy
   cannot grant it for them, so each user confirms it once on the options page
   (Options → **Protection** → **Advanced name and address detection**): turning on
   **Use the AIDR Privacy helper app** asks for it first, and when the administrator
   enabled the host a **Grant permission** button is shown while it is missing. The
   worker recreates the bridge when the permission is added or removed
   (`permissions.onAdded` / `onRemoved`), so a grant takes effect immediately instead
   of after the 60 s back-off.
3. **Turn it on.** Set managed `useNativeHost: true`, or let users opt in on the
   options page (the key is a user setting unless the administrator manages it; it only
   adds detection, so it is not one of the keys a managed policy locks by default). The
   bridge is created with `enabled` set from the effective `GuardPolicy.useNativeHost`.
   When that is `false` it reports `disabled` and never touches the native-messaging API.

Supported browsers: Chromium-based (Chrome, Edge). The host accepts only
`chrome-extension://` callers, so Firefox is not supported and reports `unavailable`.
On Firefox, `requireNativeNer` therefore blocks every prompt and upload that needs NER,
and `exactData` datasets are never checked (their scans stay incomplete): both fail
closed. Do not turn them on for Firefox fleets.

## Exact-data keys (`exactData`)

Managed policy is readable by every user of the endpoint (`chrome://policy`, the policy
registry keys, `policies.json`), so an `exactData` dataset carries no key. The host
derives one key per dataset from the organisation's EDM secret:
`HMAC-SHA256(secret, "aidr-edm-v2" 0x00 datasetId)`
(`packages/privacy/src/native/edm.ts`). Install the secret file that
`fingerprint-dataset.mjs --new-secret` wrote, and name it in the host config:

```json
{ "version": 1, "allowedExtensionIds": ["<browser-guard-id>"], "exactData": { "secretFile": "/etc/aidr/edm-secret.b64" } }
```

The path must be absolute; the file holds base64 of at least 32 bytes, otherwise the host
refuses to start. When the policy has datasets, the worker forces `useNativeHost` on, asks
the host for their keys (`edm-keys`), keeps them in memory only and gives them to the
content scripts (never to the options page or popup, never to `chrome.storage`). Until a
dataset's key has arrived, every scan with it is reported incomplete, which the guard
treats as not checked (fail closed); the worker asks the host again at most every 30 s.

What this does and does not protect: the secret and the keys are no longer visible in
browser policy, and a dataset key unlocks only its own dataset. The host runs as the
signed-in user, so its config and secret file must be readable by that user: a user who
reads that file, or attaches a debugger to the browser or the content script, can still
obtain the keys and test guesses against the fingerprints. That is why
`fingerprint-dataset.mjs` and the policy refuse datasets whose values are guessable
(below 64 bits of estimated entropy, `minEntropyBits`), see the README "Exact data match".

## Protocol (what the bridge speaks)

The bridge uses the privacy host's native-messaging protocol
(`packages/privacy/src/native/session.ts` and `host.ts`), with its persistent-session
option.

- Framing: Chrome native messaging (a 4-byte little-endian length, then UTF-8 JSON,
  frames up to 512 KiB). Chrome does the framing.
- Every request is `{v:1, id, op, ...}` and every reply must echo `{v:1, id, ok:true}`.
  Only one request is outstanding at a time.
- **One host process for all scans.** The bridge opens one port and sends
  `hello{persistent:true}`; the host answers `persistent: true` and then serves any
  number of documents on that connection, so the host process and its NER worker (the
  model loaded once) stay warm. The bridge starts the host ahead of the first prompt
  (`status()`, called when the policy loads and by the popup) and allows 15 s for that
  cold start (`NATIVE_CONNECT_TIMEOUT_MS`). Scans are queued on the connection, one
  document at a time, each with its own 2 s deadline; at most 8 wait at once. An idle
  host exits after 15 minutes and is started again on demand. A host from an earlier
  release refuses the `persistent` field and exits; the bridge then falls back to a
  plain `hello` and one host process per document, as before (and asks it for no
  exact-data keys).
- Each document: `begin{kind:"text", size, sha256, policyDigest}` →
  `write{offset, data}` in 192 KiB base64 chunks → `commit` → `read{offset}` until
  `done`. An image uses `begin{kind:"image-scan", ...}` (only when `hello` reported
  `ocr: true`) → `write` → `commit`, whose reply is
  `{decision: allow|block|review, reasons, counts, coverage, outputBytes: 0}`; nothing
  is read back. The bridge rejects a reply with output bytes, a foreign policy digest,
  unknown keys or a clean decision with counts. `edm-keys{datasetIds}` (idle only)
  returns `{keys: {datasetId: base64}}`.
- Browser Guard does not share the AIDR Privacy extension's `PolicyJSON`. It echoes
  the `policyDigest` from `hello`, so the **host's** policy decides. If that policy
  blocks text (`textAction: "block"`, or any type configured as `block` or `review`),
  the host returns no output, so the bridge has no spans and returns `null`.
- The host returns sanitised text, not offsets. The bridge rebuilds spans by lining up
  the literal text between `[TYPE]`, `[TYPE~key~token]` or `[REDACTED]` markers
  against the input. When the alignment is ambiguous it takes the widest possible
  span, which over-masks rather than leaking. `label` or `token` masking gives typed
  spans. With `redact` masking, spans get a type only when the host counted a single
  entity type; otherwise the result is `null`.

### Limits and failure handling

| Condition | Result | Counts toward backoff |
|---|---|---|
| Bridge disabled by policy | `status() = "disabled"`, `scanText → null` | no |
| `nativeMessaging` not granted, no runtime API, host not installed | `unavailable`, `null`, next attempt after 60 s | this *is* the backoff |
| Text over 1 MiB (UTF-8), or containing lone surrogates | `null`, host not contacted | no |
| 8 scans already queued on the connection | `null` at once | no |
| The 2 s deadline passes while the scan waits in the queue or for the host to start | `null`; the host start is not interrupted | no |
| The 2 s deadline passes during the scan's own exchange | `null`, port disconnected (host exits; the next scan starts a new one) | yes |
| Host start (process + `hello`) over 15 s | `null`, port disconnected | yes (the status probe backs off at once) |
| Any malformed reply (unknown key, wrong id/offset/ack, bad digest, hash mismatch, non-canonical base64, output contradicting the input) | `null` | yes |
| Host engine failure (`NER_*`, `SCAN_BUDGET`, `CONCURRENCY_LIMIT`, `DISPOSED`) | `null` | yes |
| Host policy block or review | `null` | no (the host is healthy) |

After 3 consecutive failures the bridge marks the host `unavailable` and does not
contact it for 60 s. A success resets the count. Any failure also ends the connection,
so a crashed NER worker is replaced by a fresh host. `scanText` never throws.

**Latency caveat.** The NER model is loaded once per host process, not per scan, and the
host is started before the first prompt. A scan on a warm host still has to finish
within 2 s (2.5 s in the page): a heavy model on a large prompt can exceed it, and with
`requireNativeNer` such a send is blocked. No cold-start or warm-scan latency has been
measured for this release on the target Windows or macOS hardware, and the Windows
launcher is not validated (`prepare-host.mjs` says so). Measure p95 start-up and scan
time with your model on your hardware before you require NER.

## Privacy notes

- Only the string passed to `scanText` is sent: no URL, site, tab, user or policy
  data. The status probe sends only `hello`; `edm-keys` sends only dataset ids.
- The channel is Chrome's stdio pipe to a local process. The bridge opens no socket
  or localhost HTTP endpoint, and it rejects a host whose `hello` does not declare
  `local: true`.
- Nothing is persisted. The bridge does not write to `chrome.storage` or `localStorage`
  and keeps no cache. It zeroes the input and output byte buffers after every
  scan. (JavaScript strings cannot be zeroed. That is a platform limit.)
- Host error text and `chrome.runtime.lastError` are never logged or shown. Callers
  see only `null` (plus the bridge status).
- Each pre-scan and send sends the current editor text to the one running host, so
  the host sees drafts as the user types (debounced to pauses of 250 ms), not only what
  is finally sent. It is a local process under the same user; nothing leaves the
  machine. The host keeps no document between scans: each `begin` discards the
  previous one and its buffers are zeroed.
- The SHA-256 values in the protocol are used only for transfer integrity. They are
  not stored or sent anywhere else.
