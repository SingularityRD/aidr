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
- Uploaded text files and documents are not sent to the host for NER; they are
  scanned by the rules only. Images are, for OCR (next section).

## How uploads use it (OCR)

With `useNativeHost: true` and a host whose `hello` reports `ocr: true` (a `visual`
block in the host config, i.e. local Tesseract with the Turkish and English data):

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
  `DOCUMENT_IMAGES_NOT_INSPECTED` for pictures in a document): uploaded with a
  warning, blocked in `block` mode, never treated as clean.

## What it adds

The in-browser rule layer is good at identifiers with a fixed shape or checksum: email,
phone, IBAN, TC Kimlik, card numbers, keys and secrets, IP/MAC, and similar. It cannot
reliably find things that have no fixed shape:

| Entity | Rule layer alone | With a host NER model |
|---|---|---|
| `PERSON` (a name in running text) | Only with context words or administrator literals | Detected from the model |
| `ADDRESS` | Only with address cue words (e.g. "Adresim") | Street/building phrases without a cue |
| `LOCATION` | Administrator literals only | Detected from the model |

How much this helps depends entirely on the NER model the administrator installs.
`packages/privacy` ships the host and the `LocalNerProcess` protocol, but **no model
weights and no quality evidence**. Measure precision and recall on your own data
before you depend on it. The host's own rule layer also runs, so a host result can
repeat a span Browser Guard already found locally. Callers merge the two sets. Every
host span has `source: "native-ner"` and a fixed score of `0.9`, because the host
applies policy decisions and does not export per-span scores.

## Installing the host (administrators)

Nothing in this package installs or registers the host. Follow the privacy package
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

## Protocol (what the bridge speaks)

The bridge uses the privacy host's native-messaging protocol exactly
(`packages/privacy/src/native/session.ts` and `host.ts`). It adds no extensions to it.

- Framing: Chrome native messaging (a 4-byte little-endian length, then UTF-8 JSON,
  frames up to 512 KiB). Chrome does the framing.
- Every request is `{v:1, id, op, ...}` and every reply must echo `{v:1, id, ok:true}`.
  Only one request is outstanding at a time.
- Each scan uses its own port and host process: `hello` → `begin{kind:"text", size,
  sha256, policyDigest}` → `write{offset, data}` in 192 KiB base64 chunks → `commit`
  → `read{offset}` until `done`. An image uses `begin{kind:"image-scan", ...}` (only
  after `hello` reported `ocr: true`) → `write` → `commit`, whose reply is
  `{decision: allow|block|review, reasons, counts, coverage, outputBytes: 0}`; nothing
  is read back. The bridge rejects a reply with output bytes, a foreign policy digest,
  unknown keys or a clean decision with counts. The status probe sends a single `hello` (via
  `sendNativeMessage`, or a port when that API is missing).
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
| More than 2 scans already in flight | `null` | no |
| Whole exchange (permission check + all round trips) over **2 s** | `null`, port disconnected (host exits) | yes |
| Any malformed reply (unknown key, wrong id/offset/ack, bad digest, hash mismatch, non-canonical base64, output contradicting the input) | `null` | yes |
| Host engine failure (`NER_*`, `SCAN_BUDGET`, `CONCURRENCY_LIMIT`, `DISPOSED`) | `null` | yes |
| Host policy block or review | `null` | no (the host is healthy) |

After 3 consecutive failures the bridge marks the host `unavailable` and does not
contact it for 60 s. A success resets the count. `scanText` never throws.

**Latency caveat.** The host starts a new process for each scan and loads the NER
model at startup, so a heavy model plus a large prompt can go over the 2 s budget.
A send waits for the answer (at most 2.5 s in the page); text typed and paused on is
pre-scanned, so the wait usually happens before Enter. When timeouts keep happening
the bridge backs off, and the prompt stays protected by the local rules only (and the
user is told so). Check host start-up time on your target hardware before you depend
on NER.

## Privacy notes

- Only the string passed to `scanText` is sent: no URL, site, tab, user or policy
  data. The status probe sends only `hello`.
- The channel is Chrome's stdio pipe to a local process. The bridge opens no socket
  or localhost HTTP endpoint, and it rejects a host whose `hello` does not declare
  `local: true`.
- Nothing is persisted. The bridge does not write to `chrome.storage` or `localStorage`
  and keeps no cache. It zeroes the input and output byte buffers after every
  scan. (JavaScript strings cannot be zeroed. That is a platform limit.)
- Host error text and `chrome.runtime.lastError` are never logged or shown. Callers
  see only `null` (plus the bridge status).
- Each pre-scan and send starts a host process for the current editor text, so the
  host sees drafts as the user types (debounced to pauses of 250 ms), not only what is
  finally sent. It is a local process under the same user; nothing leaves the machine.
- The SHA-256 values in the protocol are used only for transfer integrity. They are
  not stored or sent anywhere else.
