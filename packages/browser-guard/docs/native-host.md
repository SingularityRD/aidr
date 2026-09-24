# Browser Guard native host (optional NER)

Browser Guard does all of its detection inside the browser with the AIDR Privacy rule
layer. An administrator can also connect it to the **AIDR Privacy native host**
(`com.singularity.aidr_privacy`, shipped by `packages/privacy`). The host runs on the
endpoint and adds learned named-entity recognition (NER). Browser Guard sends it
the prompt text and gets back extra spans.

The host is optional. Without it, every prompt is still scanned, masked and
restored locally. The bridge (`src/background/native.ts`) returns `null` and callers
keep their local findings.

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
2. **Grant `nativeMessaging`.** The extension manifest must declare `nativeMessaging` as
   an *optional* permission. The bridge checks it with `chrome.permissions.contains` and
   never launches the host until it has been granted. A user can grant it by accepting
   the prompt from a user gesture on the options page. On managed fleets, list it in
   the extension's allowed permissions policy.
3. **Turn it on in policy.** The bridge is created with `enabled` set from the
   effective `GuardPolicy.useNativeHost`. When that is `false` it reports `disabled`
   and never touches the native-messaging API.

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
  → `read{offset}` until `done`. The status probe sends a single `hello` (via
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
When that keeps happening the bridge backs off, and the prompt stays protected by
the local rules only. Check host start-up time on your target hardware before you
depend on NER.

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
  see only `null`.
- The SHA-256 values in the protocol are used only for transfer integrity. They are
  not stored or sent anywhere else.
