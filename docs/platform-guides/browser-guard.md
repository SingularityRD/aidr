# Browser Guard

Singularity AIDR Browser Guard is a browser extension for Chrome, Edge and
Firefox. It stops personal and confidential data from reaching AI chat products
(ChatGPT, Gemini, Claude, Microsoft Copilot, Perplexity, DeepSeek, Mistral
Le Chat and Grok) by replacing it with placeholders before a prompt is sent, and
restores the originals locally in the answer.

- Product and build reference: [`packages/browser-guard/README.md`](../../packages/browser-guard/README.md)
- Deployment examples (GPO, Intune, Jamf, Firefox policies): [`deploy/browser-guard/`](../../deploy/browser-guard/README.md)

---

## For administrators

### 1. Choose how to distribute it

| Browser | Distribution | Install policy |
|---|---|---|
| Chrome | Chrome Web Store listing, or a self-hosted `.crx` + `update.xml` | `ExtensionInstallForcelist` / `ExtensionSettings` |
| Edge | Edge Add-ons listing, the Chrome Web Store build, or self-hosted | `ExtensionInstallForcelist` / `ExtensionSettings` |
| Firefox | Mozilla-signed XPI (addons.mozilla.org or self-hosted unlisted) | `policies.json` `ExtensionSettings` |

Build the store packages with `pnpm package:browser-guard`. It writes
`packages/browser-guard/dist/aidr-browser-guard-{chrome,firefox}-<version>.zip`
and a `SHA256SUMS` file; the zips are reproducible, so you can rebuild from the
tagged source and compare the hashes.

### 2. Decide the policy

Start from the managed values in
[`chrome-managed-policy.example.json`](../../deploy/browser-guard/chrome-managed-policy.example.json)
(`3rdparty.extensions.<id>`). The decisions that matter most:

| Decision | Keys | Recommendation |
|---|---|---|
| What happens when data is found | `mode`, `allowSendAnyway` | `auto` for most users; `confirm` where people need to see what was masked; `block` for highly regulated groups |
| What counts as sensitive | `enabledEntities`, `literals`, `exactData` | keep the defaults, add project code names as `literals`, and customer/employee lists as `exactData` |
| What is never shown again | `neverRestore` | keep `SECRET` and `PRIVATE_KEY` |
| Sites people may not use at all | `blockedSites` | e.g. `deepseek`, if your data policy forbids it |
| Whether users can switch it off | `allowUserPause` | `false` for enforcement, `true` during a pilot |
| Files | `fileHandling`, `maxFileBytes` | `scan` (text files are sanitised); `block` if no uploads to AI sites are allowed |
| Office and PDF documents | `documentHandling` | `mask` (default: Word/Excel/PowerPoint text is masked in place; PDFs with sensitive data are blocked); `block` if documents must not be uploaded at all |
| Reporting | `telemetry`, `policyId` | connect your AIDR control plane to see counts per site and entity type |

### 3. Deploy

Follow the section for your tooling in
[`deploy/browser-guard/README.md`](../../deploy/browser-guard/README.md):
Windows Group Policy or `.reg`, Microsoft Intune, Jamf Pro, Firefox
`policies.json`, or Chrome on Linux. Pilot in `monitor` mode first, then switch
the mode.

### 4. Connect the control plane (optional)

Set `telemetry` to `{ "controlPlaneUrl": "https://<your control plane>",
"apiKey": "<Browser Guard ingest-only key>" }`. Create the key on the dashboard's
API Keys page as a **Browser Guard ingest-only key** (owners and admins) with an
installation limit that fits your fleet. Managed policy is readable by anyone
using the browser profile (`chrome://policy`), so do not deploy a tenant key
there: an ingest-only key can only report `privacy_scan` counts from the
`browser_guard` runtime, for at most its installation limit, and every other
API endpoint refuses it. The extension then posts batches of
`privacy_scan` events to `<controlPlaneUrl>/functions/v1/ingest` about once a
minute. Each event holds only the site id, what the guard did (masked, blocked,
warned, allowed), the channel (prompt, paste, file), counts per entity type and
the policy id. Prompt text, values, masked text, file names and page URLs are
never sent. Failed uploads are retried with backoff from a bounded local queue
and never slow down typing.

### 5. Exact data match

To flag your own records (for example the customer list from a CRM) without
distributing the records themselves:

```bash
node packages/browser-guard/scripts/fingerprint-dataset.mjs \
  --in customers.csv --header --columns full_name,customer_no \
  --dataset-id crm-customers --type PERSON --key-file crm.key.b64 \
  --out crm-customers.json
```

The output holds HMAC-SHA256 fingerprints of normalised values and the HMAC
key, never the values. Add it to `exactData`. Because the key is in the dataset,
treat the dataset as confidential and deliver it only through managed policy.

### 6. Optional: better name and address detection

Names and addresses written without a label are detected by the AIDR Privacy
native host (on-device NER), which you install on the machines
(`packages/privacy/deployment`) together with an NER model you have approved (no
model ships with it). Set `useNativeHost: true` (users can also opt in on the
options page when you do not manage the key). Browsers do not let policy grant the
optional `nativeMessaging` permission, so each user accepts it once on the options
page (**Protection** → **Advanced name and address detection** → **Grant
permission**). Prompts and pastes are then scanned by the host and the rules in
parallel; when the host is not reachable the check is rules-only and the user sees
"Advanced detection is unavailable; built-in rules are active" in the popup and a
"checked with built-in rules only" note in the page. See
[`packages/browser-guard/docs/native-host.md`](../../packages/browser-guard/docs/native-host.md).

### 7. Verify

- `chrome://policy`, `edge://policy` or `about:policies` lists the policy
  without errors.
- The extension popup shows the managed mode with a lock.
- Sending `jane.doe@example.com` on a supported site in `auto` mode delivers
  `[EMAIL_1]` to the site.

### Troubleshooting

| Symptom | Check |
|---|---|
| Extension not installed | The ID/update URL in the forcelist; Firefox: the XPI must be Mozilla-signed |
| Settings not locked | The policy is under the right extension ID; values have the right type (`REG_DWORD` for booleans/integers, JSON text for arrays/objects on Windows). Any managed policy also locks `mode`, `enabledEntities`, `literals`, `maskPaste`, `restoreResponses` and `disabledSites` unless it sets `allowUserOverrides: true` |
| Nothing masked on a site | The site is in the supported list and not in `disabledSites` (a disabled site is only monitored: sends are counted, nothing is masked); `mode` is not `monitor`; the entity type is in `enabledEntities` |
| Names in running text not masked | `useNativeHost` is on, the user granted `nativeMessaging`, the popup says "Advanced detection is connected", and the host config has an approved `ner` block (without one it runs rules-only) |
| No telemetry | `controlPlaneUrl` is `https://`; the API key is valid; the machine can reach the control plane |
| Works in a normal window only | Expected: the extension is not allowed in private/incognito windows |

---

## For end users

### What you will notice

- A shield icon in the toolbar. Click it to see whether the current tab is
  protected, the mode, and how many items were masked in this session.
- When you send a prompt that contains, for example, an email address, an IBAN
  or a Turkish ID number, the site receives placeholders like `[EMAIL_1]` and
  `[IBAN_1]` instead.
- In the answer, the placeholders are shown with your original values again.
  This happens only in your browser; the AI service never sees them. Secrets
  such as API keys and private keys stay masked.
- Pasted text is masked as you paste it, and text files you upload are
  checked and, if needed, uploaded as a cleaned copy.
- Word, Excel and PowerPoint files you upload are checked the same way: the AI
  site receives a copy of the same file in which the sensitive values are
  replaced by placeholders; formatting and everything else stay as they were.
  Files with macros, a password, or links to other files are not uploaded.
- PDF files are checked but cannot be cleaned. If a PDF contains sensitive data
  it is not uploaded; copy the text you need and paste it into the prompt
  instead (pasted text is masked). Scanned PDFs (pictures of pages) cannot be
  read and are uploaded with a warning unless your organisation blocks them.

### Modes

| Mode | What happens when sensitive data is found |
|---|---|
| Auto-mask | It is replaced automatically and the prompt is sent. |
| Confirm | You see what was found and choose to send the masked version or edit. |
| Block | The prompt is not sent until the sensitive data is removed. |
| Monitor | Nothing is changed; findings are only counted. |

If your organisation manages the extension, some settings show a lock and
"Managed by your organization" and cannot be changed.

### Settings you can change

Open the options page from the popup:

- **Protection:** mode, which kinds of data to detect, paste masking, and
  whether original values are shown in answers.
- **Custom terms:** words or names you want masked, such as a project code
  name (2 to 256 characters each).
- **Protection → Advanced name and address detection:** if your IT team installed
  the AIDR Privacy helper app, turn it on here and accept the browser's permission
  prompt.
- **Sites:** turn masking on or off per site. On a site you turn off nothing is
  masked, but how often sensitive data is sent is still counted.
- **Language:** automatic, English or Turkish.
- **Pause:** if allowed, pause protection for 15 minutes from the popup.

### Your privacy

Browser Guard scans on your computer. The original values are kept in memory
only for the current browser session so they can be shown in answers (also
after you reload the page), and are cleared when you close the tab or the
browser. If your organisation has connected the AIDR
control plane, only counts (for example "2 email addresses masked on ChatGPT")
are reported, never what you typed.

### Good to know

- Only the listed AI sites are protected. Other websites, desktop apps and
  mobile apps are not.
- If an AI site changes its design, protection on that site can stop working
  until the extension is updated. Tell your IT team if a site suddenly shows no
  "Protected" status.
- If you copy or share a conversation from the AI site itself, the copy
  contains the placeholders, not your original values.
- Pictures inside documents (screenshots, scanned pages, photos of ID cards)
  are not read. Check them yourself before uploading.
