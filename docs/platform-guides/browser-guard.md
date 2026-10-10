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
| Which other AI services are used, and which are allowed | `shadowAi` | start with `{"mode": "monitor"}` to see usage on the dashboard's **Shadow AI** panel, then list the approved services in `sanctioned` and switch to `block-unsanctioned` |
| Company-internal AI portals | `customSites` | one entry per portal with its exact HTTPS hosts and the CSS selectors of its prompt box, send button and answers |
| Whether users can switch it off | `allowUserPause` | `false` for enforcement, `true` during a pilot |
| Files | `fileHandling`, `maxFileBytes` | `scan` (text files are sanitised); `block` if no uploads to AI sites are allowed |
| Office, OpenDocument and PDF documents | `documentHandling` | `mask` (default: Word/Excel/PowerPoint and ODT/ODS/ODP text is masked in place; PDFs with sensitive data are blocked; legacy .doc/.xls/.ppt are scanned but cannot be masked: blocked when they hold sensitive data, passed with a warning (blocked in `block` mode) when they could not be fully read); `block` if documents must not be uploaded at all |
| Images (screenshots, photos, pictures in documents) | `useNativeHost` + a native host with OCR | with the OCR host, an image showing sensitive data is blocked (it cannot be masked); without it images are uploaded with a "not inspected" warning (blocked in `block` mode). See [`packages/browser-guard/docs/native-host.md`](../../packages/browser-guard/docs/native-host.md) |
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

**Making NER mandatory (`requireNativeNer`).** By default a missing or slow host
only downgrades the check to the built-in rules. Set the managed key
`requireNativeNer: true` (default `false`) when that is not acceptable:

- *What it blocks:* while `PERSON`, `ADDRESS` or `LOCATION` is enabled, a prompt
  send, paste or file upload that the host did not check with NER is blocked ("Your
  organisation requires advanced name and address detection ... Nothing was sent.").
  That includes a host that is not installed, not granted `nativeMessaging`,
  crashed, backed off or slower than the 2.5 s page timeout, a rules-only host (no
  approved `ner` block), and text over the host's 200,000-character limit. A prompt
  with no findings is blocked as well, because no findings without NER is not a clean
  check. In `monitor` mode nothing is blocked; the check is recorded and the
  `privacy_scan` event carries `native_ner: "unavailable"` (or `"used"`).
- *It needs the native host:* it forces and locks `useNativeHost` on, so install
  the host with an approved NER model on every machine and have every user grant
  `nativeMessaging` before you enable it; otherwise every send on that machine is
  blocked. Pilot it in `monitor` mode and check that events report
  `native_ner: "used"`.
- *Large uploads take longer:* every text part of an upload is sent to the host and
  waited on (up to 2.5 s per scan, a new host process each time), and large
  documents are scanned in several windows, so big uploads can be noticeably slower
  than rules-only scanning; one window without an NER answer blocks the whole
  upload. Measure with your largest typical files on your target hardware.

Owners and administrators can also switch the requirement on for every enrolled
browser from the dashboard (**Browser Privacy Guard** → **Require native NER**;
multi-factor verification, audited). It is delivered in the signed dashboard policy
(managed `telemetry` and `dashboardPolicy` must be set) and merged with the managed
key: `true` from either side wins, so the dashboard cannot switch off a managed
requirement. With four-eyes change control on, switching it off in the dashboard is
refused until four-eyes is turned off by a second approver.

### 7. Verify

- `chrome://policy`, `edge://policy` or `about:policies` lists the policy
  without errors.
- The extension popup shows the managed mode with a lock.
- Sending `jane.doe@example.com` on a supported site in `auto` mode delivers
  `[EMAIL_1]` to the site.
- With `shadowAi` or `customSites` set: the options page's **AI services**
  section lists them. Browser Guard cannot see or block other AI services, nor run
  on internal hosts, until the user clicks **Allow access** there once (a managed
  policy cannot grant host access; Browser Guard deliberately does not request the
  `tabs`/browsing-history permission). Tell users to do this during rollout.

### Troubleshooting

| Symptom | Check |
|---|---|
| Extension not installed | The ID/update URL in the forcelist; Firefox: the XPI must be Mozilla-signed |
| Settings not locked | The policy is under the right extension ID; values have the right type (`REG_DWORD` for booleans/integers, JSON text for arrays/objects on Windows). Any managed policy also locks `mode`, `enabledEntities`, `literals`, `maskPaste`, `restoreResponses` and `disabledSites` unless it sets `allowUserOverrides: true` |
| Nothing masked on a site | The site is in the supported list and not in `disabledSites` (a disabled site is only monitored: sends are counted, nothing is masked); `mode` is not `monitor`; the entity type is in `enabledEntities` |
| Names in running text not masked | `useNativeHost` is on, the user granted `nativeMessaging`, the popup says "Advanced detection is connected", and the host config has an approved `ner` block (without one it runs rules-only) |
| Every send blocked with "requires advanced name and address detection" | `requireNativeNer` is on (managed key or the dashboard's **Require native NER**) and the host gave no NER answer: install the host with an approved `ner` block, grant `nativeMessaging` on the options page, and check host start-up time against the 2.5 s timeout |
| No telemetry | `controlPlaneUrl` is `https://`; the API key is valid; the machine can reach the control plane |
| Internal AI portal not masked | The host is listed exactly in `customSites` (no port or path), the options page shows the site as **Protected** (not **Needs access**), and the tab was reloaded after access was granted; check the selectors against the portal's markup |
| Shadow AI shows no usage or does not block | `shadowAi.mode` is `monitor` or `block-unsanctioned`; the options page says "Access granted" (otherwise click **Allow access**); the service is in the catalog (`packages/browser-guard/src/sites/catalog.ts`) |
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
- Word, Excel and PowerPoint files, and OpenDocument files (LibreOffice: .odt,
  .ods, .odp), are checked the same way: the AI site receives a copy of the same
  file in which the sensitive values are replaced by placeholders; formatting and
  everything else stay as they were. Files with macros, a password, or links to
  other files are not uploaded. Old-format .doc, .xls and .ppt files are checked
  but cannot be cleaned: one that contains sensitive data is not uploaded (save it
  as .docx/.xlsx/.pptx to upload a cleaned copy). If AIDR cannot read one fully
  (for example a Word 95 file), you are warned, and your organisation may block it.
- Pictures are not cleaned. If your organisation runs the AIDR Privacy helper with
  text recognition (OCR), a screenshot or a picture inside a document that shows
  sensitive data is not uploaded; crop or black it out first. Without the helper
  you are warned that the picture was not checked.
- PDF files are checked but cannot be cleaned. If a PDF contains sensitive data
  it is not uploaded; copy the text you need and paste it into the prompt
  instead (pasted text is masked). Pictures inside a PDF, including scanned
  pages, are checked by the same text recognition helper when your organisation
  runs it; without it, a PDF with pictures is uploaded with a warning that its
  pictures were not checked, unless your organisation blocks it.

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
- **AI services** (only when your organisation configured it): the internal AI
  sites Browser Guard protects and your organisation's rules for other AI
  services. Click **Allow access** once when asked; Browser Guard then learns only
  which AI service a tab opened (never the page address) and can mask your
  messages on the internal sites. An AI service your organisation has not approved
  may open a "blocked by your organization" page instead.

### Your privacy

Browser Guard scans on your computer. The original values are kept in memory
only for the current browser session so they can be shown in answers (also
after you reload the page), and are cleared when you close the tab or the
browser. If your organisation has connected the AIDR
control plane, only counts (for example "2 email addresses masked on ChatGPT")
are reported, never what you typed. If it also turned on AI service discovery,
the number of visits per AI service (for example "Midjourney: 3 visits") is
reported, never the addresses of the pages you opened.

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
