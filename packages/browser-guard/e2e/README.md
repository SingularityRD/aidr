# Browser Guard real-browser E2E

Loads the built, unpacked extension into Chromium and drives simulated AI chat
pages the way a user would, then checks what would have left the browser.
No real product is ever contacted: the real origins (`https://chatgpt.com`,
`https://gemini.google.com`, `https://claude.ai`, `https://copilot.microsoft.com`,
`https://www.perplexity.ai`, `https://chat.deepseek.com`, `https://chat.mistral.ai`,
`https://grok.com`, plus `https://example.org` for the generic adapter)
are served from `fixtures/` through Playwright's `context.route`, and every other
origin is aborted, so the run is hermetic and every request is recorded.

```bash
pnpm test:e2e:browser-guard                         # build the extension + run everything
node packages/browser-guard/e2e/run.mjs --self-test # verify the harness only (no build needed)
node packages/browser-guard/e2e/run.mjs --only auto,mode-block
node packages/browser-guard/e2e/run.mjs --list
```

| Flag | Meaning |
|------|---------|
| `--ext <dir>` | unpacked extension (default `packages/browser-guard/dist/chrome`) |
| `--only <ids>` | comma-separated scenario ids or id prefixes (`auto` = every `auto-*`) |
| `--headed` | show the browser |
| `--self-test` | use a generated throwaway MV3 extension (see below) |
| `--report <file>` | JSON report path (default `e2e/report.json`, gitignored) |
| `--list` | list scenarios |

Exit code `0` = all selected scenarios passed (skips allowed), `1` = a scenario
failed, `2` = the harness could not start (no build, no browser, extension not
loaded). A summary table is printed; failures list every failed check, page
errors and a screenshot in `e2e/artifacts/` (gitignored).

## Browser launch

Requires `playwright-core` (devDependency, pinned to 1.63.0) and its Chromium
build (`chromium-1243`, Chrome for Testing 153.0.8010.12). With `PLAYWRIGHT_BROWSERS_PATH`
unset, `/opt/pw-browsers` is used when present. Install the pinned build with the
package's own Playwright (Windows/macOS: no `--with-deps`):

```bash
node packages/browser-guard/node_modules/playwright-core/cli.js install --no-shell chromium
```

1. **Primary:** `chromium.launchPersistentContext(tmpProfile, { channel: "chromium",
   headless: true, args: ["--disable-extensions-except=<ext>", "--load-extension=<ext>"] })`.
   The `chromium` channel runs the full Chromium build in new-headless mode, which
   loads unpacked extensions (the old headless shell cannot). Verified with
   Chromium 141.0.7390.37 (`chromium-1194`).
2. **Fallback:** an explicit `executablePath`, `headless: false` plus `--headless=new`.
   Used only when the primary does not produce a service worker in time (or its
   pinned Chromium revision is not installed). The executable is `BG_E2E_CHROMIUM`
   when set; otherwise the pinned `chromium-<revision>` from the Playwright browser
   directories (`PLAYWRIGHT_BROWSERS_PATH`, `/opt/pw-browsers`,
   `%LOCALAPPDATA%\ms-playwright`, `~/.cache/ms-playwright`,
   `~/Library/Caches/ms-playwright`); if that revision is missing, the newest
   installed `chromium-*` is used and a `chromium: ... is not installed; using
   chromium-<n>` line is logged.

The extension id is taken from the service worker URL
(`chrome-extension://<id>/...`). The worker is found by listening for the
`serviceworker` event and polling `context.serviceWorkers()`; the first start of
a fresh profile on a loaded machine can take a while, so the deadline is 30s
(`BG_E2E_WORKER_TIMEOUT_MS`). If no worker has shown up after 5s, the harness
opens the extension's popup (the unpacked extension id is the first 128 bits of
SHA-256 of its absolute path, hex digits mapped to `a`-`p`), which messages and
so starts the worker. The report records which launch mode was used.

## How the harness talks to the extension

- **Content script ready:** a CDP `Runtime.executionContextCreated` event whose
  origin is the extension (the content script's isolated world).
- **Messages:** `chrome.runtime.sendMessage` from an extension page (the popup)
  with the `GuardMessage` contract in `src/types.ts` (`GET_POLICY`, `GET_STATS`).
- **Settings:** written to `chrome.storage.local.userSettings` from the service
  worker (`worker.evaluate`); the background reloads its policy on
  `storage.onChanged`. If `GET_POLICY` does not reflect the change within 2s the
  documented `SET_USER_SETTINGS` message is used instead. Each scenario waits
  until the effective policy shows its settings before opening a page.
- **Overlays:** the product renders its bubble/toast in a CLOSED shadow root (the
  host page must not read it), which page scripts and Playwright locators cannot
  enter. Overlays are found over CDP (`DOM.getDocument` with `pierce: true`) by
  `aidr|browser-guard|privacy-guard` in tag/id/class/`data-*`; bubble buttons are
  found in Chromium's accessibility tree by role and name and clicked with the mouse.
- **What the user sees vs. what the page reads:** restored values are also shown
  from a closed shadow root. `lastResponseText` reads the reply from the CDP
  accessibility tree (rendered flat tree: closed shadow content in, aria-hidden
  out) - the user's view; `lastResponsePageText` reads `innerText` in the page -
  what the chat app's own scripts see, which must still be the placeholder.

## Fixtures

`fixtures/kit.js` is shared page behaviour that mimics the real frameworks:
the prompt is read from the editor DOM at send time, Enter sends, Shift+Enter
inserts a newline/paragraph, the send button follows `input` events, the reply
streams in over several DOM updates, and file inputs upload the file bytes on
`change`. Pages POST `{site, prompt}` to the product-like endpoint; the route
layer records the body and answers with a fake model reply that echoes the
placeholders it received (`I will follow up with [EMAIL_1] and [IBAN_1] ...`).

| Page | Editor | Send | Reply |
|------|--------|------|-------|
| `chatgpt.html` | `div#prompt-textarea.ProseMirror` | `button[data-testid=send-button]` | `[data-message-author-role=assistant]` |
| `gemini.html` | `rich-textarea > div.ql-editor` | `button.send-button` | `message-content` |
| `claude.html` | `div.ProseMirror[contenteditable]` | `button[aria-label="Send message"]` | `.font-claude-message` |
| `copilot.html` | `textarea#userInput` | `button[data-testid=submit-button]` | `[data-content=ai-message]` |
| `perplexity.html` | `textarea[placeholder]` | `button[data-testid=submit-button]` | `div[id^=markdown-content-]` |
| `deepseek.html` (`https://chat.deepseek.com`) | `textarea#chat-input` | `div[role=button][aria-label=Send]` (no `<button>`) | `.ds-markdown` |
| `mistral.html` (`https://chat.mistral.ai`) | `form div.ProseMirror` (form submit) | `button[aria-label="Send question"]` | `[data-message-author-role=assistant]` |
| `grok.html` (`https://grok.com`) | `div.tiptap.ProseMirror` (form submit) | `form button[type=submit]` | `div[id^=response-].items-start .response-content-markdown` |
| `generic.html` | `form textarea` (form submit) | `button[type=submit]` | `#log article` |
| `internal.html` (`https://ai.internal.example`) | `textarea#corp-composer` | `button.corp-send` (no submit type, no "send" label) | `.corp-answer` |

| `office-word.html` (`https://word-edit.officeapps.live.com`) | `textarea#doc-comment` (the document's comment box; not a protected site) | `#doc-comment-post` | `#comments article` |
| `m365-copilot-pane.html` (`https://copilot.cloud.microsoft`, embedded by `office-word.html` as `iframe#copilot-pane`) | `#m365-chat-editor-target-element` (Lexical-style contenteditable) | `button.fai-SendButton` | `[data-testid=markdown-reply]` |

`generic.html` is also served at `https://poe.com` (a catalogued Shadow AI service),
so that a page would load there if the product's block rule did not act.

## Scenarios

| Id | What it proves |
|----|----------------|
| `preflight` | extension worker running, fixtures routed, bodies recorded, leak detector works, non-fixture origins refused (always runs first; a failure stops the run) |
| `auto-<site>` | auto mode masks email, TCKN `10000000146`, TR IBAN and an `sk-proj-` key on every site; the recorded body has placeholders only; the reply shows the original email to the user while the page's own `innerText` still reads the placeholder; nothing leaks |
| `entities-<site>` | on all eight built-in sites (ChatGPT, Gemini, Claude, Copilot, Perplexity, DeepSeek, Mistral, Grok) the customer-demo data set (`DEMO_PROMPT` in `lib/data.mjs`: e-mail, `+90 532 ...` mobile, TCKN, spaced TR IBAN, Luhn-valid card, OpenAI/GitHub/AWS-shaped keys) is masked, one placeholder per value (three distinct `SECRET`s); the reply shows every restorable original to the user while the page reads placeholders; the three keys stay placeholders (`neverRestore`) |
| `paste-entities-chatgpt` | the same text pasted: the editor and the sent body hold placeholders only |
| `native-host-fallback` | `useNativeHost: true` with no reachable host (no `nativeMessaging` grant in the test profile): the prompt is still masked by the in-browser rules, and a notice says names/addresses were checked with built-in rules only |
| `native-host-connected` | **opt-in** (`BG_E2E_NATIVE_HOST=1`; needs `packages/privacy` built): registers the real privacy host (`dist/native/host.js`, text-only config admitting the test extension id) for **Chromium only** with `scripts/native-host.mjs` (Windows HKCU / Linux `~/.config/chromium`), in a managed copy with `useNativeHost` and the `nativeMessaging` grant; the worker reports the host `connected`, `NATIVE_SCAN` returns host spans (an unlabelled street address), a prompt is masked without the rules-only notice; text with API keys is refused by the host's own policy (`findings: null`, documented limitation); the registration is removed at the end. Skipped if a Chromium registration already exists |
| `paste-chatgpt`, `paste-copilot` | pasted text lands in the editor as placeholders |
| `mode-monitor` | monitor mode sends the original prompt |
| `mode-disabled-site` | with `disabledSites: ["chatgpt"]` the original prompt is sent, and the send is still counted (the worker's per-type stats grow); the setting is reset afterwards |
| `mode-block` | block mode: no request, the page's send never runs, a bubble is shown |
| `mode-confirm` | confirm mode: bubble first, "Send masked" sends placeholders |
| `file-upload-csv` | a CSV with emails reaches the page's upload handler masked |
| `popup-status` | local settings drive the policy (nothing locked); the popup, loaded while the ChatGPT tab is active (as a toolbar click would), reports that tab as protected with its mode and non-zero stats |
| `clean-*` | text without findings is sent byte-for-byte |
| `shift-enter-*` | Shift+Enter inserts a newline and does not send |
| `edit-resend-chatgpt` | after a clean send, "Edit message" on the sent turn opens an edit form whose own primary "Send" button has no `data-testid`/`aria-label`; editing in the sensitive prompt and clicking that button sends placeholders only (one request, nothing leaks) |
| `restore-side-channels` | a hostile page cannot read restored values back: per-character `@font-face` fonts (page family and shadowed system font names, forced with `!important`) are never fetched for restored values while page text in the same fonts is (control); every restored value has the same box while the same values as page text differ in width (control); `window.find()` and select-all do not see them while page text is found (control); a sent placeholder written into a container created before the send, and a placeholder of a deleted masked paste in a new container, are not restored. With the previous inherited-font text-node rendering the font, width and find checks fail |
| `reload-restore` | after a masked send the tab's vault is in `chrome.storage.session` under `vault:<tab>:<origin>` (never in `storage.local`) and the content script's own world cannot read that area; after `page.reload()` the fixture re-renders the conversation (kept in the page's `sessionStorage`, like an SPA refetching history) and the reply shows the original email again while page `innerText` still reads the placeholder; another tab with the same placeholder does not restore it; closing the tab removes its vault |
| `frame-copilot-office` | the Microsoft 365 Copilot pane inside an Office web app: the Office page (`office-word.html`) embeds the pane (`m365-copilot-pane.html`) as a cross-origin iframe. The manifest declares `content.js` with `all_frames: true` for the pane's host; the content script's world exists in the pane frame (found over a CDP session on the out-of-process frame) and not in the Office page's frame; a prompt typed into the pane and sent with Enter carries placeholders only (one request, nothing leaks); the pane's reply shows the original email to the user while the pane's `innerText` keeps the placeholder; the Office page's own comment box is sent as typed (control: the guard does not run on the Office app). With `all_frames: false` the scenario fails (checked when it was written). The pane's markup follows `src/sites/copilot.ts`, not a live tenant (BG-LIVE). Skipped in `--self-test` (the self-test extension is top-frame only) |
| `blocked-site` | a navigation to a site with the navigation block rule `src/background/dnr.ts` installs for `blockedSites: ["gemini"]` is refused (`ERR_BLOCKED_BY_CLIENT`, nothing reaches the site) and the worker opens `blocked.html` in the tab, which loads its `ui.css` and `popup.js` and names the site. `blocked.html` is not web accessible: a web page cannot load it by the extension id while the extension's own page can (control). The rule is installed from the worker (managed storage cannot be written from a test) after the worker's start-up policy load; the policy-to-rule mapping is unit-tested |
| `custom-site` | in a managed deployment (below) with `customSites` for `https://ai.internal.example` and access granted to that host: the worker registers `content.js` for exactly that origin (`chrome.scripting`), the options-page status reports it granted and active, a click on the portal's own button (recognised only through the policy's `sendButtonSelectors`) sends placeholders only, and the reply in its `.corp-answer` block (only the policy's `responseSelectors`) shows the original email to the user while page `innerText` keeps the placeholder. With the policy's send/response selectors removed the scenario fails (checked when it was written) |
| `shadow-ai` | in the same managed deployment with `shadowAi: block-unsanctioned` (the eight built-in sites sanctioned) and access granted to `https://poe.com`: the worker installs a navigation block rule for poe.com and none for sanctioned services; a sanctioned site (Perplexity) opens; a navigation to `https://poe.com/chat/...` is refused (`ERR_BLOCKED_BY_CLIENT`, nothing reaches the fixture served there) and lands on `blocked.html?service=poe` naming "Poe"; the counts show poe blocked and perplexity visited; origins still missing for other catalogued services are reported; `storage.local` holds ids and counts only (no URL, host or path) |
| `work-accounts-block` | in a managed deployment with `workAccounts: block` (Gemini allowed for `acme.example`, ChatGPT for one workspace id): Gemini signed in with a personal gmail.com account (`/u/2/app`, `fixtures/gemini-account-personal.html`, Turkish Google bar) and ChatGPT with `_account=personal` cannot send (a bubble explains the company-account rule, no prompt request, the page never calls its send, no value leaks); the Workspace account (`/u/1/app`, `fixtures/gemini-account-workspace.html`) and the company ChatGPT workspace (`_account` cookie set as the site would) send masked prompts; the refused sends are counted |
| `work-accounts-warn` | `workAccounts: warn` (Gemini allowed for `acme.example`): the first send from a personal account is held with a Continue / Cancel warning and nothing is sent; after Continue, pressing send again sends the masked prompt once |
| `work-accounts-mask-only` | `workAccounts: mask-only` under managed `mode: monitor`: consumer Copilot (`copilot.microsoft.com`, a personal account by host) is masked anyway, while Microsoft 365 Copilot Chat at `copilot.cloud.microsoft/chat` (`fixtures/m365-copilot-chat.html`, account manager showing an `acme.example` user) stays in monitor mode and sends the prompt unchanged |

**Managed deployment (`lib/managed-deployment.mjs`).** Two things cannot be done from
a test in Chromium: writing `chrome.storage.managed` (the CDP Extensions domain refuses
it as a read-only store) and accepting `chrome.permissions.request`'s native prompt
(browser UI with no automation switch). The `custom-site`, `shadow-ai` and `work-accounts-*`
scenarios therefore launch a second browser with a copy of the build in which `background.js`
starts with a prelude answering `chrome.storage.managed.get` with the scenario's policy,
and the origins a user would grant are listed in `host_permissions` (for the browser a
granted optional host permission and a manifest host permission are the same active
permission). Everything else is the product build byte for byte; the options-page grant
flow itself is covered by `ui-ai-access.test.ts`.

Test data (`lib/data.mjs`) is synthetic and checksum-valid; TCKN and IBAN are
re-verified at import time. Scenarios whose site is not in the manifest's
`content_scripts` matches are reported as skipped, not passed.

Waits are condition polls with deadlines (`lib/expect.mjs`); "must not happen"
checks (block, Shift+Enter) poll for a bounded window.

## Self-test

`--self-test` writes a minimal MV3 extension to `os.tmpdir()`
(`lib/self-test-extension.mjs`) that implements just enough of the message
contract and page behaviour (mask one email on Enter/click/paste/upload,
block/confirm bubbles, local restore) to exercise every scenario with a reduced
data profile. It then runs a negative control: `auto-chatgpt` with the guard in
monitor mode must be reported as failing. A green self-test therefore shows the
harness loads extensions, intercepts origins, records traffic, and that its
assertions can both pass and fail — independent of the product build.

## Limits

- `chrome.storage.managed` cannot be written from a test; managed-policy locking
  is covered by the background unit tests, the popup scenario only checks that
  nothing is locked without a managed policy. The `custom-site` and `shadow-ai`
  scenarios use the managed-deployment copy described above for their policy and
  host-access grant.
- Chromium only; the Firefox build is not driven here.
- Fixtures model the product DOM targeted by `src/sites/*.ts`; they do not track
  live product markup changes.
