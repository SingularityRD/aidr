# Browser Guard real-browser E2E

Loads the built, unpacked extension into Chromium and drives simulated AI chat
pages the way a user would, then checks what would have left the browser.
No real product is ever contacted: the real origins (`https://chatgpt.com`,
`https://gemini.google.com`, `https://claude.ai`, `https://copilot.microsoft.com`,
`https://www.perplexity.ai`, plus `https://example.org` for the generic adapter)
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

Requires `playwright-core` (devDependency, pinned to 1.56.1) and its Chromium
build. With `PLAYWRIGHT_BROWSERS_PATH` unset, `/opt/pw-browsers` is used when present.

1. **Primary:** `chromium.launchPersistentContext(tmpProfile, { channel: "chromium",
   headless: true, args: ["--disable-extensions-except=<ext>", "--load-extension=<ext>"] })`.
   The `chromium` channel runs the full Chromium build in new-headless mode, which
   loads unpacked extensions (the old headless shell cannot). Verified with
   Chromium 141.0.7390.37 (`chromium-1194`).
2. **Fallback:** `executablePath: /opt/pw-browsers/chromium-1194/chrome-linux/chrome`
   (override with `BG_E2E_CHROMIUM`), `headless: false` plus `--headless=new`.
   Used only when the primary does not produce a service worker in time.

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
| `generic.html` | `form textarea` (form submit) | `button[type=submit]` | `#log article` |

## Scenarios

| Id | What it proves |
|----|----------------|
| `preflight` | extension worker running, fixtures routed, bodies recorded, leak detector works, non-fixture origins refused (always runs first; a failure stops the run) |
| `auto-<site>` | auto mode masks email, TCKN `10000000146`, TR IBAN and an `sk-proj-` key on every site; the recorded body has placeholders only; the reply shows the original email to the user while the page's own `innerText` still reads the placeholder; nothing leaks |
| `paste-chatgpt`, `paste-copilot` | pasted text lands in the editor as placeholders |
| `mode-monitor` | monitor mode sends the original prompt |
| `mode-disabled-site` | with `disabledSites: ["chatgpt"]` the original prompt is sent, and the send is still counted (the worker's per-type stats grow); the setting is reset afterwards |
| `mode-block` | block mode: no request, the page's send never runs, a bubble is shown |
| `mode-confirm` | confirm mode: bubble first, "Send masked" sends placeholders |
| `file-upload-csv` | a CSV with emails reaches the page's upload handler masked |
| `popup-status` | local settings drive the policy (nothing locked); the popup, loaded while the ChatGPT tab is active (as a toolbar click would), reports that tab as protected with its mode and non-zero stats |
| `clean-*` | text without findings is sent byte-for-byte |
| `shift-enter-*` | Shift+Enter inserts a newline and does not send |
| `restore-side-channels` | a hostile page cannot read restored values back: per-character `@font-face` fonts (page family and shadowed system font names, forced with `!important`) are never fetched for restored values while page text in the same fonts is (control); every restored value has the same box while the same values as page text differ in width (control); `window.find()` and select-all do not see them while page text is found (control); a sent placeholder written into a container created before the send, and a placeholder of a deleted masked paste in a new container, are not restored. With the previous inherited-font text-node rendering the font, width and find checks fail |
| `reload-restore` | after a masked send the tab's vault is in `chrome.storage.session` under `vault:<tab>:<origin>` (never in `storage.local`) and the content script's own world cannot read that area; after `page.reload()` the fixture re-renders the conversation (kept in the page's `sessionStorage`, like an SPA refetching history) and the reply shows the original email again while page `innerText` still reads the placeholder; another tab with the same placeholder does not restore it; closing the tab removes its vault |
| `blocked-site` | a navigation to a site with the navigation block rule `src/background/dnr.ts` installs for `blockedSites: ["gemini"]` is refused (`ERR_BLOCKED_BY_CLIENT`, nothing reaches the site) and the worker opens `blocked.html` in the tab, which loads its `ui.css` and `popup.js` and names the site. `blocked.html` is not web accessible: a web page cannot load it by the extension id while the extension's own page can (control). The rule is installed from the worker (managed storage cannot be written from a test) after the worker's start-up policy load; the policy-to-rule mapping is unit-tested |

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
  nothing is locked without a managed policy.
- Chromium only; the Firefox build is not driven here.
- Fixtures model the product DOM targeted by `src/sites/*.ts`; they do not track
  live product markup changes.
