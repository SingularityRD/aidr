# Personal vs company AI accounts (`workAccounts`)

Many AI services have a consumer product and a company product on the same website:
ChatGPT personal vs a ChatGPT Team/Enterprise/Edu workspace, a personal claude.ai account
vs a Claude Team/Enterprise organisation, Gemini with a gmail.com account vs Gemini with a
Google Workspace account, consumer Copilot vs Microsoft 365 Copilot Chat. The company
product usually comes with a contract that keeps prompts out of model training and under
the company's retention and audit settings; the personal one does not.

With the managed key `workAccounts`, Browser Guard checks which account the user is signed
in with on ChatGPT, Claude, Gemini and Copilot, and does one of three things when it is not
the organisation's account: **warn**, **block** sending, or **mask-only**.

Source: [`src/sites/accounts.ts`](../src/sites/accounts.ts) (detection and classification),
[`src/content/guard.ts`](../src/content/guard.ts) (enforcement),
[`src/background/policy.ts`](../src/background/policy.ts) (validation).

## Policy

```json
{
  "workAccounts": {
    "action": "warn",
    "unverified": "enforce",
    "sites": {
      "chatgpt": { "workspaceIds": ["<your ChatGPT workspace account id>"] },
      "claude":  { "workspaceIds": ["<your Claude organisation UUID>"] },
      "gemini":  { "emailDomains": ["acme.com.tr"] },
      "copilot": { "emailDomains": ["acme.com.tr"] }
    }
  }
}
```

| Field | Values | Meaning |
|---|---|---|
| `action` | `warn` \| `block` \| `mask-only` (required) | What happens on a listed site when the account is not confirmed as the organisation's (below). |
| `unverified` | `enforce` (default) \| `allow` | `enforce`: an account the page does not identify gets the action, like a personal one. `allow`: only accounts recognised as personal or as another organisation's get it. |
| `sites` | `chatgpt`, `claude`, `gemini`, `copilot` (at least one) | Only listed sites are checked. Every other site, and every site when the key is absent, behaves as before. |
| `sites.<site>.workspaceIds` | up to 64 ids, `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, case-insensitive | ChatGPT workspace account ids, Claude organisation UUIDs. |
| `sites.<site>.emailDomains` | up to 64 domains (a leading `@` is accepted), lowercase-compared | The signed-in account's email domain; a subdomain of a listed domain matches (`tr.acme.com.tr` matches `acme.com.tr`, `evilacme.com.tr` does not). |

A site whose two lists are both empty accepts any account the page shows as a work account
(Microsoft 365 Copilot Chat, a ChatGPT workspace, a Google account outside gmail.com). That
is weaker: it also accepts another organisation's work account. List your identifiers.

Where to find the identifiers:

- **ChatGPT workspace id**: the ChatGPT Enterprise/Team admin console (workspace settings).
  In a browser signed in to the workspace it is also the value of the `_account` cookie on
  chatgpt.com (DevTools > Application > Cookies).
- **Claude organisation UUID**: the Claude admin settings (organisation). In a browser signed
  in to the organisation it is also the value of the `lastActiveOrg` cookie on claude.ai.
- **Email domains**: your Google Workspace primary and secondary domains, your Entra ID
  verified domains (the domain part of user principal names).

Validation follows the rest of the managed policy: the key is managed-only and locked. An
invalid value is reported in `policyErrors` and fails safe: every known site in it is kept
with its valid identifiers, `action` becomes `block` and `unverified` becomes `enforce`. If
no known site remains, the key is off (there is nothing to check) and the error is still
reported.

### Actions

| Action | Prompt send | File upload | Paste |
|---|---|---|---|
| `warn` | The first send on the page (per account) is held and a dialog asks **Continue** / **Cancel**. After **Continue** the user presses send again; masking then works as usual for this page. | A one-time warning toast; the upload goes on with the usual checks. | Unchanged. |
| `block` | Refused, in every mode (like a blocked site); nothing reaches the site. | Refused. | Unchanged (nothing is sent by pasting). |
| `mask-only` | Allowed, but always masked: `monitor` mode, a user pause and a user-disabled site do not apply on that account, and **Send original** is not offered. The first masked send explains why. | The usual checks, with the same mask-only policy. | Unchanged. |

All three are organisation rules: they apply in every guard mode. Switching to the company
account in the same tab is picked up at the next send (the check runs on every send, not
once per page load).

### Messages (EN / TR)

The bubble title is "Company account not confirmed" / "Kurum hesabı doğrulanamadı". The
reason line depends on what was recognised; no id, email or domain is ever shown.

| Case | English | Türkçe |
|---|---|---|
| personal | You appear to be signed in to ChatGPT with a personal account. | ChatGPT hizmetine kişisel bir hesapla girmiş görünüyorsunuz. |
| other organisation | This ChatGPT account is not one of your organisation's approved accounts. | Bu ChatGPT hesabı, kurumunuzun onayladığı hesaplardan biri değil. |
| not identified | Singularity AIDR could not confirm that you are signed in to ChatGPT with your organisation's account. | Singularity AIDR, ChatGPT hizmetine kurumunuzun hesabıyla girdiğinizi doğrulayamadı. |
| warn | Share company data only through your organisation's account. Switch accounts, or press Continue if this is intended. | Kurum verilerini yalnızca kurumunuzun hesabıyla paylaşın. Hesabınızı değiştirin; bilerek devam ediyorsanız «Devam et» düğmesine basın. |
| block | Nothing was sent. Your organisation allows ChatGPT only with its company account. Switch to your company account and try again. | Hiçbir şey gönderilmedi. Kurumunuz ChatGPT hizmetini yalnızca kurum hesabıyla kullanmaya izin veriyor. Kurum hesabınıza geçip yeniden deneyin. |
| mask-only | This is not your organisation's account, so sensitive data is always masked here and the original cannot be sent. | Bu, kurumunuzun hesabı değil; bu nedenle burada hassas veriler her zaman maskelenir ve asıl hâli gönderilemez. |

## What each site exposes

Browser Guard reads only what the page itself shows the content script: the page URL, the
page's non-HttpOnly cookies (`document.cookie`) and the DOM. It makes no request of its own
and calls no vendor API. None of these signals is a documented vendor interface; they are
observed markup and cookies, modelled in the hermetic e2e fixtures and **not yet verified
against live tenants** (tracked as BG-LIVE). When a vendor changes its page, the signal
disappears and the account becomes *unverified*: with `unverified: "enforce"` that means
more warnings or blocks, never a personal account passing as a company one.

| Site | Signal id | Where | What it gives | Personal is recognised when |
|---|---|---|---|---|
| ChatGPT (`chatgpt.com`, `chat.openai.com`) | `chatgpt.cookie-account` | `_account` cookie: the active workspace (the web app sends it as the `ChatGPT-Account-Id` header) | workspace id | the cookie value is `personal`; no cookie = not identified |
| Claude (`claude.ai`) | `claude.cookie-org` | `lastActiveOrg` cookie: the active organisation | organisation UUID | never by itself: a personal claude.ai account also has an organisation, so only `workspaceIds` decide (anything else is "other organisation") |
| Gemini (`gemini.google.com`) | `google.account-button` | Google bar account button: `a[href*="//accounts.google.com/SignOutOptions"]`, accessible name "Google Account: Name (user@domain)" in every UI language | email domain | the domain is `gmail.com` or `googlemail.com` |
| Microsoft Copilot (`copilot.microsoft.com`) | `copilot.host` | host | consumer product | always: the consumer host is a personal (Microsoft) account, whatever its email domain |
| Microsoft 365 Copilot Chat (`m365.cloud.microsoft`, `copilot.cloud.microsoft`) | `copilot.host`, `m365.me-control` | host (Entra ID work accounts only); account manager `#mectrl_currentAccount_secondary` (user principal name) | work account, email domain | the user principal name is on outlook.com, hotmail.com, live.com, msn.com or passport.com |

Fixtures: [`e2e/fixtures/gemini-account-workspace.html`](../e2e/fixtures/gemini-account-workspace.html),
[`gemini-account-personal.html`](../e2e/fixtures/gemini-account-personal.html) (Turkish Google
bar), [`m365-copilot-chat.html`](../e2e/fixtures/m365-copilot-chat.html); the ChatGPT and
Claude cookies are set by the scenario as the site would set them
([`e2e/scenarios/work-accounts.mjs`](../e2e/scenarios/work-accounts.mjs)). Unit tests load the
same fixture pages ([`src/__tests__/work-accounts.test.ts`](../src/__tests__/work-accounts.test.ts)).

## What cannot be detected

- **Desktop and mobile apps**: the ChatGPT, Claude and Copilot desktop apps, the Microsoft 365
  Copilot app, mobile apps, and AI features inside other desktop software. Browser Guard runs
  only in Chrome, Edge and Firefox.
- **Safari** and any other browser without the extension (there is no Safari build), and
  private/incognito windows where the extension is not allowed.
- **Perplexity, DeepSeek, Mistral, Grok and custom sites**: no account signal is read there;
  they cannot be listed in `workAccounts`. Use `blockedSites` or `shadowAi` for them.
- **A consumer Google account created with a company email address** (a "conflicting" or
  unmanaged account): its email domain is the company's, so it is accepted on Gemini. Find
  and transfer such accounts in the Google Admin console (unmanaged accounts transfer tool).
- **A personal ChatGPT account** shows no workspace cookie and is "not identified" rather than
  "personal" unless the cookie says `personal`; keep `unverified: "enforce"` for ChatGPT.
- **HttpOnly cookies**: if a vendor makes `_account` or `lastActiveOrg` HttpOnly, the content
  script can no longer read it and the account becomes "not identified".
- **Which Microsoft 365 tenant**: the Copilot pages expose the user principal name, not the
  tenant id. A guest account in your tenant, or a work account of another tenant with a
  listed domain, cannot be told apart in the page.
- **The account behind an API key or a model console** (platform.openai.com, console.anthropic.com,
  AI Studio): out of scope; govern those with `shadowAi` and API key management.

## Recommended complementary controls

Browser Guard's check is an in-browser control for managed browsers. For enforcement that
also covers desktop apps, other browsers and unmanaged devices on the corporate network, pair
it with controls at the identity provider and the egress proxy (each vendor's current
documentation is authoritative; header names and plan availability change):

- **Microsoft (Copilot, Microsoft 365)**: Entra ID **Tenant Restrictions v2** (the proxy or
  Windows GPO adds the `sec-Restrict-Tenant-Access-Policy` header, or v1
  `Restrict-Access-To-Tenants` / `Restrict-Access-Context`), so only your tenant's work
  accounts can sign in through the corporate network. Block consumer Copilot
  (`copilot.microsoft.com`) with `shadowAi` (`copilot` service) if it is not sanctioned, and
  keep `m365-copilot` sanctioned.
- **Google (Gemini)**: at a TLS-inspecting proxy, add the `X-GoogApps-Allowed-Domains` header
  with your Workspace domains to block consumer Google accounts on Google services; turn the
  Gemini app on for the Workspace organisational units that may use it; transfer unmanaged
  accounts that use your domain.
- **ChatGPT**: ChatGPT Enterprise/Edu **domain verification** with SSO enforcement, so sign-ins
  with your domain land in the company workspace instead of a personal account. OpenAI also
  describes network-level workspace restrictions for proxies that inspect TLS; check the
  current mechanism and plan availability in OpenAI's enterprise documentation.
- **Claude**: Claude for Enterprise/Team SSO with domain capture, so accounts on your domain join
  the organisation. Check Anthropic's enterprise documentation for network-level organisation
  restrictions at the proxy.
- **Desktop apps**: allow or block them with your application control (Intune, AppLocker,
  WDAC, Linux package policy); Browser Guard does not see them.
- **Other browsers**: make the managed Chrome/Edge/Firefox with Browser Guard the only allowed
  browser on managed endpoints.

## Telemetry and privacy

The email local part is discarded as soon as the domain is read. The workspace id and domain
stay in the content script, are compared with the policy and are never stored, logged or
sent. On a site listed in `workAccounts`, each `privacy_scan` event carries an additive
`account_type` enum (`company`, `personal`, `other`, `unverified`), counts only, per
[`docs/contracts/privacy-telemetry.md`](../../../docs/contracts/privacy-telemetry.md). A held
`warn` send is recorded as `warned`, a refused send or upload as `blocked`.

## Status

- Implemented in the extension with unit tests and hermetic e2e scenarios
  (`work-accounts-block`, `work-accounts-mask-only`).
- Not yet verified against live ChatGPT, Claude, Gemini and Microsoft 365 tenants (BG-LIVE):
  someone with a personal and a company account on each service must confirm the signals
  above before this is sold as a control, and re-check them on each vendor UI change.
- The control plane's ingest projection does not store `account_type` yet (an older server
  drops it and still accepts the event); dashboard reporting on it is a follow-up.
