# Installing Browser Guard

[Türkçe](browser-guard.tr.md)

Singularity AIDR Browser Guard checks what you send to AI chat tools (ChatGPT,
Gemini, Claude, Microsoft Copilot, Perplexity, DeepSeek, Mistral Le Chat, Grok) and
replaces personal and confidential data with placeholders before it leaves your
browser. The original values come back in the answers, on your computer only.

**Is your computer managed by your company?** Then your IT team installs Browser
Guard for you and you do not need to do anything; it appears in the toolbar marked
"Managed by your organization". Administrators: see
[browser-guard-enterprise.md](browser-guard-enterprise.md).

## Install

You need the install link from your Singularity contact or your organisation. The
listings are unlisted: they do not show up in store search, but they install like any
other extension.

| Browser | Steps |
|---|---|
| Google Chrome 120+ | Open the Chrome Web Store link, click **Add to Chrome**, then **Add extension**. |
| Microsoft Edge 120+ | Open the Edge Add-ons link, click **Get**, then **Add extension**. |
| Mozilla Firefox 140+ | Open the `.xpi` link your organisation gives you and confirm **Add**. |

The browser warns that the extension can "Read and change your data" on the listed AI
sites and "Block content on any page". The first is how it checks your prompts on those
sites; the second is used only to block AI sites your organisation does not allow.

After installing, click the puzzle-piece icon and pin **Singularity AIDR Browser
Guard** to the toolbar. AI tabs that were already open are protected without a reload;
if the popup says **Not protected — reload this tab**, reload it.

## Check that it works

1. Open one of the supported AI sites.
2. Type a test address such as `jane.doe@example.com` in the prompt and send it.
3. The site receives `[EMAIL_1_xxxx]` instead of the address; a small "1 item masked: 1 EMAIL"
   note appears, and the answer shows the original address again.

The toolbar popup shows whether the current tab is protected and how many items were
masked in this session.

## Good to know

- All checks run in your browser. Nothing is sent to Singularity. If your organisation
  connects its AIDR control plane, only counts are reported (for example "2 e-mail
  addresses masked on ChatGPT"), never what you typed. Privacy policy:
  [store/privacy-policy.en.html](../../packages/browser-guard/store/privacy-policy.en.html).
- It does not run in private or guest windows, in other browsers, in desktop AI apps,
  or on voice input.
- Names and addresses written without a label ("Name:", "Address:") need the optional
  AIDR Privacy helper program, which your IT team installs separately.
- To remove it: right-click the toolbar icon > **Remove from Chrome** / **Remove from
  Microsoft Edge**, or `about:addons` in Firefox. A copy installed by your organisation
  can only be removed by your IT team.
