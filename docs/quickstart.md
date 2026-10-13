# Quickstart: from zero to protected

[Türkçe](quickstart.tr.md)

One page for each person who installs Singularity AIDR: a developer on a laptop, an
office user in the browser, and the IT admin who rolls it out. Each part ends with a
check that proves it works.

> **Availability.** Singularity AIDR is not yet released for customer use (see
> [Release status](../README.md#release-status)). The steps below apply once a release is
> approved and your organisation has published its installers and Browser Guard store
> links; until then the Downloads page and the store links stay empty.

Two things are true at the same time, and they do not conflict:

- **Protection runs on your computer and needs no account.** Every command, file and web
  request your AI tool tries is checked on the machine itself, even with no network and
  before anyone signs in.
- **A release build first checks that it is genuine.** It carries a release key and
  refuses to start (it blocks every action and says so) if its own files or that key do
  not check out. The desktop installers already contain the key, so you do nothing extra.
  Signing in to your company's AIDR dashboard only adds central features (dashboard,
  central rules, approvals in the browser); without it, local protection keeps working.

## A. Developer laptop (Windows or Linux)

Supported AI tools: Claude Code, OpenCode and OpenClaw are set up by the installer.
Codex, Cursor and VS Code (Cursor and VS Code: preview — no real-host acceptance evidence
yet) need one extra step that `aidr status` prints for you.

1. **Download.** Sign in to your company's AIDR dashboard and open **Downloads** (under
   **Devices & downloads**). The page
   picks the installer for your system. It also shows each file's SHA-256 and a command to
   compare it; use it if your company asks you to.
2. **Install.**
   - Windows 10/11: double-click `singularity-aidr-<version>-windows-x64.msi` and accept
     the prompt.
   - Debian / Ubuntu:

     ```sh
     sudo apt install ./singularity-aidr_<version>_amd64.deb
     ```

   - RHEL / Fedora:

     ```sh
     sudo rpm --import linux-package-signing-key.asc
     sudo dnf install ./singularity-aidr-<version>-1.x86_64.rpm
     ```

   - Any other Linux:

     ```sh
     tar -xzf singularity-aidr-<version>-linux-x64.tar.gz
     sudo ./singularity-aidr-<version>-linux-x64/install.sh
     ```

   The installer sets AIDR up for you (the user who ran it) at the end, including the
   release key, so there is nothing to configure. If none of your AI tools is installed
   yet, it says "No AI tool … was found" and finishes anyway (setup exit code `3`, not an
   error): install your AI tool, then run `aidr setup` once.
3. **Restart your AI tools.** A tool that was already open picks up AIDR only after a
   restart.
4. **Check.** Open a new terminal and run:

   ```sh
   aidr status
   aidr verify
   ```

   `aidr status` ends with one line that lists the protected tools, the tools to restart
   and the tools that need a manual step, with the exact command. `aidr verify` sends a
   harmless test command through each protected tool's AIDR check (nothing is run) and
   prints **PASS**, **FAIL** or **SKIP** for each one. You are done when your tools show
   PASS. SKIP means the check lives inside the tool (OpenCode, OpenClaw): open the tool
   once and confirm AIDR is listed there.
5. **Stay up to date.** When an AI tool starts, AIDR checks at most once a day whether
   your company's portal (or the update source IT set) has a newer version and says so
   ("… is available … To install it, run: aidr update"). Then run:

   ```sh
   aidr update --check   # is a newer version available? changes nothing
   aidr update           # verify, install, run 'aidr verify'; puts the old version back on failure
   ```

   On Linux run it as yourself, not with `sudo` (it asks for your password when it
   installs); on Windows a per-machine install needs a terminal opened with **Run as
   administrator**. `update.auto` (`notify` by default) can also be `install` (install in
   the background) or `off`. On computers IT marked as device-managed, updates come from
   IT and `aidr update` only checks.

If something is off:

- **`aidr` not found (Windows):** open a new terminal.
- **FAIL, or every action is blocked:** run `aidr doctor` (one line per check;
  `aidr doctor --verbose` adds the reason and the fix under each line) and send its
  output, or the file from `aidr support-bundle`, to your IT team. Do not uninstall AIDR
  to get unblocked.
- **Every action is blocked because the release key is missing** ("the release key …
  is not set up" or "release verification key missing"): run `aidr setup` once; it sets
  up the key the installer ships. For a manual install without the installer, ask IT for
  the release key file and run `aidr setup --release-key <file.pem>`.
- **"No AI tool … was found":** install your AI tool (Claude Code, Cursor, VS Code,
  Codex, OpenCode or OpenClaw), then run `aidr setup`.
- **macOS:** desktop installers are not offered yet. Browser Guard (part B) works on
  macOS in Chrome, Edge and Firefox.

More detail: [Desktop installers](installation/desktop-installers.md).

**Prefer a guided setup?** Open **Singularity AIDR Setup Assistant** from the
applications menu (Linux) or the last page of the Windows installer, or run
`aidr assistant` in a terminal. It shows the AI tools it found, connects to your
company if you want, protects the tools you choose, runs the same check as
`aidr verify` and links Browser Guard, in English or Turkish. Run it again
anytime. Details: [Setup Assistant](installation/desktop-installers.md#setup-assistant-aidr-assistant).

## B. Office user (Browser Guard)

Browser Guard checks what you type, paste or upload into ChatGPT, Gemini, Claude,
Microsoft Copilot, Perplexity, DeepSeek, Mistral Le Chat and Grok, and masks personal
and confidential data before it leaves your browser. It works on Windows, Linux and macOS.

1. **Is your computer managed by your company?** Then IT installs it for you; skip to
   step 4.
2. **Open the install link** from your IT team, your Singularity contact or the
   dashboard **Downloads** page. The store listings are unlisted, so searching the store
   does not find them.
   - Chrome 120+: **Add to Chrome**, then **Add extension**.
   - Edge 120+: **Get**, then **Add extension**.
   - Firefox 140+: open the `.xpi` link and click **Add**.
3. **Pin it.** Click the puzzle-piece icon and pin **Singularity AIDR Browser Guard**.
4. **Check.** Open a supported AI site, type `jane.doe@example.com` in a message and
   send it. The site receives a label such as `[EMAIL_1_xxxx]` instead of the address,
   and the answer shows your original address again, on your computer only. If the
   toolbar popup says the tab is not protected, reload the tab.

More detail: [Installing Browser Guard](installation/browser-guard.md).

## C. IT admin

### Roll out the desktop installer

Windows (Intune Win32 app, SCCM/ConfigMgr or GPO software installation):

```bat
msiexec /i singularity-aidr-<version>-windows-x64.msi /qn /l*v aidr-install.log
```

A per-machine install in the system context sets AIDR up for **each user at their next
logon**. Intune detection rule: the MSI product code, or the file
`C:\Program Files\Singularity AIDR\bundle\bin\aidr.exe`. Check the signature before you
upload: `signtool verify /pa /v <msi>`.

Linux (your internal apt/yum repository or configuration management):

```sh
sudo apt-get install -y ./singularity-aidr_<version>_amd64.deb   # Debian/Ubuntu
sudo dnf install -y ./singularity-aidr-<version>-1.x86_64.rpm     # RHEL/Fedora
sudo -u alice -H aidr setup                                       # once per user, when installed without sudo from that user
```

Setup exit codes, for scripts and detection rules: `0` protected, `3` no supported AI
tool installed for that user yet (not an error; the package and the MSI still install),
`1` a real setup problem. A manual install without the installer first needs the release
key: `aidr setup --release-key <file.pem>`.

Upgrades: deploy the newer installer the same way; registrations are kept. Add
`AIDR_MDM_MANAGED=1` to the install so endpoints leave updates to you; without it,
endpoints can update themselves from your portal with `aidr update` (`update.auto`).
Details, uninstall and package signature checks: [Desktop installers](installation/desktop-installers.md#silent-and-managed-deployment).

### Force-install Browser Guard

Add the extension to the browser's force-install list (Intune Settings catalog, GPO
ADMX, Google Admin console, or Firefox `policies.json`):

| Browser | Value |
|---|---|
| Chrome | `<CHROME_WEB_STORE_ID>;https://clients2.google.com/service/update2/crx` |
| Edge | `<EDGE_ADDONS_ID>;https://edge.microsoft.com/extensionwebstorebase/v1/crx` |
| Firefox | ID `browser-guard@singularityrd.com`, install URL where you host the signed `.xpi` |

The two store IDs exist only after Singularity publishes the store listings; your
Singularity contact gives them to you, and the dashboard Downloads page shows them when
it is configured with them. Start with a pilot group in `"mode": "monitor"`
(nothing is masked, everything is counted). Step-by-step for Intune, Google Admin,
GPO and Firefox, settings you can lock, and rollback:
[Deploying Browser Guard in an organisation](installation/browser-guard-enterprise.md).

### Approvals in a nutshell

Some actions are risky but sometimes legitimate (for example `terraform destroy` or
reading `.env`). AIDR then holds the action and a **person** decides; the AI tool can
never approve its own action.

- **Claude Code** shows its own confirmation dialog by default; the user decides there.
- **Codex, OpenCode, OpenClaw** (and Claude Code, Cursor and VS Code when
  `operator_approvals.mode` is `"operator"`): the action is blocked, and the message
  shows the exact command. The person at the keyboard runs it in their own terminal:

  ```sh
  aidr approve 3f9c2a7b        # the first 8 characters of the id are enough; type "approve"
  aidr approve                 # or: pick from a numbered list of what is waiting
  aidr pending                 # see everything that is waiting
  ```

  AIDR prints "Approved. Ask the agent to retry within 15 minutes." The approval allows
  that one action once, for 15 minutes by default.
- **With the AIDR dashboard** (managed mode), owners and admins can also approve on the
  **Approvals** page, signed in with two-step verification.

Details: [Operator approvals](configuration.md#operator-approvals).

## D. Running AIDR on your own servers (on-prem)

Laptops and browsers install exactly as above; only the dashboard they connect to runs
in your own environment.

- Single Linux host with Docker Compose: [AIDR on-prem installation](../deploy/onprem/README.md)
- Kubernetes with Helm: [Running AIDR on Kubernetes](operations/kubernetes.md)
- Overview, air-gapped installs and topologies: [On-premises deployment](deployment/onprem.md)
- Upgrades: one command, `pnpm onprem:upgrade --to <new release directory>` (backup,
  checks, upgrade, health check; stops and says what to do if a step fails):
  [Upgrading an on-prem installation](operations/onprem-upgrade.md); contracts in the
  [Upgrade runbook](../deploy/UPGRADE.md)

All install and deployment guides, by role: [Installation guides](installation/README.md).
