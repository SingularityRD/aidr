# Desktop installers (Windows and Linux)

[Türkçe](desktop-installers.tr.md)

The desktop installers put a self-contained AIDR on a workstation: no Node.js,
no package registry. Each one carries the release build of the standalone
bundle (one `aidr` program that is both the CLI and every hook, the threat
rules next to it, the Cursor and VS Code extensions, all listed in manifests
signed with the release key) and the release public key, then runs
`aidr setup` for the logged-in user.

| OS | File | Install location |
|---|---|---|
| Windows 10/11 x64 | `singularity-aidr-<version>-windows-x64.msi` (Authenticode-signed) | `C:\Program Files\Singularity AIDR\` (per-user: `%LOCALAPPDATA%\Programs\Singularity AIDR\`) |
| Debian / Ubuntu | `singularity-aidr_<version>_amd64.deb` (+ `.asc`) | `/opt/singularity-aidr/`, `/usr/bin/aidr` |
| RHEL / Fedora / SUSE | `singularity-aidr-<version>-1.x86_64.rpm` (GPG-signed) | `/opt/singularity-aidr/`, `/usr/bin/aidr` |
| Any Linux | `singularity-aidr-<version>-linux-x64.tar.gz` (+ `.asc`) | `/opt/singularity-aidr/`, `/usr/local/bin/aidr` |

**macOS installers are not offered yet.** On macOS, use the connector
packages described in [Getting Started](../getting-started.md).

> **Release status.** The installers are built by the release-candidate
> workflow (`.github/workflows/release-rc.yml`, jobs `installers-*`) and attached
> to the draft RC release. They are not a customer-approved release until the
> gated release decision in [Getting Started](../getting-started.md#current-customer-installation-status)
> says so. Every published installer is signed; a build without its signing
> secret fails instead of shipping unsigned.

## What setup does on each host

`aidr setup` runs for the user who installed (never for `root` or
`LocalSystem`) and:

- **Release key** — copies the release public key the installer placed in
  `config/release-public.pem` into `integrity.public_keys_pem` of
  `~/.singularity-aidr/config.json` and prints its fingerprint. The release
  build trusts its own rules only once this key is set up: until then every
  tool call is blocked with a message that says so and names the fix. A
  different key an administrator already configured is kept (setup says so);
  `aidr setup --force` replaces it after operator confirmation. For a manual
  install, `aidr setup --release-key <file.pem>` sets up an Ed25519 public key
  (PEM) after operator confirmation and prints its fingerprint.
- **Claude Code** — registers `"<bundle>/bin/aidr" hook pre-tool-use` (and
  `post-tool-use`, `session-start`) in `~/.claude/settings.json` (only
  AIDR-marked entries change; your own hooks stay). Before that it checks every
  bundle file and both manifest signatures against the release key and sends a
  harmless deny canary and a harmless `ls` through the hook; it registers
  nothing unless the canary is denied and `ls` is allowed. An enabled AIDR
  Claude Code plugin is left alone.
- **Codex** — registers `"<bundle>/bin/aidr" hook aidr-codex-hook` for
  PreToolUse, UserPromptSubmit and PostToolUse in `~/.codex/hooks.json` after
  the same canary check. Then trust the hooks once with `/hooks` in Codex.
- **Cursor, VS Code** — installs the extension the installer carries
  (`bundle/extensions/aidr-cursor.vsix`, `aidr-vscode.vsix`) with the editor's
  own command line when the editor is installed. Then run
  "Singularity AIDR: Enable protection" from the command palette.
- **OpenCode** — registers the `@singularityrd/aidr-opencode` package
  (OpenCode installs it from the private registry at its next start).
- **OpenClaw** — runs `openclaw plugins install` when the `openclaw` CLI is on
  `PATH`.

If no supported AI tool is installed for that user yet, setup changes no host,
exits with code 3 and the package still installs; the Linux package prints
"No AI tool … was found for <user> yet" and the command to run after
installing one (`aidr setup`). Any other non-zero code is a real setup problem.

## Quickstart

### Windows

1. Download `singularity-aidr-<version>-windows-x64.msi` from the AIDR
   dashboard's **Downloads** page.
2. Double-click it and follow the wizard ([pages below](#the-windows-install-wizard)).
   Setup runs for you at the end.
3. Restart your AI tools (Claude Code, Cursor, VS Code, ...). Open a new
   terminal and run `aidr status`, then `aidr verify`.

#### The Windows install wizard

The wizard opens in Turkish when the Windows display language is Turkish and
in English otherwise; both are in the one MSI. Screenshots are not published
yet: each placeholder below says what the screenshot will show.

1. **Welcome**: the product name, one line on what it does and the version.
   *Screenshot placeholder: dark-blue panel with the shield mark on the left;
   "Welcome to Singularity AIDR", the one-line description and "Version 0.6.0"
   on the right.*
2. **License agreement**: read it and tick "I accept" to continue.
   *Screenshot placeholder: the licence text box with the acceptance box below.*
3. **Who should be protected?**
   - *Only for me*: installs in `%LOCALAPPDATA%\Programs\Singularity AIDR\`
     for your account; no administrator rights.
   - *For all users of this computer* (default): installs in
     `C:\Program Files\Singularity AIDR\`; Windows asks for administrator
     approval (the Install button carries the shield). Other users are set up
     at their next sign-in.
   An existing "Only for me" install is preselected, so an upgrade keeps its
   scope; to change the scope, uninstall first.
   *Screenshot placeholder: two choices, each with one explanatory line.*
4. **Company connection (optional)**:
   - *Local protection only (no account)* (default): protection runs on this
     computer; nothing else to enter.
   - *Connect to my company*: the company address from your IT team (`https://`
     only; prefilled with the Singularity AIDR service, change it for an
     on-premises console) and, optionally, the enrollment code from the console
     (`aidr_enroll_…`, 55 characters, masked as you type). The format is checked
     before you can continue. See
     [Company connection from the installer](#company-connection-from-the-installer).
   *Screenshot placeholder: the two choices; the address and code fields are
   greyed out until "Connect to my company" is chosen.*
5. **Ready to install**: who is protected, the folder, the company connection
   and what setup will do. Then the progress page.
6. **Finish**: "Open the Singularity AIDR Setup Assistant" (ticked) starts
   `aidr assistant` for you, as your own account without administrator rights,
   and Setup closes without waiting for it. "View quick start" opens the
   offline guide installed in `docs\quick-start.<language>.html` of the install
   folder. If you started the installer from an administrator prompt, the
   assistant is not started from there; the page says to run `aidr assistant`
   in a normal terminal.
   *Screenshot placeholder: "Singularity AIDR is installed", the next step
   (`aidr status`), the ticked assistant box and the quick start link.*

Repair and removal (Settings > Apps, or running the MSI again) use the
standard Windows Installer pages and end on the same Finish page.

**Per-customer installer** (`SingularityAIDR-<CUSTOMER>-<version>-<arch>.msi`
or `.exe`, [Per-customer builds](../operations/customer-builds.md)): the same
pages, plus:

- *Welcome* says who it was prepared for ("Prepared for TÜBİTAK BİLGEM").
- When the customer packet names the company address, page 4 has no choices:
  it shows that address and asks only for the optional enrollment code. The
  address is handed to setup exactly as one typed on the generic page. An
  `ENROLLMENT_URL` given on the command line wins and brings back the generic
  page.
- *Ready to install* adds "Licensed to" and the last day rule and threat
  updates are accepted (the license's `expires_at` plus its grace days).
  Protection keeps working after that day.

A silent install (`/qn`) shows no pages and behaves as before: it connects to
the company only with `ENROLLMENT_URL`, otherwise the packet's address is
applied by the next confirmed `aidr setup`.

#### Company connection from the installer

The enrollment code is a one-time secret, so the installer never puts it on a
command line or in its log: the field is masked, `ENROLLMENT_CODE` is a hidden
property, and a custom action running as you writes it, with the address, to
`%USERPROFILE%\.singularity-aidr\installer-enrollment.json`, a file only your
account can open. The `aidr setup` the installer runs then applies it:
`mode: "managed"`, `control_plane.endpoint` and `auth.enrollment_token` in
`~/.singularity-aidr/config.json` (a commercial build keeps the token in the
Windows credential vault), and deletes the file. Enrollment completes when an AI tool
next starts; without a code, the AI tool shows a short code and a link to
approve this computer in your company's console.

- Pointing AIDR at a control plane is an operator action: setup applies the
  file only when the installer runs it, or when you run `aidr setup` in a
  terminal and type `connect`. A run without confirmation (for example by an
  AI tool) changes nothing and leaves the file in place.
- A file older than 3 days, or one that is not in the expected format, is
  deleted without being used; install again with fresh details.
- A computer that is already enrolled keeps its connection; the installer's
  details are deleted unused.
- With `AIDR_SKIP_SETUP=1` the file waits for the user's first `aidr setup`.
- Local protection does not depend on the connection: if it cannot be saved,
  setup says so and protection stays on.

### Debian / Ubuntu

1. Download `singularity-aidr_<version>_amd64.deb`.
2. `sudo apt install ./singularity-aidr_<version>_amd64.deb` — setup runs for
   the user who ran `sudo`.
3. Restart your AI tools, then run `aidr status` and `aidr verify`.

### RHEL / Fedora

1. Download the `.rpm` and import the package signing key once:
   `sudo rpm --import linux-package-signing-key.asc`.
2. `sudo dnf install ./singularity-aidr-<version>-1.x86_64.rpm`.
3. Restart your AI tools, then run `aidr status` and `aidr verify`.

### Tarball (any Linux)

1. `tar -xzf singularity-aidr-<version>-linux-x64.tar.gz`
2. `sudo ./singularity-aidr-<version>-linux-x64/install.sh`
3. Restart your AI tools, then run `aidr status` and `aidr verify`.

When the package manager runs without `sudo` from a user (for example from
an image build or a configuration-management agent), the package prints
`aidr setup`; each user runs it once as themselves.

## Setup Assistant (`aidr assistant`)

The Setup Assistant is the same setup as a step-by-step page in your browser,
in English or Turkish. Open it from the applications menu (**Singularity AIDR
Setup Assistant**, .deb and .rpm), from the last page of the Windows installer,
or from a terminal:

```sh
aidr assistant            # opens your default browser
aidr assistant --no-open  # prints the address instead (headless, SSH)
```

It walks through seven steps: what AIDR does; the AI tools found on this
computer (tools that are not installed are shown greyed out); the company
connection; **Protect** (the same work as `aidr setup` for the tools you
chose, with a result per tool: protected, restart needed, or the exact manual
command); the `aidr verify` check per tool; Browser Guard; and a summary. Run it
again at any time; a rerun changes nothing that is already set up.

**Company connection.** "Local protection only" is the default and needs no
account. "Connect to my company" asks for the address of your company's AIDR
dashboard, shows a short connection code and a button that opens the approval
page; the page updates by itself once someone approves the computer. Only then
are `mode: "managed"` and the address written to `~/.singularity-aidr/config.json`.
If the Windows installer saved a company address (and optionally a one-time
connection key) in `%USERPROFILE%\.singularity-aidr\installer-enrollment.json`,
the assistant fills it in and deletes the file once it has been used. The file
is ignored unless only that user can read it.

**Browser Guard links** come from the same settings the dashboard's Download
page uses (`VITE_BROWSER_GUARD_CHROME_URL`, `VITE_BROWSER_GUARD_EDGE_URL`,
`VITE_BROWSER_GUARD_FIREFOX_URL`, https only, read from the environment). When
they are not set on the computer, the assistant links to the dashboard's
Download page instead.

**How it stays private.** The page is served by `aidr` itself from `127.0.0.1`
on a random port, never from the network. The address carries a one-time
256-bit key after `#`, which the page exchanges once for a browser-only session
cookie (HttpOnly, SameSite=Strict); a copied or reused address is refused.
Requests with another host name or from another web page are refused, the page
loads nothing from outside the binary (`Content-Security-Policy: default-src
'self'`), and the assistant stops when you close it on the last page or after
30 minutes without activity. It can only detect, set up (never with `--force`
or `--release-key`), verify, show status and connect to a company; it cannot
uninstall, approve anything or change other settings. An AI agent cannot start
it: `aidr assistant` run by an agent is blocked like `aidr setup --force`
(rule `CLT-SELF-007`). The page is part of the signed `aidr` binary.

## Checking protection

`aidr status` ends with one line, for example:

```
Verdict: protected: Claude Code | restart if open before 2026-10-13T09:00:00.000Z: OpenCode | needs a manual step: Codex → Add [[hooks.PreToolUse]] ... | then run 'aidr verify'
```

- **protected** — the connector is registered;
- **restart if open before …** — setup registered it at that time; a host
  that was already running loads it only after a restart;
- **needs a manual step** — the exact command for that host.

`aidr verify` passes a harmless canary (a `curl … | bash` command against
the reserved `.invalid` domain) through each registered connector's real hook
entry point as data — nothing is executed — and reports per host:

- **PASS** — the hook denied the canary and allowed the benign `ls` twin;
- **FAIL** — it did not deny, or it denies everything (an internal error);
  tool calls of that host may run uninspected;
- **SKIP** — the connector runs only inside its host (OpenCode, OpenClaw, a
  Claude Code plugin install): restart the host and confirm there.

Neither command proves that a host executes the hook; that needs the host
itself (see the [first-customer runbook](../../deploy/FIRST_CUSTOMER.md)).

`aidr doctor` prints one line per check (configuration, release key, detection,
connectors, DLP, profiles, approvals, last verdict) and exits non-zero when one
fails; `aidr doctor --verbose` adds the reason, the path and the fix under each
line.

## Approving a blocked action

Some actions are held until a person approves them (for example `terraform
destroy` or reading `.env`). On Codex, OpenCode and OpenClaw (and on every host
with `operator_approvals.mode: "operator"`) the block message starts with the
command to run in your own terminal, for example:

```sh
aidr approve 3f9c2a7b   # the first 8 characters of the id are enough; type "approve"
aidr approve            # no id: pick from a numbered list of waiting actions
aidr pending            # list everything that is waiting
```

AIDR then prints "Approved. Ask the agent to retry within 15 minutes."; the
approval allows that one call once. The AI tool itself can never approve.
Claude Code shows its own Yes / No dialog by default instead.

## Silent and managed deployment

### Windows: Intune, SCCM/ConfigMgr, GPO

```bat
msiexec /i singularity-aidr-<version>-windows-x64.msi /qn /l*v aidr-install.log
```

- A per-machine install in the **system context** (Intune Win32 app with
  "Install behavior: System", SCCM, GPO software installation) does not run
  setup as `LocalSystem`. It registers an Active Setup entry, so `aidr setup`
  runs once for **each user at their next logon**.
- An install in a user's context runs setup for that user at the end.
- `AIDR_SKIP_SETUP=1` installs files only (golden images, staged rollouts):
  `msiexec /i … /qn AIDR_SKIP_SETUP=1`.
- `AIDR_MDM_MANAGED=1` leaves updates to your MDM: endpoints do not update
  themselves ([Device-managed machines](#device-managed-machines-intune-sccm-gpo-configuration-management)).
- A silent install needs no new property: it behaves exactly as it did before
  the wizard existed. The wizard's company page has two optional public
  properties, for **user-context** installs only:
  `ENROLLMENT_URL=https://aidr.example.com` and `ENROLLMENT_CODE=aidr_enroll_…`
  (either one is enough; `ENROLLMENT_CODE` alone uses the Singularity AIDR
  service). A malformed value fails the install with a line in the log that
  names the property, never its value. `ENROLLMENT_CODE` is hidden from the
  msiexec log, but a value on a command line can be seen by other programs
  while msiexec runs and may be kept by your deployment tool: prefer
  short-lived codes. A system-context install has no interactive user to
  connect and ignores both; enroll those users with the managed configuration
  ([`mode`](../configuration.md#mode), [`auth`](../configuration.md#auth)).
- **Language:** the MSI shows Turkish when the display language is Turkish.
  `TRANSFORMS=:1055` forces the Turkish wizard; a silent install is the same
  in both languages.
- **Per-user install without admin rights:**
  `msiexec /i … MSIINSTALLPERUSER=1 ALLUSERS=2` installs to
  `%LOCALAPPDATA%\Programs\Singularity AIDR\` and adds `bundle\bin` to the
  user's `PATH`.
- Intune detection rule: MSI product code, or file
  `C:\Program Files\Singularity AIDR\bundle\bin\aidr.exe`.
- Verify the signature before upload: `signtool verify /pa /v <msi>`.

### Linux: apt / yum / dnf / configuration management

```sh
sudo apt-get install -y ./singularity-aidr_<version>_amd64.deb      # Debian/Ubuntu
sudo dnf install -y ./singularity-aidr-<version>-1.x86_64.rpm        # RHEL/Fedora
```

Host the packages in your internal apt/yum repository as usual. A run without
an invoking user (`SUDO_USER`) installs files only and prints `aidr setup`;
run it per user, for example from a login script:
`sudo -u alice -H aidr setup`. `AIDR_INSTALL_SKIP_SETUP=1` installs files only
even when `SUDO_USER` is set.

Verify downloads before deploying:

```sh
gpg --import linux-package-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS && sha256sum --check --ignore-missing SHA256SUMS
rpm -K singularity-aidr-<version>-1.x86_64.rpm
```

## Updating

`aidr update` brings a workstation to the version your organisation published
on the download portal:

```sh
aidr update --check     # is a newer version available? changes nothing
aidr update             # download, verify, install, run 'aidr verify'; puts the old version back on failure
```

Run it as yourself. On Linux do **not** use `sudo`: it asks for your sudo
password when it installs. On Windows a per-machine install needs a terminal
opened with **Run as administrator**; a per-user install does not. Installing
replaces the protection, so `aidr update` asks you to type `update`; for
automation pass `--yes` with `AIDR_OPERATOR_NONINTERACTIVE=1`.

### Where the update comes from

| Situation | Source |
|---|---|
| Managed (enrolled) device | your organisation's portal: the SaaS or on-prem control plane in `control_plane.endpoint`, authenticated with the device's own API key (Edge Function `installer-update`) |
| Installer from your administrator | `aidr update --from <installer file or https URL>`; the signed `manifest.json` and `manifest.json.sig` must be next to it (or in the parent folder, as in the portal layout `<version>/manifest.json`), or pass `--catalog <file or URL>` |
| Internal mirror | `aidr update --from <folder or https URL holding latest.json>`, or set `update.source` |

A mirror is a copy of the portal bucket tree; `scripts/publish-installers.mjs
--dry-run --out <dir>` stages exactly that tree (see
[download-portal.md](download-portal.md#local-dry-run)). Only `https` is
downloaded.

### What is checked before anything runs

1. **Signed catalog.** The Ed25519 signatures of `latest.json` and the
   catalog, and the catalog's SHA-256 recorded in `latest.json`, are checked
   with the pinned installer-catalog key. Without a key nothing is downloaded.
2. **Installer bytes.** The download must have exactly the size and SHA-256
   of the signed catalog; otherwise it is deleted.
3. **Version.** An older version is refused unless you pass
   `--allow-downgrade` (a rollback your administrator asked for).
4. **Format.** `aidr update` picks the installer that matches how AIDR was
   installed: the `.msi` on Windows, the `.deb` when the `singularity-aidr`
   package is registered with dpkg, the `.rpm` when it is registered with rpm,
   and the `.tar.gz` otherwise. The portal publishes every format of a
   platform, so this is automatic. It refuses only when the catalog has no
   installer in that format, and then lists the formats it does offer; ask
   your administrator to publish yours. It never switches an installation
   from one format to another, and an installer you pass with `--from` must
   be in the matching format too.

The **installer-catalog key** is the public half of the key that signs the
portal catalog (its base64 form is the portal's
`AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64`, see
[download-portal.md](download-portal.md#catalog-signing-key)). Put it on each
endpoint as `config/installer-catalog-public.pem` next to
`release-public.pem` in the install folder (`/opt/singularity-aidr/config/`,
`C:\Program Files\Singularity AIDR\config\`), owned by root/Administrators, or
list it in `update.catalog_public_keys`. The file wins when both exist:

```sh
openssl pkey -in installer-catalog-key.pem -pubout -out installer-catalog-public.pem
```

### How it installs, and rollback

| Installation | Command |
|---|---|
| Windows | `msiexec /i <msi> /qn /norestart /l*v <log>` (plus `MSIINSTALLPERUSER=1 ALLUSERS=2` for a per-user install) |
| Debian / Ubuntu | `sudo dpkg -i <deb>` |
| RHEL / Fedora / SUSE | `sudo rpm -U <rpm>` (`--oldpackage` with `--allow-downgrade`) |
| Tarball | the new `bundle` is checked against the release key that is already installed, then swapped in with `sudo` (`install.sh` is not used) |

Before installing, `aidr update` copies the installer and the installed
bundle into a folder only root or administrators can change
(`/var/cache/singularity-aidr/` through sudo; `update-staging` inside the
install folder on a per-machine Windows install), checks the installer's
SHA-256 again there, and checks the bundle copy: it is the fallback. Another
program of the same user therefore cannot swap the file between the check and
the install. A damaged installation is not replaced in place (reinstall it
from the installer). Afterwards the new
bundle must pass its manifest check against the installed release key, carry
the expected version, and `aidr verify` must not report FAIL for a host that
passed before the update. Otherwise the previous bundle is put back,
registered again with `aidr setup` and checked. For MSI, `.deb` and `.rpm` the
package manager then still lists the new version: reinstall the previous
installer, or run `aidr update` again once the problem is fixed. A failed
Windows install keeps its `msiexec.log` under `~/.singularity-aidr/updates/`.

### Automatic checks: `update.auto`

| Value | Behaviour |
|---|---|
| `notify` (default) | When an AI tool starts a session, at most once per `update.check_interval_hours` (24), AIDR checks the same signed catalog and shows "Singularity AIDR v… is available … To install it, run: aidr update". |
| `install` | Also starts `aidr update --auto` in the background. It installs only a newer, verified version from the configured source (never a downgrade, never `--from`) and rolls back the same way. On Linux it needs sudo without a password, and on Windows a per-user install (a per-machine MSI needs an administrator); otherwise it keeps notifying. |
| `off` | No automatic check. |

Automatic checks run only on endpoints installed with these installers and
contact only the tenant's control plane (managed mode) or `update.source`.
Settings: [configuration.md](../configuration.md#update).

### Device-managed machines (Intune, SCCM, GPO, configuration management)

**Customers who deploy with an MDM update through the MDM**: publish the new
MSI or package there exactly like the first install. Mark those installs so
endpoints do not update themselves:

- **Windows:** add `AIDR_MDM_MANAGED=1` to the per-machine install
  (`msiexec /i … /qn AIDR_MDM_MANAGED=1`). It writes
  `HKLM\SOFTWARE\Policies\Singularity AIDR`, `MdmManaged = 1` (DWORD); you can
  also set that value with a GPO or an Intune configuration profile, or create
  the file `%ProgramData%\Singularity AIDR\mdm-managed`.
- **Linux:** set `AIDR_MDM_MANAGED=1` for the package install (it writes
  `/etc/singularity-aidr/mdm-managed`; final removal deletes it), or create
  that file from your configuration management.

On a marked machine automatic checks are off whatever `update.auto` says,
`aidr update` refuses to install and names the marker, and
`aidr update --check` still reports what is available.

## Uninstall

| OS | Command |
|---|---|
| Windows | Settings → Apps → Singularity AIDR → Uninstall, or `msiexec /x singularity-aidr-<version>-windows-x64.msi /qn` |
| Debian/Ubuntu | `sudo apt remove singularity-aidr` |
| RHEL/Fedora | `sudo dnf remove singularity-aidr` |
| Tarball | `sudo /path/to/singularity-aidr-<version>-linux-x64/uninstall.sh` |

Before the files are deleted, the uninstaller runs
`aidr uninstall --yes --keep-data` (with `AIDR_OPERATOR_NONINTERACTIVE=1`) for
the user who uninstalls: every AIDR connector registration is removed, your own
hooks stay, and `~/.singularity-aidr` (configuration, audit log) is kept. To
delete that data and the AIDR vault items too, run `aidr uninstall` yourself
**before** removing the package.

Other users of the machine who ran `aidr setup` must run `aidr uninstall`
before the package is removed. Afterwards their `~/.claude/settings.json`
keeps hook entries marked `Singularity AIDR managed installation` that point
at the removed binary; delete those entries. (On Windows, Active Setup does
not run on uninstall.)

Upgrades (`apt install` of a newer `.deb`, `dnf upgrade`, a newer MSI) keep
every registration and rerun setup for the installing user.

## Troubleshooting

- **`aidr` not found after install (Windows)** — open a new terminal; the
  `PATH` change applies to new sessions.
- **Setup said "manual step needed" for Claude Code** — `disableAllHooks` is
  set, or `~/.claude/settings.json` is not valid JSON; fix it and run
  `aidr setup` again.
- **"the installed AIDR bundle … failed verification"** — a file under the
  bundle changed. Reinstall the package; do not edit the bundle.
- **`aidr verify` reports FAIL for Claude Code** — run `aidr status` and check
  the detection self-test line; reinstall if it fails.
- **`aidr uninstall` refuses with `receipt_connector_missing`** — the package
  was removed before `aidr uninstall` ran; reinstall the same version, run
  `aidr uninstall`, then remove the package.
- **Every tool call is blocked with "the release key … is not set up"** — run
  `aidr setup` as that user (it sets up the key the installer ships), or
  `aidr setup --release-key <file.pem>` for a manual install.
- **Anything else** — `aidr doctor --verbose` shows the reason and the fix for
  each failing check; send it, or the archive from `aidr support-bundle`, to
  support.
- **Installer size** — one self-contained program serves the CLI and every
  hook, so the installed bundle is about 150 MB (it was about 900 MB with one
  program per hook).
- Logs: Windows `msiexec /l*v`; Linux the package manager output.

## Building the installers

```sh
for p in core cli claude-code codex; do pnpm --filter @singularityrd/aidr-$p build:release; done
node packages/claude-code/scripts/build-sea.mjs --prebuilt --flavor release --out /tmp/aidr-sea
node packages/claude-code/scripts/build-sea.mjs --add-extensions /tmp/aidr-sea \
  --vsix aidr-cursor.vsix --vsix aidr-vscode.vsix            # optional
node packages/claude-code/scripts/build-sea.mjs --sign /tmp/aidr-sea --key release-private.pem \
  --public-key release-public.pem
node packages/claude-code/scripts/build-sea.mjs --verify /tmp/aidr-sea --public-key release-public.pem
node deploy/installers/linux/build-linux-packages.mjs --sea-dir /tmp/aidr-sea \
  --trust-key release-public.pem --trust-key-fingerprint <sha256> --version 0.6.0 --out out \
  [--catalog-key installer-catalog-public.pem]
# Windows (WiX 5 + WixToolset.UI.wixext 5.0.2, .NET SDK, signtool):
pwsh deploy/installers/windows/build-msi.ps1 -SeaDir C:\aidr-sea -TrustKey release-public.pem `
  -TrustKeyFingerprint <sha256> -Version 0.6.0 -OutDir out -SignThumbprint <thumbprint> `
  [-CatalogKey installer-catalog-public.pem]
pnpm test:installers
```

The builders refuse a development-flavour bundle and a bundle whose manifests
are not signed by the given release key. `--verify` copies the bundle to a
temporary folder and proves that, with the release key set up, the Claude Code
and Codex hooks allow `ls -la` and deny a pipe-to-shell canary, and that
without the key every call is denied with the release-key message. The
optional catalog key is installed as `config/installer-catalog-public.pem` for
`aidr update`.

The Windows build compiles the wizard (`windows/ui/AidrUI.wxs`, strings in
`windows/ui/aidr.en-US.wxl` and `aidr.tr-TR.wxl`) once per language with the
same ProductCode and payload, then embeds the Turkish build into the English
MSI as a language transform (storage `1055`, summary languages `1033,1055`)
and checks that the transform changes only the language. **One MSI is
published per version and architecture.** The company page's custom actions
(`windows/ca/`, C#, net472) are built with `dotnet build`; the script adds the
pinned WiX UI extension itself. The wizard bitmaps (`windows/ui/banner.bmp`
493×58, `dialog.bmp` 493×312) are rendered from `banner.svg` and `dialog.svg`
by `node deploy/installers/windows/ui/render-bitmaps.mjs`; the build stops if
they are stale. The licence page is a placeholder
(`<EULA TEXT — legal review required>`, `windows/ui/eula.*.rtf`) until the
reviewed text replaces it.

`pnpm test:installers` checks the wizard sources structurally on any OS. A
real Windows machine must still confirm, before a release: the wizard renders
in English and, with a Turkish display language, in Turkish (and with
`TRANSFORMS=:1055`); "Only for me" installs without a UAC prompt into
`%LOCALAPPDATA%\Programs` and "For all users" prompts for approval; the
company page rejects a malformed address or code, the handoff file has a
user-only ACL, `aidr setup` applies and deletes it, and `msiexec /l*v` shows no
enrollment code; the Finish page starts the assistant unelevated as the user
(Task Manager, "Elevated: No") and does not start it from an elevated prompt;
`msiexec /qn` with and without `AIDR_SKIP_SETUP`/`AIDR_MDM_MANAGED` and in the
system context behaves as before; repair, removal and a major upgrade.

A local MSI without a certificate needs `-Unsigned` and is named
`…-UNSIGNED.msi`. The release workflow uses these secrets and fails when one
is missing: `AIDR_SIGNING_PUBLIC_KEY_PEM` / `AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT`
(embedded trust key), `AIDR_SIGNING_PRIVATE_KEY_PEM` (only in the
`installers-sea-sign` job, which adds the candidate VSIXs and signs both bundle
manifests between the bundle builds and packaging), `AIDR_WINDOWS_CODE_SIGNING_PFX_B64` /
`_PFX_PASSWORD` / `_THUMBPRINT` and `vars.AIDR_WINDOWS_TIMESTAMP_SERVER`
(Authenticode), `AIDR_LINUX_PACKAGE_GPG_PRIVATE_KEY` / `_PASSPHRASE` /
`_FINGERPRINT` (rpm and detached `.asc` signatures). The optional
`AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_PEM` (variable or secret) adds the
`aidr update` catalog key.

The release bundles are minified (esbuild `minify` with `keepNames`, so error
and function names stay readable) and ship without source maps. That makes
them smaller and harder to skim, not secret: the code can still be read. The
integrity signature is what refuses a changed install.

### Per-customer installers

A customer installer is the same signed product plus one vendor-signed
customer packet (`aidr-customer-packet-v1`; the vendor runbook is
[Per-customer builds](../operations/customer-builds.md)). The builders take it as an extra input:

```sh
node deploy/installers/linux/build-linux-packages.mjs ... \
  --customer-packet customer-packet.json --customer-id bilgem
pwsh deploy/installers/windows/build-msi.ps1 ... `
  -CustomerPacket customer-packet.json -CustomerId bilgem [-Bundle]
```

| Installer | Where the packet goes |
|-----------|-----------------------|
| `.msi` / `.exe` | `config\customer-packet.json`, and for a per-machine install also `%ProgramData%\Singularity AIDR\customer-packet.json`, which removal and a generic `aidr update` upgrade leave in place |
| `.deb` | `/etc/singularity-aidr/customer-packet.json`, a dpkg conffile |
| `.rpm` | `/etc/singularity-aidr/customer-packet.json`, `%config(noreplace)`; a generic RPM owns the path as `%ghost`, so upgrading to it keeps the packet |
| `.tar.gz` | `config/customer-packet.json`, installed to `<prefix>/config` |

Files are named `SingularityAIDR-<CUSTOMER>-<version>-<arch>.<ext>` (for
example `SingularityAIDR-BILGEM-1.0.0-x64.msi`) and the Windows product is
"Singularity AIDR (BILGEM)". The package name and the MSI UpgradeCode stay the
generic ones, so customer and generic installers upgrade each other. `-Bundle`
also builds a setup EXE (WiX Burn, `windows/bundle.wxs`) that wraps the signed
MSI and shows its wizard; its Burn engine is detached, signed and reattached
before the EXE is signed. The builders check the packet's shape and customer
id; its signature is checked by `scripts/customer-packet-verify.mjs` before a
build and by `aidr setup` on every endpoint, which refuses a tampered or
wrong-key packet and still installs local detection.

The `Customer Installer Build` workflow (`.github/workflows/customer-installer.yml`,
run by hand from the default branch with a promoted release tag and the
customer id) does all of this without building from source: it downloads the
release-key-signed SEA bundles the promoted release published, checks their
build attestation and Ed25519 signatures, verifies the packet (from the
`AIDR_CUSTOMER_PACKET_<ID>` environment secret, base64, or an uploaded
`customer-packet-<id>` artifact), and builds, signs (Authenticode, GPG) and
attests the customer's MSI, EXE, deb, rpm and tarball in the
`release-candidate` environment.

A real Windows machine must still confirm, for a customer build: the MSI and
EXE install per-machine with the packet in both places; removing the MSI, or
upgrading it with a generic MSI, keeps the ProgramData copy; the EXE shows the
MSI's English and Turkish wizard; and `signtool verify /pa` passes for the EXE
and its engine.
