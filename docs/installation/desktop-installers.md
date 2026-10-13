# Desktop installers (Windows and Linux)

[Türkçe](desktop-installers.tr.md)

The desktop installers put a self-contained AIDR on a workstation: no Node.js,
no package registry. Each one carries the standalone bundle built by
`pnpm build:sea` (the `aidr` CLI and the Claude Code hook binaries, with the
threat rules next to them) and the release trust public key, then runs
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

- **Claude Code** — registers the bundle's hook binaries in
  `~/.claude/settings.json` (only AIDR-marked entries change; your own hooks
  stay). Before that it checks every bundle file against its manifest and
  sends a harmless deny canary through the PreToolUse binary; it registers
  nothing if either fails. An enabled AIDR Claude Code plugin is left alone.
- **OpenCode** — registers the `@singularityrd/aidr-opencode` package
  (OpenCode installs it from the private registry at its next start).
- **OpenClaw** — runs `openclaw plugins install` when the `openclaw` CLI is on
  `PATH`.
- **Codex, Cursor, VS Code** — not bundled. `aidr status` prints the exact
  step (Codex: the `aidr-codex-hook` package; Cursor/VS Code: the signed VSIX).

## Quickstart

### Windows

1. Download `singularity-aidr-<version>-windows-x64.msi` from the AIDR
   dashboard's Download page.
2. Double-click it and accept the prompt. Setup runs for you at the end.
3. Restart your AI tools (Claude Code, Cursor, VS Code, ...). Open a new
   terminal and run `aidr status`, then `aidr verify`.

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
- **Installer size** — each installer is about 200–300 MB: every hook is a
  separate self-contained executable.
- Logs: Windows `msiexec /l*v`; Linux the package manager output.

## Building the installers

```sh
pnpm --filter @singularityrd/aidr-core build && pnpm --filter @singularityrd/aidr-cli build \
  && pnpm --filter @singularityrd/aidr-claude-code build
node packages/claude-code/scripts/build-sea.mjs --out /tmp/aidr-sea
node deploy/installers/linux/build-linux-packages.mjs --sea-dir /tmp/aidr-sea \
  --trust-key release-public.pem --trust-key-fingerprint <sha256> --version 0.6.0 --out out
# Windows (WiX 5 + signtool):
pwsh deploy/installers/windows/build-msi.ps1 -SeaDir C:\aidr-sea -TrustKey release-public.pem `
  -TrustKeyFingerprint <sha256> -Version 0.6.0 -OutDir out -SignThumbprint <thumbprint>
pnpm test:installers
```

A local MSI without a certificate needs `-Unsigned` and is named
`…-UNSIGNED.msi`. The release workflow uses these secrets and fails when one
is missing: `AIDR_SIGNING_PUBLIC_KEY_PEM` / `AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT`
(embedded trust key), `AIDR_WINDOWS_CODE_SIGNING_PFX_B64` /
`_PFX_PASSWORD` / `_THUMBPRINT` and `vars.AIDR_WINDOWS_TIMESTAMP_SERVER`
(Authenticode), `AIDR_LINUX_PACKAGE_GPG_PRIVATE_KEY` / `_PASSPHRASE` /
`_FINGERPRINT` (rpm and detached `.asc` signatures).
