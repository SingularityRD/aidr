# Install recipes: VDI, devcontainers, Remote-SSH, WSL and CI runners

[Türkçe](special-environments.tr.md)

AIDR protects an AI agent from **inside the environment where the agent's tool
calls run**: the hook is registered in the agent host's configuration for that
user on that machine. The question for every environment below is therefore
"where does the agent run, and as which user?" Install AIDR there.

| Environment | Where the agent's tools run | Install AIDR in |
|---|---|---|
| VDI / Citrix (Windows desktop) | The virtual desktop session | The golden image (per-machine MSI), setup per user at logon |
| Dev container | The container | The container image, setup as the container user |
| VS Code Remote-SSH | The remote host | The remote host, for each remote user |
| WSL | The Linux distribution | Each WSL distribution, as the WSL user |
| CI runner | The job's runner (VM or container) | The job, before the agent step |

> **Support status.** Real-host acceptance evidence exists only for the hosts
> and platforms in the [compatibility matrix](../compatibility-matrix.md) (Linux
> x64 today). None of the environments on this page has its own acceptance
> record yet; treat each recipe as a design to validate in the customer's
> pilot ring. The Cursor / VS Code extension is a preview — no real-host
> acceptance evidence yet. Windows Server multi-session hosts are not tested.

## VDI and Citrix (non-persistent desktops)

1. **Golden image.** Install the MSI per machine in the image with
   `msiexec /i singularity-aidr-<version>-windows-x64.msi /qn AIDR_MDM_MANAGED=1`.
   `AIDR_MDM_MANAGED=1` stops endpoints from updating themselves; you update by
   rebuilding the image. The per-machine install registers an Active Setup
   entry, so `aidr setup` runs for each user at logon
   ([desktop installers](desktop-installers.md#windows-intune-sccmconfigmgr-gpo)).
   On a non-persistent desktop Active Setup runs at every logon; setup is
   idempotent.
2. **Install the AI tools in the image too**, so that setup finds them at
   logon and registers the hook.
3. **Persist the per-user state** in the profile container (FSLogix, Citrix
   Profile Management): `%USERPROFILE%\.singularity-aidr` and the AI tools'
   configuration (`%USERPROFILE%\.claude`, `%USERPROFILE%\.codex`,
   `%USERPROFILE%\.config\opencode`, `%APPDATA%\Code\User`, `%APPDATA%\Cursor\User`).
   Without it:
   - each logon gets a new installation ID, and in managed mode each one
     enrolls as a **new device and uses a new seat**;
   - the operator-approval key (protected with DPAPI) and pending approvals are
     lost, so held actions stay held (they are never auto-approved);
   - the local audit log disappears at logoff.
4. **Enrollment.** Use the managed configuration in the image (machine policy
   where your release supports it, otherwise the managed `config.json`
   fields `mode`, `control_plane.endpoint`, `auth.enrollment_token`;
   see [configuration](../configuration.md#mode)). Interactive enrollment per
   session is not practical on non-persistent desktops.
5. **Central record.** Turn on managed telemetry or SIEM delivery so that
   verdicts survive the session even if the local log does not.
6. **Clock.** VDI hosts must follow the domain time hierarchy
   ([time synchronisation](../operations/onprem-runbook.md#time-synchronisation)).
7. **Check** in a test session: `aidr doctor`, `aidr verify`, log off, log on,
   `aidr status` shows the same installation ID.

## Dev containers

The host's AIDR does not see tool calls made inside a container, and the
container's AIDR does not protect the host. When the agent (for example
Claude Code in the container's terminal) runs inside the dev container,
install AIDR in the image:

```dockerfile
# .devcontainer/Dockerfile (Debian/Ubuntu base)
COPY singularity-aidr_<version>_amd64.deb /tmp/
RUN apt-get update && apt-get install -y /tmp/singularity-aidr_<version>_amd64.deb \
    && rm /tmp/singularity-aidr_<version>_amd64.deb
```

```jsonc
// .devcontainer/devcontainer.json
{
  "build": { "dockerfile": "Dockerfile" },
  "remoteUser": "vscode",
  // Keep the AIDR state (installation ID, approvals, audit log) across rebuilds.
  "mounts": [
    "source=aidr-state-${devcontainerId},target=/home/vscode/.singularity-aidr,type=volume"
  ],
  // Install the agent first, then register the AIDR hook for this user.
  "postCreateCommand": "aidr setup --host claude-code && aidr doctor"
}
```

- Verify the `.deb` signature before you add it to the image
  ([desktop installers](desktop-installers.md#linux-apt--yum--dnf--configuration-management)),
  or install from your internal apt repository.
- Managed mode: provide the machine policy file read-only
  (`/etc/singularity-aidr/managed.json`, for example as a bind mount or a
  build secret) rather than baking an enrollment credential into the image.
- The named volume keeps one installation ID per dev container; without it
  every rebuild enrolls a new device.
- The container needs the control plane's CA if it is internal
  (`NODE_EXTRA_CA_CERTS`, or the machine policy `ca_file` where supported).

## VS Code Remote-SSH

With Remote-SSH, the VS Code server, its extensions and any agent CLI started
in the integrated terminal run on the **remote** host. AIDR on the laptop does
not protect them.

1. Install the Linux package on the remote host (`.deb`, `.rpm` or tarball).
2. Each developer runs `aidr setup` once on the remote host as themselves
   (or the administrator runs `sudo -u <user> -H aidr setup`).
3. For an agent that runs as a VS Code extension in the remote extension host,
   the AIDR extension must also be installed **in the remote** ("Install in
   SSH: <host>"); this path is part of the Cursor / VS Code preview.
4. Shared build servers: every user who runs an agent needs their own setup;
   each user's installation counts as one device.
5. Check on the remote host: `aidr doctor`, `aidr verify`.

## WSL

A WSL distribution is a separate Linux system. The Windows MSI protects agents
started on Windows; it does **not** protect agents installed and started
inside WSL (for example Claude Code installed with npm inside Ubuntu on WSL).

1. In each distribution that runs an agent: install the `.deb`/`.rpm` (or the
   tarball) and run `aidr setup` as the WSL user.
2. The WSL installation has its own configuration and installation ID. In
   managed mode it enrolls as its own device; whether one seat covers a
   person's Windows and WSL installations is set by your order (see the seat
   definition in the [EULA draft](../legal/eula.en.md)).
3. If the control plane uses an internal CA, add the root to the
   distribution's trust store and to `NODE_EXTRA_CA_CERTS` (or `ca_file`).
4. Clock: WSL follows the Windows clock; after sleep, older WSL versions can
   drift. `aidr doctor` reports it; `sudo hwclock -s` resynchronises.

## CI runners

Agents increasingly run unattended in pipelines (for example `claude -p` or
`codex exec` in a job). Install AIDR in the job before the agent step and make
the job fail if protection is not in place:

```yaml
# Example (GitHub Actions syntax; adapt to GitLab CI, Jenkins, Azure DevOps)
- name: Install Singularity AIDR
  run: |
    tar -xzf singularity-aidr-${AIDR_VERSION}-linux-x64.tar.gz
    sudo ./singularity-aidr-${AIDR_VERSION}-linux-x64/install.sh
    aidr setup --host claude-code
    aidr doctor --json > aidr-doctor.json
    aidr verify
- name: Run the agent
  run: claude -p "..."
- name: Keep the AIDR audit log
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: aidr-audit
    path: ~/.singularity-aidr/audit.jsonl
```

- Prefer **local mode** on ephemeral runners: nothing to enroll, no seat used
  per job. If you need central visibility, use one long-lived, dedicated
  runner identity or ship the audit artefact to your SIEM, instead of
  enrolling every ephemeral runner.
- An `ask` in CI has no one to approve it in the job, so it stays a block and
  the step fails. That is intended: decide the exception (narrow allowlist or
  detection exception) out of band, not by disabling AIDR in the pipeline.
- Pin the AIDR version and verify the tarball's signature in the job, as for
  any other build dependency.
- `aidr doctor` exits non-zero when a check fails; `aidr verify` passes a
  harmless canary through each registered hook. Use both as gates.
