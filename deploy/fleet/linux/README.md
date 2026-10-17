# Linux fleet delivery template

By default this template installs the signed **standalone (SEA) bundle**
machine-wide: it stages the bundle in the root-owned release store
`/opt/singularity-aidr/releases/<sha256>/bundle` and registers its hooks for
every user through each host's system-wide policy with the bundle's own
`aidr machine-hooks install` (Claude Code
`/etc/claude-code/managed-settings.d/50-singularity-aidr.json`, Codex
`/etc/codex/hooks.json`). Users cannot edit or `disableAllHooks` those away, and
the endpoint needs **no Node.js**. It supports clean install, idempotent
upgrade, rollback to the prior verified release and hook-only uninstall; see
`../unix/README.md` for every option. Cursor, VS Code, OpenCode and OpenClaw
stay per-user connectors (`aidr setup` per user, as documented in
`docs/operations/hook-tamper-resistance.md`); machine policy
`protection_locked` covers the editors.

```sh
sudo ./install.sh --artifact aidr-sea.tgz --sha256 DIGEST --signature aidr-sea.tgz.sig \
  --public-key /etc/singularity-aidr/release-public.pem \
  --bundle-public-key /etc/singularity-aidr/bundle-release-public.pem \
  --control-plane-url https://aidr.example.com/functions/v1 \
  --enrollment-key-file /etc/singularity-aidr/enrollment-key \
  --protection-locked true --lock-other-hooks --heartbeat
```

The artifact is the `bin/aidr-sea/` directory that
`packages/claude-code/scripts/build-sea.mjs` produces, packed with
`tar -czf aidr-sea.tgz aidr-sea` and signed with the detached OpenSSL publisher
signature below. `--bundle-public-key` is the Ed25519 release key the bundle
manifests are signed with (required for a release-flavour bundle); it is copied
next to the release, where `aidr machine-hooks install` re-verifies every
bundle file and both manifest signatures before writing any host policy, and
where each user's `aidr setup` finds it. Policy options rewrite
`/etc/singularity-aidr/managed.json` from exactly the values given (the
previous file is kept as `managed.json.previous`); without them an existing
policy is kept. `/opt/singularity-aidr/bin/aidr` runs the active release, and
`/etc/singularity-aidr/mdm-managed` leaves updates to your fleet tooling.

The per-user path (the npm connector package for one OS user, Claude Code only,
Node.js required) is still available with `--user`. Policy, allowlists,
unrelated Claude hooks and `~/.singularity-aidr/config.json` survive upgrade,
rollback and uninstall in both scopes.

The release public key is an immutable trust input for both bundle builders and
endpoints. Obtain it through reviewed configuration management or another
authenticated channel; do not accept or rotate it alongside an artifact and its
signature. Provision the same root-owned, non-group/world-writable regular key
and parent directory on each Linux build host and endpoint (no symlinks), then
compare its canonical DER fingerprint with
the value recorded through an independent trusted channel:

```sh
sudo install -d -o root -g root -m 0755 /etc/singularity-aidr
sudo install -o root -g root -m 0644 release-public.pem /etc/singularity-aidr/release-public.pem
openssl pkey -pubin -in /etc/singularity-aidr/release-public.pem -outform DER | sha256sum
```

The fingerprint check is an operator/release gate; the builder enforces the
root-ownership and write-permission checks and verifies the artifact using the
provided key. If the key is rotated, update the trusted fingerprint through the
approved change process before building or deploying packages. Supplying an
artifact, digest, signature and replacement key through one unauthenticated
channel does not establish publisher identity.

Build an offline bundle only with that pinned path; the build verifies the
artifact before copying the key into the bundle:

```sh
./deploy/fleet/linux/build-offline-bundle.sh connector.tgz DIGEST connector.tgz.sig \
  /etc/singularity-aidr/release-public.pem aidr-fleet-linux.tar.gz
```

The scripts require a detached OpenSSL SHA-256 signature. Keep the private
signing key confined to the approved offline/release signing system:

The installer rejects archives above 256 MiB compressed, over 5,000 entries,
or over 512 MiB total regular-file size before extraction. It rejects links,
special entries, and unsafe paths as well. Do not raise those limits without a
customer-host disk-capacity and archive-format acceptance test.

Machine-wide: run `upgrade.sh` with the new signed bundle, `rollback.sh` to
return to the immediately prior release (it rechecks the retained archive
against the pinned key and re-registers it; the `--lock-other-hooks` /
`--heartbeat` choice is remembered), and `uninstall.sh` to run
`aidr machine-hooks remove`. Uninstall keeps shared release bytes, the machine
policy and every per-user connector.

Per-user (npm connector package):

```sh
sudo ./install.sh --artifact connector.tgz --sha256 DIGEST --signature connector.tgz.sig \
  --public-key /etc/singularity-aidr/release-public.pem --user alice \
  --config /etc/singularity-aidr/agent-config.json
```

Run `upgrade.sh` with the new signed artifact. Run `rollback.sh --user alice`
to return to the immediately prior release; rollback rechecks the retained
archive against the pinned key. `uninstall.sh --user alice` removes only the
managed hook entries and keeps shared release bytes and user policy/config.

When a managed hook registration is missing, mispointed or duplicated on an
endpoint, the local remediation entry point re-runs detection, re-runs the
connector's own deny canary and repairs only the marked AIDR hooks:

```sh
node deploy/fleet/unix/aidr-remediate.mjs --home /home/u             # repair
node deploy/fleet/unix/aidr-remediate.mjs --home /home/u --check     # detect only
```

It needs no root, does not install or verify a release, leaves policy,
allowlists, agent configuration, connector bytes and the receipt untouched, and
will not re-enable a host whose hooks are globally disabled. Host execution,
publisher signing and MDM delivery remain unverified.

`install-systemd.sh` installs a timer under the unprivileged `aidr-health`
account. Its JSON proves only that the release referenced by local state exists.
It does not prove Claude invoked a hook or that MDM delivered the policy. Run the
real connector canary and collect distribution evidence in the customer tenant.

`build-offline-bundle.sh` creates a transport bundle after verifying the source
artifact and includes the endpoint installer (its optional sixth argument adds
the bundle release key as `payload/bundle-release-public.pem`).
`install-systemd.sh` also places that installer beside the root-owned lifecycle
manager. A custom packaging path can set `AIDR_ENDPOINT_INSTALLER` to another
root-owned copy. Only the per-user npm path and this optional health timer need
a Node.js runtime on the endpoint; the machine-wide bundle path does not
(`aidr-fleet.sh status` falls back to a Node-free report, and `--heartbeat`
reports hook presence to the control plane every hour).
