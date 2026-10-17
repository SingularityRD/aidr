# macOS Jamf and signed PKG delivery template

`pkg/build-pkg.sh` refuses to build until the connector SHA-256 and detached
publisher signature verify, and it requires an Apple Installer signing identity.
The resulting PKG installs root-owned fleet scripts, the verified artifact and a
release public key. Its preinstall checks that key against an independently
provisioned fingerprint; postinstall verifies the payload again. The PKG
does not guess a desktop user or edit any home directory.

When the payload is the signed **standalone (SEA) bundle** (`aidr-sea/` from
`packages/claude-code/scripts/build-sea.mjs`, packed as `.tgz`), postinstall
also installs it machine-wide: the bundle is staged under
`/Library/Application Support/Singularity AIDR/releases/<sha256>/bundle`
(root-owned) and `aidr machine-hooks install` registers its hooks for every
user in Claude Code's `/Library/Application Support/ClaudeCode/managed-settings.d/`
and Codex's `/etc/codex/hooks.json`. No Node.js is needed. Pass the bundle's
Ed25519 release key as the optional eighth `build-pkg.sh` argument; the PKG
carries it as `config/bundle-release-public.pem` and the install re-verifies
every bundle file and manifest signature against it before any host policy is
written. Re-running the PKG is idempotent; a newer PKG is an upgrade. An npm
connector payload is only verified, as before (use the `*-user` Jamf actions).
Cursor, VS Code, OpenCode and OpenClaw stay per-user connectors.

The public key is an immutable input for the PKG builder. Obtain the approved
fingerprint through reviewed configuration management or another authenticated
channel, separately from the artifact/signature and PKG. On the build Mac,
compare the supplied key's canonical DER SHA-256 with that independently
approved value before building:

```sh
sudo install -d -o root -g wheel -m 0755 /etc/singularity-aidr
sudo install -o root -g wheel -m 0644 release-public.pem /etc/singularity-aidr/release-public.pem
openssl pkey -pubin -in /etc/singularity-aidr/release-public.pem -outform DER | shasum -a 256
```

Before installing the PKG on each endpoint, separately provision a real,
root-owned `/etc/singularity-aidr` directory and a root-owned regular file
`/etc/singularity-aidr/release-public.sha256` through trusted MDM configuration.
The directory and file must not be group/world writable, symlinks, or carry
ACLs. The file must contain exactly 64 lowercase hex characters followed by one LF newline,
with no whitespace, CRLF, second line or other bytes. The trusted provisioning
channel can produce the source with `printf '%s\n' "$APPROVED_SHA256"`; install
that independently delivered file on the endpoint:

```sh
sudo install -d -o root -g wheel -m 0755 /etc/singularity-aidr
sudo install -o root -g wheel -m 0644 /trusted-mdm/release-public.sha256 /etc/singularity-aidr/release-public.sha256
```

The signed PKG preinstall compares this pin to the candidate key before writing
the payload. On upgrade it also verifies the existing root-owned installed key
against the pin before replacement. A missing or different current key blocks
the upgrade. The existing installation root, config directory and key must be
real, root-owned paths without group/world write or ACLs. Changing only the pin
does not rotate an installed key. Approve
key rotation separately. Keep the private signing key in the release system.
Set `VERSION` to an approved package version (for example, `1.0.0`) and
`APPROVED_SIGNING_IDENTITY` to the actual approved Apple Installer identity;
do not treat either example as a publisher approval.

```sh
sh pkg/build-pkg.sh connector.tgz DIGEST connector.tgz.sig /etc/singularity-aidr/release-public.pem \
  "$APPROVED_SIGNING_IDENTITY" "$VERSION" "aidr-fleet-$VERSION.pkg"
```

Deploy the signed PKG to the startup volume `/` with Jamf, require Jamf's
package-signature validation. For a bundle payload the PKG has already
registered the hooks; run `jamf-policy.sh` to apply machine policy, lock other
hooks, roll back or uninstall. Jamf parameters ($4–$11) are:

| | Machine-wide: `install`, `upgrade`, `rollback`, `uninstall` | Per-user: `install-user`, `upgrade-user`, `rollback-user`, `uninstall-user` |
| --- | --- | --- |
| $4 | action | action |
| $5–$8 | artifact, lowercase SHA-256 (install/upgrade), detached signature, pinned public key | same |
| $9 | control-plane URL for `/etc/singularity-aidr/managed.json` (optional) | agent config path (optional) |
| $10 | path of a root-owned file holding the `aidr_fleet_…` enrollment key (optional) | target short user name (console user is the fallback) |
| $11 | comma-separated switches: `protection_locked`, `protection_unlocked`, `lock_other_hooks`, `unlock_other_hooks` | — |

Giving $9, $10 or a protection switch rewrites `managed.json` from exactly those
values (the previous file is kept as `managed.json.previous`); leave all three
empty to keep the existing policy, for example one your MDM delivers as a file.
The hooks and the CLI read that file on macOS as on Linux; it must stay
root-owned and not group/world writable. `lock_other_hooks` is remembered for
later upgrades and rollbacks. Rollback re-verifies the retained release against
the root-owned pinned key and registers it again. Uninstall runs
`aidr machine-hooks remove`; releases, machine policy and per-user connectors
remain for audit and safe re-enablement. See `../unix/README.md`.

The per-user actions preserve unrelated Claude hooks and existing
`~/.singularity-aidr/config.json`; their uninstall removes only the managed hook
entries; policy, allowlists, agent config, receipts and shared release bytes
remain. They need Node.js on the endpoint.

Root is used only to manage the shared release store, state and system-wide
host policy. Per-user settings are changed in the user's own session and
identity. No secrets belong in Jamf script parameters: pass the fleet
enrollment key as a root-owned file path (a fleet key is multi-use, seat-capped
and revocable, and every local user can read the machine policy by design);
`agent-config.json` may contain only the public control-plane origin and
verification material.

These templates provide local packaging and lifecycle controls. Approved Apple
Team ID and Jamf signing identity, notarization, stapling, actual Jamf delivery,
macOS compatibility, host hook execution and customer acceptance still require
external evidence on the exact signed candidate. The macOS machine-wide paths
(Claude Code managed-settings drop-in, Codex `/etc/codex`) come from the hosts'
documentation and source and have not been exercised on a Mac; a macOS SEA
binary must also be code-signed for Gatekeeper before release.
