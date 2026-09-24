# macOS Jamf and signed PKG delivery template

`pkg/build-pkg.sh` refuses to build until the connector SHA-256 and detached
publisher signature verify, and it requires an Apple Installer signing identity.
The resulting PKG installs root-owned fleet scripts, the verified artifact and a
release public key. Its preinstall checks that key against an independently
provisioned fingerprint; postinstall verifies the payload again. The PKG
does not guess a desktop user or silently edit every home directory.

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

Deploy the signed PKG to the startup volume `/` with Jamf, require Jamf's package-signature validation,
then run `jamf-policy.sh` for a specific enrolled user. Jamf parameters are:

1. action: `install`, `upgrade`, `rollback` or `uninstall`
2. connector artifact path
3. lowercase SHA-256 (required for install/upgrade)
4. detached signature path
5. pinned public key path
6. agent config path (optional)
7. target short user name (recommended; console user is the fallback)

The install and upgrade paths preserve unrelated Claude hooks and existing
`~/.singularity-aidr/config.json`. Rollback re-verifies the retained release
against the root-owned pinned key before activating it. Uninstall removes only
the managed hook entries; policy, allowlists, agent config, receipts and shared
release bytes remain for audit and safe re-enablement.

Root is used only to manage the shared release store and state. User settings are
changed in the user's own session and identity. No secrets belong in Jamf script
parameters; `agent-config.json` may contain only the public control-plane origin
and verification material. Enrollment tokens remain in the device-code flow.

These templates provide local packaging and lifecycle controls. Approved Apple
Team ID and Jamf signing identity, notarization, stapling, actual Jamf delivery,
macOS compatibility, host hook execution and customer acceptance still require
external evidence on the exact signed candidate.
