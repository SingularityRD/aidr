# macOS Jamf and signed PKG delivery template

`pkg/build-pkg.sh` refuses to build until the connector SHA-256 and detached
publisher signature verify, and it requires an Apple Installer signing identity.
The resulting PKG installs root-owned fleet scripts, the verified artifact and a
pinned release public key. Its postinstall verifies the payload again. The PKG
does not guess a desktop user or silently edit every home directory.

```sh
sh pkg/build-pkg.sh connector.tgz DIGEST connector.tgz.sig release-public.pem \
  "Developer ID Installer: Example Corp (TEAMID)" 0.6.0 aidr-fleet-0.6.0.pkg
```

Deploy the signed PKG with Jamf, require Jamf's package-signature validation,
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

These templates provide local packaging and lifecycle controls. A green local
verification does not prove Jamf delivery, macOS version compatibility, host hook
execution, publisher notarization or customer acceptance. Collect those results
on the exact signed candidate in the customer's MDM test tenant.
