# Linux fleet delivery template

This template stages a verified Claude Code connector and registers the managed
hook for one existing OS user. It supports clean install, idempotent upgrade,
rollback to the prior verified release and hook-only uninstall. Policy,
allowlists, unrelated Claude hooks and `~/.singularity-aidr/config.json` survive
upgrade, rollback and uninstall.

Provision `release-public.pem` through a trusted configuration-management path
at `/etc/singularity-aidr/release-public.pem`, owned by root and not writable by
group/other. Confirm its fingerprint out of band. Supplying an artifact, digest,
signature and key through the same unauthenticated channel does not establish
publisher identity. The scripts require a detached OpenSSL SHA-256 signature:

```sh
openssl dgst -sha256 -sign release-private.pem -out connector.tgz.sig connector.tgz
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
artifact and includes the endpoint installer. `install-systemd.sh` also places
that installer beside the root-owned lifecycle manager. A custom packaging path
can set `AIDR_ENDPOINT_INSTALLER` to another root-owned copy. The connector still
requires a supported Node.js runtime on the endpoint.
