# Installing AIDR packages

**Current status:** no customer-installable release is approved at this
checkout. The current candidate-bound evidence index has no candidate digest
and records all 30 gates as `NOT_RUN`; see the
[readiness profile](production-readiness/first-customer-ready.md). The commands
below are conditional instructions for a later approved, signed release. There
is no `VERSION` to substitute today, and a local package-gate run does not
approve a customer release.

The current release workflow targets the private `@singularityrd` GitHub
Packages registry. Under its present access model, that is suitable only for
**internal release staging**, not customer distribution: GitHub permits package-only
access to private organization packages for organization members or teams, not
external customer accounts. Do not add a buyer to the source organization or
repository merely to make installation work. A customer-facing private
registry and its invoice-to-access lifecycle must be approved and tested
before these commands become customer instructions. A source build or locally
generated tarball is for development/testing, not a supported customer
release. `aidr setup` configures local AIDR state and registers the connector of
each detected host from packages or verified artifacts you already have; it does
not download release artifacts, provision a tenant, or deploy a control plane.

## Registry access

The following GitHub Packages configuration is for an **authorized internal
organization member** running an acceptance rehearsal only. GitHub Packages
npm access requires a classic personal access token with `read:packages` and
permission to read the package. Provide the token to the package manager
through a secret manager as `NODE_AUTH_TOKEN`; never paste it into a command,
repository, or support bundle.

Add this to the internal tester's `.npmrc` (not the repository):

```ini
@singularityrd:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

Do not proceed if the approved signed version is not available to the account.
Public npm lookup is not a valid availability check for this private scope.
An external customer's registry instructions must be written after choosing a
provider that supports a customer-specific, revocable read principal; these
GitHub Packages credentials must not be repurposed for that customer.

To close COM-012, record one approved order/invoice and the resulting tenant
entitlement, grant only that buyer's registry principal access to the sold
package scope, pin the client to the exact signed version, and prove an
unauthenticated and unrelated principal cannot
download it. From a clean customer host, download the package, compare it to
the signed release digest, verify the publisher signature with a separately
delivered trust policy, install it, and record the activated version. Then
cancel/offboard: revoke registry access, test that a fresh download is denied,
and prove the installed copy loses protected-service entitlement according to
the signed licence policy. Revocation cannot erase bytes already downloaded.
Keep the registry access/audit and finance reconciliation receipts bound to
the same candidate and tenant. If air-gap is offered, repeat installation on
a disconnected host with every pinned image/dependency and the signed bundle;
do not count a connected build or an archive checksum as that proof.

GitHub's current access rule is documented in [package access control](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

## Install a connector

Use the exact version named in the approved release record. Release builds are
managed-only and verify their signed artifacts before they inspect anything: before
installing any connector, put the independently distributed Ed25519 release public key in
`integrity.public_keys_pem` in `~/.singularity-aidr/config.json` (see
[Integrity verification](integrity.md)). Without it every tool call is blocked. Tested host
versions are listed in the [compatibility matrix](compatibility-matrix.md).

| Host | Install |
| --- | --- |
| OpenClaw | `openclaw plugins install npm:@singularityrd/aidr-openclaw@VERSION` |
| Codex CLI | `npm install --global @singularityrd/aidr-codex@VERSION` |
| AIDR CLI | `npm install --global @singularityrd/aidr-cli@VERSION` |

Replace `VERSION` with the exact version in the approved release record before
running the command.

These additional connectors are release-bundle files, not public npm packages:

| Host | Release file | Install |
| --- | --- | --- |
| Claude Code | `aidr-claude-plugin-VERSION.tar.gz` | Verify the enclosing publisher-signed release bundle before extracting the archive. Provision the integrity public key separately in `integrity.public_keys_pem` ([Integrity verification](integrity.md)), then add the verified plugin directory as a local marketplace; use the included `packages/claude-code/README.md` for host-specific steps. |
| Cursor (preview — no real-host acceptance evidence yet) | `aidr-cursor.vsix` | `cursor --install-extension ./aidr-cursor.vsix` |
| VS Code (preview — no real-host acceptance evidence yet) | `aidr-vscode.vsix` | `code --install-extension ./aidr-vscode.vsix` |

Use the exact Claude archive version from the approved release record. Install
each VSIX only from the same verified release bundle, and confirm the host
reports the expected extension version after installation. Do not build a VSIX
from a source checkout for customer use.

For OpenCode, add the approved version to the OpenCode config directory's
`package.json` and enable the package in `opencode.json`:

`~/.config/opencode/package.json`:

```json
{
  "dependencies": {
    "@singularityrd/aidr-opencode": "VERSION"
  }
}
```

`~/.config/opencode/opencode.json`:

```json
{
  "plugin": ["@singularityrd/aidr-opencode"]
}
```

OpenCode installs configured npm plugins through Bun at startup. Its Bun
process must inherit `NODE_AUTH_TOKEN` and the user-level `.npmrc` settings.
The Codex package installs a hook binary but does not register or trust it;
follow the [Codex connector guide](../packages/codex/README.md) and verify the
hook in Codex before relying on it. OpenClaw also requires its host-side
installation and trust/activation checks.

## CLI and local setup

After installing the CLI, use `aidr --help` to see commands. `aidr setup` writes
local configuration and installs or updates the connector of every agent host it
detects in the home directory (Codex hook registration, OpenCode plugin pin, and
the host's own CLI for OpenClaw, a verified VSIX or a verified Claude Code plugin
directory); `aidr setup --dry-run` shows the plan first. In the default local
mode it needs no credential and no OS vault. It does not create a cloud account
or deploy the control plane. See the [CLI README](../packages/cli/README.md#setup).

For host-specific behavior and limitations, use each connector guide. For
release signing, customer kits, and deployment acceptance, follow the
[first-customer runbook](../deploy/FIRST_CUSTOMER.md) and the current
[production-readiness decision](production-readiness/first-customer-ready.md).

Registry behavior: [GitHub Packages npm authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry), [OpenCode plugins](https://dev.opencode.ai/docs/plugins/), and [OpenClaw plugin installation](https://docs.openclaw.ai/cli/plugins/install).
