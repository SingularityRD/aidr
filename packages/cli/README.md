# AIDR CLI

The `aidr` command provides local setup and diagnostics for AIDR connectors. It
does not deploy a control plane or create a cloud account.

This is not a one-command customer download. The release operator must first
grant access to a signed, approved version in the private registry. `aidr setup`
only configures local AIDR state and prints connector setup guidance; it does
not install or activate the connector.

Install the exact approved version from the private registry using
[Package Installation](../../docs/package-installation.md), then inspect the
available commands:

```sh
aidr --help
```

Run `aidr setup` only after the operator has supplied the approved runtime
configuration and selected a supported secret store. It may write local
configuration and record detected runtime state; it does not install hooks or
activate the connector, and it is not a substitute for the customer acceptance
procedure.
