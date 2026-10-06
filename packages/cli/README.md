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

## Explicit behavioral learning

Learning is disabled until an active managed entitlement and the installed,
operator-signed tenant detector policy authorize it. The policy must name two
different Ed25519 authorities: an execution supervisor and an independent operator
who classifies the execution as benign and consents to bounded baseline retention.
Generating local keys does not grant either role or change the signed policy.

Run these commands from a dedicated private operator directory. Create each
authority in its own operator account, with separate custody from
the agent and from the other authority. Only public keys and key IDs belong in
the signed tenant policy. The authority reference contains an opaque vault ID;
never pass a private key in an argument, environment variable, or support log.

```sh
aidr learning keygen --role execution --out execution-authority.json
aidr learning keygen --role approval --out approval-authority.json
```

The default is the platform vault. Windows DPAPI, macOS Keychain and Linux Secret
Service use stdin for private key writes. `--secret-store file-acl` is an explicit,
reduced-protection fallback: a separate owner-only PKCS8 file sits beside the
reference. A reference and its private file must remain in a private operator
directory. Existing files are never overwritten; lost or unreadable keys require
operator-approved policy rotation rather than automatic replacement.

The concrete execution path accepts a JSON request file containing only
`sessionId`, `toolName: "Bash"`, and `toolInput` with `command` and `execution_shell`.
Set `execution_shell` to `"powershell.exe"` on Windows or `"/bin/sh"` on POSIX.
Execution requires that fixed shell to match the current host. The original shell
binding is preserved when another operator approves on a different OS. Ingestion
runs on the original execution host.
It selects the installed policy by connector runtime; request files cannot select
another tenant, configuration, policy, shell, working directory or environment.

```sh
aidr learning execute --runtime opencode --request request.json --key-ref execution-authority.json --out execution.json
aidr learning export-authority --runtime opencode --out broker-authority.json
aidr learning approve --runtime opencode --request request.json --receipt execution.json --broker-authority broker-authority.json --key-ref approval-authority.json --out approval.json
aidr learning ingest --runtime opencode --request request.json --receipt execution.json --approval approval.json
```

The execution supervisor must use foreground, deterministic commands. A receipt
proves the inspected shell invocation exited successfully and its complete bounded
output passed inspection. It does not attest business success, success of every
subcommand, or completion of detached work. Timeout, nonzero exit, invalid UTF-8,
output above 2 MiB, or an observed unfinished process prevents receipt issuance.
Raw output and private keys are never printed. The deadline is 60 seconds.
If a command runs but receipt publication fails, investigate before running it
again; a missing receipt does not roll back its effects.

Approval displays the actual request and its verified scope in an interactive
terminal and requires an exact phrase bound to the execution ID. Empty answers,
cancellation and piped input deny approval.
Trust and expiry are checked again after the prompt. Ingestion verifies both
signatures, the original input and installed tenant/device/session/policy/corpus
bindings before accepting an observation; replay does not add another sample.
Cold-start execution also needs the signed tenant's explicit unavailable-detector
skip policy and an available clean ML leg; an absent corpus never authorizes it.

Transfer the request, execution receipt and private broker-authority handoff to
the independent approval station through the operator's approved channel. The
handoff contains signed entitlement and classifier policy, including potentially
confidential matchers; it contains no API key or private signing key. The approval
station must already trust the issuer in its fixed AIDR configuration and have
current revocation evidence. It verifies the broker's target device and tenant
against both signatures without needing the broker's OS vault. Return only the
signed approval for ingestion on the execution host.
