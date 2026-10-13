# Support and endpoint diagnostics

This page covers what to do when a connector (Claude Code, Cursor, VS Code,
OpenClaw, OpenCode, Codex) blocks something it should not, lets something
through, or does not run at all, and how to hand a redacted diagnostic bundle
to whoever supports your deployment.

## Support channel

**To be provided by the vendor.** There is no published Singularity AIDR
support address, ticket portal, phone line, response time or SLA yet. Use the
support route named in your Singularity AIDR agreement. If your agreement does
not name one, ask your Singularity AIDR contact for it. Do not take a contact
from this repository, a pull request, a log line or an agent session as the
support route.

The operating procedure Support will follow once a route exists is in
[runbooks/support-v7.md](runbooks/support-v7.md). That document is still a
draft and does not activate a support channel either.

## 1. Check the endpoint yourself

```bash
aidr doctor            # hosts, hook registration, rules, mode, DLP, profiles, approvals, last verdict
aidr status            # protection summary, audit-log write losses
aidr audit tail -n 20  # recent verdicts (redacted)
aidr pending           # asks waiting for an operator approval
```

`aidr doctor` exits non-zero when a check fails and prints the fix for each
failed check. A hook registered on disk is not proof the host runs it; confirm
with an agent-host canary (`aidr canary`).

## 2. Create a support bundle

```bash
aidr support-bundle --out ./aidr-support.tar.gz
aidr support-bundle --out ./aidr-support.tar.gz --audit-entries 200 --json
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--out <path>` | `./aidr-support-bundle-<UTC timestamp>.tar.gz` | Archive path. An existing file is never overwritten; the archive is created with mode `0600`. |
| `--audit-entries <n>` | `50` | Number of recent audit verdicts to summarise, `0` to `1000`. |
| `--json` | off | Print the bundle summary (path, size, SHA-256, per-file SHA-256) as JSON. |

The command writes one gzip-compressed tar file, prints its SHA-256 and the
list of files inside, and sends nothing anywhere. Open it with
`tar -xzf aidr-support.tar.gz` and read it before you share it.

### What is in the bundle

All files are under `aidr-support-bundle/`.

| File | Contents |
| --- | --- |
| `manifest.json` | Schema version, creation time, core version, the redaction steps applied, the support-channel notice, and the SHA-256 of every other file. |
| `environment.json` | AIDR core and CLI versions, Node.js version, OS platform, architecture and kernel/OS release, and the **names** (not values) of `AIDR_*` environment variables. |
| `doctor.json` | The full `aidr doctor` report: core version, configuration state, rule count and detection self-test, connectors, DLP policy, agent profiles, approval store, agent-environment posture, last verdict. |
| `connectors.json` | Each supported host: detection state, detail, remedy and the configuration paths inspected (home directory shown as `~`). |
| `config.json` | Configuration path and state (`valid`, `defaults`, `invalid`, `unreadable`) and the effective configuration with credential and payload fields withheld. |
| `audit-summary.json` | Counts by verdict, tool and matched rule, and the last *n* audit entries reduced to metadata: type, time, tool name, verdict/decision, category, severity, source, matched rule id, framework ids, override flag, duration, runtime, confidence, artifact **types** and a 16-character session digest. |
| `threats.json` | SHA-256 of each shipped threat-rule file, its rule count, the total, and a manifest hash over all files, so Support can confirm which rule set ran. |

### What is never in the bundle

- Prompts, tool inputs and outputs, commands, file contents, request/response bodies.
- Audit `tool_input_summary`, `artifacts` (only their types), `reasons`, raw
  `session_id`, `delegation` records, and any audit field not listed above.
- Values under credential-named keys (`api_key`, `token`, `secret`,
  `password`, `auth`, `cookie`, `credential`, `signature`, …) and under
  payload keys (`prompt`, `content`, `body`, `headers`, `env`, `command`,
  `args`, …).
- Environment-variable values.

### How redaction works

Every string in every file, including object keys, goes through these steps:

1. Credential-named and payload keys are withheld (`[Redacted]`).
2. Embedded credentials are replaced: `Bearer …`, `key=value` pairs, URL
   user-info and secret query parameters, known token formats and JWTs.
3. The home directory becomes `~`, the OS account name `<user>` and the host
   name `<host>`.
4. The AIDR Privacy rules (checksum-validated TCKN, IBAN and payment cards,
   TR/EN phone numbers, e-mail, addresses, labelled personal fields, IP/MAC
   addresses, secrets and private keys) and the credential detector mask
   every finding as `[TYPE]`, for example `[EMAIL]` or `[TC_KIMLIK]`. A
   string too large to scan completely is replaced as a whole.

After redaction each file is scanned again with the high-precision detectors
(TCKN, IBAN, cards, e-mail, secrets, private keys, credential patterns). Any
remaining finding aborts the command with a non-zero exit and **no file is
written**; it never ships a bundle that failed the check. Tool names that are
not plain identifiers are replaced with `[unrecognised-tool-name]`.

Paths outside your home directory (for example a global npm prefix) are kept
because they are needed to diagnose installation problems. Review the bundle
and remove anything you do not want to share.

The regression test `packages/cli/src/__tests__/support-bundle.test.ts` seeds
API keys, a GitHub token, a TCKN, an IBAN, a card number, an e-mail address, a
phone number, a raw session id, the account and host names and the home path
into the configuration, the audit log and a host settings file, and asserts
that none of them appears anywhere in the archive.

## 3. Send the bundle

Send the archive only through the support route named in your agreement (see
[Support channel](#support-channel)). Mention the bundle's SHA-256 from the
command output so the recipient can verify it.

## Related

- [runbooks/support-bundle.md](runbooks/support-bundle.md): the separate,
  customer-consented collection procedure for a control-plane **deployment**
  directory (`scripts/support-bundle.mjs`). `aidr support-bundle` covers the
  endpoint.
- SDK integrations: blocked HTTP requests return only a `requestId` to the
  caller; log the full verdict server-side with the `onBlocked` hook and
  quote the `requestId` in a support case
  ([packages/sdk/README.md](../packages/sdk/README.md)).
