# Customer-consented support-bundle procedure

This is a local collection procedure for a deployment summary. It does not
establish an active AIDR support team, ticket channel, secure security-reporting
route, response time, or transfer service. The current support field-acceptance
gate is open; see [Support operations](support-v7.md). Do not present this
procedure as an available customer support channel.

The bundle is a directory of JSON metadata rather than a general log archive.
For an endpoint (connector) problem use `aidr support-bundle` instead; see
[Support and endpoint diagnostics](../support-diagnostics.md).

## Collection boundary

The collector reads only these source files from the selected deployment directory:

| Source | Included fields |
| --- | --- |
| `deployment.json` | manifest version, deployment mode, development flag, source revisions, dirty-source flag, and aggregate migration/artifact counts and digests |
| `doctor-evidence.json` | presence, time, pass/fail, mode, online flag, and allowlisted diagnostic code counts |

Unknown doctor messages become `unclassified-redacted`; their original text is discarded. URLs and origins become the generic `transport-origin-policy` code. Artifact and migration inventories are validated for traversal but represented by an aggregate count and digest, so their paths do not leave the host.

The collector never opens environment files, application logs, audit events, database exports, storage objects, configuration files, home directories, or connector inputs/outputs. It does not collect URLs, hostnames, IP addresses, user identities, prompt/command content, absolute paths, credential values, or customer file content.

## Record consent and collect

Collect only after a named, customer-approved ticket route and diagnostic
consent process are active for the same accepted release and evaluation. Create
or reference the ticket through that approved route before collection. Use an
opaque ticket identifier containing only letters, digits, dots, underscores,
or hyphens. Do not put a customer name, email address, hostname, incident
description, or other personal data in the reference. No ticket URL or contact
details are available in this repository.

```bash
node scripts/support-bundle.mjs \
  --deployment /opt/aidr \
  --output /tmp/aidr-support-CASE-123456 \
  --customer-consent \
  --consent-reference CASE-123456 \
  --consent-recorded-at 2026-09-12T10:01:00.000Z
```

`--customer-consent` is a required operator attestation. The generated `consent-manifest.json` records the reference, purpose, timestamps, included sources, exclusions, and customer confirmations. It is not a substitute for the customer ticket or the organization's legal consent record.

The output defaults to a maximum of 256 KiB. Set a smaller approved boundary with `--max-bytes`; values from 512 bytes through 5 MiB are accepted. The collector validates the complete output size before creating the directory and never overwrites an existing output.

## Review and verify

Run the verifier before transfer:

```bash
node scripts/verify-support-bundle.mjs /tmp/aidr-support-CASE-123456
```

The verifier rejects extra files, missing files, symlinks, undeclared JSON fields, changed file sizes, changed SHA-256 digests, path-shaped data, URLs, email addresses, PEM material, JWT-shaped values, and common credential assignments. Review all four files manually as well:

- `consent-manifest.json` records the approved purpose and consent reference.
- `diagnostic-summary.json` contains the allowlisted structural result.
- `inventory.json` lists byte sizes and SHA-256 digests for the two data files.
- `SHA256SUMS` authenticates change detection for the three JSON files. It does not authenticate AIDR as publisher and is not a digital signature.

Transfer only the verified directory through the customer-approved ticket or secure exchange. Do not add logs, screenshots, environment files, database dumps, configuration archives, keys, or tokens to it. If support needs additional data, obtain separate purpose-specific consent and use a separately reviewed export procedure.

Delete the local bundle and revoke support access according to the ticket retention policy after the case closes. Record deletion in the ticket. The collector does not upload, transmit, schedule deletion, or prove that an external support system honored retention.

## Security regression check

Release engineering can exercise the fail-closed boundary with:

```bash
node scripts/verify-support-bundle.mjs --self-test
```

The self-test injects synthetic credential, identity, hostname and path canaries; checks deterministic output; and verifies consent, size, traversal, symlink, extra-file and tamper rejection. This is local implementation evidence. A real ticket drill, approved support contacts, response-time measurement, transfer-system controls, retention evidence, and customer acceptance remain separate production gates.
