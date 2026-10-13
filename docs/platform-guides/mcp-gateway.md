# MCP Gateway

The inline MCP gateway (`@singularityrd/aidr-mcp-gateway`) sits between an MCP
client and one or more remote MCP servers. It checks every `tools/call`
**before** the upstream server runs it, and checks the result **before** the
model sees it. It runs on the loopback interface only.

The package README (`packages/mcp-gateway/README.md`) is the reference for the
configuration file, manifest attestation and operator approval. This guide
covers deployment, the detection path, and what the gateway does and does not
cover.

## Prerequisites

- **Node.js >= 22.12.0**. The three `dist/*.mjs` files bundle the detection
  core, its JavaScript dependencies and the threat rules; pnpm and
  `node_modules` are not needed at runtime.
- An Ed25519-signed tool manifest for each upstream server, and an operator
  who can review quarantined manifests.
- An absolute, private state directory (`stateDir`): owned by the account
  that runs the gateway and not group- or world-writable. The gateway refuses
  to start otherwise.
- An operator approval key pair. Create it on the operator's machine with
  `aidr-mcp-approve --generate-key <keyFile> <keyId>` (a passphrase-encrypted
  Ed25519 key) and put the printed public key under `approvalKeys` in the
  gateway configuration. Keep the key file and its passphrase away from every
  account an agent runs under.

## Build and start

```sh
pnpm --filter @singularityrd/aidr-core build
pnpm --filter @singularityrd/aidr-mcp-gateway build
node packages/mcp-gateway/dist/aidr-mcp-gateway.mjs /secure/path/gateway.json
```

Point the MCP client at `http://127.0.0.1:<port>/mcp/<serverId>` and send
`Authorization: Bearer <token>` on every request. For a client that launches a
stdio command, use `dist/aidr-mcp-stdio.mjs` instead (see the package README).

## Request path

For each `tools/call`, the gateway runs these steps in order. It stops at the
first one that fails.

1. **Authentication and scope.** The bearer token must match a configured
   client. The tool must be on that client's allowlist for this tenant and
   server.
2. **Manifest attestation.** The upstream's signed manifest must be approved
   by an operator, and the live `tools/list` must match it exactly. An
   approval counts only when it is signed by a key in `approvalKeys` and has
   not expired, so a process that can write the state directory cannot create
   one. Unsigned, altered or expired entries are ignored and reported as
   `approval_entry_ignored` audit events, and a state file whose integrity
   seal does not verify is refused (`manifest_rejected`).
3. **Argument schema.** Arguments must validate against the signed input
   schema. Only a bounded, ReDoS-resistant subset of JSON Schema is accepted.
4. **Threat and DLP evaluation.** The call is normalised to
   `mcp__<serverId>__<toolName>`. Then it goes through the same
   `evaluateToolCall` pipeline the other connectors use: threat rules, the
   allowlist, policy, and the server's tenant DLP policy if one is configured.
5. **Upstream call.** The request goes out over the pinned-DNS transport,
   which rejects redirects and private addresses.
6. **Result inspection.** Text is scanned. Binary content gets a bounded
   inspection (see below). Output schemas are enforced.

### Decisions returned to the client

A blocked call gets a JSON-RPC error with code `-32001` and the message
`AIDR blocked MCP request: <reason>`. The response never includes the
arguments, the upstream output or the verdict's free-text reasons.

| Reason | Meaning |
|---|---|
| `arguments_blocked` | The evaluator returned `deny`. `error.data` has `category` and, for built-in rules, `threatId`. |
| `input_not_fully_inspected` | The arguments exceed an inspection limit (nesting deeper than 16 levels, more than 1024 strings, a command/URL/path field over 64 KiB, or more than 4 MiB of text in total). The core denies the call instead of judging only the inspected part (`threatId: POL-INPUT-003`). Free text over 64 KiB is scanned in overlapping windows and is not itself a reason to block. |
| `approval_required` | The evaluator returned `ask`. The gateway blocks the call and sets `operatorActionRequired: true`. |
| `detection_unavailable` | The rules could not be loaded, or the evaluator failed or returned an invalid verdict. The call is blocked. |

`ask` is never an approval prompt the agent can answer. The gateway has no
approval tool, and neither the HTTP route nor the stdio route has an approval
method. An operator resolves a recurring `ask` out of band on the gateway
host, through the AIDR allowlist or agent configuration (`detection.agentConfigPath`).
DLP rule identifiers belong to the tenant, so the gateway never returns them
to the client.

### Detection rules and configuration

The release bundle carries the repository `threats/` and `allowlists/` rule
files inside the signed artifact. On first use, the gateway writes them to
`<stateDir>/detection-rules/<sha256>/` with owner-only permissions. If an
existing copy there has been changed, the gateway refuses to use it and blocks
tool calls until that directory is removed. To use a different rule set,
configure absolute paths:

```json
{
  "detection": {
    "threatsDir": "/opt/aidr/threats",
    "allowlistsDir": "/opt/aidr/allowlists",
    "agentConfigPath": "/etc/aidr/agent-config.json"
  }
}
```

If a configured directory is missing or holds no `.yaml` rules, every
`tools/call` is blocked with `detection_unavailable`. The gateway never treats
an empty rule set as a clean result.

A DLP policy is set per server with `dlpPolicy`. The core validates it, and
its `tenantId` must match the server's tenant. Without a DLP policy, arguments
still go through threat evaluation, but tenant keyword and regex DLP rules do
not apply.

Agent permission profiles restrict which servers and tools a client may call,
on top of the signed manifest and `allowedTools`. Put a profile document in
`agentProfiles` (the same format as `agent-profiles.json`, see
[Agent permission profiles](../agent-profiles.md)); profiles that name the
`mcp-gateway` connector apply to every client, and a client may be bound to
one profile with `"profile": "<name>"`. An invalid document, or a client bound
to a profile that does not exist, refuses startup. A profile deny returns
`profile_denied` (category `agent_profile`); a profile `ask` returns
`approval_required`. A profile never lets through a call that threat or DLP
evaluation blocks.

## Binary and resource output

By default, `image` and `audio` content and `resource` blobs are accepted only
when all of these hold:

- The MIME type is on `binaryOutput.allowedMimeTypes`. The default is PNG,
  JPEG, GIF and WebP. The operator may add `audio/wav`, `audio/mpeg`,
  `audio/ogg` or `application/pdf`. Only types whose leading bytes the gateway
  can verify are allowed.
- The base64 is canonical (`invalid_binary_encoding` otherwise).
- The decoded size is within `binaryOutput.maxDecodedBytes` (default 256 KiB,
  never more than `maxBodyBytes`; `binary_output_oversize` otherwise).
- The leading bytes match the declared type (`binary_content_mismatch`
  otherwise).

Printable text runs found inside binary payloads, such as image metadata
chunks, are scanned like any other output, and so are runs of UTF-16 (LE or
BE) text. Compressed text is inflated before it is scanned: PNG `zTXt`,
compressed `iTXt` and `iCCP` chunks and PDF streams whose first filter is
`FlateDecode`. Inflation is bounded (each stream may grow to 200 times its
compressed size or 64 KiB, whichever is larger; all streams of one item
together to 4 × `maxDecodedBytes`; at most 256 streams). Exceeding a bound
refuses the output as `binary_inflation_limit`, and a compressed stream that
cannot be decoded is refused as `binary_content_mismatch`. Other PDF filters
(ASCIIHex, ASCII85, LZW, RunLength, or FlateDecode behind another filter) are
not decoded. Text-like resource blobs
(`text/*`, JSON, XML, YAML, SVG and similar) are decoded as strict UTF-8 and
scanned as text. Any other type is refused as `unsupported_binary_output`.
Each accepted binary result emits a coverage event with
`reasonCode: "binary_output_bounded_inspection"` and
`coverageStatus: "limited"`, because the gateway does not interpret pixel or
audio content. `resource_link` output is still refused.

```json
{ "binaryOutput": { "maxDecodedBytes": 131072, "allowedMimeTypes": ["image/png"] } }
```

## Server-initiated messages

The gateway returns exactly one inspected response per client request, so it
cannot pass a server's `sampling/createMessage`, `elicitation/create` or
`roots/list` request back to the client. For this reason:

- When the client sends `initialize`, the gateway removes the `sampling`,
  `elicitation` and `roots` capabilities before forwarding it, so a compliant
  server does not send these requests.
- If the server sends one anyway, the gateway applies the `serverInitiated`
  policy for its category: `sampling`, `elicitation`, `roots` or
  `notifications`. Each category is set to `deny` (the default) or `ignore`.
  - `deny` refuses the whole call with `server_initiated_method`. `error.data`
    includes `serverMethod: "<category>"`.
  - `ignore` drops the message and delivers the final result. The gateway
    emits a `server_initiated_method_ignored` coverage event for the drop.
- Any other server method is always refused. So is a server request sent in
  place of a JSON (non-SSE) response.

Events record only the fixed category. They never include the server's method
name, parameters or content.

```json
{ "serverInitiated": { "notifications": "ignore" } }
```

## Operator command diagnostics

`aidr-mcp-gateway`, `aidr-mcp-approve` and `aidr-mcp-stdio` exit with `2` on a
usage error and `1` on any other failure. On failure they print one line in
this form:

```text
AIDR MCP gateway failed: <stage>[:<detail>]
```

The stage is one of `integrity_verification_failed`, `config_unreadable`,
`config_parse_failed`, `config_invalid`, `startup_failed`,
`approval_key_unavailable`, `approval_key_generation_failed`,
`approval_failed` or `bridge_stopped`. The detail is a fixed code, for example
`enoent`, `invalid_json`, `invalid_port`, `statedir_must_be_absolute`,
`state_dir_group_or_world_writable`, `approval_key_passphrase_rejected`,
`approval_key_not_configured`, `unknown_tenant_server`,
`stdio_client_binding_rejected` or `direct_upstream_bypass_detected`. The
gateway never prints error text itself, file contents, tokens or tool data.

## Limits

- The gateway enforces only the traffic that passes through it. It does not
  control host egress. A client that can still reach the upstream server
  directly is outside its enforcement boundary.
- It supports `initialize`, `ping`, `tools/list`, `tools/call` and
  `notifications/initialized`. It does not support resources, prompts,
  pagination, streaming partial results or relaying server-initiated
  requests.
- Reputation checks (URL, file, package) run only when a first-party
  reputation endpoint is configured. Without one, those checks are inactive,
  and a call is not reported as clean because of them.
