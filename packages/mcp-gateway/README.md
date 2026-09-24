# AIDR inline MCP gateway

This loopback HTTP gateway inspects MCP tool results **before** they reach a model. It requires a high-entropy bearer token for every request, a tenant-specific explicit tool allowlist, an Ed25519 signed manifest with an operator-approved toolset, and live upstream tool-list agreement. Upstream connections use the core pinned-DNS transport with redirect, private-address and decoded-byte rejection. Text results are fully buffered and scanned; findings, unsupported output, drift, malformed/oversized streams and unavailable checks yield only a generic JSON-RPC error.

Server-initiated methods and binary or unsupported tool output are refused with a machine-readable `error.data` (`type: "mcp_gateway_refusal"`) and a redacted `aidr.mcp_gateway.coverage` event through the optional `onEvent` dependency. Startup emits one typed direct-upstream coverage event per configured server. Without an injected `directUpstreamCheck`, that surface is explicitly `unobservable`; a supplied observer may report `routed`, `unobservable`, or `bypass`, and a detected bypass refuses startup. This self-check does not force host routing or establish host-level egress control.

Build after building core, then start the self-contained bundle:

```sh
pnpm --filter @singularityrd/aidr-core build
pnpm --filter @singularityrd/aidr-mcp-gateway build
node packages/mcp-gateway/dist/aidr-mcp-gateway.mjs /secure/path/gateway.json
```

The gateway listens on `127.0.0.1` only. Point the MCP client's server URL at `http://127.0.0.1:7789/mcp/<serverId>` and send `Authorization: Bearer <token>` on every request. A remote client needs an operator-managed TLS/mTLS reverse proxy that preserves the authorization header and does not expose a bypass route to the upstream server. Configure the client to use only this URL; a host that can still call the original MCP server directly is outside the gateway's enforcement boundary.

For an MCP client that launches a stdio command, configure its command to run the bundled bridge instead:

```sh
export AIDR_MCP_CLIENT_TOKEN='<random bearer token whose SHA-256 is in gateway.json>'
node packages/mcp-gateway/dist/aidr-mcp-stdio.mjs /secure/path/gateway.json tenant-a client-a server-a AIDR_MCP_CLIENT_TOKEN
```

Pass the token through the process environment, never as a command argument. The bridge binds that token to the exact tenant, client and server in the signed gateway configuration, starts an ephemeral loopback gateway, and emits only inspected JSON-RPC responses on stdout. It accepts newline-delimited UTF-8 JSON-RPC input up to `maxBodyBytes` per frame. A rejected notification or malformed transport shuts down the bridge; stderr carries no raw tool data or token. Each client process needs its own bridge instance. Protect the environment and configuration from other local users.

Example configuration shape (replace every placeholder and keep the file private):

```json
{
  "stateDir": "/var/lib/aidr/mcp-attestation",
  "port": 7789,
  "maxBodyBytes": 262144,
  "clients": [{
    "id": "client-a",
    "tenantId": "tenant-a",
    "tokenSha256": "<64 lowercase hex SHA-256 of a random 32+ character token>",
    "allowedTools": { "server-a": ["search"] }
  }],
  "servers": [{
    "tenantId": "tenant-a",
    "id": "server-a",
    "url": "https://mcp.example.com/mcp",
    "transport": "json",
    "sessionMode": "stateless",
    "signedManifest": { "key_id": "publisher-key", "manifest": {}, "signature_b64": "..." },
    "trustedSigners": { "publisher-key": "<Ed25519 public key PEM>" },
    "revokedKeyIds": []
  }]
}
```

`transport` can be `json` or `sse`. SSE is buffered through one complete JSON-RPC result before any client response; the gateway never forwards partial events. For an upstream bearer token, set `upstreamAuthEnv` to an environment variable name; do not put the secret in the config or URL. `sessionMode: "required"` binds upstream `Mcp-Session-Id` to the authenticated client, tenant and server in memory for 30 minutes. Restart invalidates these sessions. The gateway forwards `notifications/initialized` only after manifest attestation and session validation and requires a bodyless HTTP 202 upstream acknowledgement.

On first contact or a signer, configured connection, or signed toolset change, the gateway quarantines the manifest. Review the publisher, configured endpoint and authentication identity, complete tool descriptions/schemas, requested tool allowlists, `toolsetHash`, and `bindingSha256` in the private quarantine state through an operator channel, then run:

```sh
node packages/mcp-gateway/dist/aidr-mcp-approve.mjs /secure/path/gateway.json tenant-a server-a <toolsetHash> <bindingSha256> <operatorId> "approved ticket and reason"
```

Approval is deliberately not an MCP tool or HTTP endpoint. The command requires the exact `bindingSha256` the operator reviewed; if the connection changes before approval, the old value is refused. The state directory must be writable only by the gateway operator. Rotate/revoke signer keys and client tokens through the private configuration and restart the gateway. No raw output or token is included in gateway errors or audit callback events. The signed manifest authenticates tool definitions; the operator approval binds the configured connection, not the upstream executable bytes or host routing. Attestation locks are never stolen automatically; after a lock timeout, stop every writer and verify none remains before removing only the matching `.lock` file, never the state JSON.

The three `dist/*.mjs` files bundle their own core and JavaScript dependencies. Copy all three together with `aidr-artifact.manifest.json` and `aidr-artifact.manifest.sig`; Node.js 22.12+ is required, while pnpm and `node_modules` are not. Commercial binaries refuse startup when the signed set is incomplete or changed. The signer private key and client bearer tokens are never part of the bundle.

Before starting a commercial bundle, provision the independently delivered Ed25519 artifact-verification public key in the gateway host's `~/.singularity-aidr/config.json` under `integrity.public_keys_pem`, with `integrity.enabled` and `integrity.verify_on_start` set to `true`. `scripts/deployment-prepare.mjs --artifact-verification-public-key-file <public.pem>` validates the key and writes this block to `agent-config.json`; install or merge that generated configuration at the default path for the account that runs the gateway. The gateway's own `gateway.json` is a separate file and intentionally does not accept the artifact-verification key.

In the portable customer kit, run `node deploy/gateway/aidr-mcp-gateway.mjs /secure/aidr-mcp-gateway.json`. After an operator has reviewed the quarantined connection and toolset, run `node deploy/gateway/aidr-mcp-approve.mjs /secure/aidr-mcp-gateway.json <tenantId> <serverId> <toolsetHash> <bindingSha256> <operatorId> "approved ticket and reason"`. The approval command is an operator action; it must not be exposed to an agent.

Supported scope: authenticated HTTP POST JSON-RPC `initialize`, `ping`, `tools/list`, `tools/call`, and `notifications/initialized`, with bounded JSON or finite SSE upstream responses. The stdio bridge supports those same methods and newline-delimited request framing. Tool results must have text content (optional structured JSON). Binary, image, audio, resource-link, streaming partial-result delivery, upstream pagination, server-initiated requests, and other MCP methods/notifications remain intentionally rejected. MCP clients that require those methods are not compatible yet. This package does not establish host-level egress control or proof of protection for every connector; deployment must test the exact MCP client and server pair and prevent direct upstream access.

Tool input-schema regexes use a conservative ReDoS-resistant subset: `pattern` and `patternProperties` expressions are limited to 256 characters, reject groups, alternation and backreferences, and allow at most one quantifier. Regex-matched string values and property names are limited to 4096 UTF-16 code units. One validation call also shares a 1,000,000-unit aggregate budget, charging each regex attempt by pattern-source length times input length. Schemas or arguments outside these bounds fail closed before tool execution.
