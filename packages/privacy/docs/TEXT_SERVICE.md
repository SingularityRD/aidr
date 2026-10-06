# Narrow on-prem text service

The packaged [configured broker/client deployment](CONFIGURED_BROKER.md) supplies the concrete HTTPS OIDC/JWKS + institution MDM/account broker adapter, durable login/refresh/revoke, OS-vault configuration, SDK host seam and mandatory host-output firewall examples. Use that installation path for a selected application; the lower-level callback contract below remains available for trusted integrations.

The `aidr-privacy-service` launcher owns one final text request/response route for one tenant and one configured provider. It uses the existing mTLS gateway at `POST /v1/egress`, fixed OpenAI Responses or Gemini generateContent destinations, durable state and audit, and the defense text profile. It rejects image fields, files, arbitrary upstream URLs, streaming and unsupported provider responses. It is not an OpenAI-compatible proxy and does not connect existing AIDR hooks, Chrome/native clients or other applications automatically.

Only the selected application's final send may use this route. Keep provider API credentials on the service; restrict other provider routes with the actual host/network controls. Existing core hook DLP covers tool arguments through its separate signed tenant policy. This service does not establish a guarantee for every model, browser, MCP, telemetry or reputation exit.

## Required deployment inputs

Use a supported, institution-approved Node 22.16+ Linux runtime and a dedicated service account. Prepare a private durable state directory, owned by that account with mode 0700; the SQLite file must be 0600. Use local storage, not NFS or a multi-host shared database. Follow [state recovery](STATE_RECOVERY.md) before upgrading an older RC database.

Supply all of the following through trusted deployment configuration:

- The complete `RuntimeOptions` tenant, encryption keyring, independent audit key, signed policy and pinned policy-verification keys.
- Pinned user, device and provider issuer/audience/public keys and the real broker that provisions and revokes durable sessions. The broker startup callback must return a principal produced by `runtime.identity.authenticate()` from its signed bootstrap user token after the corresponding session has been provisioned. A fabricated principal or missing/revoked session fails startup. Supply its `close()` function to stop broker resources on service shutdown. This callback is administrator code; the service does not invent IdP, MDM or provider-account evidence.
- One destination with an approved model and nonempty server-side provider API credential. Only `openai-responses` and `gemini-generate-content` are supported; their actual origins/endpoints come from the existing fixed transport.
- Server TLS certificate/key and a current enrolled-device CA. Clients must present an enrolled certificate, user/device/provider tokens and a device token bound to that exact certificate. No anonymous HTTP, forwarded-certificate header or TLS bypass is supported.
- An approved local Python inference environment, actual immutable model/tokenizer files, the reviewed model manifest and its independently distributed SHA-256. See [model setup](DEPLOYMENT.md). The launcher executes the bundled offline `ner/ner_worker.py`, checks defense TR/EN PERSON+ADDRESS capability and performs a readiness inference before listening. It supplies no weights and permits no rules-only/strict profile override. Capability declarations and this probe do not establish model accuracy; customer-data qualification remains required.

Missing or invalid configuration, model startup/inference, broker principal/session or TLS fails before the listener opens. Broker initialization is bounded to thirty seconds and receives an `AbortSignal`; the real adapter must cancel its work when signalled. Late returned broker resources are closed. Startup errors log only `SERVICE_START_FAILED`. The administrator-owned configuration module is executable trusted code: protect its files/imports and secrets, include application/model/environment artifacts in the actual signed deployment, and avoid logging tokens or content inside the broker/module.

## Start

Build only this package from the workspace root:

```sh
pnpm --filter @singularity/aidr-privacy build:release
node /opt/aidr-private/node_modules/@singularity/aidr-privacy/dist/platform/serve.js --config /opt/aidr-private/node_modules/@singularity/aidr-privacy/examples/platform/service-config.mjs
```

An administrator configuration module has this shape. The imported runtime options, TLS material and broker adapter are deployment inputs, not bundled defaults:

```js
import {runtimeOptions, tls} from './approved-runtime.mjs';
import {initializeBroker} from './session-broker.mjs';

export default {
  runtime: runtimeOptions, // RuntimeOptions excluding ner/profile/clock; exactly one destination
  ner: {
    python: '/opt/aidr-ner/bin/python3',
    manifest: '/opt/aidr-models/manifest.json',
    manifestSha256: 'REPLACE_WITH_INDEPENDENTLY_APPROVED_64_HEX_DIGEST',
  },
  tls, // Buffer key/cert/clientCa, loaded from protected mounts
  initializeBroker,
  host: '127.0.0.1',
  port: 8443,
};
```

The placeholder digest and missing imports intentionally cannot start a service. The module must not provide `profile`, an alternate NER adapter or a test clock. Bind to a specific IP address; loopback is the default. A reverse proxy must preserve the actual enrolled-device TLS channel by tunnelling it; terminating mTLS there does not preserve the required end-client certificate binding.

Run under the institution's service supervisor with a dedicated account, restrictive umask, read-only application/model/configuration mounts, bounded writable state/temp paths, CPU/memory/process limits and disabled core dumps. `SIGTERM`/`SIGINT` stops accepting connections, allows up to ten seconds for in-flight HTTP requests, then closes remaining connections, broker resources, state and the local NER process. Provider calls already sent may have completed remotely; shutdown does not undo them.

## Client contract and acceptance

Send `Content-Type: application/json`, `Authorization: Bearer <user-token>`, `x-aidr-device` and `x-aidr-provider` over the enrolled mTLS connection. Body fields are `requestId`, `destinationId`, `text` and an optional approved retry `reviewCaseId`. No image field is accepted, including an empty list. The body limit is 512 KiB; the text engine and signed policy enforce their smaller text limits.

The response is a dispatch receipt. HTTP 200 can report `sent / RESPONSE_WITHHELD` with `output: null`; external dispatch already occurred in that case. A released `output` is a JSON string containing `outputText`, not the raw upstream payload. HTTP 409 includes a review case only for the supported semantic review flow; approved retries require unchanged content/session/policy and a fresh request ID. Unknown dispatch outcomes must not be automatically retried. Never fall back to the original text when output is null.

Run the package's platform tests, then verify the exact delivered artifacts on the intended host with real brokers, enrolled certificates, approved NER and the actual provider account. The real mTLS regression uses an explicitly rules-only test runtime and a controlled outbound sink: it proves handler identity binding, request/reply sanitization and no sink call for blocked requests. It does not qualify learned-model recall, public-provider operation, network bypass restrictions or customer installation.

The package stays private. Delivering this service requires signing its exact private image/archive and binding its digest to the release evidence, together with required worker/model/environment artifacts. Adding it to the public npm package list is unnecessary and would not establish this delivery evidence.
