# Integration contract

## Text

`await engine.protect(text)` returns `{decision,output,findings,reasons,audit}`. Output can be forwarded only for `allow` or `redact` and only when non-null. Findings are UTF-16 offsets in original text and contain no original entity values. Scores are heuristic/non-calibrated. `review` is not an instruction to send raw data with a warning.

## JSON tool arguments

`await engine.protectJson(serializedJson)` returns a serialized protected output, or null. Pass raw serialized JSON to preserve duplicate-key detection. Sensitive keys and values are inspected; a sensitive key blocks rather than being renamed. Named sensitive subtrees can be replaced with a string marker. The caller must validate the resulting JSON against the tool's expected schema and deny on mismatch.

```js
import { PrivacyEngine } from '@singularity/aidr-privacy';
import { createToolGuard } from './examples/aidr-tool-guard.mjs';

const engine = new PrivacyEngine({ profile: 'strict' });
const guarded = createToolGuard(engine, async (toolName, safeArguments) => {
  // Authenticate/authorize first, then schema-validate safeArguments here.
  // Call only a destination already approved by AIDR policy.
  return existingToolTransport(toolName, safeArguments);
});
```

`existingToolTransport` is the surrounding product's transport; it is not supplied by this module. The guard test uses a fake sink to prove that block/review never invokes it. The user's real AIDR repository was not available and has not been modified.

## Streaming

```js
import { AtomicTextGate } from '@singularity/aidr-privacy';
const gate = new AtomicTextGate(engine);
for await (const chunk of boundedIncomingMessage) gate.push(chunk);
const result = await gate.finish();
// Only now, and only with a forwardable result, may egress occur.
```

`push` never emits data. The gate buffers only a complete bounded message. For long live streams, define an externally authorized framing policy rather than pretending arbitrary chunk boundaries are safe. The module does not correlate separate tool calls, separate messages or intentionally split fields.

## Logging

Log only a minimized subset of `audit` and static `reasons`, not request text, `output`, original spans re-sliced from text or dynamic exception messages. `policyId` and `keyId` must be static identifiers, not customer names. The package does not send metrics/logs remotely.

## Keys and lifecycle

Create an engine per authenticated tenant/policy/key boundary. Load tokenKey from the organization's secrets manager or protected file, not prompt/tool metadata. Use a cryptographically generated key of at least 32 bytes. Calling `dispose` clears the engine's copied key and stops further successful use, but cannot guarantee erasure of all string/GC copies. Close a LocalNerProcess separately during shutdown.

## Concurrency and cancellation

Rules execute synchronously within the async API. The engine limits concurrent text calls, but service-level admission control and JSON request concurrency still belong to the caller. A LocalNerProcess serves one request at a time; overlapping use can deny a request rather than queueing raw inputs. Provision a bounded pool externally. A timeout/abort kills the child and it must be restarted by supervised, rate-limited lifecycle code. Never reuse a timed-out child as though the request had cleanly completed.

## Browser and gateway

This is a Node library, not a browser bundle: HMAC, IP validation and subprocess integration use Node APIs. A browser extension or native/wasm port requires a separate adapter/build and tests. Node's memory footprint is not a guarantee about a future Rust/WASM version. TLS inspection, certificate trust, pinned applications, custom agents and unmanaged endpoints are outside this library.
