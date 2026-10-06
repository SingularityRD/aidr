# Behavioral learning operator runbook

Use the exact signed, customer-approved CLI/core versions supplied by the release
operator. Follow [Package installation](../package-installation.md) and
[Secret custody](secrets-management.md) first. This runbook does not make an
unapproved release, unsigned tenant configuration or test corpus customer-ready.

Learning is an explicit operator workflow. An agent callback or a caller's
`success: true` does not authorize learning. The execution broker must supervise
the actual command, then an independent operator must inspect the bound request,
classify it as benign and consent to retaining a bounded observation.

## Activate the signed tenant capability

The broker needs its existing managed enrollment and a currently valid,
issuer-signed V2 entitlement for the target tenant. Its `premium_modules` must
contain **both** `runtime_detectors` and `behavioral_learning_v1`. The fixed AIDR
configuration must already trust the approved issuer's Ed25519 public key under
`licensing.public_keys_pem`; signature and current revocation checks remain enabled.
Generating authority keys does not issue an entitlement or establish an issuer.
The baseline belongs to the original execution account's fixed AIDR profile.
A protected OS vault does not isolate secrets from processes running as that
same OS account; the independent approval account establishes separate custody.

The operator installs an issuer-signed detector policy at the broker account's
fixed path `~/.singularity-aidr/detectors/<runtime>.json`. Supported runtime
identities are `claude-code`, `cursor`, `vscode`, `openclaw`, `opencode` and `codex`.
Requests cannot select a different tenant, policy path or trust root.

The signed wrapper is `{ "alg": "ed25519", "payload": ..., "sig_b64": ... }`.
Sign the UTF-8 bytes returned by the installed core's
`canonicalDetectorPolicyPayload(payload)`, not the wrapper. The payload requires:

- `schema_version: 2`, the same `tenant_id` as the entitlement, and valid UTC
  `issued_at`/`expires_at` timestamps.
- `behavioral.enabled: true`, `learning_allowed: true` and
  `learning_capability: "durable_baseline_v1"`.
- `behavioral.learning_authorities.execution` and `.approval`: key-ID maps to
  complete Ed25519 SPKI public keys. The two roles must use different actual
  keys. Private keys, including PEM private-key tails, do not belong in policy.
- An approved, nonempty `behavioral.threat_corpus` for this tenant. It contains
  `schema_version: 1`, `tenant_id`, `corpus_id`, positive `corpus_version`,
  `model_version: "local-tinyhash-v1"`, `dimension: 100`, `entries` and `sha256`.
  Each entry has a unique `threatId`, a finite unit-normalized 100-number
  `embedding`, and `metadata.category`, `.severity` and `.description`.
  `sha256` covers the canonical UTF-8 corpus object with **only its `sha256`
  field omitted**. The containing issuer signature authenticates that digest.

The customer must approve and qualify the real corpus and its coverage. Repository
synthetic fixtures are tests, not a production threat database. Missing, empty,
incompatible or unauthenticated corpus data never authorizes execution or learning.

For deliberate cold-start collection, the signed policy must explicitly set
`behavioral.unavailable_action: "skip"`. This permits the missing baseline leg to
skip while the ML leg is available and clean; it does not bypass ML, DLP, other
execution checks or independent approval. The default is `"ask"`, and cold-start
learning does not proceed under it. Review this degraded behavior before signing.
The default warmup requires ten accepted observations, with at most five cold
observations for an identical fingerprint. Use real, individually approved benign
operations; do not manufacture noise or copy fixtures to warm a customer baseline.

When DLP is enabled, approve both actual input and output coverage. The broker's
request is inspected as `application/json`, and shell output as `text/plain`.
Include those formats in `dlp.policy.supportedFormats` and use the intended
`rules[].directions`, including `"output"` for output rules. A JSON-only policy
correctly rejects plain shell output; changing formats is an issuer policy change.

## Create independent authority keys

Use two separate operator accounts with private working directories. Keep the
execution signer away from the agent, and keep the approval signer away from
both the agent and the execution account. Two files in an agent-accessible account
do not establish independent custody.

On the execution broker account:

```sh
aidr learning keygen --role execution --out execution-authority.json
```

On the independent approval account:

```sh
aidr learning keygen --role approval --out approval-authority.json
```

Each command prints the key ID, public key and reference path. Give the issuer
only those public keys and IDs for the signed role maps. The reference uses an
opaque OS vault ID; private key values never go into command arguments, logs or
support tickets. Windows DPAPI, macOS Keychain and Linux Secret Service writes
use stdin. Validate the native vault under the actual customer account.

`--secret-store file-acl` is an explicitly selected fallback for an authority
signer: a separate owner-only PKCS8 file sits beside its reference. It has reduced
protection and still requires separate operator custody. Durable baseline
authentication independently requires a working native OS vault on the broker;
the signer fallback does not replace that vault. Missing keys do not auto-regenerate.

## Sign and install the reviewed policy

Keep the existing protected **issuer** private key on the issuer station, never
on the agent or execution broker. This issuer key differs from both learning role
keys. Prepare `policy-payload.json` containing the fully reviewed V2 payload,
real approved corpus and both public role maps. An entitlement is issued through
the existing authorized licensing process, not this script.

Save the following as `sign-learning-policy.mjs` in a private issuer working
directory with the approved core package installed. Its arguments are file paths;
none contains a private key value. The issuer station's fixed AIDR configuration
must already trust this issuer. This recipe checks the corpus digest and role
keys; the broker's provisioning verifier remains the final activation check.

```js
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  canonicalDetectorPolicyPayload, loadConfig,
  LOCAL_EMBEDDER_MODEL_VERSION, LocalEmbeddingModel,
  preparePrivateLocalDirectory, preparePrivateLocalFile,
  validateLearningAuthorities,
} from '@singularityrd/aidr-core';

const [payloadArg, keyArg, outputArg] = process.argv.slice(2);
try {
if (!payloadArg || !keyArg || !outputArg) throw new Error('Three file paths required.');
async function readBounded(path, max) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > max)
    throw new Error('Invalid input file.');
  const fd = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await fd.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino) throw new Error('Input changed.');
    const bytes = Buffer.alloc(max + 1);
    let length = 0;
    while (length < bytes.length) {
      const part = await fd.read(bytes, length, bytes.length - length, length);
      if (!part.bytesRead) break;
      length += part.bytesRead;
    }
    const after = await lstat(path);
    if (length > max || after.dev !== before.dev || after.ino !== before.ino ||
        after.size !== before.size || after.mtimeMs !== before.mtimeMs)
      throw new Error('Input changed or exceeded its bound.');
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length));
  } finally { await fd.close(); }
}
const config = await loadConfig();
if (!config.licensing.public_keys_pem.length) throw new Error('Installed issuer roots required.');
const payload = JSON.parse(await readBounded(resolve(payloadArg), 8 * 1024 * 1024));
const behavioral = payload.behavioral;
if (payload.schema_version !== 2 || behavioral?.enabled !== true ||
    behavioral.learning_allowed !== true || behavioral.learning_capability !== 'durable_baseline_v1')
  throw new Error('Reviewed V2 learning capability required.');
validateLearningAuthorities(behavioral.learning_authorities);
const { sha256, ...corpus } = behavioral.threat_corpus ?? {};
if (corpus.tenant_id !== payload.tenant_id || corpus.schema_version !== 1 ||
    corpus.model_version !== LOCAL_EMBEDDER_MODEL_VERSION || corpus.dimension !== 100 ||
    createHash('sha256').update(canonicalDetectorPolicyPayload(corpus)).digest('hex') !== sha256)
  throw new Error('Approved compatible corpus digest required.');
const model = new LocalEmbeddingModel({ modelPath: '', vectorSize: 100, similarityThreshold: 0.7 });
await model.importThreatCorpus(corpus.entries);
const keyPath = resolve(keyArg);
const keyStat = await lstat(keyPath);
if (!keyStat.isFile() || keyStat.isSymbolicLink() || keyStat.nlink !== 1)
  throw new Error('Existing protected issuer key required.');
preparePrivateLocalFile(keyPath);
const key = createPrivateKey(await readBounded(keyPath, 16 * 1024));
if (key.asymmetricKeyType !== 'ed25519') throw new Error('Ed25519 issuer required.');
const publicDer = createPublicKey(key).export({ type: 'spki', format: 'der' });
if (!config.licensing.public_keys_pem.some(pem =>
  createPublicKey(pem).export({ type: 'spki', format: 'der' }).equals(publicDer)))
  throw new Error('Issuer is not trusted by the installed configuration.');
const envelope = { alg: 'ed25519', payload,
  sig_b64: sign(null, Buffer.from(canonicalDetectorPolicyPayload(payload)), key).toString('base64') };
const output = resolve(outputArg);
preparePrivateLocalDirectory(dirname(output));
const fd = await open(output, 'wx', 0o600);
try { await fd.writeFile(JSON.stringify(envelope)); await fd.sync(); }
finally { await fd.close(); }
preparePrivateLocalFile(output);
console.log(output);
} catch {
  console.error('Policy signing failed; inspect the trusted local files and reviewed policy.');
  process.exitCode = 1;
}
```

```sh
node sign-learning-policy.mjs policy-payload.json /protected/issuer-key.pem signed-policy.json
```

The output must be a new path; do not overwrite an existing approved artifact.
If signing or publication fails, discard the incomplete new artifact after
investigation. Transfer only `signed-policy.json` through the operator-approved
channel. Keep any backup of the previous policy private.

On the broker, use the installed core's `detectorPolicyPath(runtime)` to obtain
the fixed destination, `preparePrivateLocalDirectory(dirname(destination))`,
`atomicWriteJson(destination, signedEnvelope)` and
`preparePrivateLocalFile(destination)` for the authorized policy replacement.
Reject a symlink or nonregular existing destination before replacement. Do not
copy issuer private keys, replace trust roots from a tool request or disable
signature verification. After installation, run:

```sh
aidr learning export-authority --runtime opencode --out activation-check.json
```

Successful export proves this installed policy/entitlement is currently eligible
for the handoff. An invalid grant, signature, authority map, corpus or revocation
state prevents export. Resolve the issuer configuration or restore the previous
approved policy through the same operator process; do not bypass the failure.

## Execute, review and ingest

Create a private `request.json` containing **only** this structure. The example
is a harmless Windows foreground command; the actual operator must approve their
own request. On POSIX, use `"execution_shell": "/bin/sh"` with a corresponding
foreground command.

```json
{
  "sessionId": "operator-reviewed-session",
  "toolName": "Bash",
  "toolInput": {
    "command": "Write-Output 'ordinary document'",
    "execution_shell": "powershell.exe"
  }
}
```

On the execution broker:

```sh
aidr learning execute --runtime opencode --request request.json --key-ref execution-authority.json --out execution.json
aidr learning export-authority --runtime opencode --out broker-authority.json
```

The broker uses its fixed native shell and the exact evaluated request. It has
no request-selected shell executable, working-directory, environment, config or
policy override. It requires foreground shell exit code zero, complete valid
UTF-8 output, successful output inspection and the unchanged signed activation
context. The deadline is 60 seconds and combined stdout/stderr limit is 2 MiB.
Timeout, nonzero exit, signals, excess output, invalid UTF-8 or an observed
unfinished process prevent a receipt. Raw output is not printed.

This receipt attests **foreground shell completion**, not business success,
success of every subcommand or termination of detached work. Use foreground,
deterministic operator commands. Windows does not establish whole descendant-tree
completion; POSIX also rejects an observed surviving process group. Clean output
and exit code zero alone do not establish a benign execution.

Transfer the original request, execution receipt and private broker-authority
file to the independent approval station. That station must already trust the
issuer in its own fixed AIDR configuration and maintain current revocation
evidence. The handoff contains the issuer-signed tenant policy and entitlement;
the execution authority's signed receipt separately binds the target device and
runtime, and ingestion checks the original host. The outer handoff device field
alone is not an issuer attestation. No API key or vault secret is transferred.
It includes potentially
confidential policy matchers: keep it private. Approval may run on another OS.

```sh
aidr learning approve --runtime opencode --request request.json --receipt execution.json --broker-authority broker-authority.json --key-ref approval-authority.json --out approval.json
```

Review the displayed escaped command, tenant/device/session, shell binding and
input digest. The interactive terminal requires the exact displayed
`APPROVE <execution-id>` phrase after explicit benign classification and retention
consent. Piped input, an empty answer, cancellation or a missing approval role
fails. Trust, request binding and expiry are checked again after the prompt.
Return the signed approval through the approved channel.

Ingest on the **original execution host**, preserving the original request and
shell binding:

```sh
aidr learning ingest --runtime opencode --request request.json --receipt execution.json --approval approval.json
```

Check exit code zero and `result.learning.accepted: true`. A rejected observation
sets a nonzero exit code; inspect its reason before proceeding. Ingestion verifies
both distinct signatures and tenant, device, runtime, session, input, policy,
corpus, model and entitlement bindings before its authenticated durable commit.
Receipts expire within 24 hours; they cannot be accepted after expiry. Replay
cannot add a second observation. A fresh process restores only authenticated,
still-eligible records. Observations are bounded to 30 days and session quotas;
raw commands/output are not retained as baseline observations. Policy, corpus,
authority or grant changes can invalidate eligibility; grant renewal is evaluated
against current trust/revocation evidence and the recorded original activation.

If execution happened but saving the receipt failed, investigate before rerunning
the command: receipt failure does not undo command effects. Do not delete replay
records to force an acceptance. Missing/unreadable authority keys require an
operator-approved new key and signed policy rotation. Baseline authentication
failure requires vault recovery through the existing custody process; do not
replace its key automatically or treat unsigned V1/V2 baseline files as learned
trust. Record customer acceptance separately for actual operator accounts, native
vaults, the approved corpus, real runtime and negative/restart cases.
