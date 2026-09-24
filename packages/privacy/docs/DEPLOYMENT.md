# Defense / air-gapped deployment gate

## Release status

The core is executable without an internet connection and has passing local automated tests. This is **not** evidence of actual deployment at BMC, certification, a third-party penetration test, or production NER coverage. Use only synthetic/non-sensitive integration data until the gates below are completed.

## 1. Reproducible and approved build

The full ZIP includes compiled ESM and TypeScript declarations. Production core imports only Node standard-library modules; no production npm package is required. The build uses TypeScript 5.8.3 and @types/node 22.19.7. The environment could not obtain a registry-backed lockfile (`npm --offline` cache miss); no fake integrity entries or successful dependency audit are claimed.

In a controlled connected staging environment, resolve those pinned development packages and their transitive dependencies, produce and review the lockfile, generate a complete environment SBOM, run dependency and source scans, rebuild, run all tests and compare release content. Apply the organization's signing/attestation process before importing artifacts into an air-gapped environment. The supplied checksums detect changes relative to a trusted manifest; they do not prove publisher identity.

Only Node 22.16.0 on the reported Linux architecture was executed here. Pin and test an approved supported runtime in the actual target OS/container; do not treat this as a current Node patch or CVE recommendation. No vulnerability database query/audit was run for the environment.

## 2. Approved local models

The worker is optional and has **not** run real model inference in this delivery. No default model weights are included.

Use a controlled staging host to obtain immutable, licensed model + fast-tokenizer artifacts. Reject unreviewed remote code and pickle checkpoints. Review model origin, data licensing, language/type coverage and label meanings. A generic English PER/ORG/LOC model is not a Turkish ADDRESS model.

Prepare a directory such as:

```text
/opt/aidr-models/
  model-config.json
  tr-approved/  config.json tokenizer.json model.safetensors ...
  en-approved/  config.json tokenizer.json model.safetensors ...
```

Copy and edit `ner/model-config.example.json`; paths are relative to the eventual manifest's containing directory. The approved token classifier label map must map actual base labels to canonical types, and explicitly map ordinary non-PII labels to null. Do not fabricate an ADDRESS label or Turkish support to satisfy the defense profile.

Create the inventory from locally reviewed files:

```sh
python3 /opt/aidr-privacy/ner/build_manifest.py \
  --config /opt/aidr-models/model-config.json \
  --output /opt/aidr-models/manifest.json
```

This command prints the manifest SHA-256. Review the contents and distribute the expected digest through the organization's signed configuration channel. Recomputing a digest from arbitrary downloaded files alone does not establish trust.

Build an approved CPU PyTorch / Transformers / tokenizers / safetensors virtual environment and wheelhouse. Pin exact package versions and hashes, include them in the actual deployment SBOM, and execute model acceptance tests. `ner/DEPENDENCIES.md` intentionally does not pretend an untested Python dependency stack is production locked.

## 3. Process and host isolation

Run the service and NER child as a dedicated non-root account, with model and application mounts read-only. Deny outbound network at the OS/container level. Keep model cache and temporary storage local, private and bounded. Disable core dumps and use the organization's approved swap policy. Restrict writable paths, inherited environment and process privileges.

Apply CPU, memory, file-descriptor and process-count limits. The worker uses CPU inference; any future ONNX/INT8 conversion requires numerical-equivalence and recall regression testing. No ONNX backend or measured quantization benefit is included in this release.

The supplied subprocess provider uses bounded stdin/stdout, no shell and one in-flight request. It is not an autoscaling server or worker pool. Route concurrent requests to bounded per-worker engines/providers with admission control, cancellation and rate limits in AIDR. Do not build an unbounded queue of raw sensitive prompts.

The TypeScript scan deadline is cooperative. Run the library outside a shared high-criticality event loop where a single synchronous operation could affect other tenants. Use a supervised worker/process boundary for hard cancellation and availability. Scan outages must deny external egress rather than fail open.

## 4. Start an approved provider

Adapt `ner/local-provider.example.json` with absolute paths and the reviewed 64-hex manifest digest. It is a placeholder template, not a deployable default configuration.

```ts
import { PrivacyEngine, LocalNerProcess } from '@singularityrd/aidr-privacy';

const ner = await LocalNerProcess.open({
  command: '/opt/aidr-ner/bin/python3',
  args: [
    '/opt/aidr-privacy/ner/ner_worker.py',
    '--manifest', '/opt/aidr-models/manifest.json',
    '--manifest-sha256', approvedManifestDigest,
    '--threads', '2',
  ],
  startupTimeoutMs: 120_000,
});

const privacy = new PrivacyEngine({
  profile: 'defense',
  ner,
  maxConcurrent: 1,
  nerTimeoutMs: 10_000,
  policyId: 'approved-egress-policy-v1',
});

// Forward only an allow/redact result with a non-null output.
// On shutdown, dispose the engine and close the worker.
```

`approvedManifestDigest` must be loaded from trusted deployment configuration, not from the same untrusted request being inspected. Configure timeouts from measurements on the actual hardware, not the core-only benchmark. Do not run this sample until the model/dependency acceptance gate is complete.

## 5. AIDR enforcement boundary

Bind tenant and policy to trusted authenticated identity. Authorize the tool and destination before invocation. Intercept complete prompts, agent messages, memory writes/reads where relevant, tool arguments and relevant tool results at their actual sinks. Redaction does not replace tool authorization or prevent a prompt injection from selecting an unauthorized destination.

For JSON, pass original serialized text so duplicate-key checks can run. Parsing with a permissive parser first loses that evidence. Validate the masked result against the receiving tool's schema. If required semantics are broken, block or request a local revision; never reconstruct original PII automatically.

Hold streaming text until a complete bounded message has been scanned. Independently bound the entire request and conversation. This release does not detect arbitrary sensitive phrases distributed across independent messages or unrelated JSON values. Restrict those channels or add evaluated context-aware controls.

Block unsupported binary attachments, PDFs, images, archives, custom encodings and encrypted payloads at the egress gateway until dedicated extractors/inspection paths have been implemented and validated. A filename or URL is not the contents of the referenced file. Do not mark an attachment scanned merely because its text wrapper was scanned.

## 6. Policy, audit and operations

Review dictionaries and schema policies through the existing signed configuration/change-control system. This library does not provide policy signing/distribution. Do not accept arbitrary user regular expressions; the included dictionary is a bounded literal matcher.

Use the existing AIDR RBAC/mTLS/SSO control plane. Only minimal audit summaries/static codes should enter logs or SIEM. Avoid raw prompts, original values, full result bodies or raw JSON paths in telemetry. Configure retention, access controls and alert destinations per institution. SIEM/webhook transport is not included here.

Review, bypass, emergency change and break-glass workflows must be institution-approved and auditable. The module exposes no automatic raw-text override for denied traffic. No generic “warn then send raw data” path is supplied.

## 7. Required evidence before production sign-off

| Gate | Delivered here | Required on the actual deployment |
|---|---|---|
| Core regression/property tests | Executed, reports included | Rerun on target runtime/OS |
| Artifact verification / Python offset helpers | Executed with synthetic fixture bytes | Verify approved real model artifacts |
| Local worker protocol | Executed with an explicitly fake deterministic worker | Run approved real worker end to end |
| TR/EN name/address quality | Not measured | Independently annotated domain corpus, per-language/type metrics |
| Whole-message leakage resistance | Specified test scenarios executed | Red team every supported connector/tool/file path |
| Performance | Single-process, rules-only measurements | Real models, host limits, cold start, concurrency, soak and outages |
| Model and dependency licensing | Public card review only | Legal/procurement/security approval |
| Supply chain | Source + content hashes | Reviewed locks, CVE/source scan, SBOM, signed reproducible release |
| Network restriction | No core network calls; offline worker flags | Verified OS egress deny, host isolation, traffic observation |
| Enterprise controls | Integration sample only | AIDR auth/RBAC/mTLS, policies, audit retention, incident response |
| Institutional acceptance | Not performed | Independent assessment and customer UAT/sign-off |

There is no universal certification conferred by the string `defense`. The final authority for deploying on classified or regulated systems is the customer's security/accreditation process.
