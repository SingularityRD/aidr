# Defense / air-gapped deployment gate

## Release status

The core is executable without an internet connection and has passing local automated tests. This is **not** evidence of actual deployment at BMC, certification, a third-party penetration test, or production NER coverage. Use only synthetic/non-sensitive integration data until the gates below are completed.

## 1. Reproducible and approved build

The private package includes compiled ESM and TypeScript declarations. Its text engine uses Node standard-library modules; the configured deployment also needs the installed core OS-vault package and its actual runtime dependencies, physical Python inference/parser environments and approved model files. The committed workspace lock resolves TypeScript5.9.3 and @types/node22.19.11 for this package. Use the frozen reviewed lock; a passing build alone does not establish independent supply-chain approval.

Prepare the approved complete dependency cache/image, generate the complete deployment SBOM, run dependency and source scans, rebuild with maps disabled, run all tests and compare release content. Apply the organization's signing/attestation process before importing artifacts into an air-gapped environment. The supplied checksums detect changes relative to a trusted manifest; they do not prove publisher identity. The [portable operator handoff](../deployment/PRIVATE_INSTALL.md) uses the actual installed package layout and prepares reference-only configuration without requiring a live staging host.

Only Node 22.16.0 on the reported Linux architecture was executed here. Pin and test an approved supported runtime in the actual target OS/container; do not treat this as a current Node patch or CVE recommendation. No vulnerability database query/audit was run for the environment.

## 2. Approved local models

The optional worker ran real hash-pinned public-candidate inference and fresh offline dependency replays on Windows x64 CPython 3.12.10 and Linux x86_64 CPython 3.11.2 on 2026-10-06. The Linux real-worker probe used a network-disabled container and read-only package/model mounts. The candidates remain unapproved and unqualified; measured failures and reproducible staging instructions are in `MODEL_PROVIDER.md`. No default model weights are included in the package.

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

Build an approved CPU PyTorch / Transformers / tokenizers / safetensors virtual environment and wheelhouse. Pin exact package versions and hashes, include them in the actual deployment SBOM, and execute model acceptance tests. `ner/requirements.windows-py312.lock.txt` and `ner/requirements.linux-py311.lock.txt` reproduce their respective measured probe environments; `ner/DEPENDENCIES.md` describes their platform and approval limits.

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

Review dictionaries and schema policies through the existing signed configuration/change-control system. The existing `signPolicy` helper and pinned/durable policy registry implement the envelope; institution signing identity, key custody and distribution remain operator inputs. Do not accept arbitrary user regular expressions; the included dictionary is a bounded literal matcher.

Use the existing AIDR RBAC/mTLS/SSO control plane. Only minimal audit summaries/static codes should enter logs or SIEM. Avoid raw prompts, original values, full result bodies or raw JSON paths in telemetry. Configure retention, access controls and alert destinations per institution. SIEM/webhook transport is not included here.

Review, bypass, emergency change and break-glass workflows must be institution-approved and auditable. The module exposes no automatic raw-text override for denied traffic. No generic “warn then send raw data” path is supplied.

## 7. Required evidence before production sign-off

| Gate | Delivered here | Required on the actual deployment |
|---|---|---|
| Core regression/property tests | Executed, reports included | Rerun on target runtime/OS |
| Artifact verification / Python offset helpers | Fixture tests and pinned real candidate files verified | Verify approved real model artifacts |
| Local worker protocol | Fake-worker suite plus actual offline public-candidate inference | Run approved real worker end to end |
| TR/EN name/address quality | Public synthetic comparison; candidates unqualified | Independently annotated domain corpus, per-language/type metrics |
| Whole-message leakage resistance | Specified test scenarios executed | Red team every supported connector/tool/file path |
| Performance | Single-process, rules-only measurements | Real models, host limits, cold start, concurrency, soak and outages |
| Model and dependency licensing | Public card review only | Legal/procurement/security approval |
| Supply chain | Pinned build/runtime/model locks and artifact checks | Complete deployment CVE/source scan, SBOM, institution-signed reproducible delivery |
| Network restriction | Fixed checked provider transport, offline worker flags and firewall templates | Verified OS egress deny, host isolation, traffic observation |
| Enterprise controls | Actual configured OIDC/broker, mTLS, durable policy/labels and installed MCP regression | Real institution identity/device/provider authority, audit retention, incident response |
| Institutional acceptance | Not performed | Independent assessment and customer UAT/sign-off |

There is no universal certification conferred by the string `defense`. The final authority for deploying on classified or regulated systems is the customer's security/accreditation process.
