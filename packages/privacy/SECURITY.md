## 0.4.0 enterprise trust boundary update

Read `docs/enterprise/PRODUCTION_GATES.md` before deployment. `TrustedContext`/tool principals are authenticated application inputs, not user/model claims. Local ledgers are not distributed stores. fsync evidence is not immutable storage. `installDurable` requires a real trusted writer and checkpoint recovery. Hash-pinned tool metadata does not attest remote behavior; enforce network/OS constraints in the executor. Browser PolicyJSON and enterprise signed policy are distinct and must be distributed coherently. Pattern triage is not a complete prompt-injection defense. All release metadata/limits and current test scope are in `reports/enterprise/TEST_REPORT.md`.

# Visual extension security notice — 0.2.0-rc.1

Before using screenshots see [Visual threat model](docs/VISUAL_THREAT_MODEL.md) and [Deployment gates](docs/VISUAL_DEPLOYMENT.md). The image decoder/OCR backend is part of the trusted computing base, not a sandbox. Default manual release does not produce output bytes. Automatic OCR can miss information, including confident misreads; low-confidence filtering and residual scans do not prove completeness. Source images must not be uploaded before this gate.

The previous text-core security notes below still apply.

---

# Security boundary and release status

This is a tested pre-production library candidate, not an accredited defense deployment, a compliance certification or a guarantee that all PII is removed.

## Guaranteed-by-code decisions, within the documented interface

`block` and `review` return `output: null`. The caller must not forward those requests and must never substitute original input when output is null, when an exception occurs or when the process is unavailable. Every outbound path needs interception; installing the package without connecting the sink does not protect a sink.

Detected overlapping ranges are unioned, not simply dropped by priority. Policies are evaluated before overlap merging. A weaker finding therefore cannot hide a stronger block decision or expose the tail of an overlapping sensitive value.

No raw source values are stored in finding records, static reason codes or audit summaries. **Do not log `output` or the full request/result object**: detection can miss sensitive values, and output is not proof that everything remaining is public. Metrics such as counts and lengths are also metadata; minimize and restrict them.

## Not guaranteed

1. Rules-only operation does not provide complete free-form Turkish/English name/address detection. Model misses remain misses. Confidence scores are not calibrated probabilities. Requiring model capabilities checks integration, not truth or quality.
2. Arbitrary encodings, multilingual homoglyphs, stenography/steganography, custom ciphers, multi-message exfiltration, semantically split JSON fields, and binary/file/image contents are not comprehensively analyzed. Some explicit encodings are decoded; some opaque forms are blocked. Do not interpret an opaque-encoding rule as universal detection.
3. This library does not classify all source code, national-security data, trade secrets or contextual confidentiality. Classification marks are specific uppercase line patterns, not a document classification system. Confidential datasets without such marks require controlled dictionaries, schemas, approved models and destination policy.
4. Valid checksums do not prove existence, ownership or sensitivity. Invalid unlabeled identifiers can be missed. Explicit sensitive fields are still protected when checksums fail.
5. Tamper-evident manifest hashing is not publisher authentication or software signing. The expected digest is an administrator-controlled trust anchor and must be delivered in a signed/reviewed deployment configuration. Model files must be mounted read-only to avoid verification/load TOCTOU.
6. The optional Python inference worker is source provided for local integration; actual model inference and its dependencies were not executed/validated in this delivery. Pin, scan and test them before enabling.
7. Offline HF flags and no-network TypeScript code are not an OS network sandbox. Enforce egress denial and process resource limits externally. Trusted adapters can still run arbitrary local code. Do not accept command paths, model paths, dictionaries or policy from untrusted prompts.
8. Synchronous regular-expression or parsing work can occupy the Node event loop. Size bounds and cooperative deadlines reduce risk but are not hard CPU interruption. Isolate the egress guard in bounded processes/workers, and add rate limits/admission control. JSON top-level admission control, provider pool and service-level backpressure remain caller responsibilities.
9. A token is keyed pseudonymization, not irreversible population anonymity. Same-token equality is observable. Key rotation, secrets management, cross-tenant access control and retention are external duties. Tenant ID must be derived from trusted authentication.
10. JavaScript strings and garbage-collected copies cannot be reliably zeroized. Buffers and the copied HMAC key are cleared where practical, but that is not secure-memory certification. Disable core dumps and avoid swap or apply approved encrypted swap policies.
11. No third-party penetration test, customer UAT, Windows/macOS runtime test, sustained multi-tenant load test, FIPS validation, SOC 2 / ISO / KVKK / GDPR / defense certification or independent model benchmark has been completed here.

## Safe integration

Use an allow-listed outbound destination and a fully assembled message. Buffer streaming content until its full semantic unit is validated. Reject unsupported attachments before any network send. Validate the masked JSON against the tool schema; if masking breaks required semantics, block rather than restoring the original. Never release raw data just because the model is slow or absent.

The supplied `createToolGuard` illustrates one call boundary; it does not implement user authentication, tool authorization, destination allow-listing or every AIDR hook. Execute those controls in the surrounding product.

## Reporting issues

Route security issues through the organization's existing private vulnerability-response channel. Do not post customer prompts, model training data, live credentials or personal records in public issues. Reproduce with synthetic records and include exact package version, static reason codes and environment details.


## Browser 0.3.0 boundaries

See docs/BROWSER_GAPS_AND_GATES.md. DOM guards are not a universal network/endpoint DLP boundary. The website owns its editor DOM; use the extension-origin composer for raw text isolation. Unsupported uploads are denied, never forwarded as originals. Provisioned managed policy removal quarantines instead of reverting to unmanaged defaults. The bundled Chrome extension was not installed in this policy-restricted runner; tests explicitly distinguish real browser DOM with mocked Chrome APIs from real native stdio/OCR and from unexecuted installed-extension/live-site checks. No certification, perfect recall, production acceptance or vulnerability-free assertion is made.

## 0.5.0 trust boundary

Read `docs/PLATFORM_THREAT_MODEL.md` before deployment. Broker keys, server/native processes, tenant key storage, callbacks, configuration and local DB ownership are trusted. mTLS channel binding prevents a different remote certificate from reusing device attestations; it is not a defense against arbitrary code inside the trusted server process. SQLite is same-host, DELETE-journal by default; append-only triggers/HMAC do not provide WORM or full selective rollback protection against a database administrator. Dispatch uncertainty is not silently retried.

The current evidence does not qualify real NER, corporate datasets, installed MDM distribution, live authenticated AI applications, or ASR/video/face/CAD/steganography detection. A source hash inventory is not vendor authenticity or vulnerability approval.
