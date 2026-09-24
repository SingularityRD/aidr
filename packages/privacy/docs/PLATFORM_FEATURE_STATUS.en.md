# AIDR Privacy platform — implementation vs. acceptance status (English summary)

English summary of [PLATFORM_FEATURE_STATUS.md](PLATFORM_FEATURE_STATUS.md), the Turkish
original, which remains the authoritative record. The twelve rows were written for the
standalone 0.5.0-rc.1 platform layer (`@singularityrd/aidr-privacy/platform`) and still
describe that layer in 0.6.0; the 0.6.0 repository integrations are listed in the
[package README](../README.md#status).

The document separates code that exists and has been exercised from acceptance
conditions that can only be satisfied inside a customer organization. No row is counted
as "production accepted" on the strength of synthetic test counts alone.

| Priority / area | Implemented in this release | Evidence actually executed | Acceptance that is still open |
|---|---|---|---|
| P0 Trusted user/device/provider context | Signed JWT verification; separate user, device and provider proofs; tenant/session/version/device matching; revocation checks; mTLS certificate binding by default | Real local mTLS: the bound device passes, a different authorized certificate and a certificate-less replay are rejected. OIDC code + PKCE/state/nonce module tested | No live corporate IdP/MDM/provider-account broker is connected. A signed claim is only as trustworthy as the broker that issues it. No hardware attestation |
| P0 Real TR/EN accuracy | JSONL gold-data schema; exact UTF-16 span and coverage measurement; per-language/per-type precision/recall with Wilson intervals; document/text train-test leakage check; qualification gate | 16 synthetic samples measured; two unlabelled person names were missed; the qualification result is `qualified:false`. Real OCR additionally checked against six rows' pixel bounds | No independent corporate text/image corpora. An "independent-corporate" gold label is declared by the user; it does not cryptographically prove the data source's independence |
| P0 Durable multi-tenant state | Per-tenant AES-256-GCM cells; SQLite atomic approvals/quota/policy checkpoints/dispatch; versioned deletion; key rotation; restore anchor; durable audit | Six separate processes did not exceed a shared quota. Reopen, isolation, key rotation and rollback-to-old-DB-copy tests | Multi-process on one machine only; not PostgreSQL/distributed HA or corporate backup infrastructure. Root/DB owner is outside the trust boundary. External anchor storage is the customer's job |
| P0 Final egress | Fixed upstream transport; no first request before all text/images are inspected; snapshot plus final revocation/policy check; provider response narrowing and rescan; MCP `tools/call`; durable single attempt | Real local HTTPS/mTLS ingress; tampered input, revocation and replay tests. External providers and real tool side effects are represented by test transports | Not wired to every real AIDR first-upload/provider/tool exit; no OS/network-level bypass prevention |
| P0 Mandatory install / tamper resistance | Chrome policy generator for Linux/Windows/macOS; signed endpoint health report; release hash and signature verification functions | Configuration/hash/wrong-signature/version tests. Chrome bundle rebuilt | No signed CRX/native binary, no real MDM rollout, no live signed-in ChatGPT/Gemini/Claude test. The development public ID in the bundle is not a production publisher identity |
| P1 Review / exception / incident | Turkish portal; real HTTPS API; OIDC session; RBAC/CSRF; four-eyes approval, justification, appeal, bounded TTL/uses, full action hash; encrypted history | Real HTTPS API test plus a separate Chromium DOM/fetch-fixture test. Self-approval, stale sequence, reuse and post-logout rejections | No real SSO connection and not wired to every AIDR review path. An exception cannot override identity, secret or hard-block decisions. No "WORM immutable" store |
| P1 Shadow AI / MCP discovery | Authorized signed collector ingest; versioned signed risk catalog; `AuthorizedMcpCollector` watching only approved local MCP config paths; metadata snapshot/change/deletion | A real config file was read and modified; command/env values did not reach telemetry. Catalog and replay checks tested | No endpoint/gateway/IdP sensor deployed. No automatic device discovery or network scanning. The local watcher must be started by the application; stdio discovery never runs commands |
| P1 Learned TR/EN classifier | A genuinely trained, hash-pinned, small three-class character-linear model; TypeScript inference; abstains to review when uncertain | 80 original synthetic training rows, 18 separate synthetic trials, 17 top-1 matches. Python/TypeScript probability agreement tested | Not NER; no independent or corporate model validation. Cannot approve production egress on its own and does not replace the runtime's `defense` NER requirement |
| P1 Documents / CDR | One-shot parser isolated by Linux seccomp; text PDF, narrow OOXML Word/Excel/PowerPoint, EML, ZIP, text/source files; output is reconstructed TXT only | 33 parser tests; real digital PDF / plain Word / EML / ZIP conversion. Macro, password, embedded, DTD, ZIP bomb, path and CRC rejection; real socket and `open` EPERM | Image/scanned PDF, Office with media, legacy Office, password-protected and customXML content are blocked. No format-preserving PDF/Office redaction. Even a default python-docx package can be rejected because it contains customXML |
| P1 Corporate sources / DSPM | Approved read-only local directory reader; encrypted source store; group ACLs; classification; complete snapshot replacement/deletion with generation protection | Real file/ACL/incomplete-list/deletion/symlink tests; state key rotation | No SharePoint/Drive/S3 connector, no live ACL change feed, no automatic deletion of remote copies/backups |
| P2 Model supply chain / red team / drift | Structural safetensors inspection; pickle/remote-code format rejection; full file-tree hash/signature; regression and distribution-drift metrics; component inventory | Malformed offset/shape/overlap/extra-file/wrong-signature tests; real synthetic attack and benign baseline samples | No CVE/advisory database lookup (`vulnerabilityDatabaseChecked:false`). No large attack campaign or behavioural safety evaluation; a new model is not proven safe |
| P2 Other modalities | Real PCM16 WAV reconstruction and whole-clip / marked-interval muting; trusted transcript/model/source binding; full-frame video coverage contract; separate threat model | PCM sample and corrupt-header tests; mismatched transcript and missing-frame rejection | No real ASR model, video decoder/sanitizer, face, handwriting, signature, CAD or steganography detector. Interval audio masking is review-only; auto-sendable output is `output:null` |

## Three trust boundaries that remain explicitly open

Field accuracy cannot be demonstrated without customer data. Real provider accounts cannot
be verified without the customer's session/device brokers. "No path can be bypassed"
cannot be claimed until the final egress points and network restrictions are applied to
the main product. None of these closes with another regex or more synthetic tests.

The existing Chrome content scripts and native protocol are preserved. The new server
sessions and gateway are not automatically attached to every upload path in the browser.
In this package the new layer is the `@singularityrd/aidr-privacy/platform` export.

## Test prerequisites in this repository

`pnpm test:privacy` builds the package and runs every Node suite. Tests that need a
prerequisite the machine lacks report an explicit `node:test` skip naming it rather than
passing silently:

- the two CDR parser tests need Linux, a Python 3 interpreter with the pinned packages in
  `parsers/requirements.txt` (`pypdf`, `defusedxml`) and `libseccomp`;
- the real mTLS test needs the `openssl` CLI to mint throwaway certificates;
- the visual local-process tests need a Python 3 interpreter (`AIDR_TEST_PYTHON`).
