# 0.6.0 — 2026-09-24

Integrated into the Singularity AIDR repository as `@singularityrd/aidr-privacy`.

- Renamed from `@singularity/aidr-privacy` to `@singularityrd/aidr-privacy` to match the other
  AIDR packages; license metadata is now `Proprietary` and the package ships a `LICENSE` file.
- Integrated: Browser Guard reuses the browser-safe rule layer (detectors, validators,
  normalization, spans, literal dictionary) for prompt/paste/upload inspection.
- Integrated: core DLP (`@singularityrd/aidr-core`) adopts the TR/EN detectors (TCKN, IBAN,
  Turkish phones/addresses, labelled fields, provider tokens, private keys) through a
  generated, drift-checked copy of the rule files.
- Integrated: the AIDR CLI gains a local privacy scan built on the same detectors.
- Repository tooling: root `pnpm test:privacy` builds the package and runs every Node suite
  (text, visual, browser, native, enterprise, platform). Tests whose Python parser packages,
  libseccomp, Python interpreter or `openssl` CLI are missing report a named `node:test`
  skip instead of passing. `pnpm check` type-checks the package and its extension
  `tsconfig`; `build` starts from a clean `dist/`.
- Release: new `build:release` (no source maps, artifact manifest, source-map check);
  `packages/privacy/dist` joins the release artifact set.
- Docs: rewritten README head with an honest status table; English summary of the platform
  feature status (`docs/PLATFORM_FEATURE_STATUS.en.md`) next to the Turkish original.
- No change to detection behaviour, the platform layer or the legacy Chrome/native workflow
  in this package; the legacy Chrome bundle still carries its 0.5.0-rc.1 build label.

# 0.5.0-rc.1 — 2026-09-24

Added server-side platform modules, durable SQLite adapters, pinned JWT/OIDC and mTLS context, guarded egress, encrypted review workflow/portal, authorized local MCP watcher, local DSPM snapshot/ACL, strict Linux document text reconstruction, true synthetic-trained linear risk baseline, evaluation/qualification harness, safetensors/release inspection and PCM audio helpers. Prior browser/native and text/visual APIs retained. Twelve-row acceptance status and negative results are explicit in docs. No live corporate deployment or full multimodal completeness claim.

# 0.4.0-rc.1

- New dependency-free Node enterprise SDK for signed/expiring tenant policies, durable-checkpoint-gated rollout, exact-record/fragment matching, contextual release control and provenance receipts.
- Tool descriptor hash pins, restricted schemas/scopes/origins, mandatory four-eyes approval for side effects, exact-argument/session/policy binding, single use and execution wrapper.
- Hash/HMAC chained metadata journal, local exclusive fsync sink, bounded budgets/inventory and webhook authentication envelopes.
- Browser injection/active-content triage, opt-in source-code rule and Turkish coaching. Native/browser policy digests changed: upgrade together.
- Enterprise TextResult adapter integrated with real OCR/pixel verification and disk audit.
- New module tests, current full regression, DOM/native checks, offline runnable demo and measured synthetic benchmarks. See reports/enterprise/TEST_REPORT.md.
- No claim of full vendor parity, learned-model recall, installed/live site validation, distributed storage, SSO, customer deployment or certification.

---

# 0.3.0-rc.1

- Chrome MV3 ChatGPT/Gemini/Claude adaptörleri, yerel prompt ön taraması, gönderim/yapıştırma/dosya kontrolü.
- Ayrı eklenti kökenli güvenli yazım alanı, tek kullanımlık doküman/politika bağlı aktarım.
- Ortak dedektör kaynaklarını kullanan browser-only kurallar çekirdeği; Node ip/spans ayrıştırması ve regresyon testleri.
- TXT/JSON/CSV/TSV alan/başlık duyarlı maskeleme ve formül/ambiguous JSON reddi.
- Native Messaging chunk/offset/hash/politika bağlı protokol, gerçek OCR motoruna köprü.
- Yönetilen PolicyJSON, site karantinası, provisioned-policy kaybolma kilidi, içeriksiz süreli audit.
- Linux/macOS host dosyası hazırlama ve doğrulanmamış Windows launcher kaynağı.
- Geniş Node/Python regresyon, Chrome API mock'lu gerçek Chromium DOM ve gerçek native stdio testleri.
- Kurulu eklenti/live site/Windows/macOS/gerçek NER doğrulaması tamamlanmadı; imzalı yayın ve kurum kabulü gereklidir.

---

# 0.2.0-rc.1 — Screenshot egress candidate

Added visual SDK and CLI, offline OCR worker, QR/barcode policy, geometry mapping, irreversible pixel redaction, independent PNG validation/re-encoding, residual scan, image stream and all-or-nothing multimodal gates. Kept existing text API. Added 188 Node tests and 72 Python vision tests; reran 330 existing Node and 38 Python tests. Eight real OCR synthetic pipelines and 29 ground-truth row pixel checks completed.

Default visual release is manual; no OCR or NER completeness warranty. Native dependencies, real enterprise NER validation and actual interception deployments are external requirements. CLI requires trusted private filesystem directories.

---

# 0.1.0-rc.1 — 2026-09-23

Initial standalone AIDR privacy-core candidate, local tests and reproducible measurement scripts.

Development regressions identified and corrected during this delivery included:
- Incorrectly grouped SSN strings being accepted by the standalone validator.
- Token marker separators that could be reinterpreted as labeled fields.
- Turkish dotted-I field labels missing locale-aware matching.
- Potential partial field/secret coverage, escaped-quote tails and overlapping-range tails.
- Extra normalization allocation on ordinary ASCII/Turkish text; a tested stable-character fast path was added.

Real pretrained model inference, independent TR/EN quality evaluation, downstream AIDR wiring and defense deployment approval remain release gates, not completed claims.
