# Unreleased

- Parser dependencies: pypdf 5.9.0 -> 6.19.0 (DoS advisories fixed in the 6.x line) and new pypdfium2 5.14.0 (PDFium) + Pillow 12.3.0, hash-locked in `parsers/requirements.lock.txt`; CI installs it with `--require-hashes --no-deps`.
- `DocumentCdr` opt-in raster PDF redaction (`{output:'pdf'}`): spans detected on PDFium page text (cross-checked against the TXT-path pypdf text), each page rasterized at 150 DPI with opaque boxes over the span characters and rewritten as an image-only PDF without text layer or metadata; independent re-parse with pypdf and PDFium must find the same page count and no text, else no output. `parsers/worker.py` changed: update the configured `workerSha256` pin.
- `DocumentCdr` opt-in format-preserving DOCX/XLSX/PPTX redaction (`{output:'office'}`): in-place span redaction across runs, tracked changes, field codes, comments, headers/footers, notes and footnotes; metadata/thumbnail removal; every cached formula value blanked with recalculation on load; independent re-parse and re-scan, fail closed on any residual finding. Default output stays text-only; PDF unchanged. `parsers/worker.py` changed: update the configured `workerSha256` pin.

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
