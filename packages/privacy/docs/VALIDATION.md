# Validation protocol

## What has actually run

The TypeScript compilation, Node tests, Python artifact/offset tests, CLI and AIDR guard sample tests, core benchmark and default evaluation harness were executed locally. Exact results are recorded in `reports/TEST_REPORT.md`. The Node provider tests use `tests/fixtures/mock-ner.mjs`, an explicitly deterministic fake model. Python model fixture bytes are explicitly not loadable weights.

No actual pretrained NER inference, training/fine-tuning, quantization, external API call, customer corpus evaluation or independent benchmark was run. Test coverage percentages measure executed code, not detection accuracy or absence of vulnerabilities.

## Automated suites

`tests/core.test.mjs`: developer-defined positive/negative fixtures; TR/EN formats and examples.

`tests/validators.test.mjs`: valid and invalid checksum/format cases.

`tests/normalization-fast-path.test.mjs`: fast-path invariants, prior decoding offsets and Turkish dotted-I labels.

`tests/adversarial.test.mjs`: Unicode controls, explicit encoding nesting, malformed input, opaque content, long secret/field tails and incomplete blocks.

`tests/policy.test.mjs`: overlap/policy ordering, deny/review, literal rules, configuration limits, defense capability gate, disposal and immutable results.

`tests/token.test.mjs`: tenant separation, key rotation, canonical forms, no exposed key and selected token idempotence cases.

`tests/json.test.mjs`: schema fields, nested values, numeric types, sensitive keys, duplicate keys, prototype keys, parser limits and atomic denial.

`tests/stream.test.mjs`: splits at all byte boundaries of test messages, one-byte chunks, UTF-8 errors, timeout, abort, caller mutation, size limits and one-shot completion.

`tests/ner.test.mjs`: output validation, timeouts/crashes/abort, malformed/oversized protocol data, low confidence, one-in-flight handling, language/type capabilities and actual mock-child process exchange.

`tests/integration.test.mjs`: CLI stdin/exit/JSON behavior and guard forwarding only protected calls.

`tests/property.test.mjs`: **10,000 generated cases**, using a fixed deterministic seed. These are iterations inside six Node test entries, not 10,000 separately reported Node tests: 2,000 TCKN, 2,000 Luhn, 1,500 Unicode/encoding variants, 3,000 interval unions and 1,500 Unicode source-map cases.

`ner/test_artifacts.py`: manifest/file hashing, model/tokenizer presence, traversal/symlinks/unsafe format denial, label/window validation, BIO aggregation and code-point-to-UTF-16 offsets.

## Reproduce

```sh
npm test
npm run test:coverage
npm run test:python
npm run benchmark
npm run evaluate
```

Prebuilt `dist` is included, so these do not install dependencies. Rebuild using the approved development environment before testing changed TypeScript sources.

## External corpus format

The evaluation harness accepts UTF-8 JSONL, one fully annotated document per line. `start`/`end` use ORIGINAL UTF-16 offsets. Every sensitive span must be labeled; incomplete annotation corrupts precision and leak-rate results. The following record is synthetic:

```json
{"id":"synthetic-en-001","language":"en","text":"Email: jane@example.com","entities":[{"start":7,"end":23,"type":"EMAIL"}]}
```

Run the rules baseline:

```sh
node scripts/evaluate.mjs /approved-evaluation/heldout.jsonl
```

After real model installation/approval, evaluate the actual local provider:

```sh
node scripts/evaluate.mjs /approved-evaluation/heldout.jsonl \
  --ner-config /approved-config/local-provider.json --profile defense
```

The provider JSON starts a local executable and is **administrator-controlled**. Never accept it from a web user. The report logs counts/metrics/model revision, not raw corpus text. Corpus sensitivity still requires a protected host and handling policy. The harness's `independentHeldOutBenchmark:false` is intentionally conservative; it cannot verify that an externally supplied corpus was truly unseen.

## Metrics and interpretation

Exact-span/type precision, recall and F1 distinguish incorrect/over-wide spans from correct spans. PII-character coverage measures how much annotated sensitive text is within detected masking ranges. The forwarded-positive leak rate measures positive documents that are forwarded despite incomplete masking. Block and review counts are reported separately; blocking everything is not counted as perfect recognition. Negative-document false-positive rate measures benign document disruption.

The default 107-record regression corpus was known during development. Its language labels are `unspecified` because examples include mixed-language/context/encoding fixtures. It must not be used to advertise independent Turkish-vs-English accuracy. Real language-specific evaluation requires separately labeled `tr` and `en` records.

The 78 positive regression records have a minimal gold-sensitive span. Conservative redaction can include additional surrounding text, making exact-span F1 lower even when all sensitive characters are masked. Keep exact matching and leakage metrics together; do not hide either result.

## Domain acceptance plan

Create a separately held-out, appropriately authorized dataset covering Turkish and English independently, plus mixed-language prompts. Include names with rare morphology and casing, addresses with apartment/building details, real-world formatting diversity, malformed labeled identifiers, logs, support text, source-code comments, tool arguments, JSON keys, encoded forms and adversarial split attempts.

Stratify recall/leakage by PII type, language, input length, model window boundary, encoding, scenario and confidence. Report denominators and uncertainty; a small zero-leak sample is not a proof of zero production leakage. Never ship because only micro-averaged F1 looks high.

Set release thresholds with the customer's security team, based on disclosure impact and blocking tolerance. Include non-sensitive workflow false-positive tests. Any known exploitable critical bypass must be fixed or the affected channel disabled before approval.

Run end-to-end sink tests with packet/connector observations, NER outages, corrupt models, cancellation, worker crashes, queue saturation, CPU limits, memory pressure, model updates and policy rollbacks. Confirm no raw network send occurs before an allowed decision. Test actual target operating systems and the exact signed artifacts.

## Benchmark scope

`scripts/benchmark.mjs` measures sequential warmed-up rules-only calls, 256 B to 16 KiB, plus single 64 KiB adverse-input probes. It reports median/p95/p99 and sampled total Node process RSS. It does not measure the incremental memory of just this library, real NER, worker pools, HTTP/TLS, cold startup, JSON traversal, sustained load or customer hardware. No production latency SLA follows from it.
