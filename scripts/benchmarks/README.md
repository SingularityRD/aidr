# Independent benchmark analysis (T39)

This directory contains an **analysis harness**, not a benchmark result. It does not invoke AIDR or a competitor. An independent evaluator runs both products on the same authorized workload, keeps the blind holdout out of the rule-author workflow, records raw evidence for every observation, and signs the completed input. The output remains `EVIDENCE_REVIEW_REQUIRED` and `production_accepted: false`; a release owner and customer must separately accept the study.

## Inputs

Keep the corpus, observations, raw artifacts, private key, and output outside the repository. The corpus JSON uses `schema_version: 1`, a stable `corpus_id` and `version`, distinct `rule_author_id` and `oracle_reviewer_id`, a `scope` listing `required_attack_families`, `required_connectors`, and `required_surfaces`, and `cases` with these fields. Declare the full agreed scope before collecting outcomes; absent required dimensions are reported as uncovered. The committed denominator for the sold product is `scripts/benchmarks/sold-scope.json` (see below); the list in this paragraph is a starting point, not the declaration. The starting attack-family list should cover direct and indirect injection, MCP description drift, credential exfiltration, shell obfuscation, package tampering, malicious outputs, and excessive delegated authority, adapted to the customer's actual connectors.

| Field | Values / purpose |
| --- | --- |
| `case_id` | Unique opaque identifier; avoid copying sensitive prompts into reports. |
| `partition` | `development` or evaluator-controlled `holdout`. |
| `oracle` | `malicious` or `benign`, adjudicated independently of rule authors. |
| `family`, `connector`, `surface` | Explicit coverage dimensions. Unsupported or absent observations stay visible in each dimension. |
| `content_sha256` | Required. SHA-256 of the case's normalized content. It is the case's content identity for the overlap guard and is never derived from a case title alone. |
| `content` | Optional. The case text. When present the validator normalizes it (CRLF/CR to LF, then trims) and requires `content_sha256` to equal the digest of that normalized text. When absent, `content_sha256` is still required and must be a real 64-hex digest computed by the corpus owner. |
| `derived_from_case_id` | Optional. The `case_id` this case was derived from. Must name a declared case and must stay inside the same partition. `development_derived_from` is accepted as an alias; declaring both is rejected. |

The corpus may also declare `trials_per_case_by_partition` as `{ "development": n, "holdout": n }`. The observations may declare the same object. Declared values must agree with the observations, and a partition trial difference that the corpus does not declare is rejected.

The observations JSON uses `schema_version: 1`, `workload_id`, `trials_per_case`, `candidate_product_id`, `products`, `environment`, and `measurements`. Each product has `product_id`, `version`, and the exact tested artifact's `artifact_sha256`. The shared `environment` records `environment_id`, `os`, `hardware`, `runtime`, `region`, `concurrency`, and `workload_description`. Use the same cases, trial count, workload, timeout policy, and hardware for every product; the evaluator must verify that these declarations match the actual runs.

Each measurement has `case_id`, `product_id`, `trial` (starting at 1), `action` (`block`, `approval`, `allow`, `unsupported`, `timeout`, or `error`), `phase` (`cold_local`, `warm_local`, `remote_reputation`, `policy_refresh`, or `output_inspection`), `latency_ms` (number for completed decisions; `null` otherwise), `raw_evidence_file`, and `raw_evidence_sha256`. Raw files are distinct, relative to the observations file, and checked against their hashes. For every malicious completed decision, record `side_effect_occurred` as an observed boolean. A denied response with a completed protected side effect is a failure. Never infer this boolean from the product's own verdict alone.

Each measurement may also carry `cpu_percent` (CPU utilization in percent; a multi-core host may report more than 100, and any finite value `>= 0` is accepted) and `rss_mb` (resident set size in MiB, finite and `>= 0`). Both are optional so an existing corpus keeps working. **Absent means unmeasured, not zero:** a statistic with no observation reports `measured: false`, `observations: 0` and `null` for every percentile and for the peak, and `report.gates.resource_measured` is `false`. The gate is `true` only when the candidate product has at least one completed decision row and every completed decision row carries both fields. Statistics are computed from completed decision rows only, exactly like latency, and a negative, `NaN`, or infinite value is rejected rather than clamped.

### Blind-holdout contamination guard

Validation is fail-closed before any report exists. Each refusal carries a stable `holdout guard failed [<reason>] <subject>: <detail>` message naming the offending case, and the outcome is also visible as `report.gates.holdout_partition_blind` and `report.gates.holdout_no_case_overlap`:

| Reason | Refused corpus |
| --- | --- |
| `case_id_in_multiple_partitions` | One `case_id` is declared in both partitions. |
| `duplicate_case_content` | Two cases in different partitions have identical normalized content (identical `content_sha256`). |
| `content_sha256_mismatch` | A declared `content` does not hash to the declared `content_sha256`. |
| `cross_partition_derivation` | A case's `derived_from_case_id` points at a case in the other partition. |
| `unknown_derivation_reference`, `self_derivation_reference`, `duplicate_derivation_field` | The derivation reference does not resolve, points at itself, or both field names are present. |
| `holdout_partition_empty` | No `holdout` case is declared. |
| `holdout_single_oracle_class` | The holdout holds only `malicious` or only `benign` cases. |
| `undeclared_partition_trial_difference`, `declared_partition_trials_mismatch` | Per-partition trial counts differ without a corpus declaration, or a declaration disagrees with the observations. |

An existing corpus without `content_sha256` is rejected until the owner declares the digest; that is intentional, because the guard cannot be evaluated without a content identity.

## Sold scope and the committed scaffold

`scripts/benchmarks/sold-scope.json` is the machine-readable denominator of what the product actually sells: the attack families the shipped rules and detection modules implement, the sold connectors from `deploy/native/support-matrix.json#soldConnectorScope`, and the interception surfaces (each with whether the product enforces or only observes today). Every entry carries the repository path that justifies it, and families with no shipped verdict path are listed under `out_of_scope_with_reason` instead. It is a scope declaration, not evidence.

`scripts/benchmarks/corpus.template.json` is a structurally valid, **empty** corpus scaffold whose `scope` block is generated from the sold-scope file. It contains no case, digest, evaluator identity or measurement, and it fails the sold-scope check on purpose. `node scripts/benchmarks/evaluate.mjs --corpus scripts/benchmarks/corpus.template.json --scope-file scripts/benchmarks/sold-scope.json` (also `pnpm run benchmark:scope`) reads only the corpus and the sold scope, reports the coverage verdict without needing observations, an attestation or a public key, and exits non-zero until a real corpus covers the sold scope.

With `--scope-file`, the analysis additionally asserts that

- the corpus's `required_attack_families`, `required_connectors` and `required_surfaces` equal the sold scope exactly - a missing id, an extra id or a duplicate is rejected; and
- every required family, connector and surface has at least `required_scenarios_per_family.minimum_malicious_cases` malicious cases and at least `minimum_benign_twins` benign cases declaring the same item.

A failure is fail-closed before any report exists and carries a stable token naming the item, for example `sold scope check failed [scope_attack_family_benign_twin_missing] attack family "shell-obfuscation": the corpus declares 0 benign twin(s) but the sold scope requires at least 2`. `report.gates.sold_scope_checked` is `true` only when a scope file was supplied and the check passed, and it says nothing about whether any case was detected. Without `--scope-file` every flag and gate behaves exactly as before.

## Reproducible local construction and descriptive schemas

`corpus-spec.json` and `generate-corpus.mjs` construct an open synthetic corpus with an HMAC-SHA256 counter PRNG. The generated bytes are deterministic, cover the committed sold-scope minimums, and use provenance `synthetic_open`. Synthetic provenance is categorically ineligible for `gates.customer_corpus_authorized`. Evaluator self-attestation is not customer authorization, so the local harness keeps this gate false; a separately verified customer-authority receipt remains external. The benign-generator test checks every generated benign case against every parseable `pattern` in `threats/*.yaml` to prevent trivial label leakage.

`split-corpus.mjs` assigns partitions from HMAC-SHA256 keyed by each case's content digest and writes a deterministic split manifest. The evaluator accepts `--split-manifest` only when its byte digest is in signed `payload.split_manifest_sha256`, its source digest binds the partitionless corpus content, and every assignment matches. Only then is `gates.holdout_frozen` true. Holdout ROC/AUC additionally requires a signed `{ "frozen": true, "threshold": n }` operating point. Development ROC may be measured without that operating point. Missing scores always produce `{ "measured": false, "value": null, "observations": 0 }`.

The JSON Schemas in `schemas/` are descriptive documentation, not a second validator. `evaluate.mjs` remains normative and exports its required-field arrays; `benchmark-contracts.test.mjs` fails on schema drift. `comparison-spec.json` defines the only allowed reason codes for unknown competitor cells. Unknown competitor values remain null and are never estimated.

`trusted-keys.json` is intentionally committed empty. `--trusted-keys` makes trust checking fail closed: a signed payload must name `signing_key_id`, its Ed25519 public-key fingerprint must match that entry, and the canonical base64 signature must decode to exactly 64 bytes. Each trusted key must carry a role, and only an `independent_evaluator` key can make attestation trust true. Without a trust store a valid local signature has `gates.attestation_trusted: false`. Measurement budgets enforce nonnegative values and `spent <= ceiling`; `authorization_ref` is an explicitly unverified opaque external reference, and evaluator self-authorization is refused, so authorization remains `BLOCKED_EXTERNAL` pending a separate budget-authority receipt. A duty-separation receipt is recognized only when hash-bound and signed by a different trusted `duty_separation_authority` key, while ordinary local runs report `independent: false` and `gates.independent_acceptance` always remains false.

Reports contain a domain-separated `report_sha256` commitment over their canonical JSON (with the digest fields removed before hashing); `canonical_report_sha256` remains as a compatibility alias. The digest input is exact UTF-8 and the report file is emitted with a single LF terminator. `--output` is write-once unless the operator explicitly supplies `--force`; `--reproduce <report.json>` requires byte-identical LF/UTF-8 output. Before allocating the matrix, the analyzer enforces a hard safety cap of 1,000,000 total case/product/trial cells.

## Run

An external evaluator holds an Ed25519 private key outside the repository. After the corpus and observations are frozen, the evaluator writes a signed attestation. This helper refuses to overwrite an existing attestation:

```text
node scripts/benchmarks/generate-corpus.mjs --spec scripts/benchmarks/corpus-spec.json --scope-file scripts/benchmarks/sold-scope.json --output <synthetic-corpus.json>
node scripts/benchmarks/split-corpus.mjs --corpus <corpus.json> --key <evaluator-split-key> --holdout-percent 30 --output <split-corpus.json> --split-manifest <split-manifest.json>
node scripts/benchmarks/attest.mjs --corpus <split-corpus.json> --observations <observations.json> --private-key <evaluator-private.pem> --evaluator-id <independent-evaluator-id> --split-manifest <split-manifest.json> --signing-key-id <trusted-key-id> --output <attestation.json>
node scripts/benchmarks/evaluate.mjs --corpus <split-corpus.json> --observations <observations.json> --attestation <attestation.json> --public-key <evaluator-public.pem> --trusted-keys scripts/benchmarks/trusted-keys.json --split-manifest <split-manifest.json> --output <report.json>
node scripts/benchmarks/evaluate.mjs --corpus <corpus.json> --scope-file scripts/benchmarks/sold-scope.json --observations <observations.json> --attestation <attestation.json> --public-key <evaluator-public.pem> --output <report.json>
node --test scripts/benchmarks/evaluate.test.mjs
```

The trust owner must bind the evaluator identity to the public-key fingerprint and establish independence, authorization, oracle quality, release candidate identity, environment equality, and protected side-effect evidence outside this tool. The signature proves integrity and possession of a private key, not those facts.

The report retains all case/trial/product combinations. Missing, unsupported, timeout, and error outcomes stay in the malicious and benign denominators and cannot increase prevention. Existing rates and denominators remain unchanged. It additionally reports a confusion matrix, precision, recall, F1, an explicit indeterminate bucket, and score-gated ROC/AUC. It separates prevention (block plus no side effect), held approvals, false blocks, false approvals, and latency p50/p95/p99 by phase. It reports development and holdout, family, connector, and surface separately, with Wilson 95% intervals for rates. It also reports `resources` (`cpu_percent` and `rss_mb`, each with `measured`, `observations`, `p50`, `p95`, `peak`) and `resources_by_phase` per product and per dimension. Latency excludes non-decisions and reports its sample count; resource statistics do too, and an unmeasured statistic is `null` with `observations: 0` rather than `0`. `report.gates` records `holdout_partition_blind`, `holdout_no_case_overlap`, `holdout_frozen`, `attestation_trusted`, and `resource_measured` alongside the existing gates. The 1,000 measured benign calls per connector gate is visible but does not by itself certify a false-positive target. No overall winner, zero-false-positive, evasion-resistance, SLA, or best-product claim is generated.
