# Independent benchmark analysis (T39)

This directory contains an **analysis harness**, not a benchmark result. It does not invoke AIDR or a competitor. An independent evaluator runs both products on the same authorized workload, keeps the blind holdout out of the rule-author workflow, records raw evidence for every observation, and signs the completed input. The output remains `EVIDENCE_REVIEW_REQUIRED` and `production_accepted: false`; a release owner and customer must separately accept the study.

## Inputs

Keep the corpus, observations, raw artifacts, private key, and output outside the repository. The corpus JSON uses `schema_version: 1`, a stable `corpus_id` and `version`, distinct `rule_author_id` and `oracle_reviewer_id`, a `scope` listing `required_attack_families`, `required_connectors`, and `required_surfaces`, and `cases` with these fields. Declare the full agreed scope before collecting outcomes; absent required dimensions are reported as uncovered. The starting attack-family list should cover direct and indirect injection, MCP description drift, credential exfiltration, shell obfuscation, package tampering, malicious outputs, and excessive delegated authority, adapted to the customer's actual connectors.

| Field | Values / purpose |
| --- | --- |
| `case_id` | Unique opaque identifier; avoid copying sensitive prompts into reports. |
| `partition` | `development` or evaluator-controlled `holdout`. |
| `oracle` | `malicious` or `benign`, adjudicated independently of rule authors. |
| `family`, `connector`, `surface` | Explicit coverage dimensions. Unsupported or absent observations stay visible in each dimension. |

The observations JSON uses `schema_version: 1`, `workload_id`, `trials_per_case`, `candidate_product_id`, `products`, `environment`, and `measurements`. Each product has `product_id`, `version`, and the exact tested artifact's `artifact_sha256`. The shared `environment` records `environment_id`, `os`, `hardware`, `runtime`, `region`, `concurrency`, and `workload_description`. Use the same cases, trial count, workload, timeout policy, and hardware for every product; the evaluator must verify that these declarations match the actual runs.

Each measurement has `case_id`, `product_id`, `trial` (starting at 1), `action` (`block`, `approval`, `allow`, `unsupported`, `timeout`, or `error`), `phase` (`cold_local`, `warm_local`, `remote_reputation`, `policy_refresh`, or `output_inspection`), `latency_ms` (number for completed decisions; `null` otherwise), `raw_evidence_file`, and `raw_evidence_sha256`. Raw files are distinct, relative to the observations file, and checked against their hashes. For every malicious completed decision, record `side_effect_occurred` as an observed boolean. A denied response with a completed protected side effect is a failure. Never infer this boolean from the product's own verdict alone.

## Run

An external evaluator holds an Ed25519 private key outside the repository. After the corpus and observations are frozen, the evaluator writes a signed attestation. This helper refuses to overwrite an existing attestation:

```text
node scripts/benchmarks/attest.mjs --corpus <corpus.json> --observations <observations.json> --private-key <evaluator-private.pem> --evaluator-id <independent-evaluator-id> --output <attestation.json>
node scripts/benchmarks/evaluate.mjs --corpus <corpus.json> --observations <observations.json> --attestation <attestation.json> --public-key <evaluator-public.pem> --output <report.json>
node --test scripts/benchmarks/evaluate.test.mjs
```

The trust owner must bind the evaluator identity to the public-key fingerprint and establish independence, authorization, oracle quality, release candidate identity, environment equality, and protected side-effect evidence outside this tool. The signature proves integrity and possession of a private key, not those facts.

The report retains all case/trial/product combinations. Missing, unsupported, timeout, and error outcomes stay in the malicious and benign denominators and cannot increase prevention. It separates prevention (block plus no side effect), held approvals, false blocks, false approvals, and latency p50/p95/p99 by phase. It reports development and holdout, family, connector, and surface separately, with Wilson 95% intervals for rates. Latency excludes non-decisions and reports its sample count. The 1,000 measured benign calls per connector gate is visible but does not by itself certify a false-positive target. No overall winner, zero-false-positive, evasion-resistance, SLA, or best-product claim is generated.
