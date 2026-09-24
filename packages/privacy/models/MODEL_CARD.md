# AIDR character-linear risk baseline

**Status: supplementary review-only baseline, not production-qualified; not NER.**

The included weights were actually trained in this run. They are original model output from 80 developer-authored synthetic Turkish/English examples. Eighteen separately authored synthetic examples were held out: 17 top-1 labels matched. This is not an independent benchmark, field accuracy estimate, calibrated probability or evidence of robust prompt-injection detection. Training and held-out authorship is shared and the corpus is very small.

Architecture: binary character 3–5-gram features (up to 12,000), multinomial logistic regression, three classes `benign`, `sensitive`, `injection`; NFKC/lower/dotless-i normalization. Training uses scikit-learn 1.8.0, numpy 2.3.5, C=1, max_iter=1000, random_state=1729. Runtime inference is local TypeScript with no third-party npm dependency. Reproduce with `python3 models/train.py` using the recorded training environment; approve the new hash before replacement.

`LinearRiskClassifier` checks a caller-provided SHA-256 pin. Unknown/low-confidence/risk outputs return `review`; a benign prediction returns only `no-additional-signal`, never an authorization to send. The default runtime does not automatically substitute this model for the real NER requirement. Applying it is an explicit server-side additional review signal.

Artifacts: `train.jsonl`, `heldout.jsonl`, `training-report.json`, `risk-baseline.json`, `risk-baseline.sha256`. All examples are synthetic; no user or customer documents were used. The original datasets and exported coefficients are private integration work product under the package's UNLICENSED/private notice, not third-party model weights. scikit-learn and its dependencies retain their own upstream licenses and are not bundled as runtime Python binaries.

Known limitations: obfuscation, paraphrase, multilingual code-switching, benign security quotations, source-domain shift, long inputs and unknown character sequences. Inputs are limited to 65,536 JavaScript code units. A confidence threshold is an engineering heuristic, not a calibrated risk guarantee. CPU measurements appear separately in `reports/platform/benchmark.json`.

Qualification requires organization-approved data, document-level train/test separation, per-language/type metrics, sufficient negatives and independent acceptance. The bundled qualification report intentionally fails that gate.
