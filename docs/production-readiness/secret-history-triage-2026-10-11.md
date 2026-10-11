# Secret history triage — 2026-10-11

Audit item 39 / AIDR-070. Machine-readable record: [secret-history-scan-2026-10-11.json](evidence/secret-history-scan-2026-10-11.json). Values are not recorded; only the first 8 hex characters of each value's SHA-256 are.

- Scanner: gitleaks 8.30.1 (archive sha256 checked against ci.yml).
- History: shallow=False, 1132 reachable commits, 909 scanned by gitleaks.
- Current tree: 0 findings with the current config (`pnpm verify:secrets:current` exit 0).
- Full history (current config): 83 detections, 47 distinct values; dispositions {'FP': 82, 'FP-INVALID-FIXTURE': 1}.
- New detections since the 2026-10-05 triage: 26, all false positives (FP / FP-PUBLIC-DIGEST / FP-INVALID-FIXTURE); see the JSON for each one's rationale.

## Open owner decision

The two owner-confirm rows are the same example dataset fingerprint key, in the Chrome/Firefox managed-policy examples (fingerprint `6ebab6aa`). The current config suppresses them with a value-exact allowlist. The owner or Security must confirm that this key was never used for a real dataset. If that cannot be confirmed, treat it as compromised: regenerate, re-fingerprint and redeploy. This item stays open until that decision.

There is no verified live credential. Published history was not rewritten.
