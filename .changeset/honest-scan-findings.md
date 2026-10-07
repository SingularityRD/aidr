---
"@singularityrd/aidr-core": minor
"@singularityrd/aidr-cli": minor
---

AI-infrastructure scan accuracy and honest reporting.

- The native scanner now fetches each fingerprint's own version endpoint (for
  example Ollama `/api/version`, MLflow `/version`, Open WebUI `/api/version`)
  after detection, under the same origin, timeout, size and no-redirect limits
  as the detection probes, and evaluates the CVE index's compiled semver ranges.
  Vulnerable versions are now version-confirmed, so `policy.ai_infrastructure`
  can block them.
- Scan summaries add `confirmedCritical`, `confirmedHigh`, `confirmedFindings`,
  `unconfirmedCritical`, `unconfirmedHigh` and `unconfirmedFindings`. The legacy
  `critical`, `high` and `cvesFound` totals are unchanged and still include
  unconfirmed findings.
- `aidr scan` and `aidr collect` exit statuses: `2` now means at least one
  **version-confirmed** critical or high CVE; findings whose applicability could
  not be confirmed (unknown version or a rule that cannot be evaluated) now exit
  `1` (incomplete, review required) instead of `2`. A result with unconfirmed
  findings never exits `0`. Update CI gates that treated `2` as "any critical or
  high CVE reported".
