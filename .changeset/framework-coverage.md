---
"@singularityrd/aidr-core": minor
"@singularityrd/aidr-cli": minor
"@singularityrd/aidr-dashboard": minor
---

Security framework mapping and coverage matrix.

- Every shipped detection rule is mapped to OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10), OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10) and MITRE ATLAS 2026.09 techniques in `threats/mappings/frameworks.yaml` (data, keyed by rule id, with per-file and per-category defaults). The loader still reads only `threats/*.yaml`; a test fails when a rule is unmapped or an ID is not in the official lists.
- Core: loaded rules carry `sourceFile` and `frameworks`; a matching verdict carries `Verdict.frameworks`, and local audit entries (`runtime_verdict`, `incident`) carry `frameworks: {owasp_llm, owasp_agentic, mitre_atlas}`. SIEM incident exports add them per event and as a union (JSON `frameworks`, CEF/LEEF `frameworks=`). A missing or invalid mapping file is logged and changes no decision.
- CLI: `aidr coverage [--format table|json|markdown]` prints the coverage matrix (rule count, example rules and a covered/partial/not covered/not applicable status with rationale per item) for the installed rules. `aidr audit export --format csv` gains a trailing `frameworks` column.
- Dashboard: a "Framework coverage" section on the Posture page, built from a JSON artifact bundled at build time, and framework chips on events and incidents resolved from `matched_threat_id`.
- `pnpm coverage:frameworks` checks `docs/framework-coverage.md` and the dashboard artifact for drift; `-- --write` regenerates them.
