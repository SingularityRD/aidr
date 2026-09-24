# Secret-history gate — 2026-09-23

**Decision: NO-GO for a signed production release.** This is a findings ledger, not a claim that every match is a live credential.

- The pinned official Gitleaks 8.30.1 Windows binary (SHA-256 `17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c`) passed its synthetic canary and the current-checkout scan: 1,712 files, zero findings. The single new Stripe test-fixture false positive was rewritten without changing its runtime test value; the focused test passed.
- A full-history scan of 998 commits (about 470.54 MB) returned exit 1: 296 matches across 114 paths and 37 commits. Top rule counts are `generic-api-key` 173, `private-key` 29, `sourcegraph-access-token` 26, `stripe-access-token` 18, and `jwt` 17. Most high-count paths appear in historical documentation, imported code, and synthetic security tests. **None of these matches has been classified as safe solely from its path.**
- `.env.aig` was tracked in three historical commits. It is now removed from the index without deleting the local file, and `.gitignore` excludes it. Gitleaks did not flag its historical content; that is not evidence that any values inside are safe or unused.

Before promotion, security owners must review the redacted findings against the original material in a restricted workflow, classify each unique candidate as test data, public example, or real credential, and rotate/revoke every confirmed live value. Only narrowly justified false-positive exclusions should enter `.gitleaks.toml`; then rerun both the full-history and current-checkout gates on the exact release candidate. Do not rewrite published Git history or expose raw findings as a quick fix without an explicit coordinated remediation plan.

This scan does not substitute for secret-manager inventory, provider-side revocation evidence, or signed release provenance.
