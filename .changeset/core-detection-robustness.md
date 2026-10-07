---
"@singularityrd/aidr-core": minor
---

Detection robustness fixes in the shared core.

- **Incomplete rule sets:** a corrupt, emptied, unreadable, missing or integrity-unlisted bundled rule file is now reported (`loadThreatDirectory`, `loadThreatSet`) and every non-deny verdict becomes an `ask` with a "Rules incomplete" reason (`rules_incomplete`). Previously only a completely empty rule set degraded.
- **User rules:** rules in `~/.singularity-aidr/threats` may add new IDs but can no longer replace a bundled rule; a clashing ID is logged and ignored.
- **URL leg configuration errors:** an endpoint the URL-check client rejects, or any other client failure, is an unavailable leg (review required), never a clean allow.
- **Detection time budget:** `url_check`, `file_check` and `package_check` `timeout_seconds` default to and are clamped at 3 s, and the network legs of one call share a 6 s budget (below Codex's 10 s hook timeout). New exports `MAX_DETECTION_LEG_TIMEOUT_SECONDS`, `MAX_DETECTION_BUDGET_SECONDS`, `clampLegTimeoutSeconds`.
- **Verdict cache authentication:** persisted cache entries carry an HMAC under a per-installation key (`<cache path>.key`, owner-only). Unauthenticated or mismatched entries, including existing cache files, are treated as absent.
- **Integrity resource gate:** once an integrity manifest verifies, bundled rule, trusted-domain and trusted-model-source files it does not list are refused.
- **Managed gate failure:** a failed licensing gate or unloadable managed state turns managed features off and returns the local evaluator's verdict with a notice, instead of blocking or disarming every call. An integrity failure (degraded safe mode) denies every call.
