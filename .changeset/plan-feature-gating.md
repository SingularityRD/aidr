---
"@singularityrd/aidr-core": patch
"@singularityrd/aidr-dashboard": minor
---

Plan features are enforced server-side. A shared resolver (`tenant_plan_entitlements`) decides the tenant's edition from the audited plan sources (bound Stripe subscription, billing-managed label with an active licence or approved pilot, active trial = Team) and Edge Functions refuse gated features with `402 plan_feature_required` (503 when the plan cannot be read): SCIM, SSO administration, Entra group sync, SIEM/audit export, AI Security Posture uploads and views, Browser Guard ingest, and air-gapped licences. Local detection and verdict ingest are never gated. The dashboard shows an upgrade notice on gated pages, the team audit panel shows the administrative trail (owner/admin, paginated) and audit export can export it, and event retention is capped by the plan term. Core's posture upload reports a plan refusal honestly.
