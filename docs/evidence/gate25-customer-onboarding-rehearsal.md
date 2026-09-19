# Gate 25 — customer onboarding, first successful local rehearsal

**Date:** 2026-09-18
**Gate:** `25-customer-onboarding`
**Deployment:** `.release-evidence/aidr-local-deployment-r9`
**Source commit:** `d489d561b6523d80bd8fd3a556f6dc0df83f4679`
**Classification:** `isolated_integration` — isolated local rehearsal, **not** customer field acceptance.

## What changed to make this possible

This gate had never passed. Three separate defects sat between the repository and
a running control plane, and each one had to be fixed before any onboarding check
could execute:

1. **The migration chain aborted on a fresh database.**
   `20260913000005_tenant_storage_queue_quotas.sql` ran
   `alter table storage.objects enable row level security`. That table is owned by
   `supabase_storage_admin`, not by the role applying migrations, so the statement
   failed with `SQLSTATE 42501 (must be owner of table objects)` and killed the
   whole chain. A fresh `supabase start` or `db reset` could never complete.
   Storage already enables RLS on its own tables, and Supabase documents the
   storage schema as read-only, so the statement was both unauthorised and
   unnecessary. Fixed in `d489d561`.

2. **The deployment's own API port disagreed with its configuration.**
   `deployment-prepare.mjs` publishes the gateway on `127.0.0.1:8000`, but the
   URL recorded in `deployment.json` and `.env` is whatever `--supabase-url`
   supplied. Preparing with the standalone Supabase CLI's port (`54321`) produced
   an installation that pointed every client at a port nothing was listening on.
   The rehearsal therefore prepares with `--supabase-url http://127.0.0.1:8000`.

3. **The gate could not find an installation at all.**
   The declared command was the bare `pnpm verify:customer-onboarding`, which the
   verifier correctly refuses without an operator-supplied directory — it never
   assumes a leftover `.aidr-deploy/`. The command now locates the local rehearsal
   installation and fails closed with the same operator-facing message when it is
   absent.

## Result

`verify-customer-onboarding` reported **9 checks passed** against a live
self-hosted control plane (11 containers, all healthy, 47 migrations applied):

| # | Check |
|---|---|
| 1 | first owner provisioned with a separate enterprise tenant |
| 2 | resume is idempotent; duplicate and changed configuration refused |
| 3 | provisioned owner signs in without SMTP or OAuth |
| 4 | browser onboarding sees the enterprise enrollment approval |
| 5 | ordinary authenticated session cannot provision or increase seats |
| 6 | approval and seat allocation bound to enterprise tenant |
| 7 | device flow enrolls agent in the customer's enterprise tenant |
| 8 | new customer has a published central policy before its first tool call |
| 9 | enrolled API key receives the enterprise team's published policy |

The verifier created its own disposable fixture, ran the checks, removed the
fixture, and left the installation untouched.

## What this does and does not prove

**Proves:** a self-hosted AIDR control plane can be built from this repository,
started, migrated, and onboarded — owner provisioning, idempotent resume,
browser-visible enrollment approval, tenant isolation against seat escalation,
agent device enrollment, and central policy publication before an agent's first
tool call.

**Does not prove:** anything about a real customer's environment. The deployment
is a loopback rehearsal with generated secrets, `--development` HTTP, and no TLS.
The verifier's own scope string says so: *"Isolated local rehearsal; not customer
field acceptance."* Gate 25 closes only when a named customer runs this against
their own installation.
