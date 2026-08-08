# AIDR Controlled Customer/Investor Demo Runbook

## Positioning

This runbook prepares a **controlled evaluation**, not an unrestricted
production or sale release. The demo page is deliberately synthetic and
read-only. It demonstrates the interaction model, policy evidence path,
incident review surface, tenant boundary and invoice-only commercial path.

Do not describe the demo as production-ready, sale-ready, compliant, real-time,
zero-false-positive, 99.9% SLA, or proof of AIG detection recall. Those claims
require the open evidence rows in
[`commercial-go-evidence-registry.json`](./commercial-go-evidence-registry.json).

## 1. Required configuration

For the dashboard deployment, configure:

```bash
VITE_SUPABASE_URL=https://<project>.supabase.co
VITE_SUPABASE_ANON_KEY=<public-anon-key>
VITE_AIDR_COMMERCIAL_MODE=invoice
VITE_SALES_URL=https://<approved-sales-channel>
VITE_SUPPORT_URL=https://<approved-support-channel>
VITE_STATUS_URL=https://<approved-status-page>
VITE_PRIVACY_URL=https://<approved-privacy-notice>
VITE_SECURITY_URL=https://<approved-security-page>
VITE_TERMS_URL=https://<approved-terms-page>
```

On the Supabase Edge Functions, set `AIDR_ALLOWED_ORIGINS` to the exact
dashboard origin. Never place a service-role key, signing private key,
enrollment token or API key in Vite variables or the browser bundle.

For a credentialed live evaluation, provision a dedicated demo user and
isolated tenant. Use synthetic names, fake secrets and disposable test agents.
Do not reuse an employee, customer or production tenant.

## 2. Preflight

Run from the repository root:

```bash
pnpm install --frozen-lockfile
pnpm -C packages/dashboard build
pnpm demo:preflight
pnpm -C packages/dashboard test:route-smoke
```

If credentials or a deployed base URL are not available, the safe structural
check is:

```bash
pnpm demo:preflight -- --static
pnpm -C packages/dashboard test:route-smoke:static
```

The isolated `/demo` route is allowed to render in this no-Supabase mode and
does not import a live tenant, invoke an Edge Function or execute an external
command. Other dashboard routes remain fail-closed until the public Supabase
variables are configured; this is intentional and must be stated to the
audience.

The static result is not a live demo proof. A successful non-static preflight
writes a redacted receipt to `.e2e-artifacts/demo/preflight.json`.

## 3. Twelve-minute golden path

1. Open `/demo` and read the evaluation-boundary banner aloud.
2. Show the synthetic tenant ID and fixture version; explain that no customer
   content or production endpoint is used.
3. Select **Suspicious command** and run the synthetic fixture. Show the BLOCK
   decision, reason and “no external request” statement.
4. Select **Package integrity** and run it. Explain the difference between an
   automatic block and an explicit reviewer decision.
5. Select **MCP tool request** and show the protected-resource decision.
6. Review the synthetic agent inventory and incident timeline.
7. Explain the evidence path: input → decision → redacted, tenant-scoped
   record. Do not claim this is recall or benchmark evidence.
8. Open `/pricing` and show **By order / invoice**. Do not show a checkout
   button or quote an unapproved price.
9. Open `/support`, `/status`, `/privacy`, `/security` and `/terms`. Any
   missing deployment URL must remain visibly fail-closed.
10. If a real evaluation is requested, click **Start real evaluation** and use
    the dedicated demo account at `/onboarding`. Keep the synthetic `/demo`
    page and live account clearly separated.
11. Generate a device code only on the dedicated account. Mask enrollment
    tokens during screen share and clear them immediately after the walkthrough.
12. End with limitations and the next evidence step: hosted browser trace,
    real connector matrix, customer Evaluation Charter and security/legal
    review.

## 4. Stop conditions

Stop the session and reset the demo tenant if:

- a real secret, customer data or production identifier is pasted;
- the dashboard shows an unredacted token or key;
- a route returns an unexpected error or the console reports an uncaught
  exception;
- an operator is asked to call a real malicious URL, install a real typosquat,
  or connect an unapproved model/provider;
- a participant asks for a production-readiness, compliance, SLA or recall
  conclusion that is not backed by the signed evidence registry.

## 5. Evidence packet

Retain, with secrets redacted:

- `.e2e-artifacts/demo/preflight.json`;
- `.e2e-artifacts/dashboard/route-smoke.json`;
- the exact dashboard build digest and deployment revision;
- screenshots/video of `/demo`, the live onboarding path (if used), invoice
  page and fail-closed legal/support pages;
- the signed Evaluation Charter and limitations log.

The operator must record the date, evaluator, environment, fixture version,
deployment revision, deviations and follow-up owner. Do not edit the registry
to close a hard gate from a demo screenshot.
