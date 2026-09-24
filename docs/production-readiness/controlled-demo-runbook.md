# AIDR Controlled Customer/Investor Demo Runbook

## Positioning

This runbook prepares a **controlled live evaluation** with a dedicated
account, tenant, and enrolled test agent. The customer app has no synthetic
`/demo` page; the old address redirects to the onboarding sign-in path.
Use disposable test inputs and show only verdicts and incidents actually
observed in the connected deployment.

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

If credentials or a deployed base URL are not available, the structural
check is:

```bash
pnpm demo:preflight -- --static
pnpm -C packages/dashboard test:route-smoke:static
```

All production routes, including `/demo`, show the configuration error until
the public Supabase variables are configured. A structural pass cannot confirm
sign-in, enrollment, telemetry, or enforcement.

The static result is not a live demo proof. A successful non-static preflight
writes a redacted receipt to `.e2e-artifacts/demo/preflight.json`.

## 3. Twelve-minute golden path

1. Open `/demo`; confirm the browser lands at `/login?returnTo=%2Fonboarding`
   and no synthetic fixture appears.
2. Sign in with the dedicated evaluation account and confirm `/onboarding`
   opens for the isolated tenant.
3. Generate a device code, enroll a disposable test agent on an available lab
   test host (not an accepted customer-supported host/OS/version row),
   and confirm that agent appears in `/agents` with its actual runtime and
   connection state.
4. Run the approved harmless threat probes from
   [`docs/demo/customer-threat-demo-matrix.md`](../demo/customer-threat-demo-matrix.md)
   through the enrolled host. Record the local deny/ask result and timestamp.
5. Open `/events` and `/incidents`; match the received redacted verdicts to the
   host, agent, tenant, and timestamp. If delivery is delayed or absent, state
   that result instead of substituting a fixture.
6. Open `/pricing` and show **By order / invoice**; then check `/support`,
   `/status`, `/privacy`, `/security`, and `/terms` for approved destinations.
7. Mask enrollment tokens during screen share and clear them after the
   walkthrough. Finish with the remaining acceptance evidence and owner.

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
- screenshots/video of the `/demo` redirect, authenticated onboarding, actual
  agent/events/incidents, invoice page, and legal/support pages;
- the signed Evaluation Charter and limitations log.

The operator must record the date, evaluator, environment, test agent,
deployment revision, deviations and follow-up owner. Do not edit the registry
to close a hard gate from a walkthrough screenshot.
