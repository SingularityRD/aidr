# Singularity AIDR Dashboard (Supabase)

This is a minimal multi-tenant dashboard for:

- User login (Supabase Auth)
- API key generation (hash-only storage)
- Agent inventory (per `iid`)
- Incidents view (derived from `events` telemetry)
- Billing / seat usage (order-scoped entitlements; production sale approval remains open)

## AutoSecOps integration

The authenticated AIDR dashboard can show the connected AutoSecOps runtime
health and fleet through the `autosecops-runtime` Supabase Edge Function. The
browser never receives the AutoSecOps credential and the dashboard exposes
read-only observations only.

Configure these values as Supabase Edge Function secrets (never as `VITE_*`
browser variables):

```text
AUTOSECOPS_RUNTIME_URL=https://autosecops.example.invalid
AUTOSECOPS_RUNTIME_TOKEN=<AutoSecOps-authenticated-user-or-API-session-credential>
AUTOSECOPS_AIDR_TEAM_ID=<aidr-team-uuid>
AUTOSECOPS_TEAM_ID=123
```

The bridge credential must belong to an AutoSecOps identity authorized for the
mapped team; a generic provider token is not accepted by the runtime routes.
For the Codex runtime adapter, set `AUTOSECOPS_POLICY_ENDPOINT` to the
AutoSecOps API base including `/api` (for example,
`https://autosecops.example.invalid/api`), `AUTOSECOPS_API_KEY` to the same
kind of authorized credential, and `AUTOSECOPS_TENANT_ID=team:123` together
with `AUTOSECOPS_TEAM_ID=123`.

For more than one AIDR team, use `AUTOSECOPS_RUNTIME_TEAM_MAP` as a JSON
object from AIDR team UUID to the authorized AutoSecOps numeric team ID. If
the bridge is not configured, the page fails closed and reports that state; it
does not display fabricated runtime data.

## Setup

1. Create a Supabase project and apply the schema in `supabase/migrations/`.
2. Configure Supabase Auth:

   - Email magic link works out of the box.
   - Optional: enable Google provider and add a redirect URL for the SPA callback:
     - Local dev: `http://localhost:5173/auth/callback`
     - Production: `https://YOUR_DOMAIN/auth/callback`
   - Optional SAML SSO: register the IdP in Supabase Auth, allowlist the exact
     `/auth/callback` URL, then set exactly one of `AIDR_SAML_PROVIDER_ID` (the
     Supabase SSO provider UUID) or `AIDR_SAML_DOMAIN` (a domain registered to
     that provider) in the dashboard server or Cloudflare Worker environment.
     The button is hidden when neither is set. Existing `AIDR_AUTH_METHODS`
     options remain available. This setting only starts SP-initiated login;
     tenant access requires server-side provider UUID binding and enforcement.
3. Create `packages/dashboard/.env.local`:

```bash
VITE_SUPABASE_URL=...
VITE_SUPABASE_ANON_KEY=...
# Optional: invoice-only is the proposed direct-sale default. Do not set this to
# self-service for a production release without an approved commercial change.
VITE_AIDR_COMMERCIAL_MODE=invoice
# Optional approved sales channel used by the invoice CTA.
VITE_SALES_URL=https://sales.example.invalid/request
VITE_SALES_EMAIL=sales@example.invalid
```

Both Microsoft Entra ID and Okta require separate live acceptance before SAML
can be marked ready. For each provider, retain redacted evidence for the
SP-initiated login and callback, the matching SAML provider UUID in the
tenant's authenticated session, SCIM provision/update/deactivate bound to that
same Auth user UUID, rejection of password or wrong-IdP access to the SSO
tenant, and continued access for a tenant without an SSO requirement.

| Provider | Live SAML + SCIM acceptance |
| --- | --- |
| Microsoft Entra ID | Pending |
| Okta | Pending |

## Run

```bash
pnpm install
pnpm -C packages/dashboard dev
```

The bundle's compiler targets are ES2020, Chrome 87, Edge 88, Firefox 78, and
Safari 14.1 or newer. Run customer browser acceptance on the browser versions
the deployment supports; a successful bundle build is not browser acceptance.

## Customer access smoke gate

The public product starts at `/login` and `/onboarding`. The old `/demo`
address redirects to `/login?returnTo=%2Fonboarding`; no synthetic fixture
page is reachable from the customer app. Use the operator sequence in
[`docs/production-readiness/controlled-demo-runbook.md`](../../docs/production-readiness/controlled-demo-runbook.md).

Run the customer access preflight before sharing a URL (the command name is
retained for existing automation):

```bash
pnpm demo:preflight
```

Build the production bundle before a customer/investor demo, then crawl every
public and protected SPA route through the same HTTP surface used by a static
host:

```bash
pnpm -C packages/dashboard build
pnpm -C packages/dashboard test:route-smoke
```

`test:route-smoke` fails closed when `VITE_SUPABASE_URL` or
`VITE_SUPABASE_ANON_KEY` is missing. It also checks deep-link rewrites,
security headers, protected-route session loaders, device-code expiry, secret
masking, and that no service-role/private-key material entered `dist/`.
Evidence is written to `.e2e-artifacts/dashboard/route-smoke.json`.

For a credentialed browser release gate, use
`packages/dashboard/tests/browser-smoke.manifest.json` as the canonical route,
auth, enrollment, billing, accessibility, and console-error matrix. The
repository intentionally does not install a browser runtime; execute that
manifest with the organization's approved Playwright + axe-core runner against
the deployed URL and retain redacted route/console/axe/screenshot evidence.
The browser gate requires a dedicated evaluation account in addition to the
two public Supabase build variables. A missing Supabase build configuration
renders an explicit production configuration error for every route, including
the old `/demo` address. The live browser run must verify the redirect and
complete sign-in and onboarding; the static preflight proves only source
contracts.

Deployment links are validated before rendering: `VITE_SUPPORT_URL`,
`VITE_SUPPORT_EMAIL`, `VITE_STATUS_URL`, `VITE_PRIVACY_URL`,
`VITE_SECURITY_URL`, `VITE_TERMS_URL`, `VITE_SALES_URL`, and
`VITE_SALES_EMAIL`. Support is available only through a configured safe HTTPS
URL or approved mailbox. Status, privacy, security, and terms require safe
HTTPS URLs; sales requires a safe HTTPS URL or approved mailbox. Missing or
unsafe destinations show a visible fail-closed notice. These build-time links
are not required by the Cloudflare deploy command, so verify every destination
in the deployed browser before customer onboarding; publish the
privacy/security/terms URLs before accepting customer data or selling the
deployment.

The proposed direct-sale commercial mode is invoice/order based. `VITE_AIDR_COMMERCIAL_MODE`
defaults to `invoice`; `self-service` is a legacy/staging opt-in and must not be
enabled in a sale release. This default does not make the release sale-ready.
The dashboard never grants entitlements from a
checkout link: Finance reconciliation and the tenant-scoped entitlement record
remain authoritative.

## Billing provider: Stripe (not deployed)

Lemon Squeezy was removed. Its webhook Edge Function
(`supabase/functions/lemon-webhook/`) dispatched on an unauthenticated
`meta.event_name` with no signature verification, and
`src/billing/lemon-client.ts` exported a `verifyWebhookSignature` that always
returned `true`. Both are deleted.

- Seat entitlements are reconciled by `supabase/functions/stripe-webhook`
  (signature-verified over the raw body, deduplicated by event id, gated on the
  subscription status and the configured extra-agent price). See
  [`docs/billing.md`](../../docs/billing.md).
- The dashboard bundle never holds `STRIPE_SECRET_KEY` and exposes **no**
  webhook verification helper. `src/billing/stripe-client.ts` fails closed: it
  refuses to call Stripe directly and requires a server-side Checkout Session.
- `supabase/functions/billing-checkout` still returns a Paddle URL, so there is
  currently **no** Stripe checkout path and no Stripe metadata on Stripe
  objects. Until that follow-up ships, Stripe events resolve to no tenant and
  grant nothing.
- Status: implemented and unit-tested, **not deployed and not verified against a
  live Stripe account**; `STRIPE_WEBHOOK_SECRET` is not provisioned anywhere.

For local structural checks while credentials are being provisioned, use the
explicitly non-production mode:

```bash
pnpm -C packages/dashboard test:route-smoke:static
```

The static result must never be presented as proof of live customer access.

## Connect an agent

1. Sign in to the dashboard.
2. Create an API key (shown once).
3. On the agent machine, set:

```json
{
  "auth": { "api_key": "aidr_live_..." },
  "control_plane": { "enabled": true, "send_audit_logs": true }
}
```
