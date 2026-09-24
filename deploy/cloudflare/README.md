# Cloudflare Free pilot (not customer production acceptance)

The Vite dashboard and the fixed-origin API proxy run in **one Cloudflare Worker
with Static Assets**. The existing Supabase project still provides Postgres,
Auth, Storage, Realtime and Edge Functions. D1 is not compatible with AIDR's
PostgreSQL migrations, RLS policies and Supabase Auth/Storage APIs; do not replace
the backend with D1 by changing a URL. This path introduces no new application
dependency.

For the separately named staging Worker and guarded signed-candidate rollout,
use [STAGING.md](STAGING.md). It does not route the existing landing page.

## Operator setup

1. Create a **new, isolated** Supabase Free project in the approved EU region.
   Keep its database password in a vault. Enable the Data API, but disable
   “Automatically expose new tables.” Run the canonical `supabase/migrations`
   in order, deploy the functions from `supabase/functions`, and configure the
   required function secrets. Do not reuse a paused/unknown-data project.
2. Choose the final Cloudflare Worker HTTPS origin. It can initially be a
   `workers.dev` address. Set Supabase Auth site/redirect URLs, function
   `AIDR_ALLOWED_ORIGINS`, `AIDR_DASHBOARD_URL`, and
   `AIDR_DASHBOARD_VERIFY_URL` to that exact origin. Publish only the **anon or
   publishable** Supabase API key to the Worker; never its service-role key.
   Microsoft Entra sign-in is hidden unless explicitly enabled. To enable it,
   register a Microsoft Entra application with the Supabase Auth callback
   `https://<project-ref>.supabase.co/auth/v1/callback`, configure its client ID
   and secret in Supabase Auth > Providers > Azure, and add the exact dashboard
   callback `https://<worker-domain>/auth/callback` to Supabase Auth's redirect
   URL allow list. Use the Entra tenant URL in Supabase when sign-in must be
   restricted to BMC's directory. For an approved environment, change that
   environment's version-controlled Wrangler `vars.AIDR_ENABLE_AZURE_AUTH`
   value from `"false"` to `"true"` and deploy. The checked-in default keeps
   Azure hidden; the flag only exposes the button and does not configure or
   store provider credentials. AIDR requests `openid profile email` scopes.
   Verify the real Entra login and callback in staging before enabling it for
   customers.
3. Configure the dashboard's public support, status, privacy, security, terms,
   and sales routes in the Vite build environment. Set safe HTTPS URLs for
   `VITE_SUPPORT_URL`, `VITE_STATUS_URL`, `VITE_PRIVACY_URL`,
   `VITE_SECURITY_URL`, `VITE_TERMS_URL`, and `VITE_SALES_URL`, or approved
   support/sales mailboxes with `VITE_SUPPORT_EMAIL` and `VITE_SALES_EMAIL`.
   These values are public links, not secrets. Do not use placeholder domains
   or publish a pilot until the destinations are real, approved, and reachable.
   They are Vite build values, not Cloudflare Worker secrets, and deployment
   does not reject their omission. The dashboard shows fail-closed notices for
   missing or unsafe destinations, but that does not prevent the Worker from
   serving the app. Route verification in step 6 is a required customer-release
   acceptance gate, not an optional smoke check.
4. Build and test from the repository root:

   ```sh
   pnpm --filter @singularityrd/aidr-dashboard build
   node --test deploy/cloudflare/worker.test.mjs
   pnpm dlx wrangler@4.137.0 deploy --dry-run --config deploy/cloudflare/wrangler.jsonc
   ```

5. Bind the four required values listed in `wrangler.jsonc` as Cloudflare
   Worker secrets. `AIDR_SUPABASE_ORIGIN` is the **provider** origin
   (`https://PROJECT.supabase.co`), while `AIDR_PUBLIC_ORIGIN` is the **Worker**
   origin. `AIDR_SUPABASE_ANON_KEY` is public by design. Generate an independent
   random 32-byte-or-longer `AIDR_DEVICE_START_INGRESS_SECRET` and set the same
   value only in the Supabase `device-start` function environment. The Worker
   also signs `waitlist-signup` POSTs with the route-bound context
   `waitlist-signup:v1`; setting `AIDR_WAITLIST_INGRESS_SECRET` to the same value
   in the `waitlist-signup` function enables its per-client quota and makes the
   proof mandatory. Set `TURNSTILE_SECRET_KEY` there to require server-side
   Cloudflare Turnstile verification. Do not commit
   or print secrets. In the same Cloudflare environment, set the non-secret
   Worker variables `AIDR_RELEASE_VERSION` and `AIDR_RELEASE_SHA` from the exact
   approved release tag and its 40-character source commit. `/version` returns
   503 until both values and the Worker configuration are valid; the release
   promotion flow can then verify that the deployed dashboard is the expected
   commit. Deploy with:

   ```sh
   pnpm dlx wrangler@4.137.0 deploy --config deploy/cloudflare/wrangler.jsonc
   ```

   The Worker rejects missing/invalid configuration. Its `/runtime-config.js`
   route exposes only the public origin and anon key. All other API routes are
   fixed to the configured Supabase project. `/functions/v1/device-start`
   strips client-supplied AIDR forwarding headers and signs the canonical
   Cloudflare client IP; the provider function rejects unsigned direct calls.
   Before inviting anyone, check the deployed origin itself: `/livez` and
   `/healthz` must return JSON `{"status":"alive"}`, `/version` must return
   the exact approved version and commit, and `/demo` must return a non-cached
   `302` to `/login?returnTo=%2Fonboarding`. An HTML response on these paths
   means the deployed routing is stale. `/readyz` must return a non-cached JSON
   `503` with live Auth, database RPC, Storage and Edge Function probe results;
   signing, backup, queue and public TLS remain `unverified`. `/metrics` returns
   `501`, not a successful SPA shell. Both keep the pilot outside customer
   production acceptance. The protected release workflow also
   compares the live dashboard bytes with the signed RC archive before moving
   package tags to `latest`.

   Run the external operational probe against the deployed origin with the
   approved release identity:

   ```sh
   node deploy/cloudflare/verify-operational.mjs --base-url https://YOUR-WORKER-ORIGIN --expected-version X.Y.Z --expected-sha FULL-40-CHAR-SHA --pilot
   ```

   `--pilot` verifies the live JSON routes, no-cache headers and exact release
   identity; it reports `production_ready:false`. Without `--pilot`, the same
   check exits nonzero because the missing production evidence and metrics do
   not permit GA readiness. Run it
   from an independent location on a schedule and alert an owner on failure;
   a successful local or CI test cannot establish deployed availability.

6. Use a **separate** staging project and test tenant first. In the deployed
   browser, verify `/support` has an approved HTTPS channel or support mailbox;
   `/status`, `/privacy`, `/security`, and `/terms` each open their approved
   HTTPS destination; and `/pilot` exposes an approved sales channel or
   mailbox. Confirm the actual destinations, not only that buttons are visible.
   Then verify sign-in,
   callback, a real device-code enrollment, policy retrieval, benign host tool
   execution, a blocked harmful canary, audit/telemetry receipt and tenant
   isolation. A UI page loading or `aidr status` alone is not enforcement
   evidence. The existing release readiness and native-host canary gates still
   apply. Publish signed connector/CLI artifacts through the release channel;
   send customers to the dashboard's guided onboarding page. Do not publish a
   source-tree install command as the customer product.

## Free-tier boundary

Cloudflare Workers Free has 100,000 dynamic requests/day and 10 ms CPU/request.
Static asset requests are free, but API requests and `/runtime-config.js` count
toward the dynamic quota. When that quota is exhausted, API calls fail; AIDR's
remote-policy offline grace then becomes an availability concern. Supabase Free
projects can pause for low activity and have a 500 MB database limit. Supabase's
built-in email provider permits only two Auth emails per hour per project and
is best-effort; new Free projects cannot customize its email templates. Use a
verified custom SMTP provider before onboarding pilot users, then test actual
invite, sign-in, recovery and delivery-failure flows. These
plans are suitable for our **internal or explicitly limited pilot**, not an
uninterrupted paid security service or an SLA. Track request rate, storage,
delivery failures and quota headroom before inviting a pilot. Upgrade plans
or use an accepted self-hosted deployment before making customer uptime claims.

`/livez` and `/healthz` report Worker liveness only. `/version` reports the
configured release version and source commit, and fails closed if either value
is missing or malformed. `/readyz` makes bounded, non-cached checks against
Supabase Auth's health endpoint, the `aidr_readiness_probe` database RPC,
Storage's status endpoint and the deployed `packs-manifest` Edge Function. It
coalesces concurrent probes and caches their results in the Worker isolate for
up to five seconds. A `reachable` Function result is its expected
unauthenticated rejection, not a successful customer transaction. It returns
`503` even when all four pass because signer, backup, queue and public TLS
evidence are still unverified; these checks prove component reachability,
not an authenticated customer journey or disaster recovery. `/metrics` returns
`501`, rather than fabricating request counts in ephemeral Worker memory or
falling through to the SPA. Never mark the product ready based on a successful
Cloudflare deployment alone.

For GA, a provider-backed readiness source must independently verify the live
database, Auth, Storage, Edge Functions, signer canary, recent verified backup,
delivery queue and public TLS, with bounded freshness and failure responses.
Record an external alert-delivery drill, authenticated customer-path SLI/load
measurements, a second-environment restore, and the deployed release identity
with the candidate. The current Worker has no such provider receipts, so its
`501` is the correct production gate.
