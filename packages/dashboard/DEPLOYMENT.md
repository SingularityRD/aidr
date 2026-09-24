# Dashboard deployment

The only maintained hosted pilot path is the Cloudflare Worker deployment in
[`deploy/cloudflare/README.md`](../../deploy/cloudflare/README.md). It is an
explicitly limited pilot, not customer-production acceptance. Vercel, Netlify,
and static-file hosting are not supported deployment alternatives: they do not
provide the API proxy, trusted device-start ingress, or deployment acceptance
checks.

Before building a hosted dashboard, configure the deployment-specific support,
status, privacy, security, terms, and sales links documented in
[dashboard README](README.md). The UI
fails closed with visible notices when these links are absent or unsafe; do not
accept customer data or sell a pilot until the legal and support routes are
approved and reachable.

## Local development

From the repository root:

```sh
pnpm --filter @singularityrd/aidr-dashboard dev
pnpm --filter @singularityrd/aidr-dashboard build
```

The legacy `/demo` address redirects to `/login?returnTo=%2Fonboarding`.
Validate authentication, API access, enforcement, and tenant isolation in a
deployed evaluation tenant before describing them as working for customers.
