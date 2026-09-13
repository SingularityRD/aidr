# Enterprise invoice order intake v6

The direct-sale flow now has a tenant-scoped, auditable **order request** API. It is deliberately a `pending_finance` workflow. A quote reference supplied by a customer is not proof of a signed order, issued invoice, payment, or entitlement. No route or SQL function in this change writes `entitlements`, `subscriptions`, or a paid flag.

## API contract

`invoice-entitlement` requires a verified Supabase access token and an explicit `X-AIDR-Tenant-ID` header. Both methods require an active tenant owner/admin membership, a non-revoked session, and the tenant's MFA policy. The service-role route repeats the tenant/role check inside the create transaction.

| Method | Request | Response |
| --- | --- | --- |
| `GET` | Tenant header | `{ "ok": true, "orders": [...] }`, newest first, at most 100 |
| `POST` | Tenant header and JSON `{ "request_id": "...", "requested_agents": 125, "quote_reference": "Q-..." }` | `{ "ok": true, "order": { ... } }` |

Each order contains `id`, `tenant_id`, `request_id`, `requested_agents`, nullable `quote_reference`, `status: "pending_finance"`, `created_at`, and `updated_at`. `request_id` must be 16–80 ASCII letters, numbers, underscore or hyphen. `requested_agents` must be an integer from 1 to 100,000. `quote_reference` is optional, at most 120 characters, with control characters rejected. Extra JSON fields, including `paid`, `status`, `invoice_reference`, or `entitlement`, are rejected.

For a given tenant, repeating the same `request_id` and payload returns the existing order without another audit entry. Reusing the id with different quantity or reference returns `409 invoice_order_request_conflict`. The table's unique key, transaction advisory lock, insert and `invoice_order.requested` audit entry make this concurrency-safe. Creation is limited to 10 requests per actor per minute and 50 per tenant per minute using the existing atomic rate-limit RPC.

The new table has RLS enabled with no browser policies or grants. The create and list RPCs are executable only by `service_role`; the Edge route checks the access token itself because the service role bypasses RLS. Both RPCs recheck the owner/admin membership and active tenant while holding shared row locks, so a concurrent revocation or suspension cannot pass between authorization and the database operation. Offboarding removes request rows in the same transaction that completes the existing `entitlements` commercial-retention phase, after legal-hold checks, and adds a separate `enterprise_invoice_orders` deletion-count receipt. A tenant-close trigger also cleans residual rows if a future close path skips that phase.

## What remains open

Finance must choose and authenticate one provider of record and approve the signed SKU/order/quote terms, amount, currency, tax, payment terms, invoice identifier, credit/refund/dispute behavior, and cancellation rules. A separate implementation must then verify provider-signed settlement or an approved two-person finance evidence procedure, atomically bind the exact signed order and invoice to the tenant and entitlement revision, and test seat increases/decreases, revocation, registry access and offboarding receipts. Until that happens, neither this API nor its dashboard view may be described as paid billing or active enterprise entitlement provisioning.

## Local evidence

- Focused contract test: `AIDR_TEST_NO_BUILD=1 pnpm exec vitest run supabase/functions/invoice-entitlement/__tests__/contract.test.ts` — five cases pass for tenant header, bounded order fields, forbidden payment/entitlement claims, invalid input, and tenant-bound response projection.
- On the existing local PostgreSQL stack, the new migration and `supabase/functions/invoice-entitlement/__tests__/invoice-order-transaction.sql` passed in one transaction followed by `ROLLBACK` (`psql -v ON_ERROR_STOP=1`). The smoke checked replay, changed-payload conflict, cross-tenant write/read rejection, atomic audit, unchanged entitlement and commercial-retention deletion receipt. The shared database was left unchanged.
- Fresh-install migration and deployed Edge HTTP behavior require the root integration run. This document does not claim field acceptance.
