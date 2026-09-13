# Enterprise billing v6: local workflow and release boundary

The customer-facing dashboard can submit and read tenant-scoped enterprise order requests. A request has one server-returned status, `pending_finance`. It is **not** an invoice, a payment receipt, or an entitlement grant. Finance must approve the sold SKU, quote, legal order, provider of record, invoice, payment evidence, and reconciliation before protected-agent limits change.

## Implemented local contract

| Step | Behavior |
| --- | --- |
| Request | An owner/admin enters total requested protected agents (1–100,000) and an optional quote reference. The browser sends `POST invoice-entitlement` with `X-AIDR-Tenant-ID` and a 16–80 character request ID. |
| Retry | The same tenant, quantity, quote reference, and request ID are reused after a failed response. Editing the request creates a new ID. The server's uniqueness/replay check is the authority; browser duplicate suppression is only a user-interface safeguard. |
| Review | `GET invoice-entitlement` returns tenant-bound order records. The dashboard validates tenant ID, UUIDs, request ID, quantity, status shape, and timestamps before rendering. Owner/admin role is checked in the UI; the Edge function must enforce session revocation/MFA, active membership, and role. |
| Quota | The request page does not write `entitlements`, `subscriptions`, `billing_customers`, or payment status. A pending request cannot raise the `seat_usage` allowance. |
| Optional Stripe | Self-service remains disabled by default. If separately configured, browser Checkout sends the actual tenant ID and stable request ID to `billing-checkout`. The portal, cancellation, invoice lookup, and browser-side pricing remain unavailable. |
| Pricing | The browser will not fabricate an empty invoice ledger or currency conversion. A cross-currency amount requires a Finance-approved quote; stale fallback FX rates and `.99` rounding have been removed. |

The `invoice-entitlement` Edge function and `enterprise_invoice_orders` migration are delivered in the backend workstream for this candidate. Their deployment and independent database rehearsal must be assessed with the complete candidate, not inferred from dashboard tests.

## Acceptance scenarios still required for T33

1. Finance signs the order/SKU/term/seat unit and names one provider of record. The invoice reference and payment/reconciliation evidence must refer to that order and tenant.
2. An authorized operator provisions, increases, reduces, renews, suspends, and revokes entitlement from verified order state through an audited server workflow. A pending, duplicate, altered, failed, or unlinked invoice must never grant access.
3. Test replay and concurrent requests against a deployed database, then read the effective `seat_usage`, signed entitlement refresh, installed connector behavior, and customer-visible receipt for the same tenant.
4. Reconcile provider ledger to invoice and entitlement, including failure, cancellation, refund, over-limit, and offboarding. Keep the signed order and audit evidence under the approved retention policy.
5. Repeat in both managed-cloud and customer-hosted installation with a named customer and approved commercial terms. Self-service portal/cancel/refund are out of the sold scope unless separately implemented and accepted.

Until these are evidenced, **T33 remains open for sales/field acceptance**. A pending request is operational intake only.
