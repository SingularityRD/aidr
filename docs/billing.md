# Billing and enterprise orders

The default commercial model is an enterprise quote and invoice. The enterprise invoice/order workflow uses the finance-approved order and payment ledger as its source of truth; the dashboard only accepts tenant-bound requests for additional protected agents. A request is stored as `pending_finance`; it is **not** a paid invoice and does not change the agent entitlement.

The `invoice-entitlement` Edge function and `enterprise_invoice_orders` table accept idempotent requests from an active tenant owner/admin after session and MFA checks. A repeated request ID with changed terms is rejected. Finance has not yet supplied an approved SKU, signed order, provider-of-record ledger, payment receipt or reconciliation. No production flow in this repository may infer payment from a browser request or grant seats from a pending order. Direct SQL changes to `entitlements` are not a supported sales workflow.

Existing signed entitlement snapshots and the ingest agent-seat limit are enforcement components. They are not proof of a sold or paid lifecycle. The missing audited order-to-entitlement transition must bind the approved tenant, term, quantity and payment evidence, and cover renewal, reduction, cancellation, refund and offboarding. It must be tested against both cloud and self-hosted deployments before sale.

Optional Stripe checkout/webhook code exists behind a default-disabled self-service gate. The webhook has local signature/replay tests, but no live account, approved price, webhook registration, portal, invoice retrieval, refund/cancellation or provider reconciliation acceptance. Paddle helpers are legacy and stay disabled. The dashboard does not show invented prices, exchange rates or an empty invoice ledger as a successful lookup.

The implementation boundaries and acceptance scenarios are recorded in [billing-v6.md](production-readiness/billing-v6.md) and the [commercial evidence registry](production-readiness/commercial-go-evidence-registry.json). **T33 and commercial billing approval remain open.**
