# Billing (Implementation Notes)

This repo includes **agent-seat enforcement hooks** (1 free agent by default) and a billing sync model for the direct-GA enterprise invoice/order workflow.

## What’s implemented

- Control plane data model: `entitlements` (`included_agents` + `extra_agents`)
- Control plane enforcement point: `ingest` edge function rejects new agents over limit (`402 agent_limit_exceeded`)

## Direct-GA paid flow (manual / enterprise invoice)

To grant additional paid agents for a user, increase `extra_agents`:

```sql
update public.entitlements
set extra_agents = 4
where user_id = '<auth.users.id>';
```

The signed order, invoice reference and tenant-scoped entitlement record are the
source of truth. A dashboard checkout link must never grant access by itself.

## Legacy self-service code (disabled)

Legacy Paddle/Lemon checkout and portal helpers remain in the repository only for
historical compatibility. They are not deployed or advertised for direct GA;
`VITE_AIDR_COMMERCIAL_MODE=self-service` is an explicit non-default opt-in and
requires a new commercial decision plus release evidence. The corresponding
Supabase checkout/webhook endpoints also require
`AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING=true`; otherwise they return a
fail-closed `410 disabled_for_direct_ga`. Seat enforcement remains server-side
via `ingest` (`402 agent_limit_exceeded`).

## Pricing model (proposed)

- **1 free agent**
- **$2 / month per additional agent** (proposed price; Finance must approve the
  final price book, tax, currency and minimum term before sale)
