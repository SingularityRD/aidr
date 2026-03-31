# Billing (Implementation Notes)

This repo includes **agent-seat enforcement hooks** (1 free agent by default) and a minimal billing sync model intended for Paddle (Merchant of Record).

## What’s implemented

- Control plane data model: `entitlements` (`included_agents` + `extra_agents`)
- Control plane enforcement point: `ingest` edge function rejects new agents over limit (`402 agent_limit_exceeded`)

## Minimal “paid” flow (manual)

To grant additional paid agents for a user, increase `extra_agents`:

```sql
update public.entitlements
set extra_agents = 4
where user_id = '<auth.users.id>';
```

This is enough for a first internal beta.

## Paddle (recommended)

- Sell “extra agents” as a quantity-based subscription.
- Paddle checkout is managed externally; webhooks reconcile `subscriptions` and update `entitlements.extra_agents`.
- Seat enforcement remains server-side via `ingest` (`402 agent_limit_exceeded`).

## Pricing model (proposed)

- **1 free agent**
- **$2 / month per additional agent**

