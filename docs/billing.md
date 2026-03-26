# Billing (Implementation Notes)

This repo includes **agent-seat enforcement hooks** (1 free agent by default) but does not ship a full Stripe integration yet.

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

## Stripe (recommended next)

- Sell “extra agents” as a quantity-based subscription.
- Stripe checkout/session creates/updates a subscription record keyed by `user_id`.
- Stripe webhook updates `entitlements.extra_agents` on invoice paid / subscription updated / canceled.

