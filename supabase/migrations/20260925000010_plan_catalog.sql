-- Commercial plan catalog.
--
-- LIST PRICES ONLY. These rows describe the proposed public tiers; final SKU
-- approval is COM-001 (docs/production-readiness/commercial-go-evidence-
-- registry.json). A catalog row never grants anything: tenant admission is
-- still granted only by an operator (grant_licensed_tenant_admission), the
-- verified trial path, or the audited Stripe plan path added in
-- 20260925000011_stripe_plan_admission.sql.
--
-- Column conventions:
--   included_agents     protected agents admitted per purchased seat. Free has a
--                       fixed single seat, so it admits exactly one agent.
--   min_seats           smallest purchasable seat quantity.
--   price_monthly_cents per-seat price for one month on monthly billing
--                       (null = not offered monthly / custom).
--   price_yearly_cents  per-seat price for one year on annual billing
--                       (null = custom quote).
--   retention_days      list retention term (null = contractual).
--
-- The dashboard ships a static mirror of the seed below in
-- packages/dashboard/src/billing/plans.ts; a drift test parses the block
-- between the catalog-seed markers and fails when the two disagree.

create table if not exists public.plans (
  id text primary key
    check (id in ('free', 'team', 'business', 'enterprise')),
  display_name text not null check (length(trim(display_name)) between 1 and 60),
  included_agents integer not null check (included_agents between 1 and 100000),
  min_seats integer not null check (min_seats between 1 and 100000),
  price_monthly_cents integer check (price_monthly_cents is null or price_monthly_cents >= 0),
  price_yearly_cents integer check (price_yearly_cents is null or price_yearly_cents >= 0),
  currency text not null default 'USD' check (currency = 'USD'),
  features jsonb not null default '[]'::jsonb check (jsonb_typeof(features) = 'array'),
  self_serve boolean not null default false,
  deployment text[] not null
    check (cardinality(deployment) >= 1
      and deployment <@ array['cloud', 'onprem', 'air-gapped']::text[]),
  retention_days integer check (retention_days is null or retention_days between 1 and 3650),
  active boolean not null default true,
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.plans is
  'Commercial plan catalog. List prices only; final SKU approval is COM-001. A plan row never grants admission.';

-- catalog-seed:begin
insert into public.plans
  (id, display_name, included_agents, min_seats, price_monthly_cents, price_yearly_cents, currency, features, self_serve, deployment, retention_days, active, sort_order)
values
  ('free', 'Free', 1, 1, 0, 0, 'USD', '["local_detection","dashboard"]'::jsonb, true, array['cloud'], 7, true, 10),
  ('team', 'Team', 1, 3, 2400, 24000, 'USD', '["local_detection","dashboard","browser_privacy_guard","entra_sso"]'::jsonb, true, array['cloud'], 90, true, 20),
  ('business', 'Business', 1, 25, null, 54000, 'USD', '["local_detection","dashboard","browser_privacy_guard","entra_sso","siem_export","scim","ai_security_posture"]'::jsonb, false, array['cloud','onprem'], 365, true, 30),
  ('enterprise', 'Enterprise', 1, 1, null, null, 'USD', '["local_detection","dashboard","browser_privacy_guard","entra_sso","siem_export","scim","ai_security_posture","air_gapped_deployment","dedicated_support"]'::jsonb, false, array['onprem','air-gapped'], null, true, 40)
-- catalog-seed:end
on conflict (id) do update set
  display_name = excluded.display_name,
  included_agents = excluded.included_agents,
  min_seats = excluded.min_seats,
  price_monthly_cents = excluded.price_monthly_cents,
  price_yearly_cents = excluded.price_yearly_cents,
  currency = excluded.currency,
  features = excluded.features,
  self_serve = excluded.self_serve,
  deployment = excluded.deployment,
  retention_days = excluded.retention_days,
  active = excluded.active,
  sort_order = excluded.sort_order,
  updated_at = now();

drop trigger if exists plans_touch_updated_at on public.plans;
create trigger plans_touch_updated_at
  before update on public.plans
  for each row execute procedure public.touch_updated_at();

-- The catalog is reference data. Signed-in users may read it; nobody but the
-- migration owner writes it. The public /pricing page uses the static mirror,
-- so anon needs no access.
alter table public.plans enable row level security;
revoke all on public.plans from public, anon, authenticated;
grant select on public.plans to authenticated;
grant select on public.plans to service_role;
drop policy if exists plans_select_authenticated on public.plans;
create policy plans_select_authenticated on public.plans
  for select to authenticated
  using (active);

-- teams.plan is a billing-managed label (no browser write path exists since
-- 20260922000002). Accept the catalog ids alongside the legacy 'pro' label,
-- which get_tenant_plan maps to 'team'. The label is display metadata only;
-- tenant_admissions remains the only admission authority.
alter table public.teams drop constraint if exists teams_plan_check;
alter table public.teams add constraint teams_plan_check
  check (plan in ('free', 'pro', 'team', 'business', 'enterprise'));

-- Map a stored team label to a catalog id.
create or replace function app.catalog_plan_id(p_label text)
returns text
language sql
immutable
set search_path = pg_catalog
as $$
  select case p_label
    when 'pro' then 'team'
    when 'team' then 'team'
    when 'business' then 'business'
    when 'enterprise' then 'enterprise'
    else 'free'
  end;
$$;
revoke all on function app.catalog_plan_id(text) from public, anon, authenticated;
