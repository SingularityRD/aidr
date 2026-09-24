-- A Stripe customer may be billed for more than one AIDR tenant. Keep each
-- customer-to-tenant binding distinct instead of relying on global keys.
alter table public.billing_customers
  add column id uuid;

update public.billing_customers
  set id = gen_random_uuid()
  where id is null;

alter table public.billing_customers
  alter column id set default gen_random_uuid(),
  alter column id set not null,
  drop constraint billing_customers_pkey,
  drop constraint billing_customers_provider_customer_id_key,
  add constraint billing_customers_pkey primary key (id),
  add constraint billing_customers_provider_customer_tenant_key
    unique (provider, provider_customer_id, tenant_id);
