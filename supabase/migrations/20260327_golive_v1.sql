-- Go-live v1: auth-first managed product hardening
-- Adds: enrollment tokens, billing/subscriptions, pack metadata, and audit logs.

create extension if not exists pgcrypto;

-- ── Enrollment tokens (hash-only) ──────────────────────────────────

create table if not exists public.enrollment_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  label text,
  token_hash text not null unique,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists enrollment_tokens_user_id_idx on public.enrollment_tokens (user_id);
create index if not exists enrollment_tokens_expires_at_idx on public.enrollment_tokens (expires_at desc);

alter table public.enrollment_tokens enable row level security;

drop policy if exists enrollment_tokens_select_own on public.enrollment_tokens;
create policy enrollment_tokens_select_own
on public.enrollment_tokens for select
using (user_id = auth.uid());

drop policy if exists enrollment_tokens_insert_own on public.enrollment_tokens;
create policy enrollment_tokens_insert_own
on public.enrollment_tokens for insert
with check (user_id = auth.uid());

drop policy if exists enrollment_tokens_delete_own on public.enrollment_tokens;
create policy enrollment_tokens_delete_own
on public.enrollment_tokens for delete
using (user_id = auth.uid());

-- ── Billing customers / subscriptions (read-only for end users) ────

create table if not exists public.billing_customers (
  user_id uuid primary key references auth.users (id) on delete cascade,
  provider text not null default 'paddle',
  provider_customer_id text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

drop trigger if exists billing_customers_touch_updated_at on public.billing_customers;
create trigger billing_customers_touch_updated_at
before update on public.billing_customers
for each row execute procedure public.touch_updated_at();

alter table public.billing_customers enable row level security;

drop policy if exists billing_customers_select_own on public.billing_customers;
create policy billing_customers_select_own
on public.billing_customers for select
using (user_id = auth.uid());

create table if not exists public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  provider text not null default 'paddle',
  provider_subscription_id text not null unique,
  status text not null,
  extra_agents integer not null default 0,
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists subscriptions_user_id_idx on public.subscriptions (user_id);

drop trigger if exists subscriptions_touch_updated_at on public.subscriptions;
create trigger subscriptions_touch_updated_at
before update on public.subscriptions
for each row execute procedure public.touch_updated_at();

alter table public.subscriptions enable row level security;

drop policy if exists subscriptions_select_own on public.subscriptions;
create policy subscriptions_select_own
on public.subscriptions for select
using (user_id = auth.uid());

-- ── Admin audit log (service role inserts) ─────────────────────────

create table if not exists public.admin_audit_logs (
  id bigint generated always as identity primary key,
  actor_user_id uuid,
  action text not null,
  target_user_id uuid,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists admin_audit_logs_action_idx on public.admin_audit_logs (action);
create index if not exists admin_audit_logs_created_at_idx on public.admin_audit_logs (created_at desc);

alter table public.admin_audit_logs enable row level security;

-- No public policies: this table is intentionally service-role only.

-- ── Pack metadata (service role only; client gets signed URLs) ──────

create table if not exists public.pack_versions (
  id uuid primary key default gen_random_uuid(),
  pack_id text not null,
  version text not null,
  storage_path text not null,
  manifest_json jsonb not null,
  manifest_sig_b64 text not null,
  key_id text not null,
  issued_at timestamptz not null default now(),
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  unique (pack_id, version)
);

create index if not exists pack_versions_pack_id_idx on public.pack_versions (pack_id);

alter table public.pack_versions enable row level security;
-- No public policies: served via edge function with auth + entitlement gating.

-- ── Simple rate limits (service role writes) ───────────────────────

create table if not exists public.rate_limits (
  key text not null,
  window_start bigint not null,
  count integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (key, window_start)
);

drop trigger if exists rate_limits_touch_updated_at on public.rate_limits;
create trigger rate_limits_touch_updated_at
before update on public.rate_limits
for each row execute procedure public.touch_updated_at();

alter table public.rate_limits enable row level security;
-- No public policies: service role only.

-- Atomic increment helper (service role use).
create or replace function public.increment_rate_limit(p_key text, p_window_start bigint, p_delta integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.rate_limits (key, window_start, count)
  values (p_key, p_window_start, p_delta)
  on conflict (key, window_start)
  do update set count = public.rate_limits.count + p_delta;
end;
$$;

-- Map billing webhooks by email when custom_data isn't present (service role only).
create or replace function public.user_id_by_email(p_email text)
returns uuid
language sql
security definer
set search_path = public, auth
as $$
  select u.id from auth.users u where lower(u.email) = lower(p_email) limit 1;
$$;

-- Idempotency store for billing webhooks (service role only).
create table if not exists public.billing_webhook_events (
  provider text not null default 'paddle',
  event_id text primary key,
  received_at timestamptz not null default now(),
  payload jsonb not null
);

alter table public.billing_webhook_events enable row level security;
-- No public policies: service role only.
