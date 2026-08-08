-- Device auth + pilot gating + waitlist (go-live onboarding)
--
-- Adds:
-- - public.device_sessions (OAuth-like device code flow)
-- - public.pilot_applications (manual approval gate)
-- - public.pilot_admins (admin allowlist)
-- - public.waitlist_signups (public intake)

create extension if not exists pgcrypto;

-- ── Device sessions (service role writes; no direct client read) ─────────────

create table if not exists public.device_sessions (
  id uuid primary key default gen_random_uuid(),
  device_code_hash text not null unique,
  user_code text not null unique,
  status text not null default 'pending',
  user_id uuid references auth.users (id) on delete set null,
  authorized_at timestamptz,
  exchanged_at timestamptz,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists device_sessions_expires_at_idx on public.device_sessions (expires_at desc);
create index if not exists device_sessions_user_id_idx on public.device_sessions (user_id);

alter table public.device_sessions enable row level security;
-- No public policies: served exclusively via edge functions.

-- ── Pilot applications (users can read; service role updates) ────────────────

create table if not exists public.pilot_applications (
  user_id uuid primary key references auth.users (id) on delete cascade,
  status text not null default 'pending',
  cohort text,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.pilot_applications enable row level security;

drop trigger if exists pilot_applications_touch_updated_at on public.pilot_applications;
create trigger pilot_applications_touch_updated_at
before update on public.pilot_applications
for each row execute procedure public.touch_updated_at();

drop policy if exists pilot_applications_select_own on public.pilot_applications;
create policy pilot_applications_select_own
on public.pilot_applications for select
using (user_id = auth.uid());

-- No direct insert/update policies: edge functions + service role own writes.

-- ── Pilot admins (service role writes; checked by edge function) ─────────────

create table if not exists public.pilot_admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.pilot_admins enable row level security;
-- No public policies.

-- ── Waitlist (service role writes; public edge function intake) ─────────────

create table if not exists public.waitlist_signups (
  id bigint generated always as identity primary key,
  email text not null,
  email_lower text generated always as (lower(email)) stored,
  name text,
  company text,
  message text,
  created_at timestamptz not null default now(),
  unique (email_lower)
);

alter table public.waitlist_signups enable row level security;
-- No public policies: write via edge function only.

