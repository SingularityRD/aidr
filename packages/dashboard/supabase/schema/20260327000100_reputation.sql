-- Self-hosted reputation tables (URL + file hash) for Singularity AIDR.
-- These tables are optional and can back url_check/file_check endpoints via Edge Functions.

-- ── URL reputation ────────────────────────────────────────────────

create table if not exists public.url_reputation (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  url text,
  domain text,
  is_malicious boolean not null default false,
  severity_name text not null default 'high',
  type_name text not null default 'phishing',
  flags text[] not null default '{}'::text[],
  source text,
  created_at timestamptz not null default now(),
  constraint url_reputation_target_ck check (url is not null or domain is not null)
);

create index if not exists url_reputation_user_id_idx on public.url_reputation (user_id);
create unique index if not exists url_reputation_user_url_uniq
  on public.url_reputation (user_id, url)
  where url is not null;
create unique index if not exists url_reputation_user_domain_uniq
  on public.url_reputation (user_id, domain)
  where domain is not null;

-- ── File hash reputation ──────────────────────────────────────────

create table if not exists public.file_reputation (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  sha256 text not null,
  severity text not null default 'SEVERITY_UNKNOWN',
  malware_name text[] not null default '{}'::text[],
  source text,
  created_at timestamptz not null default now(),
  unique (user_id, sha256)
);

create index if not exists file_reputation_user_id_idx on public.file_reputation (user_id);

-- ── RLS ────────────────────────────────────────────────────────────

alter table public.url_reputation enable row level security;
alter table public.file_reputation enable row level security;

-- url_reputation: owner can manage
drop policy if exists url_rep_select_own on public.url_reputation;
create policy url_rep_select_own
on public.url_reputation for select
using (user_id = auth.uid());

drop policy if exists url_rep_insert_own on public.url_reputation;
create policy url_rep_insert_own
on public.url_reputation for insert
with check (user_id = auth.uid());

drop policy if exists url_rep_update_own on public.url_reputation;
create policy url_rep_update_own
on public.url_reputation for update
using (user_id = auth.uid())
with check (user_id = auth.uid());

drop policy if exists url_rep_delete_own on public.url_reputation;
create policy url_rep_delete_own
on public.url_reputation for delete
using (user_id = auth.uid());

-- file_reputation: owner can manage
drop policy if exists file_rep_select_own on public.file_reputation;
create policy file_rep_select_own
on public.file_reputation for select
using (user_id = auth.uid());

drop policy if exists file_rep_insert_own on public.file_reputation;
create policy file_rep_insert_own
on public.file_reputation for insert
with check (user_id = auth.uid());

drop policy if exists file_rep_update_own on public.file_reputation;
create policy file_rep_update_own
on public.file_reputation for update
using (user_id = auth.uid())
with check (user_id = auth.uid());

drop policy if exists file_rep_delete_own on public.file_reputation;
create policy file_rep_delete_own
on public.file_reputation for delete
using (user_id = auth.uid());

