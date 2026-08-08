-- Commercial v1 additions: premium flags + revocations feed

-- Premium module toggles (default off)
alter table public.entitlements
	add column if not exists premium_intel boolean not null default false;
alter table public.entitlements
	add column if not exists premium_correlation boolean not null default false;
alter table public.entitlements
	add column if not exists premium_pkg_plugin boolean not null default false;

-- Revocation epoch to invalidate cached entitlements/packs quickly.
alter table public.entitlements
	add column if not exists revocation_epoch bigint not null default 1;

-- Global revocations list (service role only; no public RLS policy)
create table if not exists public.revocations (
	id bigint generated always as identity primary key,
	kind text not null,
	value text not null,
	created_at timestamptz not null default now()
);

create index if not exists revocations_kind_idx on public.revocations (kind);
create index if not exists revocations_kind_value_idx on public.revocations (kind, value);

alter table public.revocations enable row level security;
