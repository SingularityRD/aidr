-- Reputation rows are trusted by the service-role URL/file check endpoints.
-- Browser-authenticated tenants must not be able to mint or edit that trust.

-- Existing rows have no cryptographic/source provenance. Keep them readable for
-- investigation, but never let check endpoints treat them as trusted results.
alter table public.url_reputation
  add column if not exists provenance_verified boolean not null default false;
alter table public.file_reputation
  add column if not exists provenance_verified boolean not null default false;
comment on column public.url_reputation.provenance_verified is
  'Only trusted server-side ingestion may mark a reputation result verified; historical rows default false.';
comment on column public.file_reputation.provenance_verified is
  'Only trusted server-side ingestion may mark a reputation result verified; historical rows default false.';

drop policy if exists url_rep_insert_own on public.url_reputation;
drop policy if exists url_rep_update_own on public.url_reputation;
drop policy if exists url_rep_delete_own on public.url_reputation;
drop policy if exists file_rep_insert_own on public.file_reputation;
drop policy if exists file_rep_update_own on public.file_reputation;
drop policy if exists file_rep_delete_own on public.file_reputation;
drop policy if exists tenant_url_reputation_insert on public.url_reputation;
drop policy if exists tenant_url_reputation_update on public.url_reputation;
drop policy if exists tenant_url_reputation_delete on public.url_reputation;
drop policy if exists tenant_file_reputation_insert on public.file_reputation;
drop policy if exists tenant_file_reputation_update on public.file_reputation;
drop policy if exists tenant_file_reputation_delete on public.file_reputation;

revoke insert, update, delete on public.url_reputation, public.file_reputation
  from public, anon, authenticated;
revoke all on sequence public.url_reputation_id_seq, public.file_reputation_id_seq
  from public, anon, authenticated;

-- Preserve the trusted ingestion path; service_role remains server-side only.
grant insert, update, delete on public.url_reputation, public.file_reputation to service_role;
grant usage, select on sequence public.url_reputation_id_seq, public.file_reputation_id_seq
  to service_role;
