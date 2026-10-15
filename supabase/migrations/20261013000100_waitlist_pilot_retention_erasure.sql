-- Public waitlist and pilot free-text retention and erasure (CP-4).
--
-- public.waitlist_signups holds e-mail, name, company and a free-text message
-- from anonymous visitors. waitlist-signup inserts rows without a tenant, so
-- tenant offboarding never reached them and no routine deleted them.
--
-- 1. Retention: public waitlist rows (tenant_id IS NULL) are deleted 365 days
--    after created_at. waitlist-signup is insert-only (ignoreDuplicates), so
--    created_at is the original sign-up. The maintenance worker
--    (scripts/deployment-maintenance.mjs, the Helm maintenance CronJob and the
--    pg_cron schedule) calls purge_expired_waitlist_signups. Tenant-attributed
--    rows follow tenant offboarding (identity_membership) as before.
-- 2. Erasure / access by e-mail (DSAR): erase_waitlist_pilot_subject(email,
--    apply) returns what is held for that address (apply=false) or deletes the
--    waitlist row and clears the pilot application free-text notes of every
--    Auth user with that address (apply=true). Notes of a tenant under an
--    active legal hold are retained and counted. Pilot decision notes copied
--    into the append-only admin_audit_logs are not rewritten; they are counted
--    and expire with the tenant's security_audit retention / offboarding.
--    Every call writes a receipt keyed by the SHA-256 of the normalized
--    address, never the address itself.
--
-- Both functions are service_role only.

create table if not exists public.privacy_subject_requests (
  id uuid primary key default gen_random_uuid(),
  subject_email_sha256 text not null check (subject_email_sha256 ~ '^[0-9a-f]{64}$'),
  request_reference text not null check (length(trim(request_reference)) between 1 and 200),
  applied boolean not null,
  waitlist_rows integer not null check (waitlist_rows >= 0),
  pilot_notes integer not null check (pilot_notes >= 0),
  held_pilot_notes_retained integer not null check (held_pilot_notes_retained >= 0),
  audit_note_copies_retained integer not null check (audit_note_copies_retained >= 0),
  processed_at timestamptz not null default now()
);
alter table public.privacy_subject_requests enable row level security;
-- No policies: service_role / operators only.
revoke all on public.privacy_subject_requests from public, anon, authenticated;

create index if not exists waitlist_signups_public_created_idx
  on public.waitlist_signups (created_at, id) where tenant_id is null;

create or replace function public.purge_expired_waitlist_signups(p_limit integer, p_apply boolean)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_cutoff timestamptz := clock_timestamp() - interval '365 days';
  v_eligible integer;
  v_deleted integer := 0;
  v_remaining integer;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null then
    raise exception 'invalid_waitlist_purge' using errcode = '22023';
  end if;
  select count(*) into v_eligible from (
    select 1 from public.waitlist_signups
     where tenant_id is null and created_at <= v_cutoff
     limit p_limit
  ) due;
  if p_apply then
    with due as (
      select id from public.waitlist_signups
       where tenant_id is null and created_at <= v_cutoff
       order by created_at, id
       limit p_limit
       for update skip locked
    )
    delete from public.waitlist_signups w using due where w.id = due.id;
    get diagnostics v_deleted = row_count;
  end if;
  select count(*) into v_remaining from public.waitlist_signups
   where tenant_id is null and created_at <= v_cutoff;
  return jsonb_build_object('eligible', v_eligible, 'deleted', v_deleted, 'remaining', v_remaining,
    'applied', p_apply, 'retention_days', 365, 'cutoff', v_cutoff);
end;
$$;
revoke all on function public.purge_expired_waitlist_signups(integer, boolean)
  from public, anon, authenticated;
grant execute on function public.purge_expired_waitlist_signups(integer, boolean)
  to service_role;

create or replace function public.erase_waitlist_pilot_subject(
  p_email text,
  p_apply boolean,
  p_request_reference text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_email text := lower(btrim(coalesce(p_email, '')));
  v_users uuid[];
  v_waitlist jsonb;
  v_pilot jsonb;
  v_waitlist_rows integer := 0;
  v_pilot_notes integer := 0;
  v_held integer := 0;
  v_audit_copies integer := 0;
  v_tenant uuid;
begin
  if p_apply is null or length(v_email) not between 3 and 320 or position('@' in v_email) < 2
     or p_request_reference is null or length(btrim(p_request_reference)) not between 1 and 200 then
    raise exception 'invalid_subject_request' using errcode = '22023';
  end if;

  select coalesce(array_agg(u.id order by u.id), '{}') into v_users
    from auth.users u where lower(u.email) = v_email;

  -- Serialize with legal-hold placement for every tenant holding a note.
  for v_tenant in
    select distinct a.tenant_id from public.pilot_applications a
     where a.user_id = any(v_users) order by a.tenant_id
  loop
    perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  end loop;

  select coalesce(jsonb_agg(jsonb_build_object('email', w.email, 'name', w.name, 'company', w.company,
           'message', w.message, 'tenant_id', w.tenant_id, 'created_at', w.created_at) order by w.id), '[]'::jsonb),
         count(*)
    into v_waitlist, v_waitlist_rows
    from public.waitlist_signups w where w.email_lower = v_email;

  select coalesce(jsonb_agg(jsonb_build_object('user_id', a.user_id, 'tenant_id', a.tenant_id,
           'status', a.status, 'cohort', a.cohort, 'notes', a.notes, 'created_at', a.created_at,
           'updated_at', a.updated_at,
           'legal_hold', exists (select 1 from public.tenant_legal_holds h
                                  where h.tenant_id = a.tenant_id and h.released_at is null))
           order by a.tenant_id, a.user_id), '[]'::jsonb)
    into v_pilot
    from public.pilot_applications a where a.user_id = any(v_users);

  select count(*) filter (where not held), count(*) filter (where held)
    into v_pilot_notes, v_held
    from (
      select exists (select 1 from public.tenant_legal_holds h
                      where h.tenant_id = a.tenant_id and h.released_at is null) as held
        from public.pilot_applications a
       where a.user_id = any(v_users) and a.notes is not null
    ) notes;

  select count(*) into v_audit_copies
    from public.admin_audit_logs l
   where l.target_user_id = any(v_users) and l.action like 'pilot.%'
     and coalesce(l.detail->>'notes', '') <> '';

  if p_apply then
    delete from public.waitlist_signups w where w.email_lower = v_email;
    update public.pilot_applications a set notes = null
     where a.user_id = any(v_users) and a.notes is not null
       and not exists (select 1 from public.tenant_legal_holds h
                        where h.tenant_id = a.tenant_id and h.released_at is null);
  end if;

  insert into public.privacy_subject_requests(subject_email_sha256, request_reference, applied,
    waitlist_rows, pilot_notes, held_pilot_notes_retained, audit_note_copies_retained)
  values (encode(sha256(convert_to(v_email, 'UTF8')), 'hex'), btrim(p_request_reference), p_apply,
    v_waitlist_rows, v_pilot_notes, v_held, v_audit_copies);

  return jsonb_build_object(
    'applied', p_apply,
    'waitlist', case when p_apply then '[]'::jsonb else v_waitlist end,
    'pilot_applications', case when p_apply then '[]'::jsonb else v_pilot end,
    'waitlist_rows_deleted', case when p_apply then v_waitlist_rows else 0 end,
    'pilot_notes_cleared', case when p_apply then v_pilot_notes else 0 end,
    'held_pilot_notes_retained', v_held,
    'audit_note_copies_retained', v_audit_copies,
    'auth_users_matched', coalesce(array_length(v_users, 1), 0));
end;
$$;
revoke all on function public.erase_waitlist_pilot_subject(text, boolean, text)
  from public, anon, authenticated;
grant execute on function public.erase_waitlist_pilot_subject(text, boolean, text)
  to service_role;
