-- An Auth Admin soft delete clears app metadata. Preserve its ability to erase
-- the account while denying a second 14-day trial for the same verified email.
-- This is short-lived pseudonymous anti-stacking, not a lifetime person ID.
create table app.ga_trial_subject_key (
  singleton boolean primary key default true check (singleton),
  secret bytea not null check (octet_length(secret) = 32)
);
insert into app.ga_trial_subject_key(singleton, secret)
values (true, extensions.gen_random_bytes(32));
revoke all on app.ga_trial_subject_key from public, anon, authenticated, service_role;

create table app.ga_trial_subjects (
  digest bytea primary key check (octet_length(digest) = 32),
  expires_at timestamptz not null check (isfinite(expires_at))
);
create index ga_trial_subjects_expiry on app.ga_trial_subjects(expires_at);
revoke all on app.ga_trial_subjects from public, anon, authenticated, service_role;

create function app.ga_trial_subject_digest(p_email text)
returns bytea language plpgsql stable security definer
set search_path = pg_catalog, app, extensions, pg_temp as $$
declare v_secret bytea;
begin
  select secret into v_secret from app.ga_trial_subject_key where singleton;
  if v_secret is null or octet_length(v_secret) <> 32
     or p_email is null or length(btrim(p_email)) = 0 then
    raise exception 'trial_subject_key_unavailable' using errcode = '55000';
  end if;
  return extensions.hmac(convert_to(lower(btrim(p_email)), 'UTF8'), v_secret, 'sha256');
end;
$$;
revoke all on function app.ga_trial_subject_digest(text)
  from public, anon, authenticated, service_role;

create function app.ga_trial_subject_available(p_email text)
returns boolean language sql stable security definer
set search_path = pg_catalog, app, pg_temp as $$
  select not exists(select 1 from app.ga_trial_subjects
    where digest = app.ga_trial_subject_digest(p_email)
      and expires_at > clock_timestamp())
$$;
revoke all on function app.ga_trial_subject_available(text)
  from public, anon, authenticated, service_role;

-- Active trials pre-dating this migration must be attributable before the
-- digest can be backfilled. An erased owner cannot be silently declared safe.
do $$
begin
  if exists (
    select 1 from public.tenant_admissions a
      left join auth.users u on u.id = a.owner_user_id
    where a.kind = 'trial' and a.expires_at > clock_timestamp()
      and (u.id is null or (to_jsonb(u)->>'deleted_at') is not null
        or nullif(btrim(u.email), '') is null)
  ) then
    raise exception 'active_trial_subject_backfill_unavailable' using errcode = '55000';
  end if;
end;
$$;
insert into app.ga_trial_subjects(digest, expires_at)
select app.ga_trial_subject_digest(u.email), max(a.expires_at)
from public.tenant_admissions a join auth.users u on u.id = a.owner_user_id
where a.kind = 'trial' and a.expires_at > clock_timestamp()
group by app.ga_trial_subject_digest(u.email);

create function app.record_ga_trial_subject()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, app, auth, pg_temp as $$
declare v_email text;
begin
  if new.kind <> 'trial' then return new; end if;
  select u.email into v_email from auth.users u
    where u.id = new.owner_user_id and (to_jsonb(u)->>'deleted_at') is null
      and u.email_confirmed_at is not null;
  if nullif(btrim(v_email), '') is null then
    raise exception 'trial_subject_unavailable' using errcode = '55000';
  end if;
  insert into app.ga_trial_subjects(digest, expires_at)
  values (app.ga_trial_subject_digest(v_email), new.expires_at)
  on conflict (digest) do update set expires_at = excluded.expires_at
    where app.ga_trial_subjects.expires_at <= clock_timestamp();
  if not found then
    raise exception 'trial_subject_already_claimed' using errcode = '23505';
  end if;
  return new;
end;
$$;
revoke all on function app.record_ga_trial_subject()
  from public, anon, authenticated, service_role;
create trigger record_ga_trial_subject
before insert on public.tenant_admissions
for each row execute function app.record_ga_trial_subject();

-- An account may change its email before deletion. Bind that newly supplied
-- address only through the original deadline; never extend the first claim.
create function app.record_ga_trial_email_change()
returns trigger language plpgsql security definer
set search_path = pg_catalog, app, pg_temp as $$
declare v_expiry timestamptz;
begin
  if (to_jsonb(new)->>'deleted_at') is not null
     or old.email is not distinct from new.email
     or nullif(btrim(new.email), '') is null
     or not (coalesce(old.raw_app_meta_data, '{}'::jsonb) ? 'aidr_trial') then
    return new;
  end if;
  v_expiry := (old.raw_app_meta_data #>> '{aidr_trial,expires_at}')::timestamptz;
  if v_expiry > clock_timestamp() then
    insert into app.ga_trial_subjects(digest, expires_at)
      values (app.ga_trial_subject_digest(new.email), v_expiry)
    on conflict (digest) do update
      set expires_at = greatest(app.ga_trial_subjects.expires_at, excluded.expires_at);
  end if;
  return new;
end;
$$;
revoke all on function app.record_ga_trial_email_change()
  from public, anon, authenticated, service_role;
create trigger record_ga_trial_email_change
after update of email on auth.users
for each row execute function app.record_ga_trial_email_change();

-- The original account-level claim is still immutable for active accounts.
-- GoTrue first marks deleted_at, then clears metadata in a later UPDATE.
-- Permit claim removal only while the resulting Auth row remains tombstoned.
create or replace function app.protect_auth_trial_claim()
returns trigger language plpgsql security definer
set search_path = pg_catalog, auth, pg_temp as $$
begin
  if coalesce(old.raw_app_meta_data, '{}'::jsonb) ? 'aidr_trial'
     and (coalesce(new.raw_app_meta_data, '{}'::jsonb) -> 'aidr_trial')
         is distinct from (old.raw_app_meta_data -> 'aidr_trial')
     and (to_jsonb(new)->>'deleted_at') is null then
    raise exception 'trial_claim_immutable' using errcode = '42501';
  end if;
  return new;
end;
$$;

-- Keep the legal-consent wrapper and its audit transaction, adding only an
-- eligibility check before the core mutates the account or admission.
create or replace function public.start_verified_trial(
  p_user_id uuid, p_tenant_id uuid, p_terms jsonb, p_privacy jsonb
)
returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, app, auth, pg_temp as $$
declare v_config app.ga_legal_documents%rowtype; v_result jsonb; v_email text;
begin
  select * into v_config from app.ga_legal_documents where singleton for share;
  if not found then return jsonb_build_object('status', 'legal_not_configured'); end if;
  if p_terms is distinct from jsonb_build_object(
       'version', v_config.terms_version, 'sha256', v_config.terms_sha256)
     or p_privacy is distinct from jsonb_build_object(
       'version', v_config.privacy_version, 'sha256', v_config.privacy_sha256) then
    return jsonb_build_object('status', 'legal_documents_changed');
  end if;
  select email into v_email from auth.users where id = p_user_id;
  if v_email is not null and not app.ga_trial_subject_available(v_email)
     and not exists (select 1 from public.tenant_admissions
       where tenant_id = p_tenant_id and owner_user_id = p_user_id and kind = 'trial') then
    return jsonb_build_object('status', 'ineligible');
  end if;
  v_result := app.start_verified_trial_core(p_user_id, p_tenant_id);
  if v_result ->> 'status' = 'started' then
    insert into public.admin_audit_logs(
      actor_user_id, tenant_id, target_user_id, action, detail)
    values (p_user_id, p_tenant_id, p_user_id,
      'admission.trial_legal_acceptance', jsonb_build_object(
        'terms', jsonb_build_object('version', v_config.terms_version,
          'sha256', v_config.terms_sha256, 'url', v_config.terms_url),
        'privacy', jsonb_build_object('version', v_config.privacy_version,
          'sha256', v_config.privacy_sha256, 'url', v_config.privacy_url),
        'approval_reference', v_config.approval_reference));
  end if;
  return v_result;
end;
$$;

-- Preserve the original admission report, but do not advertise a repeat trial
-- when a newly registered account has the same email as a live claim.
alter function public.get_tenant_admission(uuid, uuid) set schema app;
alter function app.get_tenant_admission(uuid, uuid) rename to get_tenant_admission_core;
revoke all on function app.get_tenant_admission_core(uuid, uuid)
  from public, anon, authenticated, service_role;
create function public.get_tenant_admission(p_tenant_id uuid, p_user_id uuid)
returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, app, auth, pg_temp as $$
declare v_result jsonb; v_email text;
begin
  v_result := app.get_tenant_admission_core(p_tenant_id, p_user_id);
  if v_result ->> 'trial_available' = 'true' then
    select email into v_email from auth.users where id = p_user_id;
    if v_email is null or not app.ga_trial_subject_available(v_email) then
      v_result := jsonb_set(v_result, '{trial_available}', 'false'::jsonb);
    end if;
  end if;
  return v_result;
end;
$$;
revoke all on function public.get_tenant_admission(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.get_tenant_admission(uuid, uuid) to service_role;

-- Hourly maintenance must call this with apply=true; a failed run leaves an
-- incomplete receipt rather than silently extending pseudonymous retention.
create function public.purge_expired_ga_trial_subjects(p_limit integer, p_apply boolean)
returns jsonb language plpgsql security definer
set search_path = pg_catalog, app, pg_temp as $$
declare v_eligible integer; v_deleted integer := 0; v_remaining integer;
begin
  if p_limit is null or p_limit not between 1 and 1000 or p_apply is null then
    raise exception 'invalid_trial_subject_purge' using errcode = '22023';
  end if;
  select count(*) into v_eligible from (
    select 1 from app.ga_trial_subjects
    where expires_at <= clock_timestamp() limit p_limit
  ) due;
  if p_apply then
    with due as (
      select digest from app.ga_trial_subjects
      where expires_at <= clock_timestamp()
      order by expires_at limit p_limit for update skip locked
    )
    delete from app.ga_trial_subjects s using due where s.digest = due.digest;
    get diagnostics v_deleted = row_count;
  end if;
  select count(*) into v_remaining from app.ga_trial_subjects
    where expires_at <= clock_timestamp();
  return jsonb_build_object('eligible', v_eligible, 'deleted', v_deleted,
    'remaining', v_remaining, 'applied', p_apply);
end;
$$;
revoke all on function public.purge_expired_ga_trial_subjects(integer, boolean)
  from public, anon, authenticated;
grant execute on function public.purge_expired_ga_trial_subjects(integer, boolean)
  to service_role;
