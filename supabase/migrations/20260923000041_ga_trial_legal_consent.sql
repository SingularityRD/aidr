-- Trial activation stays disabled until an operator supplies approved,
-- immutable-by-digest Terms and Privacy documents. This migration provides no
-- document text, URL or implicit acceptance.
create table app.ga_legal_documents (
  singleton boolean primary key default true check (singleton),
  terms_version text not null
    check (terms_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'),
  terms_sha256 text not null check (terms_sha256 ~ '^[a-f0-9]{64}$'),
  terms_url text not null,
  privacy_version text not null
    check (privacy_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'),
  privacy_sha256 text not null check (privacy_sha256 ~ '^[a-f0-9]{64}$'),
  privacy_url text not null,
  approval_reference text not null
    check (length(trim(approval_reference)) between 1 and 200
      and approval_reference !~ '[[:cntrl:]]'),
  configured_at timestamptz not null default clock_timestamp(),
  check (length(terms_url) between 12 and 2048
    and terms_url ~ '^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?(/[^#[:space:]]*)?$'
    and position(chr(92) in terms_url) = 0),
  check (length(privacy_url) between 12 and 2048
    and privacy_url ~ '^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?(/[^#[:space:]]*)?$'
    and position(chr(92) in privacy_url) = 0)
);
alter table app.ga_legal_documents enable row level security;
revoke all on app.ga_legal_documents from public, anon, authenticated, service_role;

create function public.configure_ga_legal_documents(
  p_terms_version text,
  p_terms_sha256 text,
  p_terms_url text,
  p_privacy_version text,
  p_privacy_sha256 text,
  p_privacy_url text,
  p_approval_reference text
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_config app.ga_legal_documents%rowtype;
begin
  -- Table CHECK constraints are the authoritative bounds; an invalid update
  -- aborts before writing an audit receipt or enabling trials.
  insert into app.ga_legal_documents
    (singleton, terms_version, terms_sha256, terms_url,
     privacy_version, privacy_sha256, privacy_url, approval_reference)
  values (true, p_terms_version, p_terms_sha256, p_terms_url,
    p_privacy_version, p_privacy_sha256, p_privacy_url, p_approval_reference)
  on conflict (singleton) do update
    set terms_version = excluded.terms_version,
        terms_sha256 = excluded.terms_sha256,
        terms_url = excluded.terms_url,
        privacy_version = excluded.privacy_version,
        privacy_sha256 = excluded.privacy_sha256,
        privacy_url = excluded.privacy_url,
        approval_reference = excluded.approval_reference,
        configured_at = clock_timestamp()
  returning * into v_config;
  insert into public.admin_audit_logs(action, detail)
  values ('admission.ga_legal_configured', jsonb_build_object(
    'terms', jsonb_build_object('version', v_config.terms_version,
      'sha256', v_config.terms_sha256, 'url', v_config.terms_url),
    'privacy', jsonb_build_object('version', v_config.privacy_version,
      'sha256', v_config.privacy_sha256, 'url', v_config.privacy_url),
    'approval_reference', v_config.approval_reference));
  return jsonb_build_object('status', 'configured',
    'configured_at', v_config.configured_at);
end;
$$;
revoke all on function public.configure_ga_legal_documents(
  text, text, text, text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.configure_ga_legal_documents(
  text, text, text, text, text, text, text) to service_role;

create function public.get_ga_legal_documents()
returns jsonb
language plpgsql stable security definer
set search_path = pg_catalog, app, pg_temp
as $$
declare v_config app.ga_legal_documents%rowtype;
begin
  select * into v_config from app.ga_legal_documents where singleton;
  if not found then
    return jsonb_build_object('configured', false, 'terms', null,
      'privacy', null);
  end if;
  return jsonb_build_object('configured', true,
    'terms', jsonb_build_object('version', v_config.terms_version,
      'sha256', v_config.terms_sha256, 'url', v_config.terms_url),
    'privacy', jsonb_build_object('version', v_config.privacy_version,
      'sha256', v_config.privacy_sha256, 'url', v_config.privacy_url));
end;
$$;
revoke all on function public.get_ga_legal_documents()
  from public, anon, authenticated;
grant execute on function public.get_ga_legal_documents() to service_role;

-- Preserve the existing eligibility/one-trial transaction behind a private
-- core with no API role grant. The former public two-argument RPC disappears.
alter function public.start_verified_trial(uuid, uuid) set schema app;
alter function app.start_verified_trial(uuid, uuid) rename to start_verified_trial_core;
revoke all on function app.start_verified_trial_core(uuid, uuid)
  from public, anon, authenticated, service_role;

create function public.start_verified_trial(
  p_user_id uuid,
  p_tenant_id uuid,
  p_terms jsonb,
  p_privacy jsonb
)
returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_config app.ga_legal_documents%rowtype;
  v_result jsonb;
begin
  select * into v_config from app.ga_legal_documents where singleton for share;
  if not found then
    return jsonb_build_object('status', 'legal_not_configured');
  end if;
  if p_terms is distinct from jsonb_build_object(
       'version', v_config.terms_version, 'sha256', v_config.terms_sha256)
     or p_privacy is distinct from jsonb_build_object(
       'version', v_config.privacy_version, 'sha256', v_config.privacy_sha256) then
    return jsonb_build_object('status', 'legal_documents_changed');
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
revoke all on function public.start_verified_trial(uuid, uuid, jsonb, jsonb)
  from public, anon, authenticated;
grant execute on function public.start_verified_trial(uuid, uuid, jsonb, jsonb)
  to service_role;
