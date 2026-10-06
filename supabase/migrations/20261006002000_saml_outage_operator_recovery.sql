-- Offline, dual-custody recovery for a complete SAML-provider outage. Each
-- operator has a separate 32-byte HMAC key enrolled by controlled database
-- administration, never by a browser/service request. Database administrators
-- remain a trusted shared-secret custody boundary; these are MAC approvals,
-- not asymmetric signatures. The normal two-owner/session API is unchanged.
-- Service HTTP clients read policies and call the audited definer RPCs. Direct
-- table DML would bypass both normal dual approval and operator MAC approval.
revoke insert, update, delete on public.tenant_identity_policies from service_role;
create table app.tenant_saml_recovery_operator_keys (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  key_id uuid not null,
  operator_id uuid not null,
  secret bytea not null check (octet_length(secret) = 32),
  enabled boolean not null default true,
  not_before timestamptz not null,
  not_after timestamptz not null,
  primary key (tenant_id, key_id),
  unique (tenant_id, secret),
  check (isfinite(not_before) and isfinite(not_after) and not_after > not_before)
);
create unique index tenant_saml_recovery_active_operator on app.tenant_saml_recovery_operator_keys(tenant_id,operator_id) where enabled;
alter table app.tenant_saml_recovery_operator_keys enable row level security;
revoke all on app.tenant_saml_recovery_operator_keys from public, anon, authenticated, service_role;

create function app.saml_recovery_key_guard()
returns trigger language plpgsql security definer set search_path = pg_catalog, public, app, pg_temp as $$
declare v_run text := current_setting('app.aidr_offboarding_run_id',true);
begin
  if tg_op = 'DELETE' then
    if (auth.role() is not distinct from 'service_role' or session_user in ('postgres','supabase_admin','service_role'))
       and v_run ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
       and exists(select 1 from public.tenant_offboarding_runs r
         join public.tenants t on t.id = r.tenant_id
         join public.tenant_offboarding_phase_receipts p on p.run_id = r.id
         where r.id = v_run::uuid and r.tenant_id = old.tenant_id and r.status = 'running'
           and t.status = 'closing' and p.phase = 'saml_recovery_operator_keys' and p.status = 'running'
           and p.data_class = 'access_credentials' and p.operation = 'delete_records' and p.eligible_at <= clock_timestamp()
           and not exists(select 1 from public.tenant_legal_holds h where h.tenant_id = old.tenant_id and h.released_at is null)) then
      return old;
    end if;
    raise exception 'saml_recovery_key_immutable' using errcode = '42501';
  end if;
  if tg_op = 'UPDATE' then
    -- A row already held by an UPDATE must not wait for the tenant advisory
    -- lock after recovery/offboarding has taken that lock before this row.
    if (to_jsonb(new) - 'enabled') is distinct from (to_jsonb(old) - 'enabled')
       or not old.enabled or new.enabled then
      raise exception 'saml_recovery_key_immutable' using errcode = '42501';
    end if;
    return new;
  end if;
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2606));
  perform 1 from public.tenants t where t.id = new.tenant_id and t.status = 'active' for share;
  if not found or exists(select 1 from public.tenant_offboarding_runs r where r.tenant_id = new.tenant_id) then
    raise exception 'saml_recovery_tenant_inactive' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.saml_recovery_key_guard() from public, anon, authenticated, service_role;
create trigger saml_recovery_key_guard before insert or update or delete on app.tenant_saml_recovery_operator_keys
for each row execute function app.saml_recovery_key_guard();
create trigger saml_recovery_key_no_truncate before truncate on app.tenant_saml_recovery_operator_keys
for each statement execute function app.reject_audit_truncate();

create table public.tenant_saml_outage_recoveries (
  nonce uuid primary key,
  tenant_id uuid not null references public.tenants(id),
  audit_log_id bigint not null unique references public.admin_audit_logs(id) on delete cascade,
  payload_sha256 text not null check (payload_sha256 ~ '^[a-f0-9]{64}$'),
  applied_at timestamptz not null
);
alter table public.tenant_saml_outage_recoveries enable row level security;
revoke all on public.tenant_saml_outage_recoveries from public, anon, authenticated, service_role;
create trigger saml_outage_recovery_no_update before update on public.tenant_saml_outage_recoveries
for each row execute function app.reject_admin_audit_mutation();
create trigger saml_outage_recovery_delete_guard before delete on public.tenant_saml_outage_recoveries
for each row execute function app.saml_policy_request_delete_guard();
create trigger saml_outage_recovery_no_truncate before truncate on public.tenant_saml_outage_recoveries
for each statement execute function app.reject_audit_truncate();

create function public.recover_tenant_saml_outage(p_payload text, p_approvals jsonb)
returns jsonb language plpgsql security definer set search_path = pg_catalog, public, auth, app, extensions, pg_temp as $$
declare
  v_body jsonb;
  v_approval jsonb;
  v_tenant uuid;
  v_provider uuid;
  v_owner uuid;
  v_nonce uuid;
  v_key uuid;
  v_key_row app.tenant_saml_recovery_operator_keys;
  v_operators uuid[] := '{}';
  v_keys uuid[] := '{}';
  v_issued timestamptz;
  v_expires timestamptz;
  v_now timestamptz;
  v_mac bytea;
  v_expected bytea;
  v_policy public.tenant_identity_policies;
  v_audit bigint;
  v_sha text;
begin
  if p_payload is null or octet_length(p_payload) > 4096
     or jsonb_typeof(p_approvals) is distinct from 'array' then
    raise exception 'saml_recovery_invalid_request' using errcode = '22023';
  end if;
  if jsonb_array_length(p_approvals) <> 2 then
    raise exception 'saml_recovery_two_approvals_required' using errcode = '42501';
  end if;
  begin
    v_body := p_payload::jsonb;
    if jsonb_typeof(v_body) is distinct from 'object'
       or (select count(*) from jsonb_object_keys(v_body)) <> 11
       or not (v_body ?& array['purpose','schema_version','nonce','tenant_id','current_provider_id',
         'recovery_owner_id','new_provider_id','change_ref','reason','issued_at','expires_at'])
       or v_body->>'purpose' is distinct from 'aidr.saml.outage-recovery.v1'
       or jsonb_typeof(v_body->'schema_version') is distinct from 'number'
       or v_body->>'schema_version' is distinct from '1'
       or v_body->'new_provider_id' is distinct from 'null'::jsonb
       or jsonb_typeof(v_body->'issued_at') is distinct from 'number'
       or jsonb_typeof(v_body->'expires_at') is distinct from 'number'
       or (v_body->>'issued_at') !~ '^[0-9]{1,12}$'
       or (v_body->>'expires_at') !~ '^[0-9]{1,12}$'
       or jsonb_typeof(v_body->'reason') is distinct from 'string'
       or jsonb_typeof(v_body->'change_ref') is distinct from 'string'
       or (v_body->>'reason') <> btrim(v_body->>'reason')
       or (v_body->>'change_ref') <> btrim(v_body->>'change_ref')
       or char_length(v_body->>'reason') not between 12 and 500
       or char_length(v_body->>'change_ref') not between 1 and 200
       or (v_body->>'reason') ~ '[[:cntrl:]]' or (v_body->>'change_ref') ~ '[[:cntrl:]]' then
      raise exception 'invalid_payload';
    end if;
    v_tenant := (v_body->>'tenant_id')::uuid;
    v_provider := (v_body->>'current_provider_id')::uuid;
    v_owner := (v_body->>'recovery_owner_id')::uuid;
    v_nonce := (v_body->>'nonce')::uuid;
    if v_tenant is null or v_provider is null or v_owner is null or v_nonce is null
       or v_tenant::text <> v_body->>'tenant_id' or v_provider::text <> v_body->>'current_provider_id'
       or v_owner::text <> v_body->>'recovery_owner_id' or v_nonce::text <> v_body->>'nonce' then
      raise exception 'invalid_payload';
    end if;
    v_issued := to_timestamp((v_body->>'issued_at')::bigint);
    v_expires := to_timestamp((v_body->>'expires_at')::bigint);
    if v_expires <= v_issued or v_expires > v_issued + interval '5 minutes' then raise exception 'invalid_payload'; end if;
  exception when others then
    raise exception 'saml_recovery_invalid_request' using errcode = '22023';
  end;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2607));
  perform app.saml_policy_require_owner(v_tenant,v_owner);
  if exists(select 1 from public.tenant_offboarding_runs r where r.tenant_id = v_tenant)
     or exists(select 1 from public.scim_managed_memberships s where s.tenant_id = v_tenant and s.auth_user_id = v_owner)
     or not exists(select 1 from auth.users u where u.id = v_owner and nullif(btrim(u.email),'') is not null
       and (to_jsonb(u)->>'deleted_at') is null
       and coalesce((to_jsonb(u)->>'banned_until')::timestamptz,to_timestamp(0)) <= clock_timestamp()) then
    raise exception 'saml_recovery_owner_unavailable' using errcode = '42501';
  end if;
  select * into v_policy from public.tenant_identity_policies where tenant_id = v_tenant for update;
  if not found or v_policy.required_saml_provider_id is distinct from v_provider
     or v_policy.required_oidc_provider_id is not null then
    raise exception 'saml_recovery_policy_conflict' using errcode = '23505';
  end if;
  if exists(select 1 from public.tenant_saml_outage_recoveries r where r.nonce = v_nonce) then
    raise exception 'saml_recovery_nonce_consumed' using errcode = '23505';
  end if;
  -- Lock both enrolled identities before evaluation, in one stable order.
  perform 1 from app.tenant_saml_recovery_operator_keys k
    where k.tenant_id = v_tenant and k.key_id::text in (select a->>'key_id' from jsonb_array_elements(p_approvals) a)
    order by k.key_id for share;
  for v_approval in select value from jsonb_array_elements(p_approvals) loop
    if jsonb_typeof(v_approval) is distinct from 'object'
       or (select count(*) from jsonb_object_keys(v_approval)) <> 2
       or not (v_approval ?& array['key_id','mac_hex'])
       or jsonb_typeof(v_approval->'key_id') is distinct from 'string'
       or jsonb_typeof(v_approval->'mac_hex') is distinct from 'string'
       or (v_approval->>'key_id') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
       or (v_approval->>'mac_hex') !~ '^[a-f0-9]{64}$' then
      raise exception 'saml_recovery_approval_invalid' using errcode = '42501';
    end if;
    v_key := (v_approval->>'key_id')::uuid;
    select * into v_key_row from app.tenant_saml_recovery_operator_keys
      where tenant_id = v_tenant and key_id = v_key;
    if not found or not v_key_row.enabled or v_key_row.not_before > clock_timestamp()
       or v_key_row.not_after <= clock_timestamp() or v_key = any(v_keys)
       or v_key_row.operator_id = any(v_operators) then
      raise exception 'saml_recovery_approval_invalid' using errcode = '42501';
    end if;
    v_mac := decode(v_approval->>'mac_hex','hex');
    v_expected := extensions.hmac(convert_to(p_payload,'UTF8'),v_key_row.secret,'sha256');
    -- Hash before comparing so an equality timing oracle cannot reveal the
    -- expected MAC prefix. Only the full approved payload is accepted.
    if extensions.digest(v_mac,'sha256') is distinct from extensions.digest(v_expected,'sha256') then
      raise exception 'saml_recovery_approval_invalid' using errcode = '42501';
    end if;
    v_keys := array_append(v_keys,v_key);
    v_operators := array_append(v_operators,v_key_row.operator_id);
  end loop;
  v_now := clock_timestamp();
  if v_issued > v_now or v_expires <= v_now
     or exists(select 1 from app.tenant_saml_recovery_operator_keys k where k.tenant_id = v_tenant
       and k.key_id = any(v_keys) and (not k.enabled or k.not_before > v_now or k.not_after <= v_now)) then
    raise exception 'saml_recovery_approval_expired' using errcode = '42501';
  end if;
  perform app.saml_policy_require_owner(v_tenant,v_owner);
  v_sha := encode(extensions.digest(convert_to(p_payload,'UTF8'),'sha256'),'hex');
  insert into public.admin_audit_logs(actor_user_id,tenant_id,target_user_id,action,detail)
    values(null,v_tenant,v_owner,'identity.saml.outage_recovered',jsonb_build_object(
      'method','dual_operator_hmac','payload',v_body,'payload_sha256',v_sha,'operator_ids',v_operators,
      'key_ids',v_keys,'approvals',p_approvals,'old_provider_id',v_provider,'new_provider_id',null,
      'change_ref',v_body->>'change_ref','reason',v_body->>'reason')) returning id into v_audit;
  update public.tenant_identity_policies set required_saml_provider_id = null where tenant_id = v_tenant;
  v_now := clock_timestamp();
  if v_expires <= v_now or exists(select 1 from app.tenant_saml_recovery_operator_keys k
    where k.tenant_id = v_tenant and k.key_id = any(v_keys) and k.not_after <= v_now) then
    raise exception 'saml_recovery_approval_expired' using errcode = '42501';
  end if;
  insert into public.tenant_saml_outage_recoveries(nonce,tenant_id,audit_log_id,payload_sha256,applied_at)
    values(v_nonce,v_tenant,v_audit,v_sha,v_now);
  -- Audit/nonce insertion can wait too. Authority must still be current after
  -- the last write; any expired proof rolls the entire recovery back.
  perform app.saml_policy_require_owner(v_tenant,v_owner);
  if v_expires <= clock_timestamp() or exists(select 1 from app.tenant_saml_recovery_operator_keys k
    where k.tenant_id = v_tenant and k.key_id = any(v_keys) and k.not_after <= clock_timestamp()) then
    raise exception 'saml_recovery_approval_expired' using errcode = '42501';
  end if;
  return jsonb_build_object('status','recovered','method','dual_operator_hmac','nonce',v_nonce,
    'tenant_id',v_tenant,'recovery_owner_id',v_owner,'old_provider_id',v_provider,'new_provider_id',null,
    'change_ref',v_body->>'change_ref','operator_ids',v_operators,'audit_log_id',v_audit::text,'applied_at',v_now);
end;
$$;
revoke all on function public.recover_tenant_saml_outage(text,jsonb) from public, anon, authenticated;
grant execute on function public.recover_tenant_saml_outage(text,jsonb) to service_role;

-- Credentials revoke immediately, then erase through the same bounded,
-- retention/hold-aware worker as all other tenant credentials. The nonce
-- ledger belongs to the immutable admin audit's existing erasure lifecycle.
create function app.seed_saml_recovery_offboarding_phase()
returns trigger language plpgsql security definer set search_path = pg_catalog, public, app, pg_temp as $$
begin
  update app.tenant_saml_recovery_operator_keys set enabled = false where tenant_id = new.tenant_id and enabled;
  insert into public.tenant_offboarding_phase_receipts
    (run_id,phase_order,phase,data_class,operation,retention_days,eligible_at)
  select new.id,56,'saml_recovery_operator_keys','access_credentials','delete_records',p.retention_days,
    new.requested_at + make_interval(days => p.retention_days)
  from public.tenant_data_retention_policies p where p.tenant_id = new.tenant_id and p.data_class = 'access_credentials';
  if not found then raise exception 'saml_recovery_retention_policy_missing' using errcode = '23514'; end if;
  return new;
end;
$$;
revoke all on function app.seed_saml_recovery_offboarding_phase() from public, anon, authenticated, service_role;
create trigger tenant_offboarding_saml_recovery_phase after insert on public.tenant_offboarding_runs
for each row execute function app.seed_saml_recovery_offboarding_phase();
insert into public.tenant_offboarding_phase_receipts
  (run_id,phase_order,phase,data_class,operation,retention_days,eligible_at,status,attempts,completed_at)
select r.id,56,'saml_recovery_operator_keys','access_credentials','delete_records',p.retention_days,
  r.requested_at + make_interval(days => p.retention_days),
  case when r.status = 'completed' then 'completed' else 'pending' end,
  case when r.status = 'completed' then 1 else 0 end,
  case when r.status = 'completed' then now() else null end
from public.tenant_offboarding_runs r join public.tenant_data_retention_policies p
  on p.tenant_id = r.tenant_id and p.data_class = 'access_credentials';
do $migration$
declare
  v_definition text;
  v_old text := 'when ''rate_limits'' then ''public.rate_limits''';
  v_guard text := 'if v_phase.phase=''audit_logs'' then perform set_config(''app.aidr_offboarding_run_id'',p_run_id::text,true); end if;';
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure) into v_definition;
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then raise exception 'unexpected_saml_recovery_offboarding_definition'; end if;
  v_definition := replace(v_definition,v_old,'when ''saml_recovery_operator_keys'' then ''app.tenant_saml_recovery_operator_keys'' ' || v_old);
  if cardinality(string_to_array(v_definition,v_guard)) <> 2 then raise exception 'unexpected_saml_recovery_offboarding_guard'; end if;
  execute replace(v_definition,v_guard,'if v_phase.phase in (''audit_logs'',''saml_recovery_operator_keys'') then perform set_config(''app.aidr_offboarding_run_id'',p_run_id::text,true); end if;');
end;
$migration$;
create function app.assert_saml_recovery_offboarding_closure()
returns trigger language plpgsql security definer set search_path = pg_catalog, public, app, pg_temp as $$
declare v_tenant uuid; v_run uuid;
begin
  if new.status not in ('closed','completed') then return new; end if;
  if tg_table_name = 'tenants' then
    v_tenant := new.id;
    select id into v_run from public.tenant_offboarding_runs where tenant_id = v_tenant order by requested_at desc limit 1;
  else v_tenant := new.tenant_id; v_run := new.id; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text,2606));
  if v_run is null or not exists(select 1 from public.tenant_offboarding_phase_receipts
    where run_id = v_run and phase = 'saml_recovery_operator_keys' and status = 'completed')
    or exists(select 1 from app.tenant_saml_recovery_operator_keys where tenant_id = v_tenant) then
    raise exception 'saml_recovery_offboarding_incomplete' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_saml_recovery_offboarding_closure() from public, anon, authenticated, service_role;
create trigger tenants_saml_recovery_closure before update of status on public.tenants
for each row execute function app.assert_saml_recovery_offboarding_closure();
create trigger offboarding_runs_saml_recovery_closure before update of status on public.tenant_offboarding_runs
for each row execute function app.assert_saml_recovery_offboarding_closure();
