-- OIDC uses the same locked, provider-qualified SCIM binding boundary as SAML.
-- A policy read in the Edge function cannot authorize a later database write:
-- enforcement may have changed while the Auth account was being created.
create or replace function public.scim_bind_user(p_tenant_id uuid, p_scim_user_id uuid, p_auth_user_id uuid)
returns void language plpgsql security definer
set search_path = pg_catalog, public, auth, pg_temp as $$
declare v_provider_id uuid; v_oidc_provider_id uuid;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));
  perform 1 from public.tenants where id = p_tenant_id and status = 'active' for share;
  if not found then raise exception 'scim_tenant_inactive' using errcode = '42501'; end if;
  select required_saml_provider_id, required_oidc_provider_id
    into v_provider_id, v_oidc_provider_id from public.tenant_identity_policies
    where tenant_id = p_tenant_id;
  if v_provider_id is not null and not exists (
    select 1 from public.scim_users su join auth.identities i
      on i.user_id = p_auth_user_id
     and i.provider = 'sso:' || v_provider_id::text
     and i.provider_id = su.external_id
     and i.identity_data ->> 'sub' = i.provider_id
    where su.tenant_id = p_tenant_id and su.id = p_scim_user_id
      and su.active and position('@' in i.provider_id) = 0
  ) then raise exception 'scim_saml_identity_mismatch' using errcode = '42501'; end if;
  if v_oidc_provider_id is not null and not exists (
    select 1 from public.scim_users su join public.oidc_identities i
      on i.auth_user_id = p_auth_user_id and i.provider_id = v_oidc_provider_id
     and i.tenant_id = su.tenant_id and i.subject = su.external_id
    where su.tenant_id = p_tenant_id and su.id = p_scim_user_id
      and su.active and position('@' in i.subject) = 0
  ) then raise exception 'scim_oidc_identity_mismatch' using errcode = '42501'; end if;
  if (v_provider_id is not null or v_oidc_provider_id is not null) and exists (
    select 1 from public.tenant_members m
    where m.tenant_id = p_tenant_id and m.user_id = p_auth_user_id
      and not exists (
        select 1 from public.scim_managed_memberships smm
        where smm.tenant_id = p_tenant_id and smm.scim_user_id = p_scim_user_id
          and smm.auth_user_id = p_auth_user_id
      )
  ) then raise exception 'scim_cannot_take_over_manual_membership' using errcode = '42501'; end if;
  if exists (select 1 from public.tenant_members m where m.user_id = p_auth_user_id
    and m.tenant_id <> p_tenant_id) then
    raise exception 'scim_user_tenant_mismatch' using errcode = '42501';
  end if;
  if exists (select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
    where m.tenant_id = p_tenant_id and m.user_id = p_auth_user_id
      and (m.expires_at is null or m.expires_at > now()) and t.status = 'active') is false
     and exists (select 1 from public.tenant_members m where m.user_id = p_auth_user_id) then
    raise exception 'scim_user_tenant_mismatch' using errcode = '42501';
  end if;
  update public.scim_users set auth_user_id = p_auth_user_id, updated_at = now()
   where tenant_id = p_tenant_id and id = p_scim_user_id
     and (auth_user_id is null or auth_user_id = p_auth_user_id);
  if not found then raise exception 'scim_user_bind_conflict' using errcode = '23505'; end if;
  perform public.scim_reconcile_membership(p_tenant_id, p_scim_user_id);
  insert into public.admin_audit_logs(tenant_id, target_user_id, action, detail)
    values(p_tenant_id, p_auth_user_id, 'scim.user.bound', jsonb_build_object('scim_user_id', p_scim_user_id));
end;
$$;
revoke all on function public.scim_bind_user(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.scim_bind_user(uuid, uuid, uuid) to service_role;

-- Fence new OIDC state before the offboarding request. Existing rows may be
-- consumed only while their tenant is active; their tenant key cannot move.
-- INSERT takes 2606 before row locks. UPDATE already owns its OIDC row, so use
-- the tenant row lock rather than inverting the batch runner's 2606/row order.
create function app.protect_oidc_tenant_write()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  if tg_op = 'UPDATE' and new.tenant_id is distinct from old.tenant_id then
    raise exception 'oidc_tenant_immutable' using errcode = '42501';
  end if;
  if tg_op = 'INSERT' then
    perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2606));
  end if;
  perform 1 from public.tenants where id = new.tenant_id and status = 'active' for share;
  if not found or exists(select 1 from public.tenant_offboarding_runs where tenant_id = new.tenant_id) then
    raise exception 'oidc_tenant_inactive' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_oidc_tenant_write() from public, anon, authenticated, service_role;
do $$
declare v_table text;
begin
  foreach v_table in array array['oidc_providers', 'oidc_tenant_domains', 'oidc_auth_requests',
    'oidc_identities', 'oidc_login_tickets', 'oidc_sso_sessions'] loop
    execute format('create trigger oidc_tenant_write_guard before insert or update on public.%I '
      || 'for each row execute function app.protect_oidc_tenant_write()', v_table);
  end loop;
end;
$$;

-- Session binding consumes a ticket before inserting a session. Join the same
-- tenant lock before that first row update so offboarding cannot deadlock it.
do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.oidc_record_sso_session(text,uuid,uuid)'::regprocedure) into v_definition;
  v_old := '  update public.oidc_login_tickets';
  v_new := '  select tenant_id into v_expires_tenant from public.oidc_login_tickets where ticket_hash = p_ticket_hash;
  if v_expires_tenant is null then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_expires_tenant::text, 2606));
' || v_old;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_oidc_session_binding_definition';
  end if;
  v_definition := replace(v_definition, '  v_expires timestamptz;', '  v_expires timestamptz; v_expires_tenant uuid;');
  execute replace(v_definition, v_old, v_new);
end;
$migration$;

-- Routine expiry must obey the same hold/lifecycle serialization as erasure.
-- This existing service RPC keeps its signature and aggregate deletion count.
create or replace function public.oidc_prune_transient_rows() returns integer
language plpgsql security definer set search_path = pg_catalog, public, pg_temp as $$
declare v_tenant_id uuid; v_count integer := 0; v_step integer;
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  for v_tenant_id in
    select tenant_id from public.oidc_auth_requests where expires_at < now() - interval '1 hour'
    union select tenant_id from public.oidc_login_tickets where expires_at < now() - interval '1 hour'
    union select tenant_id from public.oidc_sso_sessions where expires_at < now() - interval '7 days'
    order by tenant_id
  loop
    if not pg_try_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606)) then continue; end if;
    if exists(select 1 from public.tenant_legal_holds where tenant_id = v_tenant_id and released_at is null)
      or exists(select 1 from public.tenant_offboarding_runs where tenant_id = v_tenant_id) then continue; end if;
    delete from public.oidc_auth_requests where tenant_id = v_tenant_id and expires_at < now() - interval '1 hour';
    get diagnostics v_step = row_count; v_count := v_count + v_step;
    delete from public.oidc_login_tickets where tenant_id = v_tenant_id and expires_at < now() - interval '1 hour';
    get diagnostics v_step = row_count; v_count := v_count + v_step;
    delete from public.oidc_sso_sessions where tenant_id = v_tenant_id and expires_at < now() - interval '7 days';
    get diagnostics v_step = row_count; v_count := v_count + v_step;
  end loop;
  return v_count;
end;
$$;
revoke all on function public.oidc_prune_transient_rows() from public, anon, authenticated;
grant execute on function public.oidc_prune_transient_rows() to service_role;

-- These six tables previously survived a completed live-data erasure. Keep
-- credentials at the immediate access-credential phase and durable identity /
-- configuration under their existing retention clocks. A provider cascades to
-- identities, so its phase waits for BOTH configuration and identity retention.
create function app.seed_oidc_offboarding_phases()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
begin
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  select new.id, c.phase_order, c.phase, c.data_class, 'delete_records',
    greatest(p.retention_days, coalesce(dependency.retention_days, 0)),
    new.requested_at + make_interval(days => greatest(p.retention_days, coalesce(dependency.retention_days, 0)))
  from (values
    (50, 'oidc_auth_requests', 'access_credentials'),
    (51, 'oidc_login_tickets', 'access_credentials'),
    (52, 'oidc_sso_sessions', 'access_credentials'),
    (53, 'oidc_identities', 'identity_membership'),
    (54, 'oidc_tenant_domains', 'policy_configuration'),
    (55, 'oidc_providers', 'policy_configuration')
  ) c(phase_order, phase, data_class)
  join public.tenant_data_retention_policies p on p.tenant_id = new.tenant_id and p.data_class = c.data_class
  left join public.tenant_data_retention_policies dependency
    on dependency.tenant_id = new.tenant_id and dependency.data_class = 'identity_membership'
      and c.phase = 'oidc_providers';
  if (select count(*) from public.tenant_offboarding_phase_receipts
      where run_id = new.id and phase like 'oidc_%') <> 6 then
    raise exception 'oidc_offboarding_retention_policy_missing' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.seed_oidc_offboarding_phases() from public, anon, authenticated, service_role;
create trigger tenant_offboarding_oidc_phases after insert on public.tenant_offboarding_runs
for each row execute function app.seed_oidc_offboarding_phases();

-- Never attest deletion for a historical completed run that still has OIDC data.
do $$
declare v_table text; v_residue boolean;
begin
  foreach v_table in array array['oidc_providers', 'oidc_tenant_domains', 'oidc_auth_requests',
    'oidc_identities', 'oidc_login_tickets', 'oidc_sso_sessions'] loop
    execute format('select exists(select 1 from public.tenant_offboarding_runs r join public.%I o '
      || 'on o.tenant_id = r.tenant_id where r.status = ''completed'')', v_table) into v_residue;
    if v_residue then raise exception 'completed_offboarding_has_oidc_residue'; end if;
  end loop;
end;
$$;
insert into public.tenant_offboarding_phase_receipts
  (run_id, phase_order, phase, data_class, operation, retention_days,
   eligible_at, status, attempts, completed_at)
select r.id, c.phase_order, c.phase, c.data_class, 'delete_records',
  greatest(p.retention_days, coalesce(dependency.retention_days, 0)),
  r.requested_at + make_interval(days => greatest(p.retention_days, coalesce(dependency.retention_days, 0))),
  case when r.status = 'completed' then 'completed' else 'pending' end,
  case when r.status = 'completed' then 1 else 0 end,
  case when r.status = 'completed' then now() else null end
from public.tenant_offboarding_runs r
cross join (values
  (50, 'oidc_auth_requests', 'access_credentials'),
  (51, 'oidc_login_tickets', 'access_credentials'),
  (52, 'oidc_sso_sessions', 'access_credentials'),
  (53, 'oidc_identities', 'identity_membership'),
  (54, 'oidc_tenant_domains', 'policy_configuration'),
  (55, 'oidc_providers', 'policy_configuration')
) c(phase_order, phase, data_class)
join public.tenant_data_retention_policies p on p.tenant_id = r.tenant_id and p.data_class = c.data_class
left join public.tenant_data_retention_policies dependency
  on dependency.tenant_id = r.tenant_id and dependency.data_class = 'identity_membership'
    and c.phase = 'oidc_providers';

do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure) into v_definition;
  v_old := 'when ''rate_limits'' then ''public.rate_limits''';
  v_new := 'when ''oidc_auth_requests'' then ''public.oidc_auth_requests''
    when ''oidc_login_tickets'' then ''public.oidc_login_tickets''
    when ''oidc_sso_sessions'' then ''public.oidc_sso_sessions''
    when ''oidc_identities'' then ''public.oidc_identities''
    when ''oidc_tenant_domains'' then ''public.oidc_tenant_domains''
    when ''oidc_providers'' then ''public.oidc_providers''
    ' || v_old;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_oidc_offboarding_dispatch_definition';
  end if;
  execute replace(v_definition, v_old, v_new);
end;
$migration$;

create function app.assert_oidc_offboarding_closure()
returns trigger language plpgsql security definer
set search_path = pg_catalog, public, pg_temp as $$
declare v_tenant_id uuid; v_run_id uuid; v_table text; v_residue boolean;
begin
  if new.status not in ('closed', 'completed') then return new; end if;
  if tg_table_name = 'tenants' then
    v_tenant_id := new.id;
    select id into v_run_id from public.tenant_offboarding_runs
      where tenant_id = v_tenant_id order by requested_at desc limit 1;
  else v_tenant_id := new.tenant_id; v_run_id := new.id;
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606));
  if v_run_id is null or (select count(*) from public.tenant_offboarding_phase_receipts
      where run_id = v_run_id and phase like 'oidc_%' and status = 'completed') <> 6 then
    raise exception 'oidc_offboarding_receipts_missing' using errcode = '23514';
  end if;
  foreach v_table in array array['oidc_providers', 'oidc_tenant_domains', 'oidc_auth_requests',
    'oidc_identities', 'oidc_login_tickets', 'oidc_sso_sessions'] loop
    execute format('select exists(select 1 from public.%I where tenant_id = $1)', v_table)
      into v_residue using v_tenant_id;
    if v_residue then raise exception 'oidc_offboarding_residue' using errcode = '23514'; end if;
  end loop;
  return new;
end;
$$;
revoke all on function app.assert_oidc_offboarding_closure() from public, anon, authenticated, service_role;
create trigger tenants_oidc_offboarding_closure before update of status on public.tenants
for each row execute function app.assert_oidc_offboarding_closure();
create trigger offboarding_runs_oidc_closure before update of status on public.tenant_offboarding_runs
for each row execute function app.assert_oidc_offboarding_closure();
