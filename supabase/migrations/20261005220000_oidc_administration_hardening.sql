-- Keep the newer public endpoints compatible with the reviewed rate-limit RPC.
-- The counter still accepts only service-role calls, bounded deltas and known scopes.
do $migration$
declare
  v_definition text;
  v_old text := '''apikey_create'', ''enrolltoken_create'', ''team-invite''';
begin
  select pg_get_functiondef('public.increment_rate_limit(text,bigint,integer)'::regprocedure) into v_definition;
  if position('''oidc-start''' in v_definition) > 0 then return; end if;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_rate_limit_scope_definition';
  end if;
  execute replace(v_definition, v_old, v_old || ',
    ''device_poll'', ''scim'', ''oidc-start'', ''oidc-callback'', ''oidc-break-glass''');
end
$migration$;

-- Provider-qualified subjects cannot be reassigned to a different issuer/client
-- after users have linked them. Otherwise the replacement IdP could mint the
-- same subject and receive the old user's complete Auth session.
create or replace function app.guard_oidc_provider_configuration()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if row(new.issuer, new.client_id, new.client_secret_ref, new.token_auth_method,
         new.allowed_algs, new.subject_claim, new.groups_claim, new.groups_mode,
         new.session_max_seconds, new.clock_skew_seconds, new.enabled)
     is not distinct from
     row(old.issuer, old.client_id, old.client_secret_ref, old.token_auth_method,
         old.allowed_algs, old.subject_claim, old.groups_claim, old.groups_mode,
         old.session_max_seconds, old.clock_skew_seconds, old.enabled) then
    return new; -- Login timestamps and refreshed discovery do not change identity configuration.
  end if;
  perform pg_advisory_xact_lock(hashtextextended(old.tenant_id::text, 2607));
  if exists (select 1 from public.tenant_identity_policies
             where tenant_id = old.tenant_id and required_oidc_provider_id = old.id) then
    raise exception 'oidc_provider_locked_by_enforcement' using errcode = '55000';
  end if;
  if row(new.issuer, new.client_id, new.subject_claim)
     is distinct from row(old.issuer, old.client_id, old.subject_claim)
     and exists (select 1 from public.oidc_identities where provider_id = old.id) then
    raise exception 'oidc_provider_identity_namespace_locked' using errcode = '55000';
  end if;
  return new;
end;
$$;
revoke all on function app.guard_oidc_provider_configuration() from public, anon, authenticated;
create trigger oidc_provider_configuration_guard
before update on public.oidc_providers
for each row execute function app.guard_oidc_provider_configuration();

-- Serialize domain removal with enforcement and with other domain removals.
-- An inactive tenant's lifecycle cleanup may delete its final verified domain.
create or replace function app.guard_oidc_verified_domain_removal()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if old.verified_at is null then return old; end if;
  perform pg_advisory_xact_lock(hashtextextended(old.tenant_id::text, 2607));
  if exists (
    select 1 from public.tenant_identity_policies p join public.tenants t on t.id = p.tenant_id
    where p.tenant_id = old.tenant_id and p.required_oidc_provider_id is not null and t.status = 'active'
  ) and not exists (
    select 1 from public.oidc_tenant_domains
    where tenant_id = old.tenant_id and domain <> old.domain and verified_at is not null
  ) then
    raise exception 'oidc_last_verified_domain_locked_by_enforcement' using errcode = '55000';
  end if;
  return old;
end;
$$;
revoke all on function app.guard_oidc_verified_domain_removal() from public, anon, authenticated;
create trigger oidc_verified_domain_removal_guard
before delete on public.oidc_tenant_domains
for each row execute function app.guard_oidc_verified_domain_removal();

-- Activation must use an enabled provider owned by this tenant and a verified
-- domain. Checking inside the transaction closes the Edge read/write race.
create or replace function app.guard_oidc_enforcement_configuration()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if new.required_oidc_provider_id is null then return new; end if;
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2607));
  if not exists (select 1 from public.oidc_providers
                 where id = new.required_oidc_provider_id and tenant_id = new.tenant_id and enabled) then
    raise exception 'oidc_provider_unavailable' using errcode = '22023';
  end if;
  if not exists (select 1 from public.oidc_tenant_domains
                 where tenant_id = new.tenant_id and verified_at is not null) then
    raise exception 'oidc_verified_domain_required' using errcode = '55000';
  end if;
  return new;
end;
$$;
revoke all on function app.guard_oidc_enforcement_configuration() from public, anon, authenticated;
create trigger oidc_enforcement_configuration_guard
before insert or update on public.tenant_identity_policies
for each row execute function app.guard_oidc_enforcement_configuration();

-- Take lifecycle before identity locks, the same order as OIDC state issuance.
do $migration$
declare
  v_definition text;
  v_old text := 'perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2607));';
  v_owner_check text := 'and (m.expires_at is null or m.expires_at > now()) and t.status = ''active''';
  v_owner_count text := '  select count(*), count(i.auth_user_id) into v_owner_count, v_verified_owner_count';
begin
  select pg_get_functiondef('public.oidc_set_enforcement(uuid,uuid,uuid,uuid,text,text)'::regprocedure) into v_definition;
  if position('hashtextextended(p_tenant_id::text, 2606)' in v_definition) > 0 then return; end if;
  if cardinality(string_to_array(v_definition, v_old)) <> 2 then
    raise exception 'unexpected_oidc_enforcement_lock_definition';
  end if;
  if cardinality(string_to_array(v_definition, v_owner_check)) <> 2
     or cardinality(string_to_array(v_definition, v_owner_count)) <> 2 then
    raise exception 'unexpected_oidc_enforcement_owner_definition';
  end if;
  v_definition := replace(v_definition, v_old,
    'perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));' || E'\n  ' || v_old);
  v_definition := replace(v_definition, v_owner_check, v_owner_check || E'\n       for share of m, t');
  execute replace(v_definition, v_owner_count,
    '  perform 1 from public.tenant_members m where m.tenant_id = p_tenant_id and m.role = ''owner''
    and (m.expires_at is null or m.expires_at > clock_timestamp()) for share;
' || v_owner_count);
end
$migration$;

-- Recovery-code rotation locks the tenant before the code row. Suspend follows
-- that order and rechecks the owner's current authority after every lock wait.
create or replace function public.oidc_break_glass_suspend(p_email text, p_code_hash text, p_request_id text)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, auth, extensions, pg_temp
as $$
declare
  v_tenant_id uuid;
  v_code public.identity_recovery_codes%rowtype;
  v_provider uuid;
begin
  if p_email is null or length(p_email) > 254 or p_code_hash is null
     or p_code_hash !~ '^[0-9a-f]{64}$' or p_request_id is null
     or p_request_id !~ '^[A-Za-z0-9._:-]{1,128}$' then return null; end if;
  select c.tenant_id into v_tenant_id
    from public.identity_recovery_codes c join auth.users u on u.id = c.user_id
   where c.code_hash = p_code_hash and lower(u.email) = lower(btrim(p_email));
  if not found then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2606));
  perform pg_advisory_xact_lock(hashtextextended(v_tenant_id::text, 2607));
  perform pg_advisory_xact_lock(hashtextextended(p_code_hash, 2607));
  select c.* into v_code
    from public.identity_recovery_codes c
    join auth.users u on u.id = c.user_id
    join public.tenants t on t.id = c.tenant_id and t.status = 'active'
    join public.tenant_members m
      on m.tenant_id = c.tenant_id and m.user_id = c.user_id and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > clock_timestamp())
    join public.tenant_identity_policies p
      on p.tenant_id = c.tenant_id and p.break_glass_enabled and p.required_oidc_provider_id is not null
   where c.tenant_id = v_tenant_id and c.code_hash = p_code_hash and c.used_at is null
     and c.expires_at > clock_timestamp() and lower(u.email) = lower(btrim(p_email))
   for update of c, t, m;
  if not found then return null; end if;
  select required_oidc_provider_id into v_provider
    from public.tenant_identity_policies where tenant_id = v_code.tenant_id for update;
  update public.identity_recovery_codes
     set used_at = clock_timestamp(), used_request_id = p_request_id,
         recovery_proof_challenge_hash = encode(digest('oidc_break_glass:' || v_code.id::text, 'sha256'), 'hex'),
         recovery_started_at = clock_timestamp(), recovery_request_id = p_request_id
   where id = v_code.id and used_at is null;
  if not found then return null; end if;
  update public.tenant_identity_policies
     set required_oidc_provider_id = null, updated_by = v_code.user_id where tenant_id = v_code.tenant_id;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
    values (null, v_code.tenant_id, v_code.user_id, 'identity.oidc.break_glass_enforcement_suspended',
      jsonb_build_object('recovery_code_id', v_code.id, 'request_id', p_request_id, 'suspended_provider_id', v_provider));
  return jsonb_build_object('tenant_id', v_code.tenant_id, 'user_id', v_code.user_id);
end;
$$;
revoke all on function public.oidc_break_glass_suspend(text, text, text) from public, anon, authenticated;
grant execute on function public.oidc_break_glass_suspend(text, text, text) to service_role;

-- Every retention mutation uses this one helper. Lock before checking ownership
-- and keep the tenant/member rows stable until the hold or policy write commits.
create or replace function app.retention_assert_tenant_owner(p_tenant_id uuid, p_actor_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public, pg_catalog, pg_temp
as $$
begin
  if p_tenant_id is null or p_actor_user_id is null then
    raise exception 'retention_admin_owner_required' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform 1 from public.tenants t join public.tenant_members tm on tm.tenant_id = t.id
   where t.id = p_tenant_id and t.status = 'active' and tm.user_id = p_actor_user_id
     and tm.role = 'owner' and (tm.expires_at is null or tm.expires_at > clock_timestamp())
   for share of t, tm;
  if not found then
    raise exception 'retention_admin_owner_required' using errcode = '42501';
  end if;
end;
$$;
revoke all on function app.retention_assert_tenant_owner(uuid, uuid) from public, anon, authenticated;
grant execute on function app.retention_assert_tenant_owner(uuid, uuid) to service_role;
