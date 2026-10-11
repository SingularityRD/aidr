-- Run against an isolated fully migrated database. Every fixture is rolled back.
-- public.oidc_save_provider (20261010000120): owner re-check, provider upsert
-- and admin audit commit together or not at all.
begin;
do $checks$
declare
  v_owner uuid := gen_random_uuid();
  v_admin uuid := gen_random_uuid();
  v_other_owner uuid := gen_random_uuid();
  v_backup_owner uuid := gen_random_uuid();
  v_tenant uuid := gen_random_uuid();
  v_other_tenant uuid := gen_random_uuid();
  v_provider uuid := gen_random_uuid();
  v_doc jsonb;
  v_result jsonb;
begin
  if has_function_privilege('anon', 'public.oidc_save_provider(uuid,jsonb,text,jsonb)', 'execute')
     or has_function_privilege('authenticated', 'public.oidc_save_provider(uuid,jsonb,text,jsonb)', 'execute')
     or not has_function_privilege('service_role', 'public.oidc_save_provider(uuid,jsonb,text,jsonb)', 'execute') then
    raise exception 'FAIL: oidc_save_provider must be executable by service_role only';
  end if;

  insert into auth.users(id, email)
  values (v_owner, 'oidc-save-owner-' || v_owner || '@test.invalid'),
         (v_admin, 'oidc-save-admin-' || v_admin || '@test.invalid'),
         (v_other_owner, 'oidc-save-other-' || v_other_owner || '@test.invalid'),
         (v_backup_owner, 'oidc-save-backup-' || v_backup_owner || '@test.invalid');
  insert into public.tenants(id, name, kind, created_by)
  values (v_tenant, 'OIDC save test', 'enterprise', v_owner),
         (v_other_tenant, 'OIDC save other', 'enterprise', v_other_owner);
  insert into public.tenant_members(tenant_id, user_id, role)
  values (v_tenant, v_owner, 'owner'), (v_tenant, v_admin, 'admin'), (v_tenant, v_backup_owner, 'owner'),
         (v_other_tenant, v_other_owner, 'owner');

  v_doc := jsonb_build_object(
    'id', v_provider, 'tenant_id', v_tenant, 'kind', 'generic', 'display_name', 'Fixture IdP',
    'issuer', 'https://idp.example.invalid', 'client_id', 'fixture-client',
    'client_secret_ref', null, 'token_auth_method', 'none', 'allowed_algs', jsonb_build_array('RS256'),
    'subject_claim', 'sub', 'groups_claim', null, 'groups_mode', 'ignore',
    'session_max_seconds', 43200, 'clock_skew_seconds', 60,
    'discovery', jsonb_build_object('issuer', 'https://idp.example.invalid'), 'enabled', true);

  -- 1. A non-owner writes nothing.
  begin
    perform public.oidc_save_provider(v_admin, v_doc, 'identity.oidc.provider_updated', '{}');
    raise exception 'FAIL: admin saved an OIDC provider';
  exception when insufficient_privilege then
    if sqlerrm <> 'oidc_provider_forbidden' then raise; end if;
  end;

  -- 2. An audit failure rolls the provider write back.
  create function pg_temp.fail_admin_audit() returns trigger language plpgsql as $f$
  begin raise exception 'audit_unavailable'; end $f$;
  create trigger zz_fail_admin_audit before insert on public.admin_audit_logs
    for each row execute function pg_temp.fail_admin_audit();
  begin
    perform public.oidc_save_provider(v_owner, v_doc, 'identity.oidc.provider_updated', '{}');
    raise exception 'FAIL: save succeeded without its audit row';
  exception when raise_exception then
    if sqlerrm <> 'audit_unavailable' then raise; end if;
  end;
  drop trigger zz_fail_admin_audit on public.admin_audit_logs;
  if exists (select 1 from public.oidc_providers where tenant_id = v_tenant) then
    raise exception 'FAIL: provider row survived a failed audit insert';
  end if;

  -- 3. The owner's save commits row and audit together.
  v_result := public.oidc_save_provider(v_owner, v_doc, 'identity.oidc.provider_updated',
    jsonb_build_object('request_id', 'req-1'));
  if v_result ->> 'provider_id' <> v_provider::text
     or not exists (select 1 from public.oidc_providers where id = v_provider and enabled and created_by = v_owner)
     or not exists (select 1 from public.admin_audit_logs
                     where tenant_id = v_tenant and actor_user_id = v_owner
                       and action = 'identity.oidc.provider_updated'
                       and detail ->> 'provider_id' = v_provider::text
                       and detail ->> 'request_id' = 'req-1') then
    raise exception 'FAIL: owner save did not commit provider and audit: %', v_result;
  end if;

  -- 4. Another tenant's owner cannot take over this provider id.
  begin
    perform public.oidc_save_provider(v_other_owner, v_doc || jsonb_build_object('tenant_id', v_other_tenant),
      'identity.oidc.provider_updated', '{}');
    raise exception 'FAIL: provider moved to another tenant';
  exception when insufficient_privilege then null;
  end;

  -- 5. The existing configuration guard still applies to the update path.
  insert into public.oidc_identities(provider_id, subject, auth_user_id, tenant_id)
  values (v_provider, 'owner-subject', v_owner, v_tenant);
  begin
    perform public.oidc_save_provider(v_owner, v_doc || '{"issuer":"https://replacement.example.invalid"}',
      'identity.oidc.provider_updated', '{}');
    raise exception 'FAIL: linked identity namespace changed through the RPC';
  exception when object_not_in_prerequisite_state then
    if sqlerrm <> 'oidc_provider_identity_namespace_locked' then raise; end if;
  end;

  -- 6. A demoted owner (committed before the write) is refused; nothing changes.
  update public.tenant_members set role = 'admin' where tenant_id = v_tenant and user_id = v_owner;
  begin
    perform public.oidc_save_provider(v_owner, v_doc || '{"display_name":"Changed"}',
      'identity.oidc.discovery_refreshed', '{}');
    raise exception 'FAIL: demoted owner saved the provider';
  exception when insufficient_privilege then null;
  end;
  if (select display_name from public.oidc_providers where id = v_provider) <> 'Fixture IdP'
     or exists (select 1 from public.admin_audit_logs
                 where tenant_id = v_tenant and action = 'identity.oidc.discovery_refreshed') then
    raise exception 'FAIL: refused save changed state';
  end if;

  -- 7. Unknown audit actions are refused.
  begin
    perform public.oidc_save_provider(v_other_owner, v_doc, 'identity.oidc.anything', '{}');
    raise exception 'FAIL: arbitrary audit action accepted';
  exception when invalid_parameter_value then null;
  end;
  raise notice 'oidc-provider-save: ok';
end;
$checks$;
rollback;
