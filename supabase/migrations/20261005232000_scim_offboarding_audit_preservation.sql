-- Mapping cleanup can occur after the security-audit retention phase. Do not
-- recreate an already-erased audit row during that trusted cleanup. Keep every
-- normal mapping audit and the existing membership reconciliation unchanged.
do $migration$
declare
  v_definition text;
  v_start text := '  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)';
  v_end text := '        ''role'', case when tg_op = ''INSERT'' then new.role else old.role end));';
begin
  select pg_get_functiondef('app.scim_mapping_reconcile_members()'::regprocedure) into v_definition;
  if position('mapping_cleanup' in v_definition) > 0 then return; end if;
  if cardinality(string_to_array(v_definition, v_start)) <> 2
     or cardinality(string_to_array(v_definition, v_end)) <> 2 then
    raise exception 'unexpected_scim_mapping_audit_definition';
  end if;
  v_definition := replace(v_definition, v_start, '  if not (
    tg_op = ''DELETE''
    and (auth.role() is not distinct from ''service_role'' or session_user in (''postgres'', ''service_role'', ''supabase_admin''))
    and exists (
      select 1 from public.tenant_offboarding_runs r
      join public.tenants t on t.id = r.tenant_id and t.status = ''closing''
      join public.tenant_offboarding_phase_receipts mapping_cleanup
        on mapping_cleanup.run_id = r.id and mapping_cleanup.phase = ''scim_group_role_mappings''
       and mapping_cleanup.status = ''running''
      join public.tenant_offboarding_phase_receipts audit_purge
        on audit_purge.run_id = r.id and audit_purge.phase = ''admin_audit_logs''
       and audit_purge.status = ''completed''
      where r.tenant_id = v_tenant_id and r.status = ''running''
        and not exists(select 1 from public.tenant_legal_holds h
          where h.tenant_id = r.tenant_id and h.released_at is null)
    )
  ) then' || E'\n' || v_start);
  execute replace(v_definition, v_end, v_end || E'\n  end if;');
end;
$migration$;
