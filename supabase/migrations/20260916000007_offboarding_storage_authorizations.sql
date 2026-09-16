-- Fence ALL legacy offboarding workers before applying this upgrade: a worker
-- holding an old paths-only response is not fenced by a SQL migration.
-- Durable authorization spans worker failure, NOT a transaction across HTTP.
-- Never expire/reassign an authorization after an ambiguous Storage response.
alter table public.audit_export_deletion_authorizations
  add column offboarding_run_id uuid references public.tenant_offboarding_runs(id) on delete restrict;
create index audit_export_deletion_authorizations_offboarding
  on public.audit_export_deletion_authorizations(offboarding_run_id) where offboarding_run_id is not null;

-- Do not grandfather a prior completion claim that still has export residue.
do $migration$
begin
  if exists(select 1 from public.audit_export_objects e where
    exists(select 1 from public.tenants t where t.id=e.tenant_id and t.status='closed') or
    exists(select 1 from public.tenant_offboarding_runs r where r.tenant_id=e.tenant_id and r.status='completed')) then
    raise exception 'completed_offboarding_has_storage_residue';
  end if;
end;
$migration$;

-- Preserve the complete fleet/cache/DLP/billing dispatcher. Fail on source drift.
do $migration$
declare v_definition text; v_old text; v_new text;
begin
  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure) into v_definition;
  v_old := 'if p_run_id is null or p_batch_size not between 1 and 1000 then';
  v_new := 'if current_setting(''transaction_isolation'') <> ''read committed'' then
    raise exception ''retention_requires_read_committed'' using errcode = ''25001'';
  end if;
  if p_run_id is null or p_batch_size is null or p_batch_size not between 1 and 1000 then';
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then raise exception 'unexpected_offboarding_validation_definition'; end if;
  v_definition := replace(v_definition,v_old,v_new);
  v_old := 'if v_run.status = ''completed'' then';
  v_new := 'if exists(select 1 from public.audit_export_deletion_authorizations where tenant_id=v_run.tenant_id) then
    return jsonb_build_object(''run_id'',p_run_id,''status'',''running'',''complete'',false,
      ''action'',''reconcile_storage_authorizations'',''phase'',''audit_export_objects'');
  end if;
  ' || v_old;
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then raise exception 'unexpected_offboarding_pending_definition'; end if;
  v_definition := replace(v_definition,v_old,v_new);
  v_old := 'return jsonb_build_object(''run_id'',p_run_id,''status'',''running'',''complete'',false,
      ''phase'',v_phase.phase,''action'',''delete_storage_objects'',''paths'',v_paths);';
  v_new := 'insert into public.audit_export_deletion_authorizations(path,tenant_id,offboarding_run_id)
      select value,v_run.tenant_id,p_run_id from jsonb_array_elements_text(v_paths);
    return jsonb_build_object(''run_id'',p_run_id,''status'',''running'',''complete'',false,
      ''phase'',v_phase.phase,''action'',''delete_storage_objects'',''paths'',v_paths,
      ''objects'',(select jsonb_agg(jsonb_build_object(''path'',path,''authorization_id'',authorization_id) order by path)
        from public.audit_export_deletion_authorizations where offboarding_run_id=p_run_id));';
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then raise exception 'unexpected_offboarding_storage_definition'; end if;
  execute replace(v_definition,v_old,v_new);

  -- Maintenance cannot consume offboarding authorizations and bypass its receipt.
  select pg_get_functiondef('public.ack_expired_audit_export(uuid)'::regprocedure) into v_definition;
  v_old := 'perform pg_advisory_xact_lock(hashtextextended(v_auth.tenant_id::text, 2606));';
  v_new := 'if v_auth.offboarding_run_id is not null then
    raise exception ''offboarding_authorization_requires_bound_ack'' using errcode = ''42501'';
  end if;
  ' || v_old;
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then raise exception 'unexpected_export_ack_definition'; end if;
  execute replace(v_definition,v_old,v_new);
end;
$migration$;

-- Fail closed for deployed old clients. Paths alone are not authority.
create or replace function public.ack_tenant_offboarding_objects(p_run_id uuid, p_paths text[])
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
begin
  raise exception 'offboarding_storage_authorization_required' using errcode = '42501';
end;
$$;
revoke all on function public.ack_tenant_offboarding_objects(uuid,text[]) from public, anon, authenticated, service_role;

-- The trusted worker calls this once, only after an exact Storage response AND
-- absence verification. These receipts are not independent provider erasure proof.
create function public.ack_tenant_offboarding_objects(
  p_run_id uuid, p_paths text[], p_authorization_ids uuid[]
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_run public.tenant_offboarding_runs;
  v_count integer;
  v_rows integer;
  v_remaining boolean;
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  v_count := cardinality(p_paths);
  if p_run_id is null or coalesce(v_count,0) not between 1 and 1000
    or cardinality(p_authorization_ids) is distinct from v_count
    or exists(select 1 from unnest(p_paths) p where p is null)
    or exists(select 1 from unnest(p_authorization_ids) a where a is null)
    or (select count(distinct p) from unnest(p_paths) p) <> v_count
    or (select count(distinct a) from unnest(p_authorization_ids) a) <> v_count
  then raise exception 'invalid_offboarding_object_ack' using errcode = '22023'; end if;
  select * into v_run from public.tenant_offboarding_runs where id=p_run_id;
  if not found then raise exception 'offboarding_run_not_found' using errcode = 'P0002'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_run.tenant_id::text,2606));
  if exists(select 1 from public.tenant_legal_holds where tenant_id=v_run.tenant_id and released_at is null) then
    raise exception 'active_legal_hold' using errcode = '55000';
  end if;
  if not exists(select 1 from public.tenant_offboarding_phase_receipts
    where run_id=p_run_id and phase='audit_export_objects' and status='running' and eligible_at<=now()) then
    raise exception 'offboarding_object_phase_not_active' using errcode = '42501';
  end if;
  -- Exact whole-batch pairing: no substituted path, partial ACK or token replay.
  if (select count(*) from public.audit_export_deletion_authorizations where offboarding_run_id=p_run_id) <> v_count
    or (select count(*) from unnest(p_paths,p_authorization_ids) p(path,token)
      join public.audit_export_deletion_authorizations a on a.path=p.path and a.authorization_id=p.token
      where a.tenant_id=v_run.tenant_id and a.offboarding_run_id=p_run_id) <> v_count then
    raise exception 'offboarding_object_authorization_mismatch' using errcode = '42501';
  end if;
  delete from public.audit_export_deletion_authorizations where offboarding_run_id=p_run_id;
  delete from public.audit_export_objects where tenant_id=v_run.tenant_id and path=any(p_paths);
  get diagnostics v_rows = row_count;
  if v_rows <> v_count then raise exception 'export_authorization_ledger_mismatch'; end if;
  select exists(select 1 from public.audit_export_objects where tenant_id=v_run.tenant_id) into v_remaining;
  update public.tenant_offboarding_phase_receipts
    set rows_deleted=rows_deleted+v_rows, status=case when v_remaining then 'running' else 'completed' end,
      completed_at=case when v_remaining then null else now() end
    where run_id=p_run_id and phase='audit_export_objects';
  return jsonb_build_object('run_id',p_run_id,'status','running','complete',false,
    'phase','audit_export_objects','phase_complete',not v_remaining,'rows_deleted',v_rows);
end;
$$;
revoke all on function public.ack_tenant_offboarding_objects(uuid,text[],uuid[]) from public, anon, authenticated;
grant execute on function public.ack_tenant_offboarding_objects(uuid,text[],uuid[]) to service_role;

-- Direct receipt edits or finalization cannot conceal live/pending exports.
create function app.assert_no_storage_offboarding_residue()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_tenant uuid; v_check_ledger boolean := true;
begin
  if new.status not in ('closed','completed') then return new; end if;
  if tg_table_name='tenants' then v_tenant := new.id;
  elsif tg_table_name='tenant_offboarding_runs' then v_tenant := new.tenant_id;
  else
    select tenant_id into v_tenant from public.tenant_offboarding_runs where id=new.run_id;
    v_check_ledger := new.phase='audit_export_objects';
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text,2606));
  if exists(select 1 from public.audit_export_deletion_authorizations where tenant_id=v_tenant) then
    raise exception 'offboarding_pending_storage_authorization' using errcode = '23514';
  end if;
  if v_check_ledger and exists(select 1 from public.audit_export_objects where tenant_id=v_tenant) then
    raise exception 'offboarding_storage_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_storage_offboarding_residue() from public, anon, authenticated;
create trigger tenants_storage_offboarding_residue before update of status on public.tenants
  for each row execute function app.assert_no_storage_offboarding_residue();
create trigger offboarding_runs_storage_residue before insert or update on public.tenant_offboarding_runs
  for each row execute function app.assert_no_storage_offboarding_residue();
create trigger offboarding_phases_storage_residue before insert or update on public.tenant_offboarding_phase_receipts
  for each row execute function app.assert_no_storage_offboarding_residue();

-- Export registration formerly checked active status BEFORE waiting on its
-- quota lock (2615). Recheck under the offboarding lock at the actual insert,
-- including direct service inserts, so a late reservation cannot undo closure.
create function app.protect_export_registration_during_offboarding()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text,2606));
  if not exists(select 1 from public.tenants where id=new.tenant_id and status='active')
    or exists(select 1 from public.tenant_offboarding_runs where tenant_id=new.tenant_id) then
    raise exception 'tenant_not_active_for_export' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.protect_export_registration_during_offboarding() from public, anon, authenticated;
create trigger audit_export_objects_offboarding_registration before insert on public.audit_export_objects
  for each row execute function app.protect_export_registration_during_offboarding();
