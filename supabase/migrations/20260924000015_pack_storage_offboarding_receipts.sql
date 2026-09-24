-- Fence older offboarding workers before rollout. A Storage DELETE can outlive
-- its HTTP response; pending authorizations never expire or move to a new worker.
create table public.tenant_pack_deletion_authorizations (
  storage_path text primary key,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  offboarding_run_id uuid not null references public.tenant_offboarding_runs(id) on delete restrict,
  authorization_id uuid not null unique default gen_random_uuid(),
  authorized_at timestamptz not null default now(),
  check (storage_path like tenant_id::text || '/%')
);
create index tenant_pack_deletion_authorizations_tenant
  on public.tenant_pack_deletion_authorizations(tenant_id);
alter table public.tenant_pack_deletion_authorizations enable row level security;
revoke all on public.tenant_pack_deletion_authorizations from public, anon, authenticated, service_role;
grant select on public.tenant_pack_deletion_authorizations to service_role;

-- An application-level observation, not a provider physical-erasure claim.
create table public.tenant_pack_deletion_receipts (
  offboarding_run_id uuid not null references public.tenant_offboarding_runs(id) on delete restrict,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  storage_path text not null,
  authorization_id uuid not null unique,
  observed_absent_at timestamptz not null default now(),
  primary key (offboarding_run_id, storage_path)
);
alter table public.tenant_pack_deletion_receipts enable row level security;
revoke all on public.tenant_pack_deletion_receipts from public, anon, authenticated, service_role;
grant select on public.tenant_pack_deletion_receipts to service_role;

do $migration$
declare v_definition text; v_old text; v_new text;
begin
  if exists(select 1 from public.tenant_offboarding_runs r
    join storage.objects o on o.bucket_id='aidr-packs' and o.name like r.tenant_id::text || '/%'
    where r.status='completed') then
    raise exception 'completed_offboarding_has_pack_storage_residue';
  end if;

  select pg_get_functiondef('public.run_tenant_offboarding_batch(uuid,integer)'::regprocedure)
    into v_definition;
  v_old := 'if exists(select 1 from public.audit_export_deletion_authorizations where tenant_id=v_run.tenant_id) then';
  v_new := 'if exists(select 1 from public.audit_export_deletion_authorizations where tenant_id=v_run.tenant_id)
    or exists(select 1 from public.tenant_pack_deletion_authorizations where tenant_id=v_run.tenant_id) then';
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then
    raise exception 'unexpected_pack_offboarding_pending_definition';
  end if;
  v_definition := replace(v_definition,v_old,v_new);
  v_old := '''action'',''reconcile_storage_authorizations'',''phase'',''audit_export_objects''';
  v_new := '''action'',''reconcile_storage_authorizations'',''phase'',
        case when exists(select 1 from public.tenant_pack_deletion_authorizations
          where tenant_id=v_run.tenant_id) then ''pack_versions'' else ''audit_export_objects'' end';
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then
    raise exception 'unexpected_pack_offboarding_reconciliation_definition';
  end if;
  v_definition := replace(v_definition,v_old,v_new);

  v_old := 'v_table := case v_phase.phase';
  v_new := $replacement$
  if v_phase.phase='pack_versions' then
    -- Legacy out-of-prefix references require explicit reconciliation. Never
    -- delete a global or another tenant's object based on a stale pointer.
    if exists(select 1 from public.pack_versions p where p.tenant_id=v_run.tenant_id
      and p.storage_path not like v_run.tenant_id::text || '/%') then
      raise exception 'tenant_pack_path_requires_reconciliation' using errcode='23514';
    end if;
    if exists(select 1 from storage.objects o join public.pack_versions p
        on p.storage_path=o.name and p.tenant_id is distinct from v_run.tenant_id
      where o.bucket_id='aidr-packs' and o.name like v_run.tenant_id::text || '/%') then
      raise exception 'shared_pack_path_requires_reconciliation' using errcode='23514';
    end if;
    if exists(select 1 from storage.objects o where o.bucket_id='aidr-packs'
      and o.name like v_run.tenant_id::text || '/%'
      and (o.name like '%//%' or o.name like '%/' or o.name ~ '(^|/)\.{1,2}(/|$)')) then
      raise exception 'tenant_pack_path_requires_reconciliation' using errcode='23514';
    end if;
    select coalesce(jsonb_agg(name order by name),'[]'::jsonb) into v_paths from (
      select name from storage.objects where bucket_id='aidr-packs'
        and name like v_run.tenant_id::text || '/%'
      order by name limit p_batch_size
    ) pending;
    if jsonb_array_length(v_paths)>0 then
      insert into public.tenant_pack_deletion_authorizations(storage_path,tenant_id,offboarding_run_id)
        select value,v_run.tenant_id,p_run_id from jsonb_array_elements_text(v_paths);
      return jsonb_build_object('run_id',p_run_id,'status','running','complete',false,
        'phase','pack_versions','action','delete_storage_objects','paths',v_paths,
        'objects',(select jsonb_agg(jsonb_build_object('path',storage_path,'authorization_id',authorization_id)
          order by storage_path) from public.tenant_pack_deletion_authorizations where offboarding_run_id=p_run_id));
    end if;
  end if;
  v_table := case v_phase.phase$replacement$;
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then
    raise exception 'unexpected_pack_offboarding_dispatch_definition';
  end if;
  execute replace(v_definition,v_old,v_new);

  select pg_get_functiondef('app.protect_tenant_legal_hold()'::regprocedure) into v_definition;
  v_old := 'if tg_op = ''INSERT'' and exists (
    select 1 from public.audit_export_deletion_authorizations
    where tenant_id = new.tenant_id
  ) then';
  v_new := 'if tg_op = ''INSERT'' and exists (
    select 1 from public.tenant_pack_deletion_authorizations where tenant_id = new.tenant_id
  ) then
    raise exception ''legal_hold_refused_pending_pack_deletion'' using errcode = ''55000'',
      hint = ''Fence the authorized worker and reconcile Storage before retrying hold placement; a refused hold is NOT active.'';
  end if;
  ' || v_old;
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then
    raise exception 'unexpected_pack_legal_hold_definition';
  end if;
  execute replace(v_definition,v_old,v_new);

  -- A stale REPEATABLE READ snapshot must not accept a late Storage upload
  -- after a waiting offboarding transaction closes the tenant.
  select pg_get_functiondef('app.guard_pack_storage_object_lifecycle()'::regprocedure)
    into v_definition;
  v_old := 'if tg_op in (''DELETE'', ''UPDATE'') then';
  v_new := 'if current_setting(''transaction_isolation'') <> ''read committed'' then
    raise exception ''retention_requires_read_committed'' using errcode=''25001'';
  end if;
  ' || v_old;
  if cardinality(string_to_array(v_definition,v_old)) <> 2 then
    raise exception 'unexpected_pack_storage_lifecycle_definition';
  end if;
  execute replace(v_definition,v_old,v_new);
end;
$migration$;

create function public.ack_tenant_offboarding_packs(
  p_run_id uuid, p_paths text[], p_authorization_ids uuid[]
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare v_run public.tenant_offboarding_runs; v_count integer;
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode='25001';
  end if;
  v_count := cardinality(p_paths);
  if p_run_id is null or coalesce(v_count,0) not between 1 and 1000
    or cardinality(p_authorization_ids) is distinct from v_count
    or exists(select 1 from unnest(p_paths) p where p is null)
    or exists(select 1 from unnest(p_authorization_ids) a where a is null)
    or (select count(distinct p) from unnest(p_paths) p) <> v_count
    or (select count(distinct a) from unnest(p_authorization_ids) a) <> v_count then
    raise exception 'invalid_pack_offboarding_ack' using errcode='22023';
  end if;
  select * into v_run from public.tenant_offboarding_runs where id=p_run_id;
  if not found then raise exception 'offboarding_run_not_found' using errcode='P0002'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_run.tenant_id::text,2606));
  if exists(select 1 from public.tenant_legal_holds
    where tenant_id=v_run.tenant_id and released_at is null) then
    raise exception 'active_legal_hold' using errcode='55000';
  end if;
  if v_run.status <> 'running' or not exists(select 1 from public.tenant_offboarding_phase_receipts
    where run_id=p_run_id and phase='pack_versions' and status='running' and eligible_at<=now()) then
    raise exception 'pack_offboarding_phase_not_active' using errcode='42501';
  end if;
  if exists(select 1 from unnest(p_paths) p where p not like v_run.tenant_id::text || '/%')
    or (select count(*) from public.tenant_pack_deletion_authorizations
      where offboarding_run_id=p_run_id) <> v_count
    or (select count(*) from unnest(p_paths,p_authorization_ids) p(path,token)
      join public.tenant_pack_deletion_authorizations a
        on a.storage_path=p.path and a.authorization_id=p.token
      where a.tenant_id=v_run.tenant_id and a.offboarding_run_id=p_run_id) <> v_count then
    raise exception 'pack_offboarding_authorization_mismatch' using errcode='42501';
  end if;
  if exists(select 1 from storage.objects where bucket_id='aidr-packs' and name=any(p_paths)) then
    raise exception 'pack_storage_object_still_present' using errcode='23514';
  end if;
  insert into public.tenant_pack_deletion_receipts
    (offboarding_run_id,tenant_id,storage_path,authorization_id)
    select p_run_id,v_run.tenant_id,p.path,p.token
      from unnest(p_paths,p_authorization_ids) p(path,token);
  delete from public.tenant_pack_deletion_authorizations where offboarding_run_id=p_run_id;
  return jsonb_build_object('run_id',p_run_id,'status','running','complete',false,
    'phase','pack_versions','phase_complete',false,'pack_objects_deleted',v_count);
end;
$$;
revoke all on function public.ack_tenant_offboarding_packs(uuid,text[],uuid[])
  from public, anon, authenticated;
grant execute on function public.ack_tenant_offboarding_packs(uuid,text[],uuid[]) to service_role;

create function app.assert_pack_offboarding_phase_clear()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_tenant uuid;
begin
  if new.phase <> 'pack_versions' or new.status <> 'completed' then return new; end if;
  select tenant_id into strict v_tenant from public.tenant_offboarding_runs where id=new.run_id;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text,2606));
  if exists(select 1 from public.tenant_pack_deletion_authorizations where tenant_id=v_tenant)
    or exists(select 1 from storage.objects
      where bucket_id='aidr-packs' and name like v_tenant::text || '/%')
    or exists(select 1 from public.pack_versions where tenant_id=v_tenant) then
    raise exception 'pack_offboarding_phase_residue' using errcode='23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_pack_offboarding_phase_clear() from public, anon, authenticated;
create trigger pack_offboarding_phase_clear before insert or update of status
  on public.tenant_offboarding_phase_receipts for each row
  execute function app.assert_pack_offboarding_phase_clear();

-- A late service-role metadata write cannot resurrect a pack after its phase
-- was receipted. This shares the hold/offboarding lock with Storage uploads.
create function app.guard_tenant_pack_metadata_registration()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if new.tenant_id is null then return new; end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode='25001';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text,2606));
  if not exists(select 1 from public.tenants where id=new.tenant_id and status='active')
    or exists(select 1 from public.tenant_offboarding_runs where tenant_id=new.tenant_id)
    or exists(select 1 from public.tenant_legal_holds
      where tenant_id=new.tenant_id and released_at is null) then
    raise exception 'tenant_pack_metadata_tenant_inactive' using errcode='42501';
  end if;
  return new;
end;
$$;
revoke all on function app.guard_tenant_pack_metadata_registration() from public, anon, authenticated;
create trigger tenant_pack_metadata_registration before insert or update on public.pack_versions
  for each row execute function app.guard_tenant_pack_metadata_registration();

create function app.protect_tenant_pack_metadata_legal_hold()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if old.tenant_id is null then
    if tg_op='DELETE' then return old; else return new; end if;
  end if;
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode='25001';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(old.tenant_id::text,2606));
  if exists(select 1 from public.tenant_legal_holds
    where tenant_id=old.tenant_id and released_at is null) then
    raise exception 'tenant_pack_metadata_legal_hold' using errcode='55000';
  end if;
  if tg_op='DELETE' then return old; else return new; end if;
end;
$$;
revoke all on function app.protect_tenant_pack_metadata_legal_hold() from public, anon, authenticated;
create trigger tenant_pack_metadata_legal_hold before update or delete on public.pack_versions
  for each row execute function app.protect_tenant_pack_metadata_legal_hold();
