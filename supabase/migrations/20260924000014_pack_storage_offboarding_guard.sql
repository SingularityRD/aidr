-- A tenant-specific pack must live below its tenant folder. Existing rows are
-- checked during offboarding by the trigger below; new writes cannot add an
-- untraceable tenant path.
alter table public.pack_versions add constraint pack_versions_tenant_storage_path
  check (tenant_id is null or storage_path like tenant_id::text || '/%') not valid;

create function app.guard_pack_storage_object_lifecycle()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_prefix text;
  v_old_path_removed boolean;
begin
  if tg_op in ('DELETE', 'UPDATE') then
    v_old_path_removed := tg_op = 'DELETE';
    if tg_op = 'UPDATE' then
      v_old_path_removed := new.bucket_id is distinct from old.bucket_id or new.name is distinct from old.name;
    end if;
    if old.bucket_id = 'aidr-packs' then
      v_prefix := split_part(old.name, '/', 1);
      if strpos(old.name, '/') > 0 and v_prefix ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
         and v_old_path_removed then
        v_tenant := v_prefix::uuid;
        perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
        if exists (select 1 from public.tenant_legal_holds where tenant_id = v_tenant and released_at is null) then
          raise exception 'tenant_pack_storage_legal_hold' using errcode = '55000';
        end if;
      end if;
    end if;
  end if;
  if tg_op = 'DELETE' then return old; end if;
  if new.bucket_id <> 'aidr-packs' then return new; end if;
  v_prefix := split_part(new.name, '/', 1);
  if strpos(new.name, '/') > 0 and v_prefix ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    v_tenant := v_prefix::uuid;
    perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
    if not exists (select 1 from public.tenants where id = v_tenant and status = 'active') then
      raise exception 'tenant_pack_storage_tenant_inactive' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function app.guard_pack_storage_object_lifecycle() from public, anon, authenticated;
create trigger aidr_pack_storage_lifecycle before insert or update or delete on storage.objects
  for each row execute function app.guard_pack_storage_object_lifecycle();

-- Deleting the database pointer before its private bytes would otherwise make
-- offboarding appear complete while leaving an unreachable object behind.
create function app.guard_tenant_pack_metadata_delete()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if tg_op = 'DELETE' then
    if old.tenant_id is not null and exists
       (select 1 from storage.objects where bucket_id = 'aidr-packs' and name = old.storage_path) then
      raise exception 'tenant_pack_storage_object_present' using errcode = '23514';
    end if;
    return old;
  end if;
  if old.tenant_id is not null and
     (new.tenant_id is distinct from old.tenant_id or new.storage_path is distinct from old.storage_path) and
     exists (select 1 from storage.objects where bucket_id = 'aidr-packs' and name = old.storage_path) then
    raise exception 'tenant_pack_storage_object_present' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.guard_tenant_pack_metadata_delete() from public, anon, authenticated;
create trigger tenant_pack_metadata_delete_guard before delete or update on public.pack_versions
  for each row execute function app.guard_tenant_pack_metadata_delete();

create function app.assert_no_pack_storage_at_tenant_close()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_tenant uuid;
begin
  if tg_table_name = 'tenants' then
    if new.status <> 'closed' then return new; end if;
    v_tenant := new.id;
  else
    if new.status <> 'completed' then return new; end if;
    v_tenant := new.tenant_id;
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  if exists (select 1 from storage.objects where bucket_id = 'aidr-packs' and name like v_tenant::text || '/%') then
    raise exception 'offboarding_pack_storage_residue' using errcode = '23514';
  end if;
  return new;
end;
$$;
revoke all on function app.assert_no_pack_storage_at_tenant_close() from public, anon, authenticated;
create trigger tenant_pack_storage_close_guard before update of status on public.tenants
  for each row execute function app.assert_no_pack_storage_at_tenant_close();
create trigger offboarding_pack_storage_close_guard before insert or update of status on public.tenant_offboarding_runs
  for each row execute function app.assert_no_pack_storage_at_tenant_close();
