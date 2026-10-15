-- SEC-3: a bulk audit export (the tenant's whole audit_logs or admin_audit_logs
-- trail, page by page) left no durable record of who copied it out. The
-- publication RPC only stamped audit_export_objects.published_at, and those
-- ledger rows are deleted when the object expires (one day). Publication is
-- the linearization point at which a signed download URL is released, so the
-- admin audit row is written here, in the same transaction, and a failed
-- audit insert aborts the publication (the route then returns 503 and no URL
-- leaves it). Body otherwise unchanged from
-- 20260923000020_audit_export_publication.sql.

create or replace function public.finalize_audit_export_object(
  p_tenant_id uuid, p_actor_user_id uuid, p_path text
) returns text language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_bytes bigint;
  v_created_at timestamptz;
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  if p_tenant_id is null or p_actor_user_id is null or p_path is null
    or split_part(p_path, '/', 1) <> p_tenant_id::text then
    raise exception 'invalid_export_publication' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text,2606));
  if exists(select 1 from public.tenant_legal_holds
    where tenant_id = p_tenant_id and released_at is null) then
    return 'legal_hold_active';
  end if;
  if not exists(select 1 from public.tenants
    where id = p_tenant_id and status = 'active')
    or exists(select 1 from public.tenant_offboarding_runs
      where tenant_id = p_tenant_id) then
    return 'reservation_unavailable';
  end if;
  update public.audit_export_objects set published_at = clock_timestamp()
    where path = p_path and tenant_id = p_tenant_id and created_by = p_actor_user_id
      and published_at is null and expires_at > clock_timestamp()
      and not exists(select 1 from public.audit_export_deletion_authorizations
        where path = p_path)
    returning bytes, created_at into v_bytes, v_created_at;
  if not found then return 'reservation_unavailable'; end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (p_actor_user_id, p_tenant_id, 'audit.export.published', p_actor_user_id,
    jsonb_build_object('path', p_path,
      'format', substring(p_path from '\.(csv|json)$'),
      'bytes', v_bytes,
      'reserved_at', v_created_at));
  return 'published';
end;
$$;
revoke all on function public.finalize_audit_export_object(uuid,uuid,text)
  from public, anon, authenticated;
grant execute on function public.finalize_audit_export_object(uuid,uuid,text)
  to service_role;
