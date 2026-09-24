-- An export is published only after Storage upload/sign succeeds and a fresh
-- legal-hold check wins the same tenant lock used by hold placement. Failures
-- after a confirmed upload become eligible for the authorized Storage reaper;
-- ambiguous upload failures keep normal expiry. Quota is reserved until ACK.
alter table public.audit_export_objects
  add column published_at timestamptz;

-- The existing registration trigger is the authoritative insert barrier. The
-- route's earlier hold read is only a cheap preflight, not a concurrency fence.
create or replace function app.protect_export_registration_during_offboarding()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text,2606));
  if exists(select 1 from public.tenant_legal_holds
    where tenant_id = new.tenant_id and released_at is null) then
    raise exception 'active_legal_hold' using errcode = '55000';
  end if;
  if not exists(select 1 from public.tenants where id=new.tenant_id and status='active')
    or exists(select 1 from public.tenant_offboarding_runs where tenant_id=new.tenant_id) then
    raise exception 'tenant_not_active_for_export' using errcode = '42501';
  end if;
  return new;
end;
$$;

create function public.finalize_audit_export_object(
  p_tenant_id uuid, p_actor_user_id uuid, p_path text
) returns text language plpgsql security definer set search_path = public, pg_temp as $$
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
        where path = p_path);
  if not found then return 'reservation_unavailable'; end if;
  return 'published';
end;
$$;
revoke all on function public.finalize_audit_export_object(uuid,uuid,text)
  from public, anon, authenticated;
grant execute on function public.finalize_audit_export_object(uuid,uuid,text)
  to service_role;

-- No direct ledger deletion: the HTTP upload may have succeeded despite a
-- timeout. The reaper deletes/inspects the exact Storage path before its ACK.
create function public.abandon_audit_export_object(
  p_tenant_id uuid, p_actor_user_id uuid, p_path text
) returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception 'retention_requires_read_committed' using errcode = '25001';
  end if;
  if p_tenant_id is null or p_actor_user_id is null or p_path is null
    or split_part(p_path, '/', 1) <> p_tenant_id::text then
    raise exception 'invalid_export_abandonment' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text,2606));
  update public.audit_export_objects set expires_at = least(expires_at, clock_timestamp())
    where path = p_path and tenant_id = p_tenant_id and created_by = p_actor_user_id
      and published_at is null;
  return found;
end;
$$;
revoke all on function public.abandon_audit_export_object(uuid,uuid,text)
  from public, anon, authenticated;
grant execute on function public.abandon_audit_export_object(uuid,uuid,text)
  to service_role;
