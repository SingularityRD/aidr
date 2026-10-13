-- Installer download portal (docs/installation/download-portal.md).
--
-- 1. The default installer bucket. Installer bytes, the signed catalog and the
--    signed latest.json pointer are written only by scripts/publish-installers.mjs
--    with the service role; dashboard users never read the bucket directly. The
--    installer-download Edge Function verifies the catalog and mints a
--    short-lived signed URL for one file. The bucket stays private: no storage
--    policy is created for anon or authenticated. A deployment that sets
--    AIDR_INSTALLERS_BUCKET to another name creates that bucket the same way.
--
-- 2. public.record_installer_download: the audit row written before a download
--    URL is returned. It re-checks, in the database, that the actor is an active
--    member of an active tenant, so a membership revoked between the Edge
--    Function's check and the write refuses the download (status 'forbidden').
--    The row goes to the existing append-only, tenant-scoped admin_audit_logs
--    trail (owners and admins read it through list_tenant_admin_audit_logs and the
--    audit export) as action 'installer.download' with tenant, actor, version,
--    platform, file name and SHA-256. No IP address or user agent is stored.
--
-- No new table, so no new RLS surface: the bucket has no client policies and the
-- RPC is service-role only.

insert into storage.buckets (id, name, public)
values ('aidr-installers', 'aidr-installers', false)
on conflict (id) do update set public = false;

create or replace function public.record_installer_download(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_version text,
  p_platform text,
  p_file_name text,
  p_sha256 text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  if p_actor_user_id is null or p_tenant_id is null
     or p_version is null or p_version !~ '^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}(-[0-9A-Za-z.-]{1,64})?$'
     or p_platform is null
     or p_platform not in ('windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64')
     or p_file_name is null or p_file_name !~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$'
     or p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_installer_download' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
     where m.tenant_id = p_tenant_id and m.user_id = p_actor_user_id
       and m.role in ('owner', 'admin', 'member', 'viewer')
       and (m.expires_at is null or m.expires_at > clock_timestamp())
       and t.status = 'active'
  ) then
    return jsonb_build_object('status', 'forbidden');
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
    values (p_actor_user_id, p_tenant_id, 'installer.download', p_actor_user_id,
      jsonb_build_object('version', p_version, 'platform', p_platform,
        'file', p_file_name, 'sha256', p_sha256));
  return jsonb_build_object('status', 'recorded');
end;
$$;

revoke all on function public.record_installer_download(uuid, uuid, text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.record_installer_download(uuid, uuid, text, text, text, text)
  to service_role;
