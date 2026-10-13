-- Installer download portal: several installer formats per platform
-- (docs/installation/download-portal.md, "Storage contract").
--
-- A platform can now be published in more than one format (Windows .msi; Linux
-- .deb, .rpm and .tar.gz), so the audit row of a download also records which
-- format was handed out. 20261013000600_installer_download_portal.sql is applied
-- and stays as it is; this migration replaces its six-argument
-- record_installer_download with one that takes an optional p_format.
--
-- The old call shape keeps working: p_format defaults to null, so a caller that
-- passes only the six original named arguments (an Edge Function deployed before
-- this change) resolves to this function and records the row without a format.
-- The old overload is dropped rather than kept beside the new one, because two
-- overloads that both accept the six named arguments would make the call
-- ambiguous. Everything else is unchanged: service-role only, the membership and
-- tenant re-check in the database, the append-only tenant-scoped audit trail
-- (action 'installer.download'), no IP address or user agent.

drop function if exists public.record_installer_download(uuid, uuid, text, text, text, text);

create or replace function public.record_installer_download(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_version text,
  p_platform text,
  p_file_name text,
  p_sha256 text,
  p_format text default null
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
     or p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$'
     or (p_format is not null and p_format !~ '^[a-z0-9.]{1,16}$') then
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
      jsonb_strip_nulls(jsonb_build_object('version', p_version, 'platform', p_platform,
        'format', p_format, 'file', p_file_name, 'sha256', p_sha256)));
  return jsonb_build_object('status', 'recorded');
end;
$$;

revoke all on function public.record_installer_download(uuid, uuid, text, text, text, text, text)
  from public, anon, authenticated;
grant execute on function public.record_installer_download(uuid, uuid, text, text, text, text, text)
  to service_role;
