-- Device-code remote-phishing hardening (CP-1, RFC 8628 §5.4).
--
-- A device code could be started by anyone through the public ingress and the
-- verification link (…/verify?code=XXXX) handed to a victim, who bound it to
-- their workspace with one click and nothing on screen saying a remote device
-- was being enrolled. The session now records the requester context that
-- /verify shows before anything is bound, and the binding audit row carries it:
--
--   * requested_ip: the client IP attested by the trusted ingress (HMAC proof,
--     never a caller-supplied proxy header);
--   * requested_runtime / _runtime_version / _os / _hostname: what the device
--     reported about itself (displayed as unverified);
--   * requested_scope: the access the enrollment grants (`tenant` API key);
--   * created_at (existing): when the code was requested.
--
-- device-verify binds only a session the browser looked up first (it must
-- name the looked-up session id and carry an explicit confirmation), can
-- require AAL2 (AIDR_DEVICE_VERIFY_REQUIRE_AAL2), and the code lifetime is
-- bounded to 1..15 minutes in device-start. Codes stay single-use: binding
-- requires authorized_at is null and exchange requires exchanged_at is null.

alter table public.device_sessions
  add column if not exists requested_ip text,
  add column if not exists requested_runtime text,
  add column if not exists requested_runtime_version text,
  add column if not exists requested_os text,
  add column if not exists requested_hostname text,
  add column if not exists requested_scope text not null default 'tenant';

alter table public.device_sessions drop constraint if exists device_sessions_requester_context_check;
alter table public.device_sessions add constraint device_sessions_requester_context_check check (
  (requested_ip is null or (char_length(requested_ip) between 2 and 45 and requested_ip ~ '^[0-9A-Fa-f:.]+$'))
  and (requested_runtime is null or requested_runtime ~ '^[a-z0-9][a-z0-9_.-]{0,31}$')
  and (requested_runtime_version is null
       or (char_length(requested_runtime_version) between 1 and 64 and requested_runtime_version !~ '[[:cntrl:]]'))
  and (requested_os is null or (char_length(requested_os) between 1 and 32 and requested_os !~ '[[:cntrl:]]'))
  and (requested_hostname is null or requested_hostname ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
  and requested_scope in ('tenant')
);

comment on column public.device_sessions.requested_ip is
  'Trusted-ingress attested client IP that requested the device code; shown on /verify and copied into the device.verify audit row.';

-- Same contract as 20260924000003_device_authorization_membership_lock.sql;
-- the audit row now records who requested the code that was bound.
create or replace function public.authorize_device_session(
  p_user_code text,
  p_user_id uuid,
  p_tenant_id uuid,
  p_access_token_issued_at timestamptz
)
returns table (id uuid, user_id uuid, tenant_id uuid, expires_at timestamptz)
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_revoked_before timestamptz;
  v_tenant_id uuid;
  v_session public.device_sessions%rowtype;
begin
  if nullif(trim(p_user_code), '') is null
     or p_user_id is null
     or p_access_token_issued_at is null
     or p_access_token_issued_at > clock_timestamp() + interval '5 minutes' then
    return;
  end if;

  v_tenant_id := coalesce(p_tenant_id, p_user_id);
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611));
  select s.revoked_before into v_revoked_before
    from public.identity_user_session_state s
    where s.user_id = p_user_id;
  if v_revoked_before is not null
     and p_access_token_issued_at <= v_revoked_before then
    return;
  end if;

  -- FOR SHARE conflicts with membership removal, demotion and expiry updates.
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_tenant_id
     and m.user_id = p_user_id
     and m.role in ('owner', 'admin', 'member')
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m, t;
  if not found then return; end if;

  update public.device_sessions d
     set user_id = p_user_id,
         tenant_id = v_tenant_id,
         authorized_at = clock_timestamp(),
         status = 'authorized'
   where d.user_code = upper(trim(p_user_code))
     and (d.tenant_id is null or d.tenant_id = v_tenant_id)
     and d.authorized_at is null
     and d.expires_at > clock_timestamp()
  returning d.* into v_session;
  if not found then return; end if;

  id := v_session.id;
  user_id := v_session.user_id;
  tenant_id := v_session.tenant_id;
  expires_at := v_session.expires_at;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, target_user_id, detail)
  values (p_user_id, tenant_id, 'device.verify', p_user_id,
          jsonb_build_object(
            'device_session_id', id,
            'requested_at', v_session.created_at,
            'requester_ip', v_session.requested_ip,
            'requested_runtime', v_session.requested_runtime,
            'requested_runtime_version', v_session.requested_runtime_version,
            'requested_os', v_session.requested_os,
            'requested_hostname', v_session.requested_hostname,
            'requested_scope', v_session.requested_scope));
  return next;
end;
$$;

revoke all on function public.authorize_device_session(text, uuid, uuid, timestamptz)
  from public, anon, authenticated;
grant execute on function public.authorize_device_session(text, uuid, uuid, timestamptz)
  to service_role;
