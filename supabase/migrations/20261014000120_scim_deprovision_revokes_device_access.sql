-- D12: a SCIM deprovision (active true -> false) revokes the person's device
-- access in the tenant, whatever kind of membership they hold.
--
-- Before this migration a deactivation removed only a SCIM-managed membership
-- (scim_reconcile_membership). app.revoke_member_api_keys
-- (20260923000047) then revoked that user's API keys. A user whose membership
-- was created by hand (invited before SCIM was connected, outside
-- directory-authoritative mode) kept the membership and therefore every
-- enrolled device key: the leaving employee's agents kept reporting, filing
-- approval requests and fetching policy. Pending approval requests, unused
-- enrollment codes and open device-code sessions also survived the
-- deprovision.
--
-- Now, in the same transaction as the SCIM write that deactivates the user:
--   * every API key the user owns in the tenant is revoked (device keys and
--     dashboard-issued keys alike; the retired overlap hash is cleared, so a
--     renewed key cannot be replayed through its old secret);
--   * their pending approval requests are expired, so nobody approves an
--     action for a person who left (an approval already decided carries a
--     token that lives at most 15 minutes and can only be delivered with the
--     requester's key, which is now revoked);
--   * their unused enrollment codes and open device-code sessions expire now;
--   * one admin audit row records the counts (no secrets, no identifiers
--     beyond the SCIM user id).
--
-- The membership itself is not touched here: a hand-made membership stays a
-- hand-made decision (owners use it as break-glass). Directory-authoritative
-- mode (20261007000050) is how a tenant makes the directory the only source
-- of membership. Reactivating the SCIM user never revives a revoked key; the
-- person re-enrolls their device. docs/operations/offboarding.md is the
-- runbook, including what stays on the endpoint.

create or replace function app.scim_deprovision_device_access(
  p_tenant_id uuid,
  p_auth_user_id uuid,
  p_scim_user_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_keys integer := 0;
  v_approvals integer := 0;
  v_enrollment integer := 0;
  v_sessions integer := 0;
begin
  if p_tenant_id is null or p_auth_user_id is null or p_scim_user_id is null then
    raise exception 'invalid_scim_deprovision' using errcode = '22023';
  end if;

  update public.api_keys
     set revoked = true, previous_hash = null, previous_hash_expires_at = null
   where tenant_id = p_tenant_id and user_id = p_auth_user_id and not revoked;
  get diagnostics v_keys = row_count;

  update public.approval_requests
     set status = 'expired'
   where tenant_id = p_tenant_id and requested_by = p_auth_user_id and status = 'pending';
  get diagnostics v_approvals = row_count;

  update public.enrollment_tokens
     set expires_at = least(expires_at, v_now)
   where tenant_id = p_tenant_id and user_id = p_auth_user_id
     and consumed_at is null and expires_at > v_now;
  get diagnostics v_enrollment = row_count;

  -- Device-code sessions carry no tenant; a SCIM identity belongs to exactly
  -- one tenant (scim_bind_user refuses any other membership).
  update public.device_sessions
     set expires_at = least(expires_at, v_now)
   where user_id = p_auth_user_id and exchanged_at is null and expires_at > v_now;
  get diagnostics v_sessions = row_count;

  insert into public.admin_audit_logs(tenant_id, target_user_id, action, detail)
  values (p_tenant_id, p_auth_user_id, 'scim.user.deprovisioned',
    jsonb_build_object(
      'scim_user_id', p_scim_user_id,
      'api_keys_revoked', v_keys,
      'approval_requests_expired', v_approvals,
      'enrollment_codes_expired', v_enrollment,
      'device_sessions_expired', v_sessions));

  return jsonb_build_object(
    'api_keys_revoked', v_keys,
    'approval_requests_expired', v_approvals,
    'enrollment_codes_expired', v_enrollment,
    'device_sessions_expired', v_sessions);
end;
$$;
revoke all on function app.scim_deprovision_device_access(uuid, uuid, uuid)
  from public, anon, authenticated, service_role;

create or replace function app.scim_user_deprovisioned()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
begin
  perform app.scim_deprovision_device_access(new.tenant_id, new.auth_user_id, new.id);
  return new;
end;
$$;
revoke all on function app.scim_user_deprovisioned()
  from public, anon, authenticated, service_role;

drop trigger if exists scim_users_deprovision_device_access on public.scim_users;
create trigger scim_users_deprovision_device_access
after update of active on public.scim_users
for each row
when (old.active and not new.active and new.auth_user_id is not null)
execute function app.scim_user_deprovisioned();
