-- OIDC discovery refresh writes ONLY the discovery columns.
--
-- The oidc-sso refresh_discovery action read the full provider row, fetched the
-- IdP discovery document over the network, then wrote the whole (by then
-- possibly stale) row back through public.oidc_save_provider, whose upsert
-- overwrites every column: enabled, issuer, client_id, client_secret_ref, ...
-- A slow discovery fetch therefore let a stale copy re-enable a provider that
-- another owner had just disabled (or undo any other edit made meanwhile).
--
-- public.oidc_update_provider_discovery, in one transaction:
--   1. takes the tenant lifecycle lock (2606) before any row lock, as
--      oidc_save_provider, the OIDC write guard and offboarding do;
--   2. re-checks that the actor is a live owner of an active tenant and holds
--      that membership/tenant FOR SHARE until commit;
--   3. locks the provider row and refuses with oidc_provider_changed (55000) if
--      the inputs the discovery document was validated against (issuer and
--      allowed signing algorithms) changed since the Edge function read it.
--      updated_at is deliberately NOT the token: every SSO login bumps it
--      (last_login_at), so it would refuse refreshes on any active tenant;
--   4. updates discovery and discovery_fetched_at only. Every other column is
--      left exactly as committed, so a concurrent disable stays disabled. The
--      existing triggers still apply (tenant write guard; the configuration
--      guard passes because no identity configuration changes);
--   5. writes the identity.oidc.discovery_refreshed audit row.
-- Any failure rolls back everything. Service role only.

create or replace function public.oidc_update_provider_discovery(
  p_actor_user_id uuid,
  p_tenant_id uuid,
  p_provider_id uuid,
  p_expected_issuer text,
  p_expected_allowed_algs text[],
  p_discovery jsonb,
  p_audit_detail jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_row public.oidc_providers;
  v_fetched_at timestamptz;
begin
  if p_actor_user_id is null or p_tenant_id is null or p_provider_id is null
     or p_expected_issuer is null or p_expected_allowed_algs is null
     or p_discovery is null or jsonb_typeof(p_discovery) <> 'object'
     or (p_audit_detail is not null and jsonb_typeof(p_audit_detail) <> 'object') then
    raise exception 'invalid_oidc_provider_request' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = p_tenant_id
     and m.user_id = p_actor_user_id
     and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m, t;
  if not found then
    raise exception 'oidc_provider_forbidden' using errcode = '42501';
  end if;

  select * into v_row from public.oidc_providers where id = p_provider_id for update;
  if not found then
    raise exception 'oidc_provider_changed' using errcode = '55000';
  end if;
  if v_row.tenant_id <> p_tenant_id then
    raise exception 'oidc_provider_forbidden' using errcode = '42501';
  end if;
  if v_row.issuer is distinct from p_expected_issuer
     or v_row.allowed_algs is distinct from p_expected_allowed_algs then
    raise exception 'oidc_provider_changed' using errcode = '55000';
  end if;

  update public.oidc_providers
     set discovery = p_discovery,
         discovery_fetched_at = now()
   where id = p_provider_id and tenant_id = p_tenant_id
  returning discovery_fetched_at into v_fetched_at;
  if not found then
    raise exception 'oidc_provider_changed' using errcode = '55000';
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, p_tenant_id, null, 'identity.oidc.discovery_refreshed',
          coalesce(p_audit_detail, '{}'::jsonb) || jsonb_build_object('provider_id', p_provider_id));

  return jsonb_build_object('provider_id', p_provider_id, 'tenant_id', p_tenant_id,
                            'enabled', v_row.enabled, 'discovery_fetched_at', v_fetched_at);
end;
$$;

revoke all on function public.oidc_update_provider_discovery(uuid, uuid, uuid, text, text[], jsonb, jsonb)
  from public, anon, authenticated;
grant execute on function public.oidc_update_provider_discovery(uuid, uuid, uuid, text, text[], jsonb, jsonb)
  to service_role;
