-- OIDC provider writes: owner re-check, provider upsert and audit in ONE
-- transaction.
--
-- The oidc-sso Edge function checked "is the caller an owner" once, then
-- (after a network discovery fetch) upserted oidc_providers with the service
-- role and wrote admin_audit_logs in a separate request. So:
--   * an audit insert failure returned 503 while the (possibly enabled)
--     provider stayed committed without its audit row, and
--   * an owner demoted or removed while discovery was in flight still had the
--     write committed, because nothing re-checked membership at write time.
--
-- public.oidc_save_provider does all three atomically:
--   1. takes the tenant lifecycle lock (2606) before any row lock, the order the
--      OIDC tenant write guard and the offboarding runner use;
--   2. re-checks that the actor is a live owner of an active tenant and holds
--      that membership/tenant FOR SHARE until commit, so a concurrent demotion
--      either committed first (and is seen) or waits for this transaction;
--   3. upserts the provider for that tenant only. The existing triggers still
--      apply: app.protect_oidc_tenant_write (inactive/offboarding tenant,
--      immutable tenant key) and app.guard_oidc_provider_configuration
--      (enforced provider locked, linked identity namespace locked);
--   4. writes the admin audit row. Any failure in 1-4 rolls back everything.
-- Service role only; the Edge function keeps authentication, AAL2, plan gating
-- and discovery validation.

create or replace function public.oidc_save_provider(
  p_actor_user_id uuid,
  p_provider jsonb,
  p_audit_action text,
  p_audit_detail jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_row public.oidc_providers;
  v_existing_tenant uuid;
begin
  if p_actor_user_id is null or p_provider is null or jsonb_typeof(p_provider) <> 'object'
     or p_audit_action is null
     or p_audit_action not in ('identity.oidc.provider_updated', 'identity.oidc.discovery_refreshed')
     or (p_audit_detail is not null and jsonb_typeof(p_audit_detail) <> 'object') then
    raise exception 'invalid_oidc_provider_request' using errcode = '22023';
  end if;
  v_row := jsonb_populate_record(null::public.oidc_providers, p_provider);
  if v_row.id is null or v_row.tenant_id is null then
    raise exception 'invalid_oidc_provider_request' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(v_row.tenant_id::text, 2606));
  perform 1
    from public.tenant_members m
    join public.tenants t on t.id = m.tenant_id
   where m.tenant_id = v_row.tenant_id
     and m.user_id = p_actor_user_id
     and m.role = 'owner'
     and (m.expires_at is null or m.expires_at > clock_timestamp())
     and t.status = 'active'
   for share of m, t;
  if not found then
    raise exception 'oidc_provider_forbidden' using errcode = '42501';
  end if;
  -- A provider id is never moved between tenants (the write guard refuses it
  -- too); refuse here with the same coarse answer as a non-owner.
  select tenant_id into v_existing_tenant from public.oidc_providers where id = v_row.id;
  if found and v_existing_tenant <> v_row.tenant_id then
    raise exception 'oidc_provider_forbidden' using errcode = '42501';
  end if;

  insert into public.oidc_providers as p (
    id, tenant_id, kind, display_name, issuer, client_id, client_secret_ref,
    token_auth_method, allowed_algs, subject_claim, groups_claim, groups_mode,
    session_max_seconds, clock_skew_seconds, discovery, discovery_fetched_at,
    enabled, created_by
  ) values (
    v_row.id, v_row.tenant_id, v_row.kind, v_row.display_name, v_row.issuer,
    v_row.client_id, v_row.client_secret_ref, v_row.token_auth_method,
    v_row.allowed_algs, v_row.subject_claim, v_row.groups_claim, v_row.groups_mode,
    v_row.session_max_seconds, v_row.clock_skew_seconds, v_row.discovery,
    case when v_row.discovery is not null then now() end,
    coalesce(v_row.enabled, false), p_actor_user_id
  )
  on conflict (id) do update set
    kind = excluded.kind,
    display_name = excluded.display_name,
    issuer = excluded.issuer,
    client_id = excluded.client_id,
    client_secret_ref = excluded.client_secret_ref,
    token_auth_method = excluded.token_auth_method,
    allowed_algs = excluded.allowed_algs,
    subject_claim = excluded.subject_claim,
    groups_claim = excluded.groups_claim,
    groups_mode = excluded.groups_mode,
    session_max_seconds = excluded.session_max_seconds,
    clock_skew_seconds = excluded.clock_skew_seconds,
    discovery = excluded.discovery,
    discovery_fetched_at = excluded.discovery_fetched_at,
    enabled = excluded.enabled
  where p.tenant_id = excluded.tenant_id;
  if not found then
    raise exception 'oidc_provider_forbidden' using errcode = '42501';
  end if;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, target_user_id, action, detail)
  values (p_actor_user_id, v_row.tenant_id, null, p_audit_action,
          coalesce(p_audit_detail, '{}'::jsonb) || jsonb_build_object('provider_id', v_row.id));

  return jsonb_build_object('provider_id', v_row.id, 'tenant_id', v_row.tenant_id,
                            'enabled', coalesce(v_row.enabled, false));
end;
$$;

revoke all on function public.oidc_save_provider(uuid, jsonb, text, jsonb)
  from public, anon, authenticated;
grant execute on function public.oidc_save_provider(uuid, jsonb, text, jsonb) to service_role;
