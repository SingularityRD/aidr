-- Dashboard-pushed Browser Guard setting: require native NER
-- (packages/browser-guard/README.md "Dashboard policy", docs/ai-governance.md).
--
-- Owners and administrators can require native NER (PERSON/ADDRESS/LOCATION through
-- the Browser Guard native host) for every enrolled browser of the tenant. The
-- setting is stored next to the other tenant AI governance options
-- (public.tenant_ai_governance_settings: members read it under the existing RLS,
-- nobody writes it directly) and is delivered to browsers inside the signed
-- browser-guard-policy document as `browser_guard.require_native_ner`. Browser Guard
-- merges it with the managed `requireNativeNer` key: true wins.
--
-- Writes go through public.update_browser_guard_settings only (service role, called
-- by the ai-governance Edge Function after session, identity barrier, membership,
-- AAL2 and rate-limit checks). The RPC:
--   * re-checks owner/admin on an active tenant under row locks
--     (app.ai_governance_actor_role);
--   * serialises with the other governance settings changes (same advisory lock as
--     update_ai_governance_settings);
--   * refuses to switch the requirement OFF while four-eyes change control is on
--     (relaxing a protection needs a second person: turning four-eyes off is itself
--     a policy change request another owner/admin must approve);
--   * writes an audit row (admin_audit_logs, plus the team audit log) in the same
--     transaction for every actual change.
--
-- Additive and idempotent: one defaulted column, one new function; no grant to
-- clients. Offboarding already deletes the whole settings row
-- (20260927000042_ai_governance_retention_offboarding.sql).

alter table public.tenant_ai_governance_settings
  add column if not exists browser_guard_require_native_ner boolean not null default false;

comment on column public.tenant_ai_governance_settings.browser_guard_require_native_ner is
  'Browser Guard: native NER is mandatory for every enrolled browser (signed browser-guard-policy document, require_native_ner). Changed only through update_browser_guard_settings.';

create or replace function public.update_browser_guard_settings(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_require_native_ner boolean
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_role text;
  v_old public.tenant_ai_governance_settings;
  v_new public.tenant_ai_governance_settings;
begin
  if p_tenant_id is null or p_actor_user_id is null or p_require_native_ner is null then
    raise exception 'invalid_browser_guard_settings' using errcode = '22023';
  end if;
  v_role := app.ai_governance_actor_role(p_tenant_id, p_actor_user_id);
  if v_role is null or v_role not in ('owner', 'admin') then
    raise exception 'ai_governance_forbidden' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':policy-change', 0));
  insert into public.tenant_ai_governance_settings (tenant_id, updated_by, updated_at)
  values (p_tenant_id, p_actor_user_id, v_now)
  on conflict (tenant_id) do nothing;
  select * into v_old from public.tenant_ai_governance_settings where tenant_id = p_tenant_id for update;

  if v_old.browser_guard_require_native_ner = p_require_native_ner then
    return jsonb_build_object('require_native_ner', v_old.browser_guard_require_native_ner, 'changed', false);
  end if;

  -- Relaxing the requirement under four-eyes change control needs a second person.
  if not p_require_native_ner and v_old.policy_four_eyes then
    raise exception 'browser_guard_four_eyes_required' using errcode = '42501';
  end if;

  update public.tenant_ai_governance_settings
     set browser_guard_require_native_ner = p_require_native_ner,
         updated_by = p_actor_user_id, updated_at = v_now
   where tenant_id = p_tenant_id
  returning * into v_new;

  perform app.ai_governance_audit(p_tenant_id, p_actor_user_id, 'browser_guard.settings_updated',
    jsonb_build_object('require_native_ner_from', v_old.browser_guard_require_native_ner,
      'require_native_ner_to', v_new.browser_guard_require_native_ner));
  return jsonb_build_object('require_native_ner', v_new.browser_guard_require_native_ner, 'changed', true);
end;
$$;
revoke all on function public.update_browser_guard_settings(uuid, uuid, boolean) from public, anon, authenticated;
grant execute on function public.update_browser_guard_settings(uuid, uuid, boolean) to service_role;
