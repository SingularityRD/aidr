-- Read-only admission checks no longer serialize one tenant's whole ingest path.
--
-- tenant_admission_capacity() took the tenant's EXCLUSIVE transaction advisory
-- lock. It is called on every ingest request through get_tenant_admission(),
-- and by the api_keys / enrollment_tokens / agents admission triggers, none of
-- which count or allocate anything. A local load/soak drill (2026-10-11,
-- docs/production-readiness/load-soak-drill-2026-10-11.md) showed one busy
-- tenant's ingest requests queueing on that lock inside PostgREST transactions,
-- holding the shared PostgREST connection pool while they waited, so the quiet
-- tenant's requests timed out with it (PGRST003).
--
-- Every caller that counts or allocates (register_agent_for_ingest,
-- register_browser_guard_agent_for_ingest, the event seat-admission trigger,
-- issue_device_enrollment_token, start_verified_trial_core,
-- grant/revoke_licensed_tenant_admission) still takes the EXCLUSIVE lock itself
-- before calling this function, and a session that holds the exclusive lock can
-- take the shared one on the same key. A shared lock still waits for, and blocks,
-- every exclusive holder, so a capacity read cannot interleave with an admission
-- or seat writer (scripts/tenant-ga-admission-concurrency-postgres.test.mjs);
-- concurrent readers simply stop excluding each other. The row-level FOR SHARE
-- locks below are unchanged.
create or replace function public.tenant_admission_capacity(p_tenant_id uuid)
returns integer
language plpgsql volatile security definer
set search_path = pg_catalog, public, app, pg_temp
as $$
declare
  v_mode text;
  v_admission public.tenant_admissions%rowtype;
  v_included integer;
  v_extra integer;
  v_seats integer;
begin
  if p_tenant_id is null then return 0; end if;
  perform pg_advisory_xact_lock_shared(hashtextextended(p_tenant_id::text, 0));
  select mode into v_mode from app.tenant_admission_config
    where singleton for share;
  if v_mode is null or v_mode = 'unconfigured' then return 0; end if;
  perform 1 from public.tenants t
    where t.id = p_tenant_id and t.status = 'active' for share;
  if not found then return 0; end if;

  if v_mode = 'pilot' then
    perform 1 from public.pilot_applications p
      where p.tenant_id = p_tenant_id and p.status = 'approved'
      limit 1 for share;
    if not found then return 0; end if;
    -- The pilot decision trigger updates the application before entitlements.
    select e.included_agents into v_included from public.entitlements e
      where e.tenant_id = p_tenant_id for share;
    if not found then return 0; end if;
  else
    -- Trial/license grants allocate entitlements before admission rows.
    select e.included_agents into v_included from public.entitlements e
      where e.tenant_id = p_tenant_id for share;
    if not found then return 0; end if;
    select * into v_admission from public.tenant_admissions a
      where a.tenant_id = p_tenant_id and a.revoked_at is null
        and a.starts_at <= clock_timestamp()
        and a.expires_at > clock_timestamp()
      for share;
    if not found then return 0; end if;
  end if;

  select s.extra_agents into v_extra
    from public.effective_tenant_seats(p_tenant_id) s;
  v_seats := greatest(0, coalesce(v_included, 0) + coalesce(v_extra, 0));
  if v_mode = 'pilot' then return v_seats; end if;
  return least(v_seats, v_admission.seats);
end;
$$;
revoke all on function public.tenant_admission_capacity(uuid)
  from public, anon, authenticated;
grant execute on function public.tenant_admission_capacity(uuid)
  to service_role;
