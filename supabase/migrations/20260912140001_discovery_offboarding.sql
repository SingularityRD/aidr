-- Delete discovery endpoint identity at the endpoint_identity retention phase,
-- rather than waiting for later commercial retention to close the tenant.
create function app.purge_discovery_at_endpoint_identity_phase() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_tenant uuid;
  v_status text;
  v_items bigint;
  v_collectors bigint;
begin
  if new.phase <> 'agents' or new.data_class <> 'endpoint_identity'
    or new.status <> 'completed' or old.status = 'completed'
  then return new; end if;
  select r.tenant_id, r.status into v_tenant, v_status
  from public.tenant_offboarding_runs r where r.id = new.run_id;
  if v_tenant is null or v_status <> 'running' or new.eligible_at > now() then
    raise exception 'discovery_offboarding_phase_invalid' using errcode = '42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  if exists (
    select 1 from public.tenant_legal_holds h
    where h.tenant_id = v_tenant and h.released_at is null
  ) then raise exception 'discovery_offboarding_legal_hold' using errcode = '42501'; end if;
  select count(*) into v_items from public.tenant_discovery_items
    where tenant_id = v_tenant;
  delete from public.tenant_discovery_collectors where tenant_id = v_tenant;
  get diagnostics v_collectors = row_count;
  -- The phase receipt counts the dependent discovery observations removed by
  -- this trigger as well as the agents deleted by the offboarding RPC.
  update public.tenant_offboarding_phase_receipts
    set rows_deleted = rows_deleted + v_items + v_collectors
    where run_id = new.run_id and phase = new.phase and status = 'completed';
  return new;
end;
$$;
revoke all on function app.purge_discovery_at_endpoint_identity_phase()
  from public, anon, authenticated;
create trigger tenant_offboarding_purge_discovery
after update of status on public.tenant_offboarding_phase_receipts
for each row execute function app.purge_discovery_at_endpoint_identity_phase();
