-- Registration and event upsert use separate transactions. Recheck seats at
-- the write boundary so a completed seat reduction cannot admit new events.
create index if not exists agents_tenant_seat_rank_idx
  on public.agents (tenant_id, first_seen, id);

create or replace function app.enforce_event_seat_admission()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, pg_temp
as $$
declare
  v_included integer;
  v_extra integer;
  v_allowed integer;
  v_first_seen timestamptz;
  v_prior bigint;
  v_existing_agent uuid;
  v_existing_user uuid;
begin
  if new.tenant_id is null or new.agent_id is null then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;

  -- The same order as register_agent_for_ingest: tenant, entitlement, agent.
  -- The entitlement row lock linearizes this insert with a billing reduction.
  perform pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 0));
  select e.included_agents into v_included
    from public.entitlements e
   where e.tenant_id = new.tenant_id
   for update;
  if not found then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  select a.first_seen into v_first_seen
    from public.agents a
   where a.id = new.agent_id and a.tenant_id = new.tenant_id
     and a.user_id = new.user_id
   for key share;
  if not found then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;

  -- A retry of an already stored event creates no telemetry. Lock that row
  -- until ON CONFLICT DO NOTHING finishes; never launder an ID across agents.
  select ev.agent_id, ev.user_id into v_existing_agent, v_existing_user
    from public.events ev
   where ev.tenant_id = new.tenant_id and ev.event_id = new.event_id
   for share;
  if found then
    if v_existing_agent = new.agent_id and v_existing_user = new.user_id then
      return new;
    end if;
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;

  select s.extra_agents into v_extra
    from public.effective_tenant_seats(new.tenant_id) s;
  v_allowed := greatest(0, coalesce(v_included, 0) + coalesce(v_extra, 0));
  if v_allowed = 0 then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  select count(*) into v_prior
    from public.agents a
   where a.tenant_id = new.tenant_id
     and (a.first_seen, a.id) < (v_first_seen, new.agent_id);
  if v_prior >= v_allowed then
    raise exception 'agent_seat_not_authorized' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function app.enforce_event_seat_admission()
  from public, anon, authenticated, service_role;

drop trigger if exists events_seat_admission on public.events;
create trigger events_seat_admission
before insert on public.events
for each row execute function app.enforce_event_seat_admission();
