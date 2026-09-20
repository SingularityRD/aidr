-- Stable event identity makes agent retries idempotent. Existing rows receive a
-- deterministic legacy identity before the column becomes mandatory.
alter table public.events
  add column if not exists event_id text;

update public.events
set event_id = 'legacy:' || id::text
where event_id is null;

alter table public.events
  alter column event_id set not null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'events_event_id_format_check'
      and conrelid = 'public.events'::regclass
  ) then
    alter table public.events
      add constraint events_event_id_format_check
      check (event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$');
  end if;
end;
$$;

create unique index if not exists events_tenant_event_id_uniq
  on public.events (tenant_id, event_id);

comment on column public.events.event_id is
  'Agent-assigned stable delivery identity; unique per tenant for idempotent retry.';
