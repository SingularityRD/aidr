-- Tenant and audit hardening for production control-plane deployments.
--
-- This migration deliberately fails on pre-existing cross-tenant events
-- instead of silently rewriting evidence. Resolve those rows with a reviewed
-- data migration before applying it to an existing project.

create extension if not exists pgcrypto;

do $$
begin
  if exists (
    select 1
    from public.events ev
    join public.agents ag on ag.id = ev.agent_id
    where ev.user_id is distinct from ag.user_id
  ) then
    raise exception 'tenant_hardening: events contain cross-tenant agent references';
  end if;
end;
$$;

-- Make the tenant + installation ownership pair addressable by a composite FK.
create unique index if not exists agents_user_id_id_uniq
  on public.agents (user_id, id);

alter table public.events
  drop constraint if exists events_agent_owner_fkey;
alter table public.events
  add constraint events_agent_owner_fkey
  foreign key (user_id, agent_id)
  references public.agents (user_id, id)
  on delete cascade;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'entitlements_included_agents_nonnegative'
      and conrelid = 'public.entitlements'::regclass
  ) then
    alter table public.entitlements
      add constraint entitlements_included_agents_nonnegative
      check (included_agents >= 0);
  end if;
  if not exists (
    select 1 from pg_constraint
    where conname = 'entitlements_extra_agents_nonnegative'
      and conrelid = 'public.entitlements'::regclass
  ) then
    alter table public.entitlements
      add constraint entitlements_extra_agents_nonnegative
      check (extra_agents >= 0);
  end if;
end;
$$;

-- Atomic one-time enrollment exchange. The previous read-then-update flow
-- allowed two concurrent requests to observe the same unused token. Only the
-- service role can invoke this function; the Edge Function still validates
-- the returned owner and applies seat limits before issuing a key.
create or replace function public.consume_enrollment_token(p_token_hash text)
returns table (id uuid, user_id uuid, expires_at timestamptz)
language sql
security definer
set search_path = public
as $$
  update public.enrollment_tokens
  set consumed_at = now()
  where token_hash = p_token_hash
    and consumed_at is null
    and expires_at > now()
  returning enrollment_tokens.id, enrollment_tokens.user_id, enrollment_tokens.expires_at;
$$;

revoke all on function public.consume_enrollment_token(text) from public, anon, authenticated;
grant execute on function public.consume_enrollment_token(text) to service_role;

-- Audit rows are append-only. Team deletion is restricted while audit rows
-- exist, preventing an ON DELETE CASCADE from destroying the evidence trail.
alter table public.audit_logs
  drop constraint if exists audit_logs_team_id_fkey;
alter table public.audit_logs
  add constraint audit_logs_team_id_fkey
  foreign key (team_id)
  references public.teams (id)
  on delete restrict;

create or replace function public.reject_audit_mutation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  raise exception 'audit_logs are append-only';
end;
$$;
revoke all on function public.reject_audit_mutation() from public, anon, authenticated;

drop trigger if exists audit_logs_append_only on public.audit_logs;
create trigger audit_logs_append_only
before update or delete on public.audit_logs
for each row execute function public.reject_audit_mutation();

drop policy if exists audit_logs_delete_admin on public.audit_logs;

-- Do not allow a team to be left without an owner through a normal member
-- update/delete. Service-role offboarding can archive/delete the whole team
-- through an explicit reviewed workflow.
create or replace function public.guard_team_owner()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Auth account deletion cascades through team_members as the database
  -- owner. Service-role offboarding is an explicit control-plane workflow;
  -- normal authenticated DML still cannot remove the final owner.
  if current_user in ('postgres', 'service_role') then
    return coalesce(new, old);
  end if;
  if tg_op = 'DELETE' and old.role = 'owner' and not exists (
    select 1 from public.team_members
    where team_id = old.team_id and role = 'owner' and id <> old.id
  ) then
    raise exception 'team must retain at least one owner';
  end if;
  if tg_op = 'UPDATE' and old.role = 'owner' and new.role <> 'owner' and not exists (
    select 1 from public.team_members
    where team_id = old.team_id and role = 'owner' and id <> old.id
  ) then
    raise exception 'team must retain at least one owner';
  end if;
  return coalesce(new, old);
end;
$$;
revoke all on function public.guard_team_owner() from public, anon, authenticated;

drop trigger if exists team_members_owner_guard on public.team_members;
create trigger team_members_owner_guard
before update or delete on public.team_members
for each row execute function public.guard_team_owner();
