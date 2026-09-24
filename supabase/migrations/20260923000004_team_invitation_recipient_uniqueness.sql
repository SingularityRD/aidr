-- Keep at most one unaccepted, unexpired invitation for a tenant/email pair.
-- This migration is ordered after the other 20260923 migrations in this checkout.
-- Existing rows are retained; fail closed if earlier writes already left a
-- duplicate live pair so an operator can review it before enabling the guard.
alter table public.team_invitations
  add column live_slot boolean not null default false;

do $$
begin
  if exists (
    select 1
      from public.team_invitations
     where accepted_at is null and expires_at > now()
     group by tenant_id, lower(email)
    having count(*) > 1
  ) then
    raise exception 'team_invitation_live_recipient_duplicates_exist';
  end if;
end;
$$;

update public.team_invitations
   set live_slot = true
 where accepted_at is null and expires_at > now();

create or replace function public.sync_team_invitation_live_slot()
returns trigger
language plpgsql
set search_path = public, pg_catalog
as $$
begin
  new.live_slot := new.accepted_at is null and new.expires_at > now();
  return new;
end;
$$;
revoke all on function public.sync_team_invitation_live_slot() from public, anon, authenticated;

create trigger team_invitations_live_slot
before insert or update of accepted_at, expires_at, live_slot on public.team_invitations
for each row execute function public.sync_team_invitation_live_slot();

create unique index team_invitations_one_live_recipient_idx
  on public.team_invitations (tenant_id, lower(email))
  where live_slot;
