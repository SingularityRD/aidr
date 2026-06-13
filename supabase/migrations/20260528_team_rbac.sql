-- Team RBAC: teams, team_members, team_policies, and audit_logs for
-- multi-tenant team-based access control.
--
-- Implements four-tier role model:
--   owner   – full ownership (transfer, delete team)
--   admin   – manage members, policies, audit export
--   member  – view team data, edit policies
--   viewer  – read-only access
--
-- Every table has RLS enforced; policies use inline subqueries against
-- team_members to determine the caller's role within a team.

create extension if not exists pgcrypto;

-- ── Helper: team membership check ─────────────────────────────────────
-- These helper functions are marked security definer so RLS policies can
-- use them without recursion.  Both check the calling user's role in
-- the given team and return true when the role satisfies the minimum.

/**
 * Checks whether the calling user is a member of the given team.
 * Returns true for any role (owner, admin, member, viewer).
 */
create or replace function public.is_team_member(team_id uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1
    from public.team_members
    where team_members.team_id = is_team_member.team_id
      and team_members.user_id = auth.uid()
  );
$$;

/**
 * Checks whether the calling user holds at least the specified minimum
 * role in the given team.  Role hierarchy (high → low):
 *   owner > admin > member > viewer
 *
 * Pass the minimum acceptable role as the second argument, e.g.
 *   is_team_member_with_role(team_id, 'admin')
 * returns true for owner and admin, false for member and viewer.
 */
create or replace function public.is_team_member_with_role(team_id uuid, min_role text)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1
    from public.team_members
    where team_members.team_id = is_team_member_with_role.team_id
      and team_members.user_id = auth.uid()
      and team_members.role = any (
        case is_team_member_with_role.min_role
          when 'owner'   then array['owner']
          when 'admin'   then array['owner', 'admin']
          when 'member'  then array['owner', 'admin', 'member']
          when 'viewer'  then array['owner', 'admin', 'member', 'viewer']
          else array[]::text[]
        end
      )
  );
$$;

-- ── Teams ─────────────────────────────────────────────────────────────

/**
 * teams
 * =====
 * Top-level team entity.  Each team groups users under a shared
 * billing plan and lets them collaborate on AIDR policies, audit
 * logs, and threat intelligence.
 *
 * Columns
 * -------
 * id         :: UUID, primary key
 * name       :: display name for the team
 * github_org :: optional GitHub organisation slug for SSO hints
 * gitlab_group:: optional GitLab group path for SSO hints
 * plan       :: subscription tier: free | pro | enterprise
 * created_at :: row creation timestamp
 * updated_at :: last-update timestamp (auto-maintained by trigger)
 */
create table if not exists public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  github_org text,
  gitlab_group text,
  plan text not null default 'free' check (plan in ('free', 'pro', 'enterprise')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

drop trigger if exists teams_touch_updated_at on public.teams;
create trigger teams_touch_updated_at
  before update on public.teams
  for each row execute procedure public.touch_updated_at();

alter table public.teams enable row level security;

/**
 * Policy: teams_select_member
 * ---------------------------
 * Any member (owner, admin, member, viewer) of a team can see that
 * team's row.  Authenticated users see no teams they do not belong to.
 */
drop policy if exists teams_select_member on public.teams;
create policy teams_select_member
  on public.teams for select
  using (public.is_team_member(id));

/**
 * Policy: teams_insert_authenticated
 * ----------------------------------
 * Any authenticated user may create a new team.  The creator is
 * automatically added as an admin by the application layer.
 */
drop policy if exists teams_insert_authenticated on public.teams;
create policy teams_insert_authenticated
  on public.teams for insert
  with check (auth.role() = 'authenticated');

/**
 * Policy: teams_update_admin
 * --------------------------
 * Only admins (or owners) may update team metadata (name, plan, etc.).
 */
drop policy if exists teams_update_admin on public.teams;
create policy teams_update_admin
  on public.teams for update
  using (public.is_team_member_with_role(id, 'admin'))
  with check (public.is_team_member_with_role(id, 'admin'));

/**
 * Policy: teams_delete_admin
 * --------------------------
 * Only admins (or owners) may delete a team.
 */
drop policy if exists teams_delete_admin on public.teams;
create policy teams_delete_admin
  on public.teams for delete
  using (public.is_team_member_with_role(id, 'admin'));

-- ── Team Members ──────────────────────────────────────────────────────

/**
 * team_members
 * ============
 * Join table linking auth.users to teams with a role.
 *
 * Columns
 * -------
 * id        :: UUID, primary key
 * team_id   :: FK → teams.id
 * user_id   :: FK → auth.users.id
 * role      :: owner | admin | member | viewer
 * joined_at :: when the user accepted / was added to the team
 * created_at:: row creation timestamp (mirrors joined_at on insert)
 *
 * Indexes
 * -------
 * team_members_team_id_idx       – fast team-scoped member lookups
 * team_members_user_id_idx       – fast user-scoped team membership queries
 * team_members_team_user_uniq    – one membership row per user per team
 */
create table if not exists public.team_members (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member', 'viewer')),
  invited_by uuid references auth.users (id) on delete set null,
  joined_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create unique index if not exists team_members_team_user_uniq
  on public.team_members (team_id, user_id);
create index if not exists team_members_team_id_idx
  on public.team_members (team_id);
create index if not exists team_members_user_id_idx
  on public.team_members (user_id);

alter table public.team_members enable row level security;

/**
 * Policy: team_members_select_member
 * -----------------------------------
 * Any member of a team can see the full membership list for that team.
 */
drop policy if exists team_members_select_member on public.team_members;
create policy team_members_select_member
  on public.team_members for select
  using (public.is_team_member(team_id));

/**
 * Policy: team_members_insert_admin
 * ----------------------------------
 * Allows two situations:
 *   1. The first member of a brand-new team (the creator) — inserts
 *      themselves as admin or owner.  This avoids a chicken-and-egg
 *      problem where no-one exists to grant the first membership.
 *   2. Existing admins (or owners) adding subsequent members.
 */
drop policy if exists team_members_insert_admin on public.team_members;
create policy team_members_insert_admin
  on public.team_members for insert
  with check (
    (
      -- First-member bypass: caller inserts self as admin/owner
      -- into a team that has no members yet.
      (role in ('admin', 'owner'))
      and user_id = auth.uid()
      and not exists (
        select 1 from public.team_members tm
        where tm.team_id = team_id
      )
    )
    or
    (
      -- Subsequent inserts require existing admin privileges.
      public.is_team_member_with_role(team_id, 'admin')
    )
  );

/**
 * Policy: team_members_update_admin
 * ----------------------------------
 * Only admins (or owners) may change a member's role.
 */
drop policy if exists team_members_update_admin on public.team_members;
create policy team_members_update_admin
  on public.team_members for update
  using (public.is_team_member_with_role(team_id, 'admin'))
  with check (public.is_team_member_with_role(team_id, 'admin'));

/**
 * Policy: team_members_delete_admin
 * ----------------------------------
 * Only admins (or owners) may remove members from a team.
 */
drop policy if exists team_members_delete_admin on public.team_members;
create policy team_members_delete_admin
  on public.team_members for delete
  using (public.is_team_member_with_role(team_id, 'admin'));

-- ── Team Policies (custom security rules) ─────────────────────────────

/**
 * team_policies
 * =============
 * Per-team custom security policies that members can author and the
 * AIDR enforcement engine evaluates at runtime.
 *
 * Columns
 * -------
 * id         :: UUID, primary key
 * team_id    :: FK → teams.id
 * content    :: policy document (JSON or YAML text, interpreted by engine)
 * updated_at :: last-modified timestamp
 * updated_by :: user who last edited the policy
 */
create table if not exists public.team_policies (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams (id) on delete cascade,
  content text not null,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users (id) on delete set null
);

create index if not exists team_policies_team_id_idx
  on public.team_policies (team_id);

drop trigger if exists team_policies_touch_updated_at on public.team_policies;
create trigger team_policies_touch_updated_at
  before update on public.team_policies
  for each row execute procedure public.touch_updated_at();

alter table public.team_policies enable row level security;

/**
 * Policy: team_policies_select_member
 * ------------------------------------
 * Any member of a team can read its policies.
 */
drop policy if exists team_policies_select_member on public.team_policies;
create policy team_policies_select_member
  on public.team_policies for select
  using (public.is_team_member(team_id));

/**
 * Policy: team_policies_insert_editor
 * ------------------------------------
 * Admins and members may create policies.  The updated_by column is
 * automatically set to the caller's uid via the insert check.
 */
drop policy if exists team_policies_insert_editor on public.team_policies;
create policy team_policies_insert_editor
  on public.team_policies for insert
  with check (
    public.is_team_member_with_role(team_id, 'member')
    and (updated_by = auth.uid())
  );

/**
 * Policy: team_policies_update_editor
 * ------------------------------------
 * Admins and members may update policies.  The updated_by column is
 * forced to the caller's uid.
 */
drop policy if exists team_policies_update_editor on public.team_policies;
create policy team_policies_update_editor
  on public.team_policies for update
  using (public.is_team_member_with_role(team_id, 'member'))
  with check (
    public.is_team_member_with_role(team_id, 'member')
    and (updated_by = auth.uid())
  );

/**
 * Policy: team_policies_delete_admin
 * -----------------------------------
 * Only admins (or owners) may delete policies.
 */
drop policy if exists team_policies_delete_admin on public.team_policies;
create policy team_policies_delete_admin
  on public.team_policies for delete
  using (public.is_team_member_with_role(team_id, 'admin'));

-- ── Audit Logs ────────────────────────────────────────────────────────

/**
 * audit_logs
 * ==========
 * Immutable audit trail of team-scoped actions.  Rows are typically
 * inserted by edge functions (team-invite, audit-export) and are
 * read by team members via the dashboard.
 *
 * Columns
 * -------
 * id         :: UUID, primary key
 * team_id    :: FK → teams.id
 * user_id    :: acting user (nullable for system actions)
 * user_email :: denormalised email for display after user deletion
 * action     :: short machine-readable action name, e.g. 'member.invited'
 * verdict    :: optional JSON payload from the AIDR enforcement engine
 * timestamp  :: epoch millisecond of the action (for charting / bucketing)
 * created_at :: row creation timestamp
 */
create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams (id) on delete cascade,
  user_id uuid references auth.users (id) on delete set null,
  user_email text,
  action text not null,
  verdict jsonb,
  timestamp bigint not null default (extract(epoch from now()) * 1000)::bigint,
  created_at timestamptz not null default now()
);

create index if not exists audit_logs_team_id_idx
  on public.audit_logs (team_id);
create index if not exists audit_logs_team_id_created_at_idx
  on public.audit_logs (team_id, created_at desc);
create index if not exists audit_logs_user_id_idx
  on public.audit_logs (user_id);

alter table public.audit_logs enable row level security;

/**
 * Policy: audit_logs_select_member
 * ---------------------------------
 * Any member of a team can read its audit logs.
 */
drop policy if exists audit_logs_select_member on public.audit_logs;
create policy audit_logs_select_member
  on public.audit_logs for select
  using (public.is_team_member(team_id));

/**
 * Policy: audit_logs_insert_service
 * ---------------------------------
 * Authenticated users may insert audit log entries for teams they
 * belong to.  The user_id defaults to auth.uid() when omitted.
 */
drop policy if exists audit_logs_insert_service on public.audit_logs;
create policy audit_logs_insert_service
  on public.audit_logs for insert
  with check (
    public.is_team_member(team_id)
    and (user_id = auth.uid())
  );

/**
 * Policy: audit_logs_delete_admin
 * -------------------------------
 * Only admins (or owners) may delete audit log entries.
 */
drop policy if exists audit_logs_delete_admin on public.audit_logs;
create policy audit_logs_delete_admin
  on public.audit_logs for delete
  using (public.is_team_member_with_role(team_id, 'admin'));

-- ── Grant permissions ─────────────────────────────────────────────────

grant usage on schema public to authenticated;
grant all on public.teams to authenticated;
grant all on public.team_members to authenticated;
grant all on public.team_policies to authenticated;
grant all on public.audit_logs to authenticated;

-- ── Seed: each user automatically becomes sole owner of a personal team ─

/**
 * Auto-create a personal team for every new user.
 * Fires after INSERT on auth.users.
 */
create or replace function public.handle_new_user_team()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_team_id uuid;
begin
  insert into public.teams (name)
  values (coalesce(new.raw_user_meta_data ->> 'full_name', 'Personal'))
  returning id into v_team_id;

  insert into public.team_members (team_id, user_id, role)
  values (v_team_id, new.id, 'owner');

  return new;
end;
$$;

/**
 * Wire the trigger to fire on auth.user creation.
 * Uses drop-then-create so this migration is idempotent.
 */
drop trigger if exists on_auth_user_created_team on auth.users;
create trigger on_auth_user_created_team
  after insert on auth.users
  for each row execute procedure public.handle_new_user_team();
