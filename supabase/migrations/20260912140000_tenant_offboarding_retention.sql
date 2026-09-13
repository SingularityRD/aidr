-- Tenant offboarding, data-class retention and legal-hold controls.
--
-- Offboarding deliberately retains the tenant tombstone, phase receipts and
-- this migration's policy snapshot. Database and live object bytes are
-- covered. Backup copies remain governed by the separately approved backup
-- retention/key-destruction process and are never represented as deleted here.

create table public.tenant_data_retention_policies (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  data_class text not null check (data_class in (
    'temporary_exports', 'access_credentials', 'telemetry',
    'endpoint_identity', 'security_intelligence', 'policy_configuration',
    'identity_membership', 'commercial_records', 'security_audit',
    'operational_ephemera'
  )),
  retention_days integer not null check (retention_days between 0 and 3650),
  description text not null check (length(trim(description)) between 1 and 500),
  covers_backups boolean not null default false check (covers_backups = false),
  updated_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id, data_class)
);

create trigger tenant_data_retention_policies_touch_updated_at
before update on public.tenant_data_retention_policies
for each row execute procedure public.touch_updated_at();

create function app.seed_tenant_retention_policies() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  insert into public.tenant_data_retention_policies
    (tenant_id, data_class, retention_days, description)
  values
    (new.id, 'temporary_exports', 0, 'Temporary private export objects and their live storage bytes'),
    (new.id, 'access_credentials', 0, 'API key hashes, enrollment tokens and device authorization sessions'),
    (new.id, 'telemetry', new.retention_days, 'Agent runtime events and incident telemetry'),
    (new.id, 'endpoint_identity', new.retention_days, 'Enrolled endpoint and agent identity records'),
    (new.id, 'security_intelligence', new.retention_days, 'Tenant-scoped URL and file reputation records'),
    (new.id, 'policy_configuration', new.retention_days, 'Runtime policy, revision, rollout and pack metadata'),
    (new.id, 'identity_membership', new.retention_days, 'Tenant/team membership, invitations and pilot admission'),
    (new.id, 'commercial_records', greatest(new.retention_days, 2555), 'Entitlement, subscription and billing records'),
    (new.id, 'security_audit', greatest(new.retention_days, 365), 'Security, administrative and revocation audit evidence'),
    (new.id, 'operational_ephemera', least(new.retention_days, 7), 'Tenant-scoped rate-limit and transient operational state')
  on conflict (tenant_id, data_class) do nothing;
  return new;
end;
$$;
revoke all on function app.seed_tenant_retention_policies() from public, anon, authenticated;

create trigger tenants_seed_retention_policies
after insert on public.tenants
for each row execute function app.seed_tenant_retention_policies();

insert into public.tenant_data_retention_policies
  (tenant_id, data_class, retention_days, description)
select t.id, p.data_class, p.retention_days, p.description
from public.tenants t
cross join lateral (values
  ('temporary_exports', 0, 'Temporary private export objects and their live storage bytes'),
  ('access_credentials', 0, 'API key hashes, enrollment tokens and device authorization sessions'),
  ('telemetry', t.retention_days, 'Agent runtime events and incident telemetry'),
  ('endpoint_identity', t.retention_days, 'Enrolled endpoint and agent identity records'),
  ('security_intelligence', t.retention_days, 'Tenant-scoped URL and file reputation records'),
  ('policy_configuration', t.retention_days, 'Runtime policy, revision, rollout and pack metadata'),
  ('identity_membership', t.retention_days, 'Tenant/team membership, invitations and pilot admission'),
  ('commercial_records', greatest(t.retention_days, 2555), 'Entitlement, subscription and billing records'),
  ('security_audit', greatest(t.retention_days, 365), 'Security, administrative and revocation audit evidence'),
  ('operational_ephemera', least(t.retention_days, 7), 'Tenant-scoped rate-limit and transient operational state')
) as p(data_class, retention_days, description)
on conflict (tenant_id, data_class) do nothing;

-- Commercial entitlement snapshots outlive endpoint identity under the
-- default policy. Preserve the snapshot and clear only its optional agent
-- pointer when the shorter-lived endpoint row is removed.
alter table public.entitlement_snapshots drop constraint if exists entitlement_snapshots_agent_id_fkey;
alter table public.entitlement_snapshots drop constraint if exists snapshots_tenant_agent_fkey;
alter table public.entitlement_snapshots
  add constraint snapshots_tenant_agent_fkey
  foreign key (tenant_id, agent_id) references public.agents(tenant_id, id)
  on delete set null (agent_id);

create table public.tenant_legal_holds (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  hold_reference text not null check (length(trim(hold_reference)) between 1 and 200),
  reason text not null check (length(trim(reason)) between 1 and 2000),
  placed_by uuid not null,
  placed_at timestamptz not null default now(),
  released_by uuid,
  released_at timestamptz,
  release_reason text,
  check (
    (released_at is null and released_by is null and release_reason is null)
    or
    (released_at is not null and released_by is not null and release_reason is not null and length(trim(release_reason)) between 1 and 2000)
  )
);
create unique index tenant_legal_holds_one_active
  on public.tenant_legal_holds(tenant_id) where released_at is null;
create index tenant_legal_holds_history
  on public.tenant_legal_holds(tenant_id, placed_at desc);

create function app.protect_tenant_legal_hold() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(coalesce(new.tenant_id, old.tenant_id)::text, 2606));
  if tg_op = 'DELETE' then
    raise exception 'legal_hold_history_is_immutable' using errcode = '42501';
  end if;
  if tg_op = 'UPDATE' then
    if old.released_at is not null
      or new.id is distinct from old.id
      or new.tenant_id is distinct from old.tenant_id
      or new.hold_reference is distinct from old.hold_reference
      or new.reason is distinct from old.reason
      or new.placed_by is distinct from old.placed_by
      or new.placed_at is distinct from old.placed_at
      or new.released_at is null
      or new.released_by is null
      or new.release_reason is null
    then
      raise exception 'legal_hold_update_must_be_a_single_release' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function app.protect_tenant_legal_hold() from public, anon, authenticated;
create trigger tenant_legal_holds_protect
before insert or update or delete on public.tenant_legal_holds
for each row execute function app.protect_tenant_legal_hold();

create table public.tenant_offboarding_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  requested_by uuid not null,
  requested_at timestamptz not null default now(),
  status text not null default 'requested' check (status in (
    'requested', 'running', 'waiting_retention', 'blocked_legal_hold',
    'completed', 'failed'
  )),
  completed_at timestamptz,
  last_error text,
  backup_scope text not null default 'excluded_external_retention'
    check (backup_scope = 'excluded_external_retention'),
  backup_exception text not null default
    'Backup copies are excluded from this live-data receipt and require separate expiry or key-destruction evidence.',
  check ((status = 'completed') = (completed_at is not null))
);
create unique index tenant_offboarding_one_active
  on public.tenant_offboarding_runs(tenant_id) where status <> 'completed';
create index tenant_offboarding_runs_tenant_history
  on public.tenant_offboarding_runs(tenant_id, requested_at desc);

create table public.tenant_offboarding_phase_receipts (
  run_id uuid not null references public.tenant_offboarding_runs(id) on delete restrict,
  phase_order integer not null check (phase_order between 1 and 100),
  phase text not null,
  data_class text not null,
  operation text not null check (operation in ('delete_records', 'delete_storage_objects')),
  retention_days integer not null check (retention_days between 0 and 3650),
  eligible_at timestamptz not null,
  status text not null default 'pending' check (status in ('pending', 'waiting_retention', 'running', 'completed')),
  rows_deleted bigint not null default 0 check (rows_deleted >= 0),
  attempts integer not null default 0 check (attempts >= 0),
  started_at timestamptz,
  completed_at timestamptz,
  primary key (run_id, phase),
  unique (run_id, phase_order),
  check ((status = 'completed') = (completed_at is not null))
);

alter table public.tenant_data_retention_policies enable row level security;
alter table public.tenant_legal_holds enable row level security;
alter table public.tenant_offboarding_runs enable row level security;
alter table public.tenant_offboarding_phase_receipts enable row level security;
revoke all on public.tenant_data_retention_policies, public.tenant_legal_holds,
  public.tenant_offboarding_runs, public.tenant_offboarding_phase_receipts
  from public, anon, authenticated;
grant select, insert, update on public.tenant_data_retention_policies,
  public.tenant_legal_holds, public.tenant_offboarding_runs,
  public.tenant_offboarding_phase_receipts to service_role;

create function public.request_tenant_offboarding(p_tenant_id uuid, p_requested_by uuid)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_run public.tenant_offboarding_runs;
  v_phase_count integer;
begin
  if p_tenant_id is null or p_requested_by is null then
    raise exception 'tenant_and_requester_required' using errcode = '22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606));
  if not exists (select 1 from public.tenants where id = p_tenant_id) then
    raise exception 'tenant_not_found' using errcode = 'P0002';
  end if;
  select * into v_run from public.tenant_offboarding_runs
   where tenant_id = p_tenant_id
   order by requested_at desc limit 1;
  if found then
    return jsonb_build_object('run_id', v_run.id, 'tenant_id', v_run.tenant_id,
      'status', v_run.status, 'resumed', true, 'backup_scope', v_run.backup_scope,
      'backup_exception', v_run.backup_exception);
  end if;
  select count(*) into v_phase_count from public.tenant_data_retention_policies
   where tenant_id = p_tenant_id;
  if v_phase_count <> 10 then
    raise exception 'retention_policy_incomplete' using errcode = '23514';
  end if;
  update public.tenants set status = 'closing' where id = p_tenant_id and status <> 'closed';
  update public.api_keys set revoked = true where tenant_id = p_tenant_id and not revoked;
  update public.scim_tokens set revoked_at = coalesce(revoked_at,now()) where tenant_id = p_tenant_id;
  update public.delegated_credential_grants set revoked_at = coalesce(revoked_at,now()) where tenant_id = p_tenant_id;
  update public.delegated_credential_receipts
    set state='revoked', revoked_at=coalesce(revoked_at,now())
    where tenant_id=p_tenant_id and state <> 'revoked';
  insert into public.tenant_offboarding_runs(tenant_id, requested_by, status)
  values (p_tenant_id, p_requested_by,
    case when exists(select 1 from public.tenant_legal_holds where tenant_id=p_tenant_id and released_at is null)
      then 'blocked_legal_hold' else 'requested' end)
  returning * into v_run;
  insert into public.tenant_offboarding_phase_receipts
    (run_id, phase_order, phase, data_class, operation, retention_days, eligible_at)
  select v_run.id, c.phase_order, c.phase, c.data_class, c.operation,
    p.retention_days, v_run.requested_at + make_interval(days => p.retention_days)
  from (values
    (1, 'audit_export_objects', 'temporary_exports', 'delete_storage_objects'),
    (2, 'agent_policy_receipts', 'policy_configuration', 'delete_records'),
    (3, 'agent_policy_assignments', 'policy_configuration', 'delete_records'),
    (4, 'events', 'telemetry', 'delete_records'),
    (5, 'entitlement_snapshots', 'commercial_records', 'delete_records'),
    (6, 'api_keys', 'access_credentials', 'delete_records'),
    (7, 'enrollment_tokens', 'access_credentials', 'delete_records'),
    (8, 'device_sessions', 'access_credentials', 'delete_records'),
    (9, 'scim_tokens', 'access_credentials', 'delete_records'),
    (10, 'identity_recovery_codes', 'access_credentials', 'delete_records'),
    (11, 'identity_password_recovery_grants', 'access_credentials', 'delete_records'),
    (12, 'agents', 'endpoint_identity', 'delete_records'),
    (13, 'url_reputation', 'security_intelligence', 'delete_records'),
    (14, 'file_reputation', 'security_intelligence', 'delete_records'),
    (15, 'tenant_runtime_policies', 'policy_configuration', 'delete_records'),
    (16, 'runtime_policy_revisions', 'policy_configuration', 'delete_records'),
    (17, 'team_policies', 'policy_configuration', 'delete_records'),
    (18, 'pack_versions', 'policy_configuration', 'delete_records'),
    (19, 'tenant_identity_policies', 'policy_configuration', 'delete_records'),
    (20, 'subscriptions', 'commercial_records', 'delete_records'),
    (21, 'billing_customers', 'commercial_records', 'delete_records'),
    (22, 'billing_webhook_events', 'commercial_records', 'delete_records'),
    (23, 'entitlements', 'commercial_records', 'delete_records'),
    (24, 'delegated_credential_receipts', 'security_audit', 'delete_records'),
    (25, 'delegated_credential_grants', 'security_audit', 'delete_records'),
    (26, 'revocations', 'security_audit', 'delete_records'),
    (27, 'audit_logs', 'security_audit', 'delete_records'),
    (28, 'admin_audit_logs', 'security_audit', 'delete_records'),
    (29, 'team_invitations', 'identity_membership', 'delete_records'),
    (30, 'pilot_applications', 'identity_membership', 'delete_records'),
    (31, 'scim_group_memberships', 'identity_membership', 'delete_records'),
    (32, 'scim_managed_memberships', 'identity_membership', 'delete_records'),
    (33, 'scim_group_role_mappings', 'identity_membership', 'delete_records'),
    (34, 'scim_groups', 'identity_membership', 'delete_records'),
    (35, 'scim_users', 'identity_membership', 'delete_records'),
    (36, 'team_members', 'identity_membership', 'delete_records'),
    (37, 'tenant_members', 'identity_membership', 'delete_records'),
    (38, 'waitlist_signups', 'identity_membership', 'delete_records'),
    (39, 'rate_limits', 'operational_ephemera', 'delete_records')
  ) as c(phase_order, phase, data_class, operation)
  join public.tenant_data_retention_policies p
    on p.tenant_id = p_tenant_id and p.data_class = c.data_class;
  return jsonb_build_object('run_id', v_run.id, 'tenant_id', v_run.tenant_id,
    'status', v_run.status, 'resumed', false, 'backup_scope', v_run.backup_scope,
    'backup_exception', v_run.backup_exception);
end;
$$;
revoke all on function public.request_tenant_offboarding(uuid, uuid) from public, anon, authenticated;
grant execute on function public.request_tenant_offboarding(uuid, uuid) to service_role;

create function public.run_tenant_offboarding_batch(p_run_id uuid, p_batch_size integer default 100)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_run public.tenant_offboarding_runs;
  v_phase public.tenant_offboarding_phase_receipts;
  v_table text;
  v_order_by text := 'ctid';
  v_rows bigint := 0;
  v_remaining boolean := false;
  v_paths jsonb;
begin
  if p_run_id is null or p_batch_size not between 1 and 1000 then
    raise exception 'invalid_offboarding_batch' using errcode = '22023';
  end if;
  select * into v_run from public.tenant_offboarding_runs where id = p_run_id;
  if not found then raise exception 'offboarding_run_not_found' using errcode = 'P0002'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_run.tenant_id::text, 2606));
  if exists(select 1 from public.tenant_legal_holds where tenant_id=v_run.tenant_id and released_at is null) then
    update public.tenant_offboarding_runs set status='blocked_legal_hold', last_error='active legal hold' where id=p_run_id;
    return jsonb_build_object('run_id',p_run_id,'status','blocked_legal_hold','complete',false);
  end if;
  if v_run.status = 'completed' then
    return jsonb_build_object('run_id',p_run_id,'status','completed','complete',true,
      'backup_scope',v_run.backup_scope,'backup_exception',v_run.backup_exception);
  end if;
  select * into v_phase from public.tenant_offboarding_phase_receipts
   where run_id=p_run_id and status <> 'completed' order by eligible_at, phase_order limit 1;
  if not found then
    update public.teams set name='Deleted tenant', github_org=null, gitlab_group=null where tenant_id=v_run.tenant_id;
    update public.tenants set name='Deleted tenant', created_by=null, status='closed', closed_at=coalesce(closed_at,now())
     where id=v_run.tenant_id;
    update public.tenant_offboarding_runs set status='completed', completed_at=now(), last_error=null where id=p_run_id
     returning * into v_run;
    return jsonb_build_object('run_id',p_run_id,'status','completed','complete',true,
      'backup_scope',v_run.backup_scope,'backup_exception',v_run.backup_exception);
  end if;
  if now() < v_phase.eligible_at then
    update public.tenant_offboarding_phase_receipts set status='waiting_retention' where run_id=p_run_id and phase=v_phase.phase;
    update public.tenant_offboarding_runs set status='waiting_retention',last_error=null where id=p_run_id;
    return jsonb_build_object('run_id',p_run_id,'status','waiting_retention','complete',false,
      'phase',v_phase.phase,'data_class',v_phase.data_class,'eligible_at',v_phase.eligible_at);
  end if;
  update public.tenant_offboarding_runs set status='running',last_error=null where id=p_run_id;
  update public.tenant_offboarding_phase_receipts
    set status='running', attempts=attempts+1, started_at=coalesce(started_at,now())
    where run_id=p_run_id and phase=v_phase.phase;
  if v_phase.operation = 'delete_storage_objects' then
    select coalesce(jsonb_agg(path order by path),'[]'::jsonb) into v_paths from (
      select path from public.audit_export_objects where tenant_id=v_run.tenant_id order by path limit p_batch_size
    ) pending;
    if jsonb_array_length(v_paths)=0 then
      update public.tenant_offboarding_phase_receipts set status='completed',completed_at=now()
       where run_id=p_run_id and phase=v_phase.phase;
      return jsonb_build_object('run_id',p_run_id,'status','running','complete',false,
        'phase',v_phase.phase,'phase_complete',true,'rows_deleted',0);
    end if;
    return jsonb_build_object('run_id',p_run_id,'status','running','complete',false,
      'phase',v_phase.phase,'action','delete_storage_objects','paths',v_paths);
  end if;
  v_table := case v_phase.phase
    when 'agent_policy_receipts' then 'public.agent_policy_receipts'
    when 'agent_policy_assignments' then 'public.agent_policy_assignments'
    when 'events' then 'public.events'
    when 'entitlement_snapshots' then 'public.entitlement_snapshots'
    when 'api_keys' then 'public.api_keys'
    when 'enrollment_tokens' then 'public.enrollment_tokens'
    when 'device_sessions' then 'public.device_sessions'
    when 'scim_tokens' then 'public.scim_tokens'
    when 'identity_recovery_codes' then 'public.identity_recovery_codes'
    when 'identity_password_recovery_grants' then 'public.identity_password_recovery_grants'
    when 'agents' then 'public.agents'
    when 'url_reputation' then 'public.url_reputation'
    when 'file_reputation' then 'public.file_reputation'
    when 'tenant_runtime_policies' then 'public.tenant_runtime_policies'
    when 'runtime_policy_revisions' then 'public.runtime_policy_revisions'
    when 'team_policies' then 'public.team_policies'
    when 'pack_versions' then 'public.pack_versions'
    when 'tenant_identity_policies' then 'public.tenant_identity_policies'
    when 'subscriptions' then 'public.subscriptions'
    when 'billing_customers' then 'public.billing_customers'
    when 'billing_webhook_events' then 'public.billing_webhook_events'
    when 'entitlements' then 'public.entitlements'
    when 'delegated_credential_receipts' then 'public.delegated_credential_receipts'
    when 'delegated_credential_grants' then 'public.delegated_credential_grants'
    when 'revocations' then 'public.revocations'
    when 'audit_logs' then 'public.audit_logs'
    when 'admin_audit_logs' then 'public.admin_audit_logs'
    when 'team_invitations' then 'public.team_invitations'
    when 'pilot_applications' then 'public.pilot_applications'
    when 'scim_group_memberships' then 'public.scim_group_memberships'
    when 'scim_managed_memberships' then 'public.scim_managed_memberships'
    when 'scim_group_role_mappings' then 'public.scim_group_role_mappings'
    when 'scim_groups' then 'public.scim_groups'
    when 'scim_users' then 'public.scim_users'
    when 'team_members' then 'public.team_members'
    when 'tenant_members' then 'public.tenant_members'
    when 'waitlist_signups' then 'public.waitlist_signups'
    when 'rate_limits' then 'public.rate_limits'
    else null end;
  if v_table is null then raise exception 'unknown_offboarding_phase' using errcode='23514'; end if;
  if v_phase.phase='delegated_credential_receipts' then v_order_by := 'delegation_depth desc, ctid'; end if;
  if v_phase.phase='audit_logs' then perform set_config('app.aidr_offboarding_run_id',p_run_id::text,true); end if;
  execute format('delete from %s where ctid in (select ctid from %s where tenant_id=$1 order by %s limit $2)',v_table,v_table,v_order_by)
    using v_run.tenant_id,p_batch_size;
  get diagnostics v_rows = row_count;
  execute format('select exists(select 1 from %s where tenant_id=$1)',v_table) into v_remaining using v_run.tenant_id;
  update public.tenant_offboarding_phase_receipts
    set rows_deleted=rows_deleted+v_rows,
        status=case when v_remaining then 'running' else 'completed' end,
        completed_at=case when v_remaining then null else now() end
    where run_id=p_run_id and phase=v_phase.phase;
  return jsonb_build_object('run_id',p_run_id,'status','running','complete',false,
    'phase',v_phase.phase,'phase_complete',not v_remaining,'rows_deleted',v_rows);
end;
$$;
revoke all on function public.run_tenant_offboarding_batch(uuid, integer) from public, anon, authenticated;
grant execute on function public.run_tenant_offboarding_batch(uuid, integer) to service_role;

create function public.ack_tenant_offboarding_objects(p_run_id uuid, p_paths text[])
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_run public.tenant_offboarding_runs;
  v_rows bigint := 0;
  v_remaining boolean;
begin
  if p_run_id is null or coalesce(cardinality(p_paths),0) not between 1 and 1000
    or exists(select 1 from unnest(p_paths) p where p is null)
  then raise exception 'invalid_offboarding_object_ack' using errcode='22023'; end if;
  select * into v_run from public.tenant_offboarding_runs where id=p_run_id;
  if not found then raise exception 'offboarding_run_not_found' using errcode='P0002'; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_run.tenant_id::text,2606));
  if exists(select 1 from public.tenant_legal_holds where tenant_id=v_run.tenant_id and released_at is null) then
    update public.tenant_offboarding_runs set status='blocked_legal_hold',last_error='active legal hold' where id=p_run_id;
    return jsonb_build_object('run_id',p_run_id,'status','blocked_legal_hold','complete',false,
      'phase','audit_export_objects');
  end if;
  if not exists(
    select 1 from public.tenant_offboarding_phase_receipts
    where run_id=p_run_id and phase='audit_export_objects'
      and status='running' and eligible_at <= now()
  ) then
    raise exception 'offboarding_object_phase_not_active' using errcode='42501';
  end if;
  if exists(select 1 from unnest(p_paths) p where p !~ ('^'||v_run.tenant_id::text||'/[0-9a-f-]{36}[.](csv|json)$')) then
    raise exception 'offboarding_object_path_outside_tenant' using errcode='42501';
  end if;
  delete from public.audit_export_objects where tenant_id=v_run.tenant_id and path=any(p_paths);
  get diagnostics v_rows = row_count;
  select exists(select 1 from public.audit_export_objects where tenant_id=v_run.tenant_id) into v_remaining;
  update public.tenant_offboarding_phase_receipts
   set rows_deleted=rows_deleted+v_rows,
       status=case when v_remaining then 'running' else 'completed' end,
       completed_at=case when v_remaining then null else now() end
   where run_id=p_run_id and phase='audit_export_objects';
  return jsonb_build_object('run_id',p_run_id,'status','running','complete',false,
    'phase','audit_export_objects','phase_complete',not v_remaining,'rows_deleted',v_rows);
end;
$$;
revoke all on function public.ack_tenant_offboarding_objects(uuid, text[]) from public, anon, authenticated;
grant execute on function public.ack_tenant_offboarding_objects(uuid, text[]) to service_role;

-- Normal audit evidence stays append-only. Only the service-only offboarding
-- RPC may delete it, for the bound run and while no legal hold is active.
create or replace function public.reject_audit_mutation()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare v_run_id text := current_setting('app.aidr_offboarding_run_id',true);
begin
  if tg_op='DELETE' and current_user in ('postgres','service_role')
    and v_run_id ~ '^[0-9a-f-]{36}$'
    and exists(
      select 1 from public.tenant_offboarding_runs r
      where r.id=v_run_id::uuid and r.tenant_id=old.tenant_id and r.status='running'
        and not exists(select 1 from public.tenant_legal_holds h where h.tenant_id=r.tenant_id and h.released_at is null)
    )
  then return old; end if;
  raise exception 'audit_logs are append-only';
end;
$$;
revoke all on function public.reject_audit_mutation() from public, anon, authenticated;
