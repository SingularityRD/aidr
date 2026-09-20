-- Ordered, non-overlapping policy rollout plans.
--
-- A rollout is deliberately separate from tenant_runtime_policies: the tenant
-- policy remains the fallback while an operator advances one ordered batch at a
-- time.  A target may occur only once in a rollout, and the batch order is
-- represented by constrained ring_order/batch_order columns rather than by an
-- unordered agent array.  A receipt is still an agent-reported load receipt;
-- rollout progress must never be read as host-enforcement attestation.

create table public.policy_rollouts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  version bigint not null,
  status text not null default 'running' check (status in ('running', 'paused', 'completed', 'cancelled')),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz,
  unique (tenant_id, id),
  foreign key (tenant_id, version) references public.runtime_policy_revisions(tenant_id, version) on delete cascade,
  check ((status = 'completed' and completed_at is not null) or status <> 'completed')
);

create trigger policy_rollouts_touch_updated_at
before update on public.policy_rollouts
for each row execute procedure public.touch_updated_at();

create table public.policy_rollout_batches (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  rollout_id uuid not null,
  ring_order integer not null check (ring_order > 0 and ring_order <= 1000),
  batch_order integer not null check (batch_order > 0 and batch_order <= 1000),
  target_count integer not null check (target_count between 1 and 200),
  status text not null default 'pending' check (status in ('pending', 'active', 'completed', 'cancelled')),
  created_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  unique (tenant_id, id),
  unique (tenant_id, id, rollout_id),
  unique (tenant_id, rollout_id, ring_order, batch_order),
  foreign key (tenant_id, rollout_id) references public.policy_rollouts(tenant_id, id) on delete cascade,
  check ((status = 'pending' and started_at is null and completed_at is null)
      or (status = 'active' and started_at is not null and completed_at is null)
      or (status = 'completed' and started_at is not null and completed_at is not null)
      or (status = 'cancelled'))
);

create unique index policy_rollout_one_active_batch
  on public.policy_rollout_batches(tenant_id, rollout_id) where status = 'active';

create table public.policy_rollout_targets (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  rollout_id uuid not null,
  batch_id uuid not null,
  agent_id uuid not null,
  acknowledged_at timestamptz,
  last_receipt_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (batch_id, agent_id),
  -- This is the non-overlap invariant: one agent has one ordered position in a
  -- rollout, even when batches are submitted in separate statements.
  unique (tenant_id, rollout_id, agent_id),
  foreign key (tenant_id, rollout_id) references public.policy_rollouts(tenant_id, id) on delete cascade,
  foreign key (tenant_id, batch_id, rollout_id) references public.policy_rollout_batches(tenant_id, id, rollout_id) on delete cascade,
  foreign key (agent_id, tenant_id) references public.agents(id, tenant_id) on delete cascade
);

create index policy_rollout_targets_progress_idx
  on public.policy_rollout_targets(tenant_id, rollout_id, batch_id);

create function app.enforce_policy_rollout_status() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if tg_op = 'INSERT' and new.status <> 'running' then
    raise exception 'policy_rollout_status_conflict' using errcode = 'PT409';
  end if;
  if tg_op = 'UPDATE' and old.status <> new.status and not (
    (old.status = 'running' and new.status in ('paused', 'completed', 'cancelled'))
    or (old.status = 'paused' and new.status in ('running', 'cancelled'))
  ) then
    raise exception 'policy_rollout_status_conflict' using errcode = 'PT409';
  end if;
  if new.status = 'completed' and (not exists (
    select 1 from public.policy_rollout_batches where tenant_id = new.tenant_id and rollout_id = new.id
  ) or exists (
    select 1 from public.policy_rollout_batches b
    left join app.policy_rollout_target_evidence target
      on target.tenant_id = b.tenant_id and target.batch_id = b.id and target.rollout_id = b.rollout_id
    where b.tenant_id = new.tenant_id and b.rollout_id = new.id
    group by b.id, b.status, b.target_count
    having b.status <> 'completed' or count(target.agent_id) filter (where target.evidence_state = 'current') <> b.target_count
  )) then
    raise exception 'policy_rollout_status_conflict' using errcode = 'PT409';
  end if;
  return new;
end;
$$;
revoke all on function app.enforce_policy_rollout_status() from public, anon, authenticated;
create trigger policy_rollout_status
before insert or update of status on public.policy_rollouts
for each row execute function app.enforce_policy_rollout_status();

alter table public.policy_rollouts enable row level security;
alter table public.policy_rollout_batches enable row level security;
alter table public.policy_rollout_targets enable row level security;
revoke all on public.policy_rollouts, public.policy_rollout_batches, public.policy_rollout_targets from anon, authenticated;
grant all on public.policy_rollouts, public.policy_rollout_batches, public.policy_rollout_targets to service_role;

-- Only contiguous batches may be stored, and only completed predecessors can
-- become active. This protects ordering even if a trusted worker updates a batch
-- directly instead of using the RPC below.
create function app.enforce_policy_rollout_batch_order() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_parent_status text;
begin
  if tg_op = 'INSERT' then
    select status into v_parent_status from public.policy_rollouts
     where tenant_id = new.tenant_id and id = new.rollout_id for update;
    if v_parent_status is distinct from 'running' or exists (
      select 1 from public.policy_rollout_batches successor
       where successor.tenant_id = new.tenant_id and successor.rollout_id = new.rollout_id
         and (successor.ring_order, successor.batch_order) > (new.ring_order, new.batch_order)
         and successor.status in ('active', 'completed')
    ) then
      raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
    end if;
  end if;
  if tg_op = 'INSERT' and new.status = 'completed' then
    raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
  end if;
  if tg_op = 'UPDATE' and old.status <> new.status and not (
    (old.status = 'pending' and new.status in ('active', 'cancelled'))
    or (old.status = 'active' and new.status in ('completed', 'cancelled'))
  ) then
    raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
  end if;
  if tg_op = 'UPDATE' and (new.tenant_id <> old.tenant_id or new.rollout_id <> old.rollout_id) then
    raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
  end if;
  if tg_op = 'UPDATE' and new.target_count <> old.target_count then
    raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
  end if;
  if tg_op = 'UPDATE' and (new.ring_order <> old.ring_order or new.batch_order <> old.batch_order) then
    raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
  end if;
  if new.status = 'completed' and (
    select count(*) from app.policy_rollout_target_evidence
     where tenant_id = new.tenant_id and batch_id = new.id and evidence_state = 'current'
  ) <> new.target_count then
    raise exception 'policy_rollout_receipts_unconfirmed' using errcode = 'PT409';
  end if;
  if new.status = 'active' and exists (
    select 1 from public.policy_rollout_batches b
    left join app.policy_rollout_target_evidence t on t.tenant_id = b.tenant_id and t.batch_id = b.id
    where b.tenant_id = new.tenant_id and b.rollout_id = new.rollout_id
      and (b.ring_order, b.batch_order) < (new.ring_order, new.batch_order)
    group by b.id, b.target_count
    having count(t.agent_id) filter (where t.evidence_state = 'current') <> b.target_count
  ) then
    raise exception 'policy_rollout_receipts_unconfirmed' using errcode = 'PT409';
  end if;
  if new.status in ('pending', 'active', 'completed') then
    if new.batch_order > 1 and not exists (
      select 1
        from public.policy_rollout_batches previous
       where previous.tenant_id = new.tenant_id
         and previous.rollout_id = new.rollout_id
         and previous.ring_order = new.ring_order
         and previous.batch_order = new.batch_order - 1
         and previous.id <> new.id
    ) then
      raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
    end if;
    if new.ring_order > 1 and new.batch_order = 1 then
      if not exists (
        select 1
          from public.policy_rollout_batches previous
         where previous.tenant_id = new.tenant_id
           and previous.rollout_id = new.rollout_id
           and previous.ring_order = new.ring_order - 1
           and previous.id <> new.id
      ) or exists (
        select 1
          from generate_series(1, new.ring_order - 1) expected(ring_order)
         where not exists (
           select 1
             from public.policy_rollout_batches previous
            where previous.tenant_id = new.tenant_id
              and previous.rollout_id = new.rollout_id
              and previous.ring_order = expected.ring_order
              and previous.batch_order = 1
              and previous.id <> new.id
         )
      ) then
        raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
      end if;
    end if;
    if new.status in ('active', 'completed') and exists (
      select 1
        from public.policy_rollout_batches previous
       where previous.tenant_id = new.tenant_id
         and previous.rollout_id = new.rollout_id
         and (previous.ring_order, previous.batch_order) < (new.ring_order, new.batch_order)
         and previous.status <> 'completed'
         and previous.id <> new.id
    ) then
      raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function app.enforce_policy_rollout_batch_order() from public, anon, authenticated;
create trigger policy_rollout_batch_order
before insert or update on public.policy_rollout_batches
for each row execute function app.enforce_policy_rollout_batch_order();

-- A global publication or an ordinary targeted stage supersedes any running
-- rollout. Remove only assignments owned by that rollout; unrelated targeted
-- stages keep their existing compatibility semantics.
create function app.cancel_policy_rollouts(p_tenant_id uuid) returns void
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  -- Lock parents BEFORE deleting assignments: a racing resume may have activated
  -- another batch while holding its parent row. Its assignment must be removed
  -- after that transaction commits, never missed by an earlier DELETE snapshot.
  update public.policy_rollouts set status = 'cancelled', updated_at = now()
   where tenant_id = p_tenant_id and status in ('running', 'paused');
  update public.policy_rollout_batches set status = 'cancelled', completed_at = coalesce(completed_at, now())
   where tenant_id = p_tenant_id and status <> 'completed'
     and rollout_id in (select id from public.policy_rollouts where tenant_id = p_tenant_id and status = 'cancelled');
  delete from public.agent_policy_assignments assignment
   using public.policy_rollout_targets target, public.policy_rollouts rollout
   where assignment.tenant_id = p_tenant_id and target.tenant_id = p_tenant_id
     and target.agent_id = assignment.agent_id and target.rollout_id = rollout.id
     and rollout.tenant_id = p_tenant_id and rollout.status = 'cancelled'
     and assignment.version = rollout.version;
end;
$$;
revoke all on function app.cancel_policy_rollouts(uuid) from public, anon, authenticated;

-- Add the hook to the original publication and stage CAS functions without
-- duplicating/replacing their authorization or CAS bodies. Fail deployment on
-- dependency drift rather than silently install a partial cancellation path.
do $migration$
declare definition text;
begin
  select pg_get_functiondef('public.publish_runtime_policy(uuid,uuid,bigint,jsonb)'::regprocedure) into definition;
  if position('delete from public.agent_policy_assignments where tenant_id = p_tenant_id; return result;' in definition) = 0 then
    raise exception 'unexpected publish function definition';
  end if;
  definition := replace(definition,
    'delete from public.agent_policy_assignments where tenant_id = p_tenant_id; return result;',
    'perform app.cancel_policy_rollouts(p_tenant_id); delete from public.agent_policy_assignments where tenant_id = p_tenant_id; return result;');
  execute definition;
end;
$migration$;

do $migration$
declare definition text;
begin
  select pg_get_functiondef('public.stage_runtime_policy(uuid,uuid,bigint,bigint,jsonb,uuid[])'::regprocedure) into definition;
  if position('v_version := v_latest + 1;' in definition) = 0 then
    raise exception 'unexpected stage function definition';
  end if;
  definition := replace(definition,
    'v_version := v_latest + 1;',
    'perform app.cancel_policy_rollouts(p_tenant_id); v_version := v_latest + 1;');
  execute definition;
end;
$migration$;

-- The API sends a normalized ring list:
-- [{"ring_order":1,"batches":[{"batch_order":1,"agent_ids":["..."]}]}].
-- Validation and assignment of the first batch happen in one transaction.  The
-- target uniqueness constraint is intentionally backed by the same transaction
-- so a partial plan can never be acknowledged as a complete rollout.
create function public.create_policy_rollout(
  p_tenant_id uuid,
  p_user_id uuid,
  p_expected_version bigint,
  p_expected_revision_version bigint,
  p_policy jsonb,
  p_rings jsonb
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_current bigint;
  v_latest bigint;
  v_version bigint;
  v_rollout public.policy_rollouts%rowtype;
  v_ring jsonb;
  v_batch jsonb;
  v_agent jsonb;
  v_ring_order integer;
  v_batch_order integer;
  v_expected_ring integer := 1;
  v_expected_batch integer;
  v_agent_id uuid;
  v_batch_id uuid;
  v_first_batch_id uuid;
  v_ring_count integer := 0;
  v_batch_count integer := 0;
  v_target_count integer := 0;
  v_ring_batches jsonb;
begin
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
     where m.tenant_id = p_tenant_id and m.user_id = p_user_id
       and m.role in ('owner', 'admin')
       and (m.expires_at is null or m.expires_at > now())
       and t.status = 'active'
  ) then
    raise exception 'policy_forbidden' using errcode = '42501';
  end if;
  if p_expected_version is null or p_expected_version < 0
     or p_expected_revision_version is null or p_expected_revision_version < p_expected_version
     or p_policy is null or jsonb_typeof(p_policy) <> 'object'
     or octet_length(p_policy::text) > 65536
     or p_rings is null or jsonb_typeof(p_rings) <> 'array'
     or jsonb_array_length(p_rings) < 1 or jsonb_array_length(p_rings) > 100 then
    raise exception 'invalid_policy_rollout' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 911));
  select version into v_current from public.tenant_runtime_policies where tenant_id = p_tenant_id;
  if coalesce(v_current, 0) <> p_expected_version then
    raise exception 'policy_version_conflict' using errcode = 'PT409';
  end if;
  select coalesce(max(version), 0) into v_latest
    from public.runtime_policy_revisions where tenant_id = p_tenant_id;
  if v_latest <> p_expected_revision_version then
    raise exception 'policy_revision_conflict' using errcode = 'PT409';
  end if;

  v_version := v_latest + 1;
  insert into public.runtime_policy_revisions(tenant_id, version, policy, updated_by)
  values (p_tenant_id, v_version, p_policy, p_user_id);
  insert into public.policy_rollouts(tenant_id, version, status, created_by)
  values (p_tenant_id, v_version, 'running', p_user_id)
  returning * into v_rollout;

  for v_ring in select value from jsonb_array_elements(p_rings) loop
    if jsonb_typeof(v_ring) <> 'object'
       or (v_ring->>'ring_order') is null
       or (v_ring->>'ring_order') !~ '^[1-9][0-9]{0,3}$'
       or jsonb_typeof(v_ring->'batches') is distinct from 'array'
       or jsonb_array_length(v_ring->'batches') < 1
       or jsonb_array_length(v_ring->'batches') > 1000 then
      raise exception 'invalid_policy_rollout' using errcode = '22023';
    end if;
    v_ring_order := (v_ring->>'ring_order')::integer;
    if v_ring_order <> v_expected_ring then
      raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
    end if;
    v_expected_ring := v_expected_ring + 1;
    v_ring_count := v_ring_count + 1;
    v_expected_batch := 1;

    for v_batch in select value from jsonb_array_elements(v_ring->'batches') loop
      if jsonb_typeof(v_batch) <> 'object'
         or (v_batch->>'batch_order') is null
         or (v_batch->>'batch_order') !~ '^[1-9][0-9]{0,3}$'
         or jsonb_typeof(v_batch->'agent_ids') is distinct from 'array'
         or jsonb_array_length(v_batch->'agent_ids') < 1
         or jsonb_array_length(v_batch->'agent_ids') > 200 then
        raise exception 'invalid_policy_rollout' using errcode = '22023';
      end if;
      v_batch_order := (v_batch->>'batch_order')::integer;
      if v_batch_order <> v_expected_batch then
        raise exception 'policy_rollout_order_conflict' using errcode = 'PT409';
      end if;
      v_expected_batch := v_expected_batch + 1;
      v_batch_count := v_batch_count + 1;
      if v_batch_count > 1000 or v_target_count + jsonb_array_length(v_batch->'agent_ids') > 20000 then
        raise exception 'invalid_policy_rollout' using errcode = '22023';
      end if;

      insert into public.policy_rollout_batches
        (tenant_id, rollout_id, ring_order, batch_order, target_count, status, started_at)
      values
        (p_tenant_id, v_rollout.id, v_ring_order, v_batch_order, jsonb_array_length(v_batch->'agent_ids'),
         case when v_first_batch_id is null then 'active' else 'pending' end,
         case when v_first_batch_id is null then now() else null end)
      returning id into v_batch_id;
      if v_first_batch_id is null then v_first_batch_id := v_batch_id; end if;

      for v_agent in select value from jsonb_array_elements(v_batch->'agent_ids') loop
        if jsonb_typeof(v_agent) <> 'string'
           or (v_agent #>> '{}') !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
          raise exception 'invalid_policy_rollout_agents' using errcode = '22023';
        end if;
        v_agent_id := (v_agent #>> '{}')::uuid;
        if not exists (select 1 from public.agents where id = v_agent_id and tenant_id = p_tenant_id) then
          raise exception 'invalid_policy_rollout_agents' using errcode = '22023';
        end if;
        if exists (
          select 1 from public.policy_rollout_targets t
           where t.tenant_id = p_tenant_id and t.rollout_id = v_rollout.id and t.agent_id = v_agent_id
        ) then
          raise exception 'policy_rollout_overlap' using errcode = 'PT409';
        end if;
        if exists (
          select 1
            from public.policy_rollout_targets t
            join public.policy_rollouts r on r.tenant_id = t.tenant_id and r.id = t.rollout_id
           where t.tenant_id = p_tenant_id and t.agent_id = v_agent_id
             and r.status in ('running', 'paused')
        ) then
          raise exception 'policy_rollout_overlap' using errcode = 'PT409';
        end if;
        insert into public.policy_rollout_targets(tenant_id, rollout_id, batch_id, agent_id)
        values (p_tenant_id, v_rollout.id, v_batch_id, v_agent_id);
        v_target_count := v_target_count + 1;
      end loop;

      -- Keep the first batch's targets on the same policy selection path as the
      -- existing targeted-stage API. Later batches remain pending until all
      -- first-batch receipts are accepted.
      if v_batch_id = v_first_batch_id then
        insert into public.agent_policy_assignments(tenant_id, agent_id, version, assigned_by)
        select p_tenant_id, t.agent_id, v_version, p_user_id
          from public.policy_rollout_targets t
         where t.tenant_id = p_tenant_id and t.rollout_id = v_rollout.id and t.batch_id = v_batch_id
        on conflict (agent_id) do update
          set version = excluded.version, assigned_by = excluded.assigned_by, assigned_at = now();
      end if;
    end loop;
  end loop;

  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
  values (p_user_id, p_tenant_id, 'policy.rollout.create',
    jsonb_build_object('rollout_id', v_rollout.id, 'version', v_version,
      'ring_count', v_ring_count, 'batch_count', v_batch_count, 'target_count', v_target_count));

  select jsonb_build_object(
    'targeted', v_target_count, 'current', 0, 'stale', 0, 'unknown', v_target_count,
    'observed_ack_percent', 0, 'receipt_type', 'agent_reported_policy_loaded'
  ) into v_ring_batches;
  return jsonb_build_object(
    'rollout_id', v_rollout.id, 'version', v_version, 'status', v_rollout.status,
    'ring_count', v_ring_count, 'batch_count', v_batch_count,
    'target_count', v_target_count, 'rollout_progress', v_ring_batches
  );
end;
$$;
revoke all on function public.create_policy_rollout(uuid, uuid, bigint, bigint, jsonb, jsonb) from public, anon, authenticated;
grant execute on function public.create_policy_rollout(uuid, uuid, bigint, bigint, jsonb, jsonb) to service_role;

-- Compact, key-sorted JSON for the string/list runtime policy vocabulary. Kept
-- recursive for additive policy objects; equality is fail-closed for any future
-- numeric representation that differs from the Edge canonicalPolicy encoder.
create function app.policy_rollout_canonical_json(value jsonb) returns text
language sql immutable strict set search_path = public, pg_temp as $$
  select case jsonb_typeof(value)
    when 'object' then '{' || coalesce((select string_agg(to_jsonb(key)::text || ':' || app.policy_rollout_canonical_json(val), ',' order by key collate "C") from jsonb_each(value) e(key, val)), '') || '}'
    when 'array' then '[' || coalesce((select string_agg(app.policy_rollout_canonical_json(val), ',' order by ord) from jsonb_array_elements(value) with ordinality e(val, ord)), '') || ']'
    else value::text end;
$$;
revoke all on function app.policy_rollout_canonical_json(jsonb) from public, anon, authenticated;

-- Evidence is live, not a sticky acknowledgement bit. Pending targets and
-- missing/deleted receipts are unknown; superseded assignments are outdated.
create view app.policy_rollout_target_evidence as
select t.*, case
  when t.acknowledged_at is null or receipt.agent_id is null then 'unknown'
  when assignment.version is distinct from r.version or receipt.version <> r.version
    or receipt.received_at < b.started_at
    or receipt.policy_sha256 <> encode(sha256(convert_to(app.policy_rollout_canonical_json(revision.policy), 'UTF8')), 'hex') then 'outdated'
  when t.last_receipt_at is null or t.last_receipt_at < clock_timestamp() - interval '5 minutes'
    or receipt.received_at < clock_timestamp() - interval '5 minutes'
    or receipt.received_at > clock_timestamp() then 'stale'
  else 'current' end as evidence_state
from public.policy_rollout_targets t
join public.policy_rollouts r on r.tenant_id = t.tenant_id and r.id = t.rollout_id
join public.policy_rollout_batches b on b.tenant_id = t.tenant_id and b.id = t.batch_id
join public.runtime_policy_revisions revision on revision.tenant_id = r.tenant_id and revision.version = r.version
left join public.agent_policy_assignments assignment on assignment.tenant_id = t.tenant_id and assignment.agent_id = t.agent_id
left join public.agent_policy_receipts receipt on receipt.tenant_id = t.tenant_id and receipt.agent_id = t.agent_id;
revoke all on app.policy_rollout_target_evidence from public, anon, authenticated;

-- Read-only progress is computed from receipts and never uses a host-side claim
-- of enforcement. The five-minute freshness window matches policy-management's
-- existing stale receipt classification.
create function public.read_policy_rollout_progress(
  p_tenant_id uuid,
  p_rollout_id uuid default null
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_rollout public.policy_rollouts%rowtype;
  v_rings jsonb;
  v_progress jsonb;
begin
  select * into v_rollout
    from public.policy_rollouts
   where tenant_id = p_tenant_id and (p_rollout_id is null or id = p_rollout_id)
   order by created_at desc limit 1;
  if not found then
    return jsonb_build_object(
      'rollout_id', null, 'status', 'none', 'version', null,
      'rings', '[]'::jsonb, 'receipt_type', 'agent_reported_policy_loaded',
      'rollout_progress', jsonb_build_object(
        'targeted', 0, 'current', 0, 'stale', 0, 'unknown', 0,
        'observed_ack_percent', 0
      )
    );
  end if;

  with batch_stats as (
    select b.ring_order, b.batch_order, b.status, b.target_count as targeted,
      count(t.agent_id) filter (where t.evidence_state = 'current')::integer as fresh_count,
      count(t.agent_id) filter (where t.evidence_state = 'stale')::integer as stale_count,
      count(t.agent_id) filter (where t.evidence_state = 'outdated')::integer as outdated_count,
      (b.target_count - count(t.agent_id) + count(t.agent_id) filter (where t.evidence_state = 'unknown'))::integer as unknown_count
      from public.policy_rollout_batches b
      left join app.policy_rollout_target_evidence t
        on t.tenant_id = b.tenant_id and t.batch_id = b.id and t.rollout_id = b.rollout_id
     where b.tenant_id = p_tenant_id and b.rollout_id = v_rollout.id
     group by b.ring_order, b.batch_order, b.status, b.target_count
  ), ring_stats as (
    select ring_order, sum(targeted) as targeted, sum(fresh_count) as fresh_count,
      sum(stale_count) as stale_count, sum(outdated_count) as outdated_count, sum(unknown_count) as unknown_count,
      jsonb_agg(jsonb_build_object(
        'batch_order', batch_order, 'status', status, 'targeted', targeted,
        'current', fresh_count, 'stale', stale_count, 'outdated', outdated_count, 'unknown', unknown_count,
        'receipt_type', 'agent_reported_policy_loaded'
      ) order by batch_order) as batches
      from batch_stats group by ring_order
  )
  select coalesce(jsonb_agg(jsonb_build_object('ring_order', ring_order, 'batches', batches,
    'targeted', targeted, 'current', fresh_count, 'stale', stale_count, 'outdated', outdated_count, 'unknown', unknown_count,
    'observed_ack_percent', round(fresh_count * 100.0 / targeted, 2), 'receipt_type', 'agent_reported_policy_loaded')
    order by ring_order), '[]'::jsonb),
    jsonb_build_object('targeted', coalesce(sum(targeted), 0), 'current', coalesce(sum(fresh_count), 0),
      'stale', coalesce(sum(stale_count), 0), 'outdated', coalesce(sum(outdated_count), 0), 'unknown', coalesce(sum(unknown_count), 0),
      'observed_ack_percent', coalesce(round(sum(fresh_count) * 100.0 / nullif(sum(targeted), 0), 2), 0),
      'receipt_type', 'agent_reported_policy_loaded')
    into v_rings, v_progress from ring_stats;

  return jsonb_build_object(
    'rollout_id', v_rollout.id, 'version', v_rollout.version, 'status', v_rollout.status,
    'rings', v_rings, 'rollout_progress', v_progress,
    'receipt_type', 'agent_reported_policy_loaded'
  );
end;
$$;
revoke all on function public.read_policy_rollout_progress(uuid, uuid) from public, anon, authenticated;
grant execute on function public.read_policy_rollout_progress(uuid, uuid) to service_role;

-- Advance only after the active batch is fully acknowledged. This helper is
-- also called by the resume trigger below so receipts accepted while paused are
-- not lost when an operator resumes the plan.
create function app.advance_policy_rollout(p_tenant_id uuid, p_rollout_id uuid, p_batch_id uuid)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_rollout public.policy_rollouts%rowtype;
  v_batch public.policy_rollout_batches%rowtype;
  v_next public.policy_rollout_batches%rowtype;
begin
  select * into v_rollout from public.policy_rollouts
   where tenant_id = p_tenant_id and id = p_rollout_id for update;
  if not found or v_rollout.status <> 'running' then return; end if;
  select * into v_batch from public.policy_rollout_batches
   where tenant_id = p_tenant_id and id = p_batch_id and rollout_id = p_rollout_id
     and status = 'active' for update;
  if not found then return; end if;
  -- Every released cohort must still have complete, fresh, confirmed evidence.
  -- The immutable count prevents deleted agents from shrinking the denominator.
  if exists (
    select 1 from public.policy_rollout_batches b
    left join app.policy_rollout_target_evidence t on t.tenant_id = b.tenant_id and t.batch_id = b.id
    where b.tenant_id = p_tenant_id and b.rollout_id = p_rollout_id
      and (b.ring_order, b.batch_order) <= (v_batch.ring_order, v_batch.batch_order)
    group by b.id, b.target_count
    having count(t.agent_id) filter (where t.evidence_state = 'current') <> b.target_count
  ) then return; end if;

  update public.policy_rollout_batches
     set status = 'completed', completed_at = now()
   where tenant_id = p_tenant_id and id = p_batch_id;
  select * into v_next from public.policy_rollout_batches
   where tenant_id = p_tenant_id and rollout_id = p_rollout_id and status = 'pending'
   order by ring_order, batch_order limit 1;
  if found then
    update public.policy_rollout_batches set status = 'active', started_at = now()
     where tenant_id = p_tenant_id and id = v_next.id;
    insert into public.agent_policy_assignments(tenant_id, agent_id, version, assigned_by)
    select p_tenant_id, target.agent_id, v_rollout.version, v_rollout.created_by
      from public.policy_rollout_targets target
     where target.tenant_id = p_tenant_id and target.batch_id = v_next.id
    on conflict (agent_id) do update
      set version = excluded.version, assigned_by = excluded.assigned_by, assigned_at = now();
  else
    update public.policy_rollouts set status = 'completed', completed_at = now()
     where tenant_id = p_tenant_id and id = p_rollout_id;
  end if;
end;
$$;
revoke all on function app.advance_policy_rollout(uuid, uuid, uuid) from public, anon, authenticated;

create function app.resume_policy_rollout() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_batch public.policy_rollout_batches%rowtype;
begin
  if new.status = 'running' and old.status = 'paused' then
    for v_batch in select * from public.policy_rollout_batches
     where tenant_id = new.tenant_id and rollout_id = new.id and status = 'active'
    loop
      perform app.advance_policy_rollout(new.tenant_id, new.id, v_batch.id);
    end loop;
  end if;
  return new;
end;
$$;
revoke all on function app.resume_policy_rollout() from public, anon, authenticated;
create trigger policy_rollouts_resume
after update of status on public.policy_rollouts
for each row execute function app.resume_policy_rollout();

-- Extend receipt recording without changing its existing boolean contract. An
-- accepted receipt marks the active or paused batch target. Once every target
-- in a running batch has reported, the next ordered batch is activated atomically.
create or replace function public.record_policy_receipt(p_key_hash text, p_version bigint, p_policy_sha256 text)
returns boolean language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_key public.api_keys;
  v_recorded boolean;
  v_batch public.policy_rollout_batches%rowtype;
  v_rollout public.policy_rollouts%rowtype;
begin
  select * into v_key from public.api_keys
   where not revoked and (key_hash = p_key_hash
      or (previous_hash = p_key_hash and previous_hash_expires_at > now()))
   order by (key_hash = p_key_hash) desc limit 1 for share;
  if not found or v_key.agent_id is null then return false; end if;
  if not exists (
    select 1 from public.tenant_members m join public.tenants t on t.id = m.tenant_id
     where m.user_id = v_key.user_id and m.tenant_id = v_key.tenant_id
       and (m.expires_at is null or m.expires_at > now()) and t.status = 'active'
  ) then return false; end if;
  if p_policy_sha256 is null or p_policy_sha256 !~ '^[a-f0-9]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended(v_key.tenant_id::text, 911));
  if not exists (select 1 from public.runtime_policy_revisions
    where tenant_id = v_key.tenant_id and version = p_version
      and encode(sha256(convert_to(app.policy_rollout_canonical_json(policy), 'UTF8')), 'hex') = p_policy_sha256
  ) then return false; end if;
  if p_version is distinct from coalesce((select version from public.agent_policy_assignments
       where tenant_id = v_key.tenant_id and agent_id = v_key.agent_id),
      (select version from public.tenant_runtime_policies where tenant_id = v_key.tenant_id), 0) then return false; end if;

  insert into public.agent_policy_receipts(tenant_id, agent_id, version, policy_sha256)
  values (v_key.tenant_id, v_key.agent_id, p_version, p_policy_sha256)
  on conflict (agent_id) do update
    set version = excluded.version, policy_sha256 = excluded.policy_sha256, received_at = now();
  -- Exact current assignment was checked under the publication lock. A cancelled
  -- rollout can legitimately return an agent to an older tenant fallback.
  v_recorded := found;
  if not v_recorded then return false; end if;

  -- Lock the rollout before its batch. Resume uses the same parent-then-child
  -- order, so an acknowledgement racing a resume cannot deadlock.
  select r.* into v_rollout
    from public.policy_rollouts r
    join public.policy_rollout_batches b
      on b.tenant_id = r.tenant_id and b.rollout_id = r.id and b.status in ('active', 'completed')
    join public.policy_rollout_targets target
      on target.tenant_id = b.tenant_id and target.batch_id = b.id and target.rollout_id = b.rollout_id
   where r.tenant_id = v_key.tenant_id and r.version = p_version
     and r.status in ('running', 'paused', 'completed') and target.agent_id = v_key.agent_id
     and exists (
       select 1 from public.agent_policy_assignments assignment
        where assignment.tenant_id = r.tenant_id and assignment.agent_id = v_key.agent_id
          and assignment.version = p_version
     )
   order by r.created_at desc limit 1
   for update of r;
  if found then
    select b.* into v_batch
      from public.policy_rollout_batches b
      join public.policy_rollout_targets target
        on target.tenant_id = b.tenant_id and target.batch_id = b.id and target.rollout_id = b.rollout_id
     where b.tenant_id = v_rollout.tenant_id and b.rollout_id = v_rollout.id
       and b.status in ('active', 'completed') and target.agent_id = v_key.agent_id
     for update;
    if found then
      update public.policy_rollout_targets
         set acknowledged_at = coalesce(acknowledged_at, now()), last_receipt_at = now()
       where tenant_id = v_key.tenant_id and batch_id = v_batch.id and agent_id = v_key.agent_id;
      if v_rollout.status = 'running' then
        select * into v_batch from public.policy_rollout_batches
         where tenant_id = v_rollout.tenant_id and rollout_id = v_rollout.id and status = 'active';
        if found then perform app.advance_policy_rollout(v_batch.tenant_id, v_batch.rollout_id, v_batch.id); end if;
      end if;
    end if;
  end if;
  return true;
end;
$$;
revoke all on function public.record_policy_receipt(text, bigint, text) from public, anon, authenticated;
grant execute on function public.record_policy_receipt(text, bigint, text) to service_role;
