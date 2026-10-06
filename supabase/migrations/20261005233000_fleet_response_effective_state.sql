-- Status must reflect an offline command's elapsed TTL even before the
-- endpoint polls/reports again. This read-only projection uses the same
-- expiration semantics as the authenticated command consumer: an undelivered
-- command expires; a delivered/acknowledged command has an unknown outcome.
-- Stored terminal receipts and completion timestamps remain authoritative.
create or replace function public.get_fleet_response_playbook(p_tenant_id uuid, p_run_id uuid)
returns jsonb
language sql stable security definer set search_path = public, pg_temp as $$
  with selected_run as (
    select r.* from public.fleet_response_playbook_runs r
    where r.tenant_id = p_tenant_id and r.id = p_run_id
  ), effective_steps as (
    select s.step_id, s.ordinal, s.command_type, s.command_id, c.expires_at,
      case
        when c.state in ('pending', 'delivered', 'acknowledged')
             and c.expires_at <= statement_timestamp()
          then case when c.state = 'pending' then 'expired' else 'outcome_unknown' end
        else c.state
      end as state,
      case
        when c.state in ('pending', 'delivered', 'acknowledged')
             and c.expires_at <= statement_timestamp() then 'ttl_elapsed'
        else c.result_code
      end as result_code
    from public.fleet_response_playbook_steps s
    join selected_run r on r.id = s.run_id
    join public.fleet_response_commands c on c.id = s.command_id
  )
  select jsonb_build_object(
    'id', r.id,
    'tenant_id', r.tenant_id,
    'actor_user_id', r.actor_user_id,
    'agent_id', r.agent_id,
    'incident_reference', r.incident_id,
    'playbook_id', r.playbook_id,
    'reason', r.reason,
    'state', case
      when r.state = 'running' and p.current_state in ('expired', 'outcome_unknown')
        then case when p.has_applied then 'partial' else p.current_state end
      else r.state
    end,
    'current_step', r.current_step,
    'expires_at', r.expires_at,
    'result_code', case
      when r.state = 'running' and p.current_state in ('expired', 'outcome_unknown')
        then 'ttl_elapsed'
      else r.result_code
    end,
    'created_at', r.created_at,
    'completed_at', r.completed_at,
    'steps', p.steps
  )
  from selected_run r
  cross join lateral (
    select coalesce(jsonb_agg(jsonb_build_object(
      'step_id', s.step_id,
      'ordinal', s.ordinal,
      'command_type', s.command_type,
      'command_id', s.command_id,
      'state', s.state,
      'result_code', s.result_code,
      'expires_at', s.expires_at
    ) order by s.ordinal), '[]'::jsonb) as steps,
      max(s.state) filter (where s.ordinal = r.current_step) as current_state,
      coalesce(bool_or(s.ordinal < r.current_step and s.state = 'succeeded'), false) as has_applied
    from effective_steps s
  ) p;
$$;
revoke all on function public.get_fleet_response_playbook(uuid, uuid)
  from public, anon, authenticated;
grant execute on function public.get_fleet_response_playbook(uuid, uuid) to service_role;
