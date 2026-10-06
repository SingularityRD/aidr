-- The endpoint's applied result is evidence even when the actor can no longer
-- queue the next action (or its tenant queue is full). Keep the command result,
-- step-one receipt and result audit atomic; roll back ONLY the attempted next
-- command/step and mark the playbook partial with a bounded failure code.
-- Credential and command-binding checks remain outside this exception block.
do $migration$
declare
  v_definition text;
  v_start text := '    v_next := public.queue_bounded_fleet_response_command(';
  v_end text := '    set current_step = 2 where id = v_run.id;';
begin
  select pg_get_functiondef('public.advance_fleet_response_playbook_step()'::regprocedure) into v_definition;
  if position('next_step_queue_failed_' in v_definition) > 0 then return; end if;
  if cardinality(string_to_array(v_definition, v_start)) <> 2
     or cardinality(string_to_array(v_definition, v_end)) <> 2 then
    raise exception 'unexpected_response_playbook_advance_definition';
  end if;
  v_definition := replace(v_definition, v_start, '    begin' || E'\n' || v_start);
  execute replace(v_definition, v_end, v_end || E'\n' || '    exception when others then
      update public.fleet_response_playbook_runs
      set state = ''partial'', completed_at = now(),
          result_code = ''next_step_queue_failed_'' || lower(sqlstate)
      where id = v_run.id;
    end;');
end;
$migration$;
