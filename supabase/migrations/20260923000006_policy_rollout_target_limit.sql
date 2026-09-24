-- Keep the RPC cap aligned with policy-management's 64 KiB request limit.
do $migration$
declare definition text;
begin
  select pg_get_functiondef('public.create_policy_rollout(uuid,uuid,bigint,bigint,jsonb,jsonb)'::regprocedure)
    into definition;
  if position('> 20000 then' in definition) > 0 then
    definition := replace(definition, '> 20000 then', '> 1667 then');
  elsif position('> 1667 then' in definition) = 0 then
    raise exception 'unexpected create_policy_rollout target limit';
  end if;
  execute definition;
end;
$migration$;
