-- New customer provisioning includes a usable first central policy. Existing
-- customer policies and bootstrap receipts remain unchanged.
do $migration$
declare definition text;
begin
  select pg_get_functiondef('public.bootstrap_customer(uuid,uuid,text,integer)'::regprocedure) into definition;
  if position('v_record := jsonb_build_object' in definition) = 0 then raise exception 'unexpected bootstrap function definition'; end if;
  definition := replace(definition, 'v_record := jsonb_build_object', 'perform public.publish_runtime_policy(v_team_id, p_user_id, 0, ''{"command_default":"allow","file_default":"allow","url_default":"allow","package_default":"allow","mcp_unknown":"ask","mcp_risky":"deny"}''::jsonb); v_record := jsonb_build_object');
  execute definition;
end;
$migration$;
