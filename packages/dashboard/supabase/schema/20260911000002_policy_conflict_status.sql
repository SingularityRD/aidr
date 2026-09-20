-- An optimistic version mismatch is a client conflict, not a retriable
-- PostgreSQL serialization failure. PostgREST must answer HTTP 409 immediately.
do $$
declare definition text;
begin
  select pg_get_functiondef('public.publish_runtime_policy(uuid,uuid,bigint,jsonb)'::regprocedure) into definition;
  if position('errcode = ''40001''' in definition) = 0 then
    raise exception 'expected publish_runtime_policy conflict guard is missing';
  end if;
  execute replace(definition, 'errcode = ''40001''', 'errcode = ''PT409''');
end;
$$;
