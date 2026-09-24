-- A least-privilege database probe for the dashboard readiness endpoint.
-- The OpenAPI root is intentionally restricted to service_role by the API gateway.
create or replace function public.aidr_readiness_probe()
returns jsonb
language sql
stable
security invoker
set search_path = pg_catalog
as $$ select jsonb_build_object('ok', true) $$;

revoke all on function public.aidr_readiness_probe() from public, authenticated;
grant execute on function public.aidr_readiness_probe() to anon;
