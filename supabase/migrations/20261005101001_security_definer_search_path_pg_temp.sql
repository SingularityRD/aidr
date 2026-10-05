-- Forward hardening; applied migrations are not edited.
--
-- 1. Every SECURITY DEFINER function in the application schemas (public, app)
--    pins an explicit search_path that ends with pg_temp. Without an explicit
--    pg_temp entry PostgreSQL searches the session's temporary schema FIRST for
--    relations and types, so a caller able to create temp objects could shadow
--    an unqualified table or type used by a privileged function body. Listing
--    pg_temp last makes it the lowest-priority schema.
--    Existing search_path values are preserved (so no name resolution changes);
--    pg_temp is appended. A function with an empty path becomes
--    "pg_catalog, pg_temp". Functions already ending in pg_temp are untouched, so
--    the migration is idempotent. scripts/security-definer-search-path.test.mjs
--    fails for any SECURITY DEFINER function that lacks it after the full chain.
--
-- 2. app.tenant_admission_config (the singleton deployment-mode row) enables row
--    level security with NO policies: deny by default for every non-owner role,
--    in addition to the existing REVOKE ALL. The SECURITY DEFINER admission
--    functions run as the table owner, which RLS does not bind (FORCE is
--    deliberately not set, otherwise the owner-run functions would also be denied).

do $$
declare
  fn record;
  current_path text;
  new_path text;
begin
  for fn in
    select p.oid, p.oid::regprocedure as signature, p.proconfig
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where p.prosecdef
      and n.nspname in ('public', 'app')
      -- Extension-owned functions are managed by their extension.
      and not exists (
        select 1 from pg_depend d
        where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e'
      )
      and not exists (
        select 1 from unnest(coalesce(p.proconfig, array[]::text[])) c
        where c ~* '^search_path=.*pg_temp'
      )
  loop
    select substring(c from '^search_path=(.*)$')
      into current_path
    from unnest(coalesce(fn.proconfig, array[]::text[])) c
    where c like 'search_path=%'
    limit 1;

    if current_path is null or btrim(current_path) in ('', '""') then
      new_path := 'pg_catalog, pg_temp';
    else
      new_path := current_path || ', pg_temp';
    end if;

    execute format('alter function %s set search_path = %s', fn.signature, new_path);
  end loop;
end
$$;

alter table app.tenant_admission_config enable row level security;
-- Intentionally no policy: there is no non-owner access path to this table.
revoke all on app.tenant_admission_config from public, anon, authenticated, service_role;
