\pset footer off
\pset format unaligned
\pset tuples_only on
\pset fieldsep '|'
select 'server_version|' || current_setting('server_version');
select 'aidr_migrations|' || count(*) || '|' || max(name) || '|' || md5(string_agg(name||sha256, '' order by name)) from public.aidr_schema_migrations;
-- per-table row count + content hash for every application/auth/storage/vault table
select format('select %L || ''|'' || count(*) || ''|'' || coalesce(md5(string_agg(md5(t::text), '''' order by md5(t::text))), ''empty'') from %I.%I t', 'tbl|' || n.nspname || '.' || c.relname, n.nspname, c.relname)
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p') and n.nspname in ('public','app','auth','storage','vault','supabase_functions')
order by n.nspname, c.relname \gexec
select 'rls_tables_enabled|' || count(*) filter (where c.relrowsecurity) || '|of|' || count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r';
select 'rls_tables_disabled|' || coalesce(string_agg(c.relname, ',' order by c.relname), '') from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r' and not c.relrowsecurity;
select 'policies|' || count(*) || '|' || md5(string_agg(schemaname||tablename||policyname||coalesce(qual,'')||coalesce(with_check,''), '' order by schemaname, tablename, policyname)) from pg_policies;
select 'functions_hash|' || count(*) || '|' || md5(string_agg(p.oid::regprocedure::text || md5(p.prosrc) || p.prosecdef::text || coalesce(array_to_string(p.proconfig, ','), ''), '' order by p.oid::regprocedure::text)) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('public','app');
select 'grants_hash|' || md5(string_agg(grantee||table_schema||table_name||privilege_type, '' order by grantee, table_schema, table_name, privilege_type)) from information_schema.role_table_grants where table_schema in ('public','app','storage');
\set QUIET on
do $$ declare ok boolean; begin select decrypted_secret = 'drill-vault-secret-value-6f3c' into ok from vault.decrypted_secrets where name = 'drill_secret'; raise notice 'vault_secret|%', ok; exception when others then raise notice 'vault_secret|error: %', sqlerrm; end $$;
select 'sentinel|' || count(*) || '|' || max(id) || '|' || max(written_at) from public.drill_sentinel;
-- RLS behaviour: anon sees nothing; an authenticated user sees only own tenant data
select 'anon_select_privileges|' || count(*) filter (where has_table_privilege('anon', c.oid, 'SELECT')) || '|of|' || count(*) || '|' || coalesce(string_agg(c.relname, ',' order by c.relname) filter (where has_table_privilege('anon', c.oid, 'SELECT')), '') from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r';
select set_config('drill.uid', (select id::text from auth.users where email = 'drill-user-1@drill.invalid'), false) \g /dev/null
begin;
select set_config('request.jwt.claims', json_build_object('sub', current_setting('drill.uid'), 'role', 'authenticated', 'aal', 'aal1', 'iat', extract(epoch from now())::int)::text, true) \g /dev/null
set local role authenticated;
select 'user1_visible|tenants=' || (select count(*) from public.tenants) || '|teams=' || (select count(*) from public.teams) || '|audit_logs=' || (select count(*) from public.audit_logs) || '|foreign_audit=' || (select count(*) from public.audit_logs a where not exists (select 1 from public.tenant_members m where m.tenant_id = a.tenant_id and m.user_id = current_setting('drill.uid')::uuid)) || '|storage_objects=' || (select count(*) from storage.objects);
rollback;
select 'extensions|' || string_agg(extname || '=' || extversion, ',' order by extname) from pg_extension;
select 'extensions_behind|' || coalesce(string_agg(e.extname || ':' || e.extversion || '->' || a.default_version, ',' order by e.extname), '') from pg_extension e join pg_available_extensions a on a.name = e.extname where a.default_version <> e.extversion;
select 'db_size_bytes|' || sum(pg_database_size(datname)) from pg_database;
select 'collation_mismatch|' || coalesce(string_agg(datname, ','), '') from pg_database where datcollversion is distinct from pg_database_collation_actual_version(oid) and datallowconn;
