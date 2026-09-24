// Run only against a disposable local Supabase DB after migrations. Rolls back.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name a disposable Supabase db container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");

const [owner, manualUser, managedUser, tenant, manualScim, managedScim, group] =
	Array.from({ length: 7 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const migration = [
	...(process.argv.includes("--with-migration")
		? ["20260923000049_scim_canonical_manual_membership_guard.sql"]
		: []),
	...(process.argv.includes("--with-lock-order-migration")
		? ["20260924000004_scim_reconciliation_lock_order.sql"]
		: []),
].map((file) => readFileSync(new URL(`../supabase/migrations/${file}`, import.meta.url), "utf8")).join("\n");
const lockOrderAssertion = process.argv.includes("--with-lock-order-migration") ? String.raw`
do $$ declare v_replace text; v_delete text; v_mapping text;
begin
  select pg_get_functiondef('public.scim_replace_group_members(uuid,uuid,uuid[],bigint)'::regprocedure) into v_replace;
  select pg_get_functiondef('public.scim_delete_group(uuid,uuid,bigint)'::regprocedure) into v_delete;
  select pg_get_functiondef('app.scim_mapping_reconcile_members()'::regprocedure) into v_mapping;
  if v_replace not ilike '%array_agg(id order by id)%'
     or v_delete not ilike '%array_agg(user_id order by user_id)%'
     or v_mapping not ilike '%order by sgm.user_id%' then
    raise exception 'SCIM reconciliation does not acquire user locks in deterministic order';
  end if;
end $$;
` : "";

const sql = String.raw`
\set ON_ERROR_STOP on
begin;
${migration}

do $$ begin
  if has_function_privilege('authenticated', 'public.scim_reconcile_membership(uuid,uuid)', 'EXECUTE')
     or has_function_privilege('anon', 'public.scim_reconcile_membership(uuid,uuid)', 'EXECUTE')
     or not has_function_privilege('service_role', 'public.scim_reconcile_membership(uuid,uuid)', 'EXECUTE')
  then raise exception 'SCIM reconciliation role boundary changed'; end if;
end $$;

${lockOrderAssertion}

insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values
  ('${owner}', 'owner-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{"aidr_scim_provisioned":true}', '{}'::jsonb),
  ('${manualUser}', 'manual-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{"aidr_scim_provisioned":true}', '{}'::jsonb),
  ('${managedUser}', 'managed-${marker}@example.invalid', 'authenticated', 'authenticated', '00000000-0000-0000-0000-000000000000', '{"aidr_scim_provisioned":true}', '{}'::jsonb);
insert into public.tenants(id, name, kind, created_by)
values ('${tenant}', 'SCIM manual membership regression', 'team', '${owner}');
insert into public.teams(id, tenant_id, name)
values ('${tenant}', '${tenant}', 'SCIM manual membership regression');
insert into public.team_members(team_id, tenant_id, user_id, role)
values ('${tenant}', '${tenant}', '${owner}', 'owner');
insert into public.scim_users(id, tenant_id, external_id, user_name, normalized_user_name, auth_user_id)
values
  ('${manualScim}', '${tenant}', 'manual-${marker}', 'manual-${marker}@example.invalid', 'manual-${marker}@example.invalid', '${manualUser}'),
  ('${managedScim}', '${tenant}', 'managed-${marker}', 'managed-${marker}@example.invalid', 'managed-${marker}@example.invalid', '${managedUser}');
insert into public.scim_groups(id, tenant_id, external_id, display_name)
values ('${group}', '${tenant}', 'operators-${marker}', 'Operators');
insert into public.scim_group_role_mappings(tenant_id, external_group_id, role, created_by)
values ('${tenant}', 'operators-${marker}', 'admin', '${owner}');
insert into public.scim_group_memberships(tenant_id, group_id, user_id)
values ('${tenant}', '${group}', '${manualScim}'), ('${tenant}', '${group}', '${managedScim}');

-- A canonical-only manual membership has no legacy team_members twin.
insert into public.tenant_members(tenant_id, user_id, role)
values ('${tenant}', '${manualUser}', 'viewer');
do $$ begin
  begin
    perform public.scim_reconcile_membership('${tenant}', '${manualScim}');
    raise exception 'SCIM took over a manual canonical membership';
  exception when sqlstate '42501' then
    if sqlerrm <> 'scim_cannot_take_over_manual_membership' then raise; end if;
  end;
  if (select role from public.tenant_members where tenant_id = '${tenant}' and user_id = '${manualUser}') <> 'viewer'
     or exists (select 1 from public.team_members where team_id = '${tenant}' and user_id = '${manualUser}')
     or exists (select 1 from public.scim_managed_memberships where tenant_id = '${tenant}' and scim_user_id = '${manualScim}')
  then raise exception 'manual canonical membership changed after rejected SCIM takeover'; end if;
end $$;

select public.scim_reconcile_membership('${tenant}', '${managedScim}');
do $$ begin
  if (select role from public.tenant_members where tenant_id = '${tenant}' and user_id = '${managedUser}') <> 'admin'
     or (select role from public.team_members where team_id = '${tenant}' and user_id = '${managedUser}') <> 'admin'
     or not exists (select 1 from public.scim_managed_memberships where tenant_id = '${tenant}' and scim_user_id = '${managedScim}')
  then raise exception 'new SCIM-managed membership was not established'; end if;
end $$;
select public.scim_update_user('${tenant}', '${managedScim}', null, false, null);
do $$ begin
  if exists (select 1 from public.tenant_members where tenant_id = '${tenant}' and user_id = '${managedUser}')
     or exists (select 1 from public.team_members where team_id = '${tenant}' and user_id = '${managedUser}')
     or exists (select 1 from public.scim_managed_memberships where tenant_id = '${tenant}' and scim_user_id = '${managedScim}')
     or (select role from public.tenant_members where tenant_id = '${tenant}' and user_id = '${manualUser}') <> 'viewer'
  then raise exception 'SCIM deactivation did not revoke only its own membership'; end if;
end $$;

rollback;
select 'SCIM_CANONICAL_MEMBERSHIP_ROLLBACK';
`;

const result = spawnSync("docker", [
	"exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
	"-U", "postgres", "-d", "postgres", "-q", "-At",
], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 120_000 });
if (result.error) throw result.error;
assert.equal(result.status, 0, `SCIM canonical membership regression failed:\n${result.stdout}\n${result.stderr}`);
assert.match(result.stdout, /SCIM_CANONICAL_MEMBERSHIP_ROLLBACK/);
console.log("SCIM canonical membership passed: manual role preserved, managed grant/revoke atomic, deterministic reconciliation lock order, rollback.");
