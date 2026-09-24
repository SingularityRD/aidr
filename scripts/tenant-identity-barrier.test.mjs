import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";
import {
	analyzeIdentityBarrier,
	IDENTITY_BARRIER_EXCEPTIONS,
} from "./lib/tenant-identity-barrier.mjs";

const migrationsDir = new URL("../supabase/migrations/", import.meta.url);
const migrations = await Promise.all(
	(await readdir(migrationsDir))
		.filter((name) => name.endsWith(".sql"))
		.sort()
		.map(async (name) => ({ name, sql: await readFile(new URL(name, migrationsDir), "utf8") })),
);

const SWEEP = `do $$
declare v_table record;
begin
  for v_table in
    select distinct c.table_name
    from information_schema.columns c
    join pg_class pc on pc.relname = c.table_name
    join pg_namespace pn on pn.oid = pc.relnamespace and pn.nspname = c.table_schema
    where c.table_schema = 'public' and c.column_name = 'tenant_id'
      and pc.relkind in ('r', 'p') and pc.relrowsecurity
  loop
    execute format('drop policy if exists tenant_identity_access_restrict on public.%I', v_table.table_name);
    execute format(
      'create policy tenant_identity_access_restrict on public.%I as restrictive for all to authenticated using (public.tenant_identity_access_allowed(tenant_id)) with check (public.tenant_identity_access_allowed(tenant_id))',
      v_table.table_name
    );
  end loop;
end;
$$;`;
const BARRIER = (table) => `create policy tenant_identity_access_restrict on public.${table}
  as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(tenant_id))
  with check (public.tenant_identity_access_allowed(tenant_id));`;
const TENANTS = `create table public.tenants (id uuid primary key);
alter table public.tenants enable row level security;
create policy tenant_identity_access_restrict on public.tenants as restrictive for all to authenticated
  using (public.tenant_identity_access_allowed(id)) with check (public.tenant_identity_access_allowed(id));`;
const replay = (...sqls) =>
	analyzeIdentityBarrier(
		sqls.map((sql, index) => ({ name: `2026010100000${index}_case.sql`, sql })),
		{},
	);
const missingTables = (result) => result.missing.map(({ table }) => table);

test("every RLS tenant table in the canonical migrations carries the identity barrier", () => {
	const result = analyzeIdentityBarrier(migrations);
	assert.deepEqual(
		result.missing,
		[],
		`tenant tables without restrictive public.tenant_identity_access_allowed(tenant_id): ${result.missing
			.map(({ table, createdIn }) => `${table} (${createdIn})`)
			.join(", ")}. Add a tenant_identity_access_restrict policy or a reasoned IDENTITY_BARRIER_EXCEPTIONS entry.`,
	);
	assert.deepEqual(result.staleExceptions, [], "remove exceptions that are no longer needed");
	for (const [table, reason] of Object.entries(IDENTITY_BARRIER_EXCEPTIONS)) {
		assert.ok(typeof reason === "string" && reason.length >= 40, `${table} exception needs a reason`);
	}
	// Sanity: the replay actually saw the tables it is meant to police.
	for (const table of ["events", "posture_findings", "tenant_members", "tenants", "api_keys"]) {
		assert.ok(result.tables.get(table)?.rls, `${table} expected to be an RLS table`);
	}
});

test("posture_findings was missing the barrier before 20260925000060 and has it after", () => {
	const before = analyzeIdentityBarrier(
		migrations.filter(({ name }) => name < "20260925000060"),
	);
	assert.ok(missingTables(before).includes("posture_findings"));
	const posture = analyzeIdentityBarrier(migrations).tables.get("posture_findings");
	assert.equal(posture.policies.get("tenant_identity_access_restrict")?.column, "tenant_id");
});

test("a tenant table created after the last sweep without its own barrier fails", () => {
	const table = "create table public.widgets (id uuid primary key, tenant_id uuid not null);\nalter table public.widgets enable row level security;";
	assert.deepEqual(missingTables(replay(TENANTS, SWEEP, table)), ["widgets"]);
	assert.deepEqual(missingTables(replay(TENANTS, table, SWEEP)), []);
	assert.deepEqual(missingTables(replay(TENANTS, SWEEP, table, BARRIER("widgets"))), []);
});

test("tables without RLS or without tenant_id are out of scope; added columns are tracked", () => {
	assert.deepEqual(
		missingTables(replay(TENANTS, "create table public.plans (id text primary key);\nalter table public.plans enable row level security;")),
		[],
	);
	assert.deepEqual(missingTables(replay(TENANTS, "create table public.raw (tenant_id uuid);")), []);
	assert.deepEqual(
		missingTables(
			replay(
				TENANTS,
				"create table public.late (id uuid);\nalter table public.late enable row level security;",
				"alter table public.late add column if not exists tenant_id uuid references public.tenants(id);",
			),
		),
		["late"],
	);
	// A column merely named like tenant_id inside a constraint is not a column.
	assert.deepEqual(
		missingTables(
			replay(
				TENANTS,
				"create table public.x (id uuid, other uuid, check (other <> 'tenant_id'::text::uuid));\nalter table public.x enable row level security;",
			),
		),
		[],
	);
});

test("weak, dropped, commented or function-body policies do not count", () => {
	const table = "create table public.w (tenant_id uuid);\nalter table public.w enable row level security;";
	const permissive = "create policy tenant_identity_access_restrict on public.w for all to authenticated using (public.tenant_identity_access_allowed(tenant_id));";
	const selectOnly = "create policy b on public.w as restrictive for select to authenticated using (public.tenant_identity_access_allowed(tenant_id));";
	const wrongRole = "create policy b on public.w as restrictive for all to service_role using (public.tenant_identity_access_allowed(tenant_id));";
	const member = "create policy b on public.w as restrictive for all to authenticated using (app.is_tenant_member(tenant_id));";
	const commented = `-- ${BARRIER("w").replace(/\n/g, " ")}`;
	const inBody = `create function f() returns void language sql as $body$ ${BARRIER("w")} $body$;`;
	for (const policy of [permissive, selectOnly, wrongRole, member, commented, inBody]) {
		assert.deepEqual(missingTables(replay(TENANTS, table, policy)), ["w"], policy);
	}
	const dropped = "drop policy if exists tenant_identity_access_restrict on public.w;";
	assert.deepEqual(missingTables(replay(TENANTS, table, BARRIER("w"), dropped)), ["w"]);
	// A policy on another schema's same-named table is not this table's barrier.
	assert.deepEqual(
		missingTables(replay(TENANTS, table, BARRIER("w").replace("public.w", "storage.w"))),
		["w"],
	);
});

test("recreated and renamed tables keep an accurate state", () => {
	const table = "create table public.w (tenant_id uuid);\nalter table public.w enable row level security;";
	assert.deepEqual(
		missingTables(replay(TENANTS, table, BARRIER("w"), `drop table public.w;\n${table}`)),
		["w"],
	);
	assert.deepEqual(
		missingTables(replay(TENANTS, table, BARRIER("w"), "create table if not exists public.w (tenant_id uuid);")),
		[],
	);
	assert.deepEqual(
		missingTables(replay(TENANTS, table, BARRIER("w"), "alter table public.w rename to v;")),
		[],
	);
});

test("the tenants root table needs the barrier on its id", () => {
	assert.deepEqual(
		missingTables(replay("create table public.tenants (id uuid primary key);\nalter table public.tenants enable row level security;")),
		["tenants"],
	);
	assert.deepEqual(missingTables(replay(TENANTS)), []);
});

test("exceptions must be exercised", () => {
	const table = "create table public.w (tenant_id uuid);\nalter table public.w enable row level security;";
	const reason = { w: "service-role-only ledger read through a definer RPC that applies the barrier" };
	const excepted = analyzeIdentityBarrier([{ name: "20260101000000_a.sql", sql: `${TENANTS}\n${table}` }], reason);
	assert.deepEqual(excepted.missing, []);
	assert.deepEqual(excepted.excepted, ["w"]);
	const stale = analyzeIdentityBarrier(
		[{ name: "20260101000000_a.sql", sql: `${TENANTS}\n${table}\n${BARRIER("w")}` }],
		reason,
	);
	assert.deepEqual(stale.staleExceptions, ["w"]);
});
