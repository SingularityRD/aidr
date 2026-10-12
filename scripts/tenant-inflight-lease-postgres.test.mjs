// Shared fair-share leases (supabase/migrations/20261011000500_tenant_inflight_shared_leases.sql)
// against a real, disposable PostgreSQL with the canonical migrations applied.
//
// AIDR_TEST_DISPOSABLE_DB=1 AIDR_POSTGRES_DOCKER_CONTAINER=supabase_db_aidr \
//   node scripts/tenant-inflight-lease-postgres.test.mjs
//
// Part 1 runs in one transaction that ends in ROLLBACK: tenant resolution from
// the key hash, every admission rule, expiry and reuse, exactly-once release,
// argument validation and privileges. Part 2 commits leases in a scope of its
// own from many concurrent sessions, checks the scope never exceeds its
// capacity, and deletes that scope again.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm a disposable database");
assert.match(container ?? "", /^[A-Za-z0-9_.-]+$/, "isolated PostgreSQL container required");
const docker = process.env.AIDR_DOCKER_BIN ?? "docker";
const psql = ["exec", "-i", "-e", "PGPASSWORD=postgres", container, "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"];

const [owner, member, otherOwner, tenant, otherTenant] = Array.from({ length: 5 }, () => randomUUID());
const marker = randomUUID().replaceAll("-", "");
const hex = () => randomBytes(32).toString("hex");
const [activeHash, retiredHash, staleRetiredHash, revokedHash, otherHash, unknownHash, unknownHash2] = Array.from({ length: 7 }, hex);
const scope = `pgtest-${marker.slice(0, 12)}`;
const acquire = (hash, capacity = 10, max = 7, floor = 2, seconds = 60, s = scope) =>
	`public.acquire_tenant_inflight_lease('${s}','${hash}',${capacity},${max},${floor},${seconds})`;
const expect = (label, condition) => `do $t$ begin if not (${condition}) then raise exception '${label}'; end if; end $t$;`;
const expectError = (label, statement, sqlstate) => `do $t$ begin
  begin ${statement}; raise exception '${label}';
  exception when sqlstate '${sqlstate}' then null; end;
end $t$;`;

const part1 = String.raw`
begin;
update app.tenant_admission_config set mode = 'pilot' where singleton;
insert into auth.users(id,email,aud,role,instance_id,raw_app_meta_data,raw_user_meta_data)
values ('${owner}','lease-owner-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}'),
       ('${member}','lease-member-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}'),
       ('${otherOwner}','lease-other-${marker}@example.invalid','authenticated','authenticated','00000000-0000-0000-0000-000000000000','{}','{}');
insert into public.tenants(id,name,kind,created_by)
values ('${tenant}','Lease ${marker}','team','${owner}'), ('${otherTenant}','Other lease ${marker}','team','${otherOwner}');
insert into public.teams(id,tenant_id,name) values ('${tenant}','${tenant}','Lease ${marker}'), ('${otherTenant}','${otherTenant}','Other lease ${marker}');
insert into public.team_members(team_id,tenant_id,user_id,role)
values ('${tenant}','${tenant}','${owner}','owner'), ('${tenant}','${tenant}','${member}','member'),
       ('${otherTenant}','${otherTenant}','${otherOwner}','owner');
insert into public.entitlements(user_id,tenant_id,included_agents) values ('${owner}','${tenant}',2), ('${otherOwner}','${otherTenant}',1);
insert into public.pilot_applications(user_id,tenant_id,status) values ('${owner}','${tenant}','approved'), ('${otherOwner}','${otherTenant}','approved');
insert into public.api_keys(user_id,tenant_id,label,key_hash,previous_hash,previous_hash_expires_at,rotated_at)
values ('${member}','${tenant}','active','${activeHash}','${retiredHash}',clock_timestamp() + interval '1 hour',clock_timestamp()),
       ('${owner}','${tenant}','stale','${hex()}','${staleRetiredHash}',clock_timestamp() - interval '1 second',clock_timestamp() - interval '1 hour'),
       ('${owner}','${tenant}','revoked','${revokedHash}',null,null,null),
       ('${otherOwner}','${otherTenant}','other','${otherHash}',null,null,null);
update public.api_keys set revoked = true where key_hash = '${revokedHash}';

-- Resolution: charging mirrors authentication's active / retired-hash lookup.
${expect("active hash charges its tenant", `${acquire(activeHash, 1000, 1000)} ->> 'charged_to' = '${tenant}'`)}
${expect("retired hash in its window charges its tenant", `${acquire(retiredHash, 1000, 1000)} ->> 'charged_to' = '${tenant}'`)}
${expect("retired hash after its window is unresolved", `${acquire(staleRetiredHash, 1000, 1000)} ->> 'charged_to' = 'unresolved'`)}
${expect("revoked key is unresolved", `${acquire(revokedHash, 1000, 1000)} ->> 'charged_to' = 'unresolved'`)}
${expect("unknown key is unresolved", `${acquire(unknownHash, 1000, 1000)} ->> 'charged_to' = 'unresolved'`)}
${expect("other tenant charged separately", `${acquire(otherHash, 1000, 1000)} ->> 'charged_to' = '${otherTenant}'`)}
${expect("six live leases", `(select count(*) from app.tenant_inflight_slots where scope = '${scope}' and expires_at > clock_timestamp()) = 6`)}
delete from app.tenant_inflight_scopes where scope = '${scope}';

-- Per-tenant max, then capacity - per-tenant max slots one tenant alone never takes.
select ${acquire(activeHash)} from generate_series(1, 7);
${expect("tenant max refuses the 8th", `${acquire(activeHash)} ->> 'reason' = 'tenant_max'`)}
${expect("other tenant admitted beside a capped tenant", `(${acquire(otherHash)} ->> 'admitted')::boolean`)}
${expect("other tenant admitted twice", `(${acquire(otherHash)} ->> 'admitted')::boolean`)}
${expect("other tenant admitted three times", `(${acquire(otherHash)} ->> 'admitted')::boolean`)}
${expect("capacity refuses the 11th", `${acquire(otherHash)} ->> 'reason' = 'capacity'`)}
-- Free two of the capped tenant's leases: it stays above its share (10 / 2 = 5) and is shed,
-- the other tenant fills the freed capacity up to its share.
select public.release_tenant_inflight_lease('${scope}', slot, lease_id) from app.tenant_inflight_slots
  where scope = '${scope}' and charged_to = '${tenant}' order by slot limit 2;
${expect("over-share tenant shed", `${acquire(activeHash)} ->> 'reason' = 'fair_share'`)}
${expect("under-share tenant admitted (4)", `(${acquire(otherHash)} ->> 'admitted')::boolean`)}
${expect("under-share tenant admitted (5)", `(${acquire(otherHash)} ->> 'admitted')::boolean`)}
${expect("shares converged 5/5", `(select count(*) filter (where charged_to = '${tenant}') = 5 and count(*) filter (where charged_to = '${otherTenant}') = 5 from app.tenant_inflight_slots where scope = '${scope}' and expires_at > clock_timestamp())`)}
${expect("freed slot rows were reused", `(select count(*) from app.tenant_inflight_slots where scope = '${scope}') = 10`)}
delete from app.tenant_inflight_scopes where scope = '${scope}';

-- Unresolved keys: one shared party; under pressure one lease per key.
select ${acquire(activeHash, 10, 5, 2)} from generate_series(1, 2);
select ${acquire(unknownHash, 10, 5, 2)} from generate_series(1, 2);
select ${acquire(unknownHash2, 10, 5, 2)};
${expect("unresolved key busy under pressure", `${acquire(unknownHash, 10, 5, 2)} ->> 'reason' = 'unresolved_key_busy'`)}
${expect("a new unresolved key still admitted", `(${acquire(hex(), 10, 5, 2)} ->> 'admitted')::boolean`)}
${expect("unresolved charged as one party", `(select count(*) filter (where charged_to = 'unresolved') = 4 from app.tenant_inflight_slots where scope = '${scope}' and expires_at > clock_timestamp())`)}
delete from app.tenant_inflight_scopes where scope = '${scope}';

-- The floor: with many active parties each may still hold floor leases.
select ${acquire(activeHash, 6, 4, 2)} from generate_series(1, 2);
select ${acquire(otherHash, 6, 4, 2)} from generate_series(1, 2);
${expect("floor admits a third party (1)", `(${acquire(unknownHash, 6, 4, 2)} ->> 'admitted')::boolean`)}
${expect("floor admits a third party (2)", `(${acquire(unknownHash2, 6, 4, 2)} ->> 'admitted')::boolean`)}
delete from app.tenant_inflight_scopes where scope = '${scope}';

-- Expiry: a lease whose worker died stops counting and its slot is reused; its
-- late release is a no-op; a live release frees exactly once.
create temp table lease_t on commit drop as select ${acquire(activeHash, 1, 1, 1)} as l;
${expect("second lease refused at capacity 1", `${acquire(activeHash, 1, 1, 1)} ->> 'admitted' = 'false'`)}
update app.tenant_inflight_slots set expires_at = clock_timestamp() - interval '1 millisecond' where scope = '${scope}';
create temp table lease_u on commit drop as select ${acquire(activeHash, 1, 1, 1)} as l;
${expect("expired slot reclaimed", `(select (l ->> 'reclaimed')::boolean and (l ->> 'slot')::int = 1 from lease_u)`)}
${expect("late release of the expired lease is a no-op", `not public.release_tenant_inflight_lease('${scope}', 1, (select (l ->> 'lease_id')::uuid from lease_t))`)}
${expect("live lease still held", `(select count(*) from app.tenant_inflight_slots where scope = '${scope}' and expires_at > clock_timestamp()) = 1`)}
${expect("release frees the live lease", `public.release_tenant_inflight_lease('${scope}', 1, (select (l ->> 'lease_id')::uuid from lease_u))`)}
${expect("second release is a no-op", `not public.release_tenant_inflight_lease('${scope}', 1, (select (l ->> 'lease_id')::uuid from lease_u))`)}
${expect("slot free after release", `(select lease_id is null and charged_to is null and expires_at is null from app.tenant_inflight_slots where scope = '${scope}' and slot = 1)`)}

-- Arguments are validated; a bad call raises instead of admitting.
${expectError("bad scope accepted", `perform ${acquire(activeHash, 10, 7, 2, 60, "Bad Scope")}`, "22023")}
${expectError("bad hash accepted", `perform ${acquire("not-a-hash")}`, "22023")}
${expectError("max above capacity accepted", `perform ${acquire(activeHash, 5, 6, 2)}`, "22023")}
${expectError("floor above max accepted", `perform ${acquire(activeHash, 10, 3, 4)}`, "22023")}
${expectError("zero lease accepted", `perform ${acquire(activeHash, 10, 7, 2, 0)}`, "22023")}
${expectError("null lease id accepted", `perform public.release_tenant_inflight_lease('${scope}', 1, null)`, "22023")}

-- Privileges: only service_role executes; nobody reads the lease tables directly.
${expect("anon cannot execute acquire", `not has_function_privilege('anon', 'public.acquire_tenant_inflight_lease(text,text,integer,integer,integer,integer)', 'execute')`)}
${expect("authenticated cannot execute acquire", `not has_function_privilege('authenticated', 'public.acquire_tenant_inflight_lease(text,text,integer,integer,integer,integer)', 'execute')`)}
${expect("authenticated cannot execute release", `not has_function_privilege('authenticated', 'public.release_tenant_inflight_lease(text,integer,uuid)', 'execute')`)}
${expect("service_role executes acquire", `has_function_privilege('service_role', 'public.acquire_tenant_inflight_lease(text,text,integer,integer,integer,integer)', 'execute')`)}
${expect("service_role cannot read slots", `not has_table_privilege('service_role', 'app.tenant_inflight_slots', 'select')`)}
${expect("authenticated cannot read slots", `not has_table_privilege('authenticated', 'app.tenant_inflight_slots', 'select')`)}
${expect("lease tables are unlogged", `(select bool_and(relpersistence = 'u') from pg_class where oid in ('app.tenant_inflight_slots'::regclass, 'app.tenant_inflight_scopes'::regclass))`)}
rollback;
select 'TENANT_INFLIGHT_LEASE_ROLLBACK';
`;

const first = spawnSync(docker, psql, { input: part1, encoding: "utf8", maxBuffer: 8 << 20, timeout: 120_000 });
if (first.error) throw first.error;
assert.equal(first.status, 0, `shared lease PostgreSQL regression failed:\n${first.stdout}\n${first.stderr}`);
assert.match(first.stdout, /TENANT_INFLIGHT_LEASE_ROLLBACK/);

// Part 2: concurrent acquires from separate sessions (separate PostgREST
// connections in production) never exceed the scope's capacity.
const concurrentScope = `pgtest-race-${marker.slice(0, 8)}`;
const capacity = 5;
const sessions = 24;
function race() {
	return new Promise((resolve, reject) => {
		const child = spawn(docker, psql, { stdio: ["pipe", "pipe", "pipe"] });
		let out = "";
		let err = "";
		child.stdout.on("data", (chunk) => { out += chunk; });
		child.stderr.on("data", (chunk) => { err += chunk; });
		child.on("error", reject);
		child.on("close", (code) => code === 0 ? resolve(out.trim()) : reject(new Error(err)));
		child.stdin.end(`select ${acquire(hex(), capacity, capacity, 1, 60, concurrentScope)} ->> 'admitted';\n`);
	});
}
try {
	const outcomes = await Promise.all(Array.from({ length: sessions }, race));
	assert.equal(outcomes.filter((value) => value === "true").length, capacity, `admitted: ${outcomes.join(",")}`);
	assert.equal(outcomes.filter((value) => value === "false").length, sessions - capacity);
} finally {
	const cleanup = spawnSync(docker, psql, {
		input: `delete from app.tenant_inflight_scopes where scope = '${concurrentScope}';\n`,
		encoding: "utf8",
		timeout: 30_000,
	});
	assert.equal(cleanup.status, 0, cleanup.stderr);
}
console.log(`Shared fair-share leases passed: key-hash resolution, cap/share/capacity/floor/unresolved rules, expiry reuse, exactly-once release, argument validation, privileges (rolled back); ${sessions} concurrent sessions admitted exactly ${capacity}.`);
