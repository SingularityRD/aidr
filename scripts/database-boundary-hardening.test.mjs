import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
	compatibleInstalledHashes,
	isAuditedLegacyMigration,
	migrationHashesMatch,
} from "./lib/migration-hash-compat.mjs";
import {
	forbiddenMigrationControls,
	MIGRATION_FILENAME_PATTERN,
	migrationOrderError,
} from "./lib/migration-contract.mjs";

const migrationsDir = new URL("../supabase/migrations/", import.meta.url);
const hardening = await readFile(
	new URL("20260922000002_database_boundary_hardening.sql", migrationsDir),
	"utf8",
);
const teamRead = await readFile(
	new URL("20260923000014_team_read_rls.sql", migrationsDir),
	"utf8",
);
const incidentView = await readFile(
	new URL("20260923000015_incident_events_view.sql", migrationsDir),
	"utf8",
);
const identityBarrierHardening = await readFile(
	new URL("20260922000007_identity_recovery_and_team_barrier_hardening.sql", migrationsDir),
	"utf8",
);
const idempotentTeamCreation = await readFile(
	new URL("20260924000010_idempotent_team_creation.sql", migrationsDir),
	"utf8",
);
const policyDraftMigration = await readFile(
	new URL("20260916000003_policy_document_draft_cas.sql", migrationsDir),
	"utf8",
);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

test("canonical migrations cannot escape the deployment transaction", async () => {
	for (const name of (await readdir(migrationsDir)).filter((entry) => entry.endsWith(".sql"))) {
		const sql = await readFile(new URL(name, migrationsDir), "utf8");
		assert.deepEqual(forbiddenMigrationControls(sql), [], `${name} contains transaction control`);
	}
});

test("transaction scanner rejects disguised SQL and psql escapes without inspecting quoted bodies", () => {
	for (const sql of [
		"END;",
		"BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;",
		"/* leading comment */ BEGIN;",
		"START /* split */ TRANSACTION;",
		"ROLLBACK TO SAVEPOINT before_change;",
		"ABORT;",
		"PREPARE TRANSACTION 'escape';",
		"\\connect postgres",
		"select 'COMMIT' \\gexec",
	]) {
		assert.notDeepEqual(forbiddenMigrationControls(sql), [], sql);
	}
	for (const sql of [
		"select 'BEGIN; COMMIT; \\connect';",
		String.raw`select E'quoted \' COMMIT; text';`,
		"select \"END\" from example;",
		"-- COMMIT; \\gexec\nselect 1;",
		"/* BEGIN; /* ROLLBACK; */ COMMIT; */ select 1;",
		"create function f() returns void language plpgsql as $$ begin perform 1; end; $$;",
	]) {
		assert.deepEqual(forbiddenMigrationControls(sql), [], sql);
	}
	assert.notDeepEqual(forbiddenMigrationControls(String.raw`select '\'; COMMIT;`), []);
});

test("migration names and inventory order use one strict deployment contract", () => {
	assert.equal(MIGRATION_FILENAME_PATTERN.test("20260923000000_safe_name.sql"), true);
	assert.equal(MIGRATION_FILENAME_PATTERN.test("20260923000000_hyphen-name.sql"), false);
	assert.equal(MIGRATION_FILENAME_PATTERN.test("20260923000000_Upper.sql"), false);
	assert.equal(migrationOrderError([
		{ name: "20260923000000_first.sql" },
		{ name: "20260923000001_second.sql" },
	]), null);
	assert.match(migrationOrderError([
		{ name: "20260923000001_second.sql" },
		{ name: "20260923000000_first.sql" },
	]), /not strictly chronological/);
	assert.match(migrationOrderError([
		{ name: "20260923000000_first.sql" },
		{ name: "20260923000000_duplicate.sql" },
	]), /not strictly chronological/);
});

test("self-hosted migration runner rejects an unordered manifest before database access", async () => {
	const directory = await mkdtemp(join(tmpdir(), "aidr-migration-order-"));
	try {
		await writeFile(join(directory, "deployment.json"), JSON.stringify({
			mode: "self-hosted",
			migrations: [
				{ name: "20260923000001_second.sql", sha256: "b".repeat(64) },
				{ name: "20260923000000_first.sql", sha256: "a".repeat(64) },
			],
		}));
		const result = spawnSync(process.execPath, [fileURLToPath(new URL("deployment-migrate.mjs", import.meta.url)), directory], {
			encoding: "utf8",
			timeout: 10_000,
		});
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /not strictly chronological/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

const migrationRunnerDockerDriver = `
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.AIDR_MIGRATION_TEST_DOCKER_LOG, JSON.stringify(args) + "\\n");
let input = "";
for await (const chunk of process.stdin) input += chunk;
if (args.includes("-tAc")) {
  process.stdout.write("t\\n");
} else if (process.env.AIDR_MIGRATION_TEST_UNEXPECTED_LEDGER === "1") {
  const guard = input.indexOf("database contains a migration absent from the deployment manifest");
  const migration = input.indexOf("CREATE TABLE public.migration_runner_fixture");
  if (guard < 0 || migration < 0 || guard > migration) {
    process.stderr.write("test double did not see the unknown-ledger guard before migration SQL\\n");
    process.exit(72);
  }
  process.stderr.write("ERROR: database contains an unexpected migration ledger row\\n");
  process.exit(1);
}
`;

async function runMigrationRunner(t, migrations, { unexpectedLedger = false } = {}) {
	const directory = await mkdtemp(join(tmpdir(), "aidr-migration-runner-"));
	t.after(() => rm(directory, { recursive: true, force: true }));
	const migrationDirectory = join(directory, "migrations");
	await mkdir(migrationDirectory);
	for (const migration of migrations) {
		await writeFile(join(migrationDirectory, migration.name), migration.sql);
	}
	const entries = migrations.map(({ name, sql }) => ({ name, sha256: sha256(sql) }));
	await writeFile(join(directory, "deployment.json"), JSON.stringify({ mode: "self-hosted", migrations: entries }));
	const driver = join(directory, "docker-driver.mjs");
	const dockerLog = join(directory, "docker.log");
	await writeFile(driver, migrationRunnerDockerDriver);
	const result = spawnSync(process.execPath, [fileURLToPath(new URL("deployment-migrate.mjs", import.meta.url)), directory], {
		encoding: "utf8",
		timeout: 15_000,
		env: {
			...process.env,
			NODE_ENV: "test",
			AIDR_MIGRATION_TEST_DOCKER_DRIVER: driver,
			AIDR_MIGRATION_TEST_DOCKER_LOG: dockerLog,
			AIDR_MIGRATION_TEST_UNEXPECTED_LEDGER: unexpectedLedger ? "1" : "0",
		},
	});
	return { result, dockerLog };
}

test("self-hosted migration runner rejects an empty plan before database access", async (t) => {
	const { result, dockerLog } = await runMigrationRunner(t, []);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /migration inventory must not be empty/);
	await assert.rejects(readFile(dockerLog), { code: "ENOENT" });
});

test("self-hosted migration runner rejects ledger rows absent from the manifest before apply", async (t) => {
	const { result, dockerLog } = await runMigrationRunner(t, [
		{ name: "20260923000000_fixture.sql", sql: "CREATE TABLE public.migration_runner_fixture(id integer);\n" },
	], { unexpectedLedger: true });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /database contains an unexpected migration ledger row/);
	assert.equal((await readFile(dockerLog, "utf8")).trim().split(/\r?\n/).length, 2, "runner performs readiness probe and apply connection");
});

test("the one pre-release transaction-wrapper edit has an exact hash compatibility path", () => {
	const name = "20260916000003_policy_document_draft_cas.sql";
	const oldHash = "7e978767c0e454550ee35fc9f52da5bea77863ca53c0652090e8bebca291016b";
	const newHash = "bb4efd0be81d191565826d910843a0c0a2a879f77ddcb84d991d277544c070cf";
	const legacySql = policyDraftMigration
		.replace("before applying this migration.", "before entering this transaction.")
		.replace("-- compilation with direct table writes. Read/delete policies are unchanged.\n\n", "-- compilation with direct table writes. Read/delete policies are unchanged.\nbegin;\n\n")
		.replace(/\n$/, "\n\ncommit;\n");
	assert.equal(sha256(policyDraftMigration), newHash);
	assert.equal(sha256(legacySql), oldHash);
	assert.notDeepEqual(forbiddenMigrationControls(legacySql), []);
	assert.equal(isAuditedLegacyMigration(name, oldHash, legacySql), true);
	assert.equal(isAuditedLegacyMigration(name, oldHash, `${legacySql}-- changed\n`), false);
	assert.equal(migrationHashesMatch(name, oldHash, newHash, policyDraftMigration), true);
	assert.equal(migrationHashesMatch(name, oldHash, newHash, `${policyDraftMigration}-- changed\n`), false);
	assert.equal(migrationHashesMatch("20260916000004_other.sql", oldHash, newHash, policyDraftMigration), false);
	assert.equal(migrationHashesMatch(name, newHash, oldHash, legacySql), false);
	assert.deepEqual(compatibleInstalledHashes(name, newHash, policyDraftMigration), [newHash, oldHash]);
	assert.deepEqual(compatibleInstalledHashes(name, newHash, `${policyDraftMigration}-- changed\n`), [newHash]);
});

test("browser ACLs are reset and regranted without RLS-bypassing privileges", () => {
	assert.match(hardening, /revoke all privileges on all tables in schema public from public, anon, authenticated/i);
	assert.match(hardening, /revoke all privileges on all sequences in schema public from public, anon, authenticated/i);
	assert.match(hardening, /revoke execute on all functions in schema public, app from public, anon, authenticated/i);
	assert.match(hardening, /alter default privileges for role postgres in schema app\s+revoke execute on functions/i);
	assert.match(hardening, /grant update \(role\) on public\.team_members to authenticated/i);
	assert.match(hardening, /grant execute on function public\.tenant_identity_access_allowed\(uuid\) to authenticated/i);
	assert.doesNotMatch(hardening, /grant all[^;]+to authenticated/i);
	assert.match(hardening, /drop policy if exists audit_logs_insert_service/i);
});

test("team reads use live row membership while browser writes keep a tenant claim", () => {
	for (const table of ["agents", "events", "team_policies", "audit_logs"]) {
		assert.match(teamRead, new RegExp(`create policy tenant_${table}_select on public\\.${table} for select to authenticated\\s+using \\(app\\.is_tenant_member\\(tenant_id\\)\\)`, "i"));
	}
	for (const table of ["agents", "events"]) {
		assert.match(teamRead, new RegExp(`create policy tenant_active_member_restrict on public\\.${table}[\\s\\S]*?with check \\(tenant_id = app\\.current_tenant_id\\(\\) and app\\.is_tenant_member\\(tenant_id\\)\\)`, "i"));
	}
	assert.match(teamRead, /drop policy if exists team_policies_select_member on public\.team_policies/i);
	assert.match(teamRead, /drop policy if exists audit_logs_select_member on public\.audit_logs/i);
});

test("the incident view retains invoker RLS and includes recorded incidents", () => {
	assert.match(incidentView, /create or replace view public\.incident_events\s+with \(security_invoker = true\)/i);
	assert.match(incidentView, /ev\.type in \('incident', 'incident_record'\)/i);
});

test("team creation cannot self-select billing or detach tenant identity", () => {
	assert.match(hardening, /security definer[\s\S]+p_plan is distinct from 'free'/i);
	assert.match(hardening, /values \(v_team_id, v_team_id, trim\(p_name\), 'free'\)/i);
	assert.match(hardening, /values \(v_team_id, v_team_id, v_user_id, 'owner'\)/i);
	assert.match(hardening, /teams_tenant_matches_id check \(tenant_id = id\) not valid/i);
	assert.match(hardening, /drop policy if exists teams_delete_admin/i);
});

test("team creation checks the serialized identity barrier before bypassing RLS", () => {
	const teamFunction = identityBarrierHardening.slice(
		identityBarrierHardening.indexOf("create or replace function public.create_team_tenant"),
	);
	const lock = teamFunction.indexOf("pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611))");
	const barrier = teamFunction.indexOf("tenant_identity_access_allowed(v_team_id)");
	const insert = teamFunction.indexOf("insert into public.tenants");
	assert.ok(lock >= 0 && barrier > lock && insert > barrier);
});

test("team-create retries are durable per request without limiting workspaces per user", () => {
	assert.match(idempotentTeamCreation, /primary key \(actor_user_id, request_id\)/i);
	assert.match(idempotentTeamCreation, /request_id uuid not null/i);
	assert.match(idempotentTeamCreation, /drop function if exists public\.create_team_tenant\(text, text\)/i);
	assert.match(idempotentTeamCreation, /create function public\.create_team_tenant\(\s*p_name text,\s*p_request_id uuid,/i);
	const lock = idempotentTeamCreation.indexOf(
		"pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611))",
	);
	const lookup = idempotentTeamCreation.indexOf("from public.team_creation_requests r");
	const insert = idempotentTeamCreation.indexOf("insert into public.tenants");
	const ledger = idempotentTeamCreation.indexOf("insert into public.team_creation_requests");
	assert.ok(lock >= 0 && lookup > lock && insert > lookup && ledger > insert);
	assert.match(idempotentTeamCreation, /v_existing_name <> trim\(p_name\)[\s\S]+request ID was reused with a different name/i);
	assert.match(idempotentTeamCreation, /grant execute on function public\.create_team_tenant\(text, uuid, text\) to authenticated/i);
	assert.match(idempotentTeamCreation, /revoke all on table public\.team_creation_requests from public, anon, authenticated, service_role/i);
});

test("audit exports use the immediate identity barrier", () => {
	assert.match(
		hardening,
		/create policy audit_exports_read_own_tenant[\s\S]+tenant_identity_access_allowed\(app\.current_tenant_id\(\)\)/i,
	);
});
