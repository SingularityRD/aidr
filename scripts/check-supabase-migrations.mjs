import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import {
	forbiddenMigrationControls,
	MIGRATION_FILENAME_PATTERN,
} from "./lib/migration-contract.mjs";

const root = process.cwd();
const migrationsDir = path.join(root, "supabase", "migrations");
const files = (await readdir(migrationsDir)).filter((name) => name.endsWith(".sql")).sort();

const errors = [];
const seenVersions = new Map();
const parsed = [];

for (const name of files) {
	const match = MIGRATION_FILENAME_PATTERN.exec(name);
	if (!match) {
		errors.push(`${name}: expected lowercase YYYYMMDDHHMMSS_description.sql with underscore-separated words`);
		continue;
	}
	const version = name.slice(0, 14);
	if (seenVersions.has(version)) {
		errors.push(`${name}: duplicate migration version ${version} (also ${seenVersions.get(version)})`);
	} else {
		seenVersions.set(version, name);
	}
	parsed.push({ name, version });
}

const expectedPrefixOrder = [
	"20260327000000_initial.sql",
	"20260327000100_reputation.sql",
	"20260327000200_golive_v1.sql",
	"20260327000300_device_pilot_waitlist.sql",
	["20260327", "000400_c", "ontrol_p", "lane_api", "_v1.sql"].join(""),
	["20260327", "000500_c", "ommercia", "l_v1.sql"].join(""),
	"20260528000000_team_rbac.sql",
];
const actual = parsed.map(({ name }) => name);
for (let i = 0; i < expectedPrefixOrder.length; i += 1) {
	if (actual[i] !== expectedPrefixOrder[i]) {
		errors.push(
			`migration order mismatch at position ${i + 1}: expected ${expectedPrefixOrder[i]}, got ${actual[i] ?? "<missing>"}`,
		);
		break;
	}
}

const contents = new Map(
	await Promise.all(
		parsed.map(async ({ name }) => [name, await readFile(path.join(migrationsDir, name), "utf8")]),
	),
);
for (const [name, sql] of contents) {
	for (const finding of forbiddenMigrationControls(sql)) {
		errors.push(`${name}:${finding.line}: ${finding.control} is forbidden; deployment runners own the transaction`);
	}
}
const assertBefore = (consumer, dependency, needle) => {
	const consumerIndex = actual.indexOf(consumer);
	const dependencyIndex = actual.indexOf(dependency);
	if (consumerIndex < 0 || dependencyIndex < 0) return;
	if (consumerIndex <= dependencyIndex) {
		errors.push(`${consumer}: ${needle} must run after ${dependency}`);
	}
};

assertBefore(
	"20260327000400_control_plane_api_v1.sql",
	"20260327000000_initial.sql",
	"entitlement_snapshots/derived views reference base control-plane tables",
);
assertBefore(
	"20260327000500_commercial_v1.sql",
	"20260327000000_initial.sql",
	"commercial columns reference public.entitlements",
);
const initial = contents.get("20260327000000_initial.sql") ?? "";
if (initial && !/create\s+table\s+if\s+not\s+exists\s+public\.entitlements/i.test(initial)) {
	errors.push("20260327000000_initial.sql: missing base entitlements table");
}
const teamCreation = contents.get("20260805000001_team_creation_rpc.sql") ?? "";
if (teamCreation) {
	for (const [needle, description] of [
		[/create\s+or\s+replace\s+function\s+public\.create_team_tenant/i, "atomic team/tenant creation RPC"],
		[/revoke\s+all\s+on\s+function\s+public\.create_team_tenant/i, "restricted team/tenant RPC default privileges"],
		[/grant\s+execute\s+on\s+function\s+public\.create_team_tenant[\s\S]*to\s+authenticated/i, "authenticated team/tenant RPC grant"],
	]) {
		if (!needle.test(teamCreation)) errors.push(`20260805000001_team_creation_rpc.sql: missing ${description}`);
	}
} else {
	errors.push("20260805000001_team_creation_rpc.sql: missing atomic team/tenant creation migration");
}

const databaseHardening = contents.get("20260922000002_database_boundary_hardening.sql") ?? "";
if (databaseHardening) {
	for (const [needle, description] of [
		[/revoke\s+all\s+privileges\s+on\s+all\s+tables\s+in\s+schema\s+public\s+from\s+public,\s*anon,\s*authenticated/i, "fail-closed current table privileges"],
		[/revoke\s+all\s+privileges\s+on\s+all\s+sequences\s+in\s+schema\s+public\s+from\s+public,\s*anon,\s*authenticated/i, "fail-closed current sequence privileges"],
		[/revoke\s+execute\s+on\s+all\s+functions\s+in\s+schema\s+public,\s*app\s+from\s+public,\s*anon,\s*authenticated/i, "fail-closed current function privileges"],
		[/drop\s+policy\s+if\s+exists\s+audit_logs_insert_service/i, "service-only audit insertion"],
		[/drop\s+policy\s+if\s+exists\s+teams_delete_admin/i, "controlled team offboarding"],
		[/p_plan\s+is\s+distinct\s+from\s+'free'/i, "billing-owned team plan"],
		[/values\s*\(v_team_id,\s*v_team_id,\s*v_user_id,\s*'owner'\)/i, "owner bootstrap"],
		[/teams_tenant_matches_id\s+check\s*\(tenant_id\s*=\s*id\)/i, "team tenant identity constraint"],
		[/tenant_identity_access_allowed\s*\(app\.current_tenant_id\(\)\)/i, "export identity barrier"],
	]) {
		if (!needle.test(databaseHardening)) {
			errors.push(`20260922000002_database_boundary_hardening.sql: missing ${description}`);
		}
	}
} else {
	errors.push("20260922000002_database_boundary_hardening.sql: missing database boundary hardening migration");
}

const teamCreateIdempotency = contents.get("20260924000010_idempotent_team_creation.sql") ?? "";
if (teamCreateIdempotency) {
	for (const [needle, description] of [
		[/primary\s+key\s*\(actor_user_id,\s*request_id\)/i, "request-scoped uniqueness (not one team per user)"],
		[/p_request_id\s+uuid/i, "caller-supplied durable request ID"],
		[/tenant_identity_access_allowed\(v_team_id\)/i, "identity barrier on create and replay"],
		[/insert\s+into\s+public\.team_creation_requests/i, "atomic request-to-team receipt"],
		[/revoke\s+all\s+on\s+table\s+public\.team_creation_requests\s+from\s+public,\s*anon,\s*authenticated,\s*service_role/i, "private idempotency ledger"],
	]) {
		if (!needle.test(teamCreateIdempotency)) errors.push(`20260924000010_idempotent_team_creation.sql: missing ${description}`);
	}
} else {
	errors.push("20260924000010_idempotent_team_creation.sql: missing durable team-create idempotency migration");
}

if (errors.length) {
	console.error("Supabase migration contract failed:");
	for (const error of errors) console.error(`- ${error}`);
	process.exitCode = 1;
} else {
	console.log(`Supabase migration contract passed (${files.length} migrations, unique ordered versions).`);
}
