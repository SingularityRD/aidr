import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const migrationsDir = path.join(root, "supabase", "migrations");
const files = (await readdir(migrationsDir)).filter((name) => name.endsWith(".sql")).sort();

const errors = [];
const seenVersions = new Map();
const parsed = [];

for (const name of files) {
	const match = /^(\d{14})_([a-z0-9][a-z0-9_-]*)\.sql$/i.exec(name);
	if (!match) {
		errors.push(`${name}: expected YYYYMMDDHHMMSS_description.sql (14-digit unique version)`);
		continue;
	}
	const [, version] = match;
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
	"20260327000400_control_plane_api_v1.sql",
	"20260327000500_commercial_v1.sql",
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

if (errors.length) {
	console.error("Supabase migration contract failed:");
	for (const error of errors) console.error(`- ${error}`);
	process.exitCode = 1;
} else {
	console.log(`Supabase migration contract passed (${files.length} migrations, unique ordered versions).`);
}
