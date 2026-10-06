import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

function step(workflow, name) {
	const marker = `      - name: ${name}`;
	const start = workflow.indexOf(marker);
	assert.notEqual(start, -1, `workflow step is missing: ${name}`);
	const next = /\n {6}- name:|\n {2}[A-Za-z0-9_-]+:/.exec(workflow.slice(start + marker.length));
	return workflow.slice(start, next ? start + marker.length + next.index : undefined);
}

test("CI and RC block on isolated identity, offboarding and retention PostgreSQL suites", () => {
	for (const [file, stopName, gateName, nextGateName] of [
		["ci.yml", "Stop pinned local Supabase stack", "Blocking reputation, offboarding and retention PostgreSQL gates", "Type, lint, audit, tests, coverage and release build"],
		["release-rc.yml", "Stop local Supabase", "Blocking offboarding and retention PostgreSQL gates", "Full deterministic quality gate"],
	]) {
		const workflow = read(`.github/workflows/${file}`);
		const gate = step(workflow, gateName);
		assert.match(gate, /^\s+set -euo pipefail\r?$/m);
		assert.match(gate, /docker pull supabase\/postgres:17\.6\.1\.136/);
		for (const suite of ["oidc-administration", "saml-administration", "fleet-signed-delivery"]) {
			const command = `node --test scripts/${suite}-postgres.test.mjs`;
			assert.ok(gate.split(/\r?\n/).includes(`          ${command}`), `${file}: ${suite} must be an unconditional command`);
			assert.ok(gate.indexOf("docker pull supabase/postgres:17.6.1.136") < gate.indexOf(command));
			assert.ok(gate.indexOf(command) < gate.indexOf("pnpm verify:offboarding"));
		}
		assert.match(gate, /pnpm verify:offboarding/);
		assert.match(gate, /pnpm verify:retention/);
		assert.ok(gate.indexOf("docker pull") < gate.indexOf("pnpm verify:offboarding"));
		assert.ok(gate.indexOf("pnpm verify:offboarding") < gate.indexOf("pnpm verify:retention"));
		assert.doesNotMatch(gate, /(?:^|\n)\s+(?:if:|continue-on-error:)|\$\{\{\s*secrets\.|SUPABASE_ACCESS_TOKEN|SUPABASE_DB_URL|SERVICE_ROLE_KEY/);
		assert.match(workflow, /pnpm supabase:check/);
		assert.ok(workflow.indexOf(`      - name: ${stopName}`) < workflow.indexOf(`      - name: ${gateName}`));
		assert.ok(workflow.indexOf(`      - name: ${gateName}`) < workflow.indexOf(`      - name: ${nextGateName}`));
	}
});

test("the workflow contract is itself part of the required migration check", () => {
	const scripts = JSON.parse(read("package.json")).scripts;
	assert.match(scripts["supabase:check"], /scripts\/database-workflow-gates\.test\.mjs/);
	assert.match(scripts["supabase:check:edge-typed-slice"], /supabase\/functions\/response-playbooks\/index\.ts/);
	assert.match(scripts["verify:offboarding"], /scripts\/billing-offboarding-postgres\.test\.mjs/);
	assert.match(scripts["verify:offboarding"], /scripts\/pack-offboarding-guard-postgres\.test\.mjs/);
	assert.match(scripts["verify:offboarding"], /scripts\/oidc-scim-offboarding-postgres\.test\.mjs/);
	assert.match(scripts["verify:retention"], /scripts\/retention-holds-postgres\.test\.mjs/);
	for (const file of ["billing-offboarding-postgres.test.mjs", "pack-offboarding-guard-postgres.test.mjs", "retention-holds-postgres.test.mjs"])
		assert.match(read(`scripts/${file}`), /supabase\/postgres:17\.6\.1\.136/);
});

test("CI and RC run team resource RLS, invitation audit, and pilot audit RPCs against the reset PostgreSQL schema", () => {
	for (const [file, gateName] of [
		["ci.yml", "Pinned local Supabase schema contract"],
		["release-rc.yml", "Supabase migration, reset, lint and live boundary gate"],
	]) {
		const gate = step(read(`.github/workflows/${file}`), gateName);
		const reset = gate.indexOf("db reset --local --no-seed");
		const boundary = gate.indexOf("node scripts/database-boundary-hardening-postgres.mjs");
		const resources = gate.indexOf("node scripts/team-resource-read-rls-postgres.mjs");
		const invitations = gate.indexOf("node scripts/team-invitation-atomic-audit-postgres.mjs");
		const pilot = gate.indexOf("pnpm verify:supabase-pilot-audit-live");
		assert.ok(reset >= 0 && reset < boundary && boundary < resources && resources < invitations && invitations < pilot);
		assert.match(gate, /AIDR_TEST_DISPOSABLE_DB: "1"/);
		assert.doesNotMatch(gate, /continue-on-error:/);
	}
	const scripts = JSON.parse(read("package.json")).scripts;
	assert.equal(scripts["verify:supabase-pilot-audit-live"],
		"node scripts/pilot-application-atomic-audit-postgres.mjs && node --test scripts/pilot-decision-notes-postgres.test.mjs");
});

test("CI and RC block on installed Auth, invitation, and membership-key rollback fixtures", () => {
	for (const [file, gateName] of [
		["ci.yml", "Pinned local Supabase schema contract"],
		["release-rc.yml", "Supabase migration, reset, lint and live boundary gate"],
	]) {
		const gate = step(read(`.github/workflows/${file}`), gateName);
		const reset = gate.indexOf("db reset --local --no-seed");
		for (const command of [
			"node scripts/ga-trial-auth-delete-postgres.test.mjs --installed",
			"node scripts/team-invitation-acceptance-postgres.mjs --installed",
			"node scripts/member-api-key-revocation-postgres.mjs",
		]) {
			assert.ok(gate.indexOf(command) > reset, `${file}: ${command} must follow reset`);
		}
		assert.match(gate, /AIDR_TEST_DISPOSABLE_DB: "1"/);
		assert.doesNotMatch(gate, /ga-trial-auth-delete-http|device-membership-token-concurrency|continue-on-error:/);
	}
});
