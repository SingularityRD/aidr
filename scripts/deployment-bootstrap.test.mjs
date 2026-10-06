import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const PREVIOUS_OWNER_ID = "22222222-2222-4222-8222-222222222222";
const NEW_OWNER_ID = "33333333-3333-4333-8333-333333333333";
const PREVIOUS_OWNER_EMAIL = "owner@example.test";
const NEW_OWNER_EMAIL = "successor@example.test";
const vendorEnv = Object.fromEntries((await readFile(path.resolve(import.meta.dirname, "../deploy/upstream/docker/.env.example"), "utf8"))
	.split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line))
	.map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));

const temporaryDirectories = [];
const servers = [];

afterEach(async () => {
	await Promise.all(
		servers.splice(0).map(
			(server) =>
				new Promise((done) => {
					server.closeIdleConnections();
					server.close(done);
				}),
		),
	);
	await Promise.all(
		temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
	);
});

function json(response, status, value) {
	response.writeHead(status, { "content-type": "application/json" });
	response.end(JSON.stringify(value));
}

/**
 * Model just enough of the Supabase REST surface for the transfer path: the Auth
 * admin user listing, and team_members reads (by user / by role), the owner
 * upsert and the demotion patch. `state.members` is the live membership map.
 */
function handlers(state) {
	return async (request, response) => {
		const url = new URL(request.url, "http://127.0.0.1");
		state.calls.push(`${request.method} ${url.pathname}${url.search}`);
		let body = "";
		for await (const chunk of request) body += chunk;

		if (url.pathname === "/auth/v1/admin/users") {
			if (request.method === "POST") {
				state.created = JSON.parse(body);
				return json(response, 200, { id: PREVIOUS_OWNER_ID, email: state.created.email });
			}
			return json(response, 200, { users: state.accounts });
		}
		if (url.pathname === "/rest/v1/rpc/bootstrap_customer") {
			state.bootstrap = JSON.parse(body);
			return json(response, 200, {
				tenant_id: TENANT_ID,
				user_id: state.bootstrap.p_user_id,
				name: "Customer",
				seats: state.bootstrap.p_seats,
			});
		}
		if (url.pathname === "/rest/v1/rpc/configure_tenant_admission_mode") {
			state.admissionMode = JSON.parse(body).p_mode;
			return json(response, 200, { status: "configured", mode: state.admissionMode });
		}
		if (url.pathname !== "/rest/v1/team_members") return json(response, 404, {});

		const rows = Object.entries(state.members).map(([user_id, role]) => ({ user_id, role }));
		if (request.method === "GET") {
			const userId = url.searchParams.get("user_id")?.replace("eq.", "");
			const role = url.searchParams.get("role")?.replace("eq.", "");
			if (userId) return json(response, 200, rows.filter((row) => row.user_id === userId));
			if (role) return json(response, 200, rows.filter((row) => row.role === role));
			return json(response, 200, rows);
		}
		if (request.method === "POST") {
			const payload = JSON.parse(body);
			state.members[payload.user_id] = payload.role;
			state.writes.push({ method: "POST", ...payload });
			return json(response, 201, [{ user_id: payload.user_id, role: payload.role }]);
		}
		if (request.method === "PATCH") {
			const userId = url.searchParams.get("user_id")?.replace("eq.", "");
			const role = url.searchParams.get("role")?.replace("eq.", "");
			const payload = JSON.parse(body);
			// A conditional update changes nothing when the row no longer holds the
			// expected role, which is exactly what the driver must detect.
			if (!userId || state.members[userId] !== role) return json(response, 200, []);
			state.members[userId] = payload.role;
			state.writes.push({ method: "PATCH", user_id: userId, ...payload });
			return json(response, 200, [{ user_id: userId, role: payload.role }]);
		}
		return json(response, 405, {});
	};
}

async function fixture({ receipt = true, members = {}, transferReceipt = null, mode = "self-hosted", host = "127.0.0.1" } = {}) {
	const state = { accounts: [], members: { ...members }, writes: [], calls: [] };
	const server = createServer(await handlers(state));
	servers.push(server);
	await new Promise((done) => server.listen(0, host, done));
	const address = server.address();
	const origin = `http://${host === "::1" ? "[::1]" : host}:${address.port}`;
	const directory = await mkdtemp(path.join(os.tmpdir(), "aidr-bootstrap-"));
	temporaryDirectories.push(directory);
	await writeFile(
		path.join(directory, "deployment.json"),
		JSON.stringify({
			mode,
			supabase_url: origin,
			dashboard_url: origin,
			development: true,
		}),
	);
	await writeFile(
		path.join(directory, ".env"),
		"SERVICE_ROLE_KEY=test-service-role\nANON_KEY=test-anon-key\n",
	);
	if (receipt) {
		await writeFile(
			path.join(directory, "bootstrap-receipt.json"),
			JSON.stringify(
				{
					bootstrap_id: "44444444-4444-4444-8444-444444444444",
					email: PREVIOUS_OWNER_EMAIL,
					name: "Customer",
					seats: 5,
					supabase_url: origin,
					state: "complete",
					tenant_id: TENANT_ID,
					user_id: PREVIOUS_OWNER_ID,
				},
				null,
				2,
			),
		);
	}
	state.accounts = [
		{ id: PREVIOUS_OWNER_ID, email: PREVIOUS_OWNER_EMAIL, email_confirmed_at: "2026-01-01T00:00:00.000Z" },
		{ id: NEW_OWNER_ID, email: NEW_OWNER_EMAIL, email_confirmed_at: "2026-01-01T00:00:00.000Z" },
	];
	if (transferReceipt) {
		await writeFile(
			path.join(directory, "owner-transfer-receipt.json"),
			JSON.stringify(transferReceipt, null, 2),
		);
	}
	return { directory, state };
}

function runScript(directory, args, stdin = "", preload = null) {
	const child = spawn(
		process.execPath,
		[...(preload ? ["--require", preload] : []), path.resolve("scripts/deployment-bootstrap.mjs"), "--deployment", directory, ...args],
		{ cwd: process.cwd(), stdio: ["pipe", "pipe", "pipe"] },
	);
	let stdout = "";
	let stderr = "";
	child.stdout.setEncoding("utf8").on("data", (chunk) => {
		stdout += chunk;
	});
	child.stderr.setEncoding("utf8").on("data", (chunk) => {
		stderr += chunk;
	});
	child.stdin.end(stdin);
	return new Promise((done) => child.on("close", (status) => done({ status, stdout, stderr })));
}

function transfer(directory, { confirmation = NEW_OWNER_EMAIL, requestedBy = PREVIOUS_OWNER_ID } = {}) {
	return runScript(
		directory,
		["--transfer-owner", NEW_OWNER_EMAIL, ...(requestedBy ? ["--requested-by", requestedBy] : [])],
		confirmation === null ? "" : `${confirmation}\n`,
	);
}

for (const [name, value, kind] of [
	...["ANON_KEY", "SERVICE_ROLE_KEY", "JWT_SECRET", "POSTGRES_PASSWORD"].map((name) => [name, vendorEnv[name], "public vendor"]),
	["JWT_SECRET", "REPLACE_WITH_THE_DEPLOYMENT_PRIVATE_JWT_SECRET", "non-API placeholder"],
]) {
	test(`bootstrap rejects the ${kind} ${name} before any request or receipt mutation`, async () => {
		const f = await fixture({ members: { [PREVIOUS_OWNER_ID]: "owner" } });
		const originalReceipt = await readFile(path.join(f.directory, "bootstrap-receipt.json"), "utf8");
		const configured = { SERVICE_ROLE_KEY: "test-service-role", ANON_KEY: "test-anon-key", [name]: value };
		await writeFile(path.join(f.directory, ".env"), Object.entries(configured).map(([key, value]) => `${key}=${value}`).join("\n") + "\n");
		const result = await transfer(f.directory);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /shared vendor credentials/);
		assert.deepEqual(f.state.calls, []);
		assert.equal(await readFile(path.join(f.directory, "bootstrap-receipt.json"), "utf8"), originalReceipt);
		assert.equal(existsSync(path.join(f.directory, "owner-transfer-receipt.json")), false);
		assert.equal((result.stdout + result.stderr).includes(value), false, "credential values must not be printed");
	});
}

test("ownership transfer works on an explicitly configured IPv6 loopback deployment", async () => {
	const accepted = await fixture({ host: "::1", members: { [PREVIOUS_OWNER_ID]: "owner" } });
	const result = await transfer(accepted.directory);
	assert.equal(result.status, 0, result.stderr);
	assert.equal(accepted.state.members[NEW_OWNER_ID], "owner");
});

test("ownership transfer rejects an account whose email is not confirmed", async () => {
	const f = await fixture({ members: { [PREVIOUS_OWNER_ID]: "owner" } });
	f.state.accounts.find((account) => account.id === NEW_OWNER_ID).email_confirmed_at = null;
	const result = await transfer(f.directory);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /must already have a confirmed account/);
	assert.deepEqual(f.state.writes, []);
	assert.equal(existsSync(path.join(f.directory, "owner-transfer-receipt.json")), false);
});

test("development mode never admits a non-HTTP credential endpoint", async () => {
	const f = await fixture({ members: { [PREVIOUS_OWNER_ID]: "owner" } });
	await writeFile(path.join(f.directory, "deployment.json"), JSON.stringify({ mode: "self-hosted", development: true, supabase_url: "ftp://localhost" }));
	const result = await transfer(f.directory);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /HTTPS required/);
	assert.deepEqual(f.state.calls, []);
});

test("transfer requires the current owner and records both principals", async () => {
	// 1. The recorded bootstrap principal is no longer the tenant's owner: the
	//    transfer must refuse and leave every membership untouched.
	const refused = await fixture({ members: { [PREVIOUS_OWNER_ID]: "admin" } });
	const refusal = await transfer(refused.directory);
	assert.notEqual(refusal.status, 0, "a transfer without the current owner must fail");
	assert.match(refusal.stderr, /not the tenant's current owner/);
	assert.equal(refused.state.writes.length, 0, "no membership may change without the current owner");
	assert.equal(
		existsSync(path.join(refused.directory, "owner-transfer-receipt.json")),
		false,
		"a refused transfer must not write a receipt",
	);

	// 2. With the current owner present, ownership moves to a second account and
	//    both principals are recorded.
	const accepted = await fixture({ members: { [PREVIOUS_OWNER_ID]: "owner" } });
	const result = await transfer(accepted.directory);
	assert.equal(result.status, 0, result.stderr);
	assert.equal(accepted.state.members[NEW_OWNER_ID], "owner", "the second owner must be added");
	assert.equal(accepted.state.members[PREVIOUS_OWNER_ID], "admin", "the bootstrap principal must be demoted");
	const addIndex = accepted.state.writes.findIndex(
		(write) => write.method === "POST" && write.user_id === NEW_OWNER_ID,
	);
	const demoteIndex = accepted.state.writes.findIndex(
		(write) => write.method === "PATCH" && write.user_id === PREVIOUS_OWNER_ID,
	);
	assert.ok(addIndex >= 0, "the second owner must be added");
	assert.ok(demoteIndex > addIndex, "the previous owner is demoted only after the second owner exists");

	const receipt = JSON.parse(
		await readFile(path.join(accepted.directory, "owner-transfer-receipt.json"), "utf8"),
	);
	assert.equal(receipt.state, "complete");
	assert.equal(receipt.tenant_id, TENANT_ID);
	assert.deepEqual(receipt.previous_owner, {
		user_id: PREVIOUS_OWNER_ID,
		email: PREVIOUS_OWNER_EMAIL,
		role_before: "owner",
		role_after: "admin",
	});
	assert.deepEqual(receipt.new_owner, {
		user_id: NEW_OWNER_ID,
		email: NEW_OWNER_EMAIL,
		role: "owner",
	});
	assert.equal(receipt.authorized_by, PREVIOUS_OWNER_ID);
});

test("transfer refuses without a completed bootstrap receipt or a second owner account", async () => {
	const missingReceipt = await fixture({ receipt: false, members: { [PREVIOUS_OWNER_ID]: "owner" } });
	const missing = await transfer(missingReceipt.directory);
	assert.notEqual(missing.status, 0);
	assert.match(missing.stderr, /completed bootstrap receipt/);
	assert.equal(missingReceipt.state.writes.length, 0);

	const noSecondAccount = await fixture({ members: { [PREVIOUS_OWNER_ID]: "owner" } });
	noSecondAccount.state.accounts = [
		{ id: PREVIOUS_OWNER_ID, email: PREVIOUS_OWNER_EMAIL, email_confirmed_at: "2026-01-01T00:00:00.000Z" },
	];
	const absent = await transfer(noSecondAccount.directory);
	assert.notEqual(absent.status, 0);
	assert.match(absent.stderr, /must already have a confirmed account/);
	assert.equal(noSecondAccount.state.writes.length, 0);
});

test("transfer refuses a caller that is not the current owner and an unconfirmed stdin operator", async () => {
	const wrongCaller = await fixture({ members: { [PREVIOUS_OWNER_ID]: "owner" } });
	const refused = await transfer(wrongCaller.directory, {
		requestedBy: NEW_OWNER_ID,
		confirmation: NEW_OWNER_EMAIL,
	});
	assert.notEqual(refused.status, 0);
	assert.match(refused.stderr, /must be the current owner/);
	assert.equal(wrongCaller.state.writes.length, 0);

	const unconfirmed = await fixture({ members: { [PREVIOUS_OWNER_ID]: "owner" } });
	const silent = await transfer(unconfirmed.directory, { confirmation: null });
	assert.notEqual(silent.status, 0);
	assert.match(silent.stderr, /Confirmation must repeat/);
	assert.equal(unconfirmed.state.writes.length, 0);
	assert.equal(existsSync(path.join(unconfirmed.directory, "owner-transfer-receipt.json")), false);
});

test("bootstrap still provisions the first owner from a piped password", async () => {
	const fresh = await fixture({ receipt: false });
	const password = "test-only-password-16";
	const licenseExpiresAt = "2027-01-01T00:00:00.000Z";
	const result = await runScript(
		fresh.directory,
		["--email", PREVIOUS_OWNER_EMAIL, "--name", "Customer", "--seats", "5", "--license-expires-at", licenseExpiresAt, "--license-reference", "TEST-CONTRACT-001"],
		`${password}\n`,
	);
	assert.equal(result.status, 0, result.stderr);
	const receipt = JSON.parse(
		await readFile(path.join(fresh.directory, "bootstrap-receipt.json"), "utf8"),
	);
	assert.equal(receipt.state, "complete");
	assert.equal(receipt.user_id, PREVIOUS_OWNER_ID);
	assert.equal(receipt.tenant_id, TENANT_ID);
	assert.equal(fresh.state.created.app_metadata.aidr_bootstrap_id, receipt.bootstrap_id);
	assert.equal(fresh.state.bootstrap.p_seats, 5);
	assert.equal(fresh.state.bootstrap.p_license_expires_at, licenseExpiresAt);
	assert.equal(fresh.state.bootstrap.p_license_reference, "TEST-CONTRACT-001");
	assert.equal(fresh.state.admissionMode, "onprem");
	assert.ok(!result.stdout.includes(password), "the password must never reach stdout");
});

test("bootstrap refuses missing contract terms before creating an account or configuring admission", async () => {
	const fresh = await fixture({ receipt: false });
	const result = await runScript(fresh.directory,
		["--email", PREVIOUS_OWNER_EMAIL, "--name", "Customer", "--seats", "5"],
		"test-only-password-16\n");
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /license-expires-at/);
	assert.deepEqual(fresh.state.calls, [], "invalid contract input must be rejected before every API call");
	assert.equal(fresh.state.created, undefined);
	assert.equal(fresh.state.admissionMode, undefined);
});

test("bootstrap refuses an invalid password before creating a receipt or calling the API", async () => {
	const fresh = await fixture({ receipt: false });
	const result = await runScript(fresh.directory,
		["--email", PREVIOUS_OWNER_EMAIL, "--name", "Customer", "--seats", "5", "--license-expires-at", "2027-01-01T00:00:00.000Z", "--license-reference", "TEST-CONTRACT-001"],
		"too-short\n");
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /Password must be 16/);
	assert.deepEqual(fresh.state.calls, [], "invalid password must be rejected before every API call");
	assert.equal(fresh.state.created, undefined);
	assert.equal(fresh.state.admissionMode, undefined);
	assert.equal(existsSync(path.join(fresh.directory, "bootstrap-receipt.json")), false);
});

test("bootstrap refuses cloud deployments before any API call", async () => {
	const cloud = await fixture({ receipt: false, mode: "cloud" });
	const result = await runScript(cloud.directory,
		["--email", PREVIOUS_OWNER_EMAIL, "--name", "Customer", "--seats", "5", "--license-expires-at", "2027-01-01T00:00:00.000Z", "--license-reference", "TEST-CONTRACT-001"],
		"test-only-password-16\n");
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /only supported for self-hosted installations/);
	assert.deepEqual(cloud.state.calls, [], "cloud mode must be rejected before even a health/read API request");
	assert.equal(cloud.state.created, undefined);
	assert.equal(cloud.state.admissionMode, undefined);
});

test("bootstrap receipt update failure before rename preserves the prior receipt", async () => {
	const fresh = await fixture();
	const receiptPath = path.join(fresh.directory, "bootstrap-receipt.json");
	const before = await readFile(receiptPath);
	const preload = path.join(fresh.directory, "fail-fsync.cjs");
	await writeFile(preload, [
		"const fs = require('node:fs');",
		"fs.fsyncSync = () => { const error = new Error('simulated receipt fsync failure'); error.code = 'EIO'; throw error; };",
		"require('node:module').syncBuiltinESMExports();",
	].join("\n"));
	const result = await runScript(fresh.directory,
		["--email", PREVIOUS_OWNER_EMAIL, "--name", "Customer", "--seats", "5", "--license-expires-at", "2027-01-01T00:00:00.000Z", "--license-reference", "TEST-CONTRACT-001", "--resume"],
		"", preload);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /simulated receipt fsync failure/);
	assert.deepEqual(fresh.state.calls, [], "receipt must flush before any API request");
	assert.deepEqual(await readFile(receiptPath), before, "failed staging must leave the old receipt byte-for-byte intact");
	assert.deepEqual((await readdir(fresh.directory)).filter((name) => name.startsWith("bootstrap-receipt.json.") && name.endsWith(".tmp")), []);
});

test("bootstrap resume atomically updates an existing receipt and completes", async () => {
	const fresh = await fixture();
	const licenseExpiresAt = "2027-01-01T00:00:00.000Z";
	const result = await runScript(fresh.directory,
		["--email", PREVIOUS_OWNER_EMAIL, "--name", "Customer", "--seats", "5", "--license-expires-at", licenseExpiresAt, "--license-reference", "TEST-CONTRACT-001", "--resume"]);
	assert.equal(result.status, 0, result.stderr);
	const receipt = JSON.parse(await readFile(path.join(fresh.directory, "bootstrap-receipt.json"), "utf8"));
	assert.equal(receipt.state, "complete");
	assert.equal(receipt.license_expires_at, licenseExpiresAt);
	assert.equal(receipt.license_reference, "TEST-CONTRACT-001");
	assert.equal(fresh.state.admissionMode, "onprem");
	assert.ok(fresh.state.calls.some((call) => call.includes("/rest/v1/rpc/bootstrap_customer")));
});

const TRANSFER_RECEIPT_BASE = {
	bootstrap_id: "44444444-4444-4444-8444-444444444444",
	tenant_id: TENANT_ID,
	supabase_url: "http://127.0.0.1",
	authorized_by: PREVIOUS_OWNER_ID,
	previous_owner: {
		user_id: PREVIOUS_OWNER_ID,
		email: PREVIOUS_OWNER_EMAIL,
		role_before: "owner",
		role_after: "admin",
	},
	new_owner: { user_id: NEW_OWNER_ID, email: NEW_OWNER_EMAIL, role: "owner" },
};

test("transfer completes an interrupted run and never transfers the same deployment twice", async () => {
	// The demotion landed but the run died before the receipt was closed: the
	// remaining work is to verify the final state and close the receipt.
	const interrupted = await fixture({
		members: { [PREVIOUS_OWNER_ID]: "admin", [NEW_OWNER_ID]: "owner" },
		transferReceipt: { ...TRANSFER_RECEIPT_BASE, state: "in_progress" },
	});
	const resumed = await transfer(interrupted.directory);
	assert.equal(resumed.status, 0, resumed.stderr);
	assert.equal(interrupted.state.writes.length, 0, "a resume must not change membership again");
	const closed = JSON.parse(
		await readFile(path.join(interrupted.directory, "owner-transfer-receipt.json"), "utf8"),
	);
	assert.equal(closed.state, "complete");
	assert.equal(closed.previous_owner.user_id, PREVIOUS_OWNER_ID);
	assert.equal(closed.new_owner.user_id, NEW_OWNER_ID);
	assert.ok(Number.isFinite(Date.parse(closed.last_resume_attempted_at)), "a resumed transfer records its atomic preflight checkpoint");

	const completed = await fixture({
		members: { [PREVIOUS_OWNER_ID]: "owner" },
		transferReceipt: { ...TRANSFER_RECEIPT_BASE, state: "complete" },
	});
	const twice = await transfer(completed.directory);
	assert.notEqual(twice.status, 0);
	assert.match(twice.stderr, /already exists/);
	assert.equal(completed.state.writes.length, 0);
});

test("owner-transfer receipt write failure preserves the prior receipt before any API call", async () => {
	const interrupted = await fixture({
		members: { [PREVIOUS_OWNER_ID]: "admin", [NEW_OWNER_ID]: "owner" },
		transferReceipt: { ...TRANSFER_RECEIPT_BASE, state: "in_progress" },
	});
	const receiptPath = path.join(interrupted.directory, "owner-transfer-receipt.json");
	const before = await readFile(receiptPath);
	const preload = path.join(interrupted.directory, "fail-fsync.cjs");
	await writeFile(preload, [
		"const fs = require('node:fs');",
		"fs.fsyncSync = () => { const error = new Error('simulated receipt fsync failure'); error.code = 'EIO'; throw error; };",
		"require('node:module').syncBuiltinESMExports();",
	].join("\n"));
	const result = await runScript(interrupted.directory,
		["--transfer-owner", NEW_OWNER_EMAIL, "--requested-by", PREVIOUS_OWNER_ID],
		`${NEW_OWNER_EMAIL}\n`, preload);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /simulated receipt fsync failure/);
	assert.deepEqual(interrupted.state.calls, [], "failed receipt checkpoint must stop before all ownership API reads and writes");
	assert.deepEqual(await readFile(receiptPath), before, "failed staging must leave the prior transfer receipt byte-for-byte intact");
	assert.deepEqual((await readdir(interrupted.directory)).filter((name) => name.startsWith("owner-transfer-receipt.json.") && name.endsWith(".tmp")), []);
});
