import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { chmodSync, linkSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, test } from "node:test";
import { applyRecovery, prepareApprovals, preparePayload, readCustodyKey, signPayload, validatePayload } from "./saml-outage-recovery.mjs";

const now = 1_800_000_000;
const tenant = "11111111-1111-4111-8111-111111111111";
const provider = "22222222-2222-4222-8222-222222222222";
const owner = "33333333-3333-4333-8333-333333333333";
const nonce = "44444444-4444-4444-8444-444444444444";
const keys = [
	{ key_id: "55555555-5555-4555-8555-555555555555", tenant_id: tenant, operator_id: "66666666-6666-4666-8666-666666666666", secret_hex: "01".repeat(32) },
	{ key_id: "77777777-7777-4777-8777-777777777777", tenant_id: tenant, operator_id: "88888888-8888-4888-8888-888888888888", secret_hex: "02".repeat(32) },
];
const input = { tenant_id: tenant, current_provider_id: provider, recovery_owner_id: owner, nonce, change_ref: "INC-18", reason: "Primary and secondary identity providers are unavailable." };
const payload = preparePayload(input, now);
const receipts = keys.map((key) => signPayload(payload, key, now));
const directories = [];
const servers = [];

afterEach(async () => {
	for (const server of servers.splice(0)) {
		server.closeIdleConnections();
		await new Promise((done) => server.close(done));
	}
	for (const directory of directories.splice(0)) {
		assert.equal(dirname(directory), resolve(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	}
});

function temporary() {
	const directory = mkdtempSync(join(resolve(tmpdir()), "aidr-saml-recovery-"));
	directories.push(directory);
	return directory;
}

function result(overrides = {}) {
	return { status: "recovered", method: "dual_operator_hmac", nonce, tenant_id: tenant, recovery_owner_id: owner,
		old_provider_id: provider, new_provider_id: null, change_ref: "INC-18", operator_ids: keys.map((key) => key.operator_id),
		audit_log_id: "123", applied_at: "2027-01-15T08:00:00+00:00", ...overrides };
}

async function endpoint(handler) {
	const server = createServer(handler);
	servers.push(server);
	await new Promise((done) => server.listen(0, "127.0.0.1", done));
	return `http://127.0.0.1:${server.address().port}`;
}

function json(response, status, body) {
	response.writeHead(status, { "Content-Type": "application/json" });
	response.end(JSON.stringify(body));
}

function apply(supabaseUrl, overrides = {}) {
	return applyRecovery({ payload, receipts, supabaseUrl, serviceKey: "fixture-service-key", development: true, ...overrides }, now);
}

test("prepare and sign bind deterministic exact UTF-8 bytes with independent HMACs", () => {
	assert.equal(payload, preparePayload(input, now));
	assert.equal(validatePayload(payload, now).expires_at, now + 300);
	assert.deepEqual(prepareApprovals(payload, receipts, now), receipts.map(({ key_id, mac_hex }) => ({ key_id, mac_hex })));
	assert.equal(receipts[0].payload_sha256, createHash("sha256").update(payload, "utf8").digest("hex"));
	assert.equal(receipts[0].mac_hex, createHmac("sha256", Buffer.from(keys[0].secret_hex, "hex")).update(payload, "utf8").digest("hex"));
	assert.equal(JSON.stringify(receipts).includes(keys[0].secret_hex), false);
	const unicode = preparePayload({ ...input, reason: "İki kimlik sağlayıcısı kesintide; onaylı kurtarma 🛡️." }, now);
	assert.equal(signPayload(unicode, keys[0], now).payload_sha256, createHash("sha256").update(Buffer.from(unicode)).digest("hex"));
});

test("payload validation rejects ambiguous, unsupported, malformed and expired requests", () => {
	const parsed = JSON.parse(payload);
	const invalid = [
		"{}", `${payload}\n`, payload.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
		JSON.stringify({ ...parsed, purpose: "other" }), JSON.stringify({ ...parsed, schema_version: "1" }),
		JSON.stringify({ ...parsed, new_provider_id: provider }), JSON.stringify({ ...parsed, nonce: "bad" }),
		JSON.stringify({ ...parsed, tenant_id: tenant.toUpperCase().replace("1111", "AAAA") }),
		JSON.stringify({ ...parsed, reason: "short" }), JSON.stringify({ ...parsed, reason: " untrimmed reason " }),
		JSON.stringify({ ...parsed, reason: "Reason with\ncontrol" }), JSON.stringify({ ...parsed, change_ref: "" }),
		JSON.stringify({ ...parsed, reason: "Reason has an unpaired surrogate \ud800" }),
		JSON.stringify({ ...parsed, issued_at: now + 1 }), JSON.stringify({ ...parsed, expires_at: now }),
		JSON.stringify({ ...parsed, expires_at: now + 301 }), JSON.stringify({ ...parsed, issued_at: now + 0.5 }),
		JSON.stringify({ ...parsed, extra: true }),
	];
	for (const text of invalid) assert.throws(() => validatePayload(text, now));
	assert.throws(() => validatePayload(payload, now + 300), /currently valid/);
	assert.throws(() => signPayload(payload, { ...keys[0], secret_hex: "01" }, now), /32 bytes/);
	assert.throws(() => signPayload(payload, { ...keys[0], tenant_id: provider }, now), /another tenant/);
	assert.throws(() => signPayload(payload, { ...keys[0], extra: true }, now), /unexpected/);
});

test("rejected local approval inputs never contact the endpoint", async () => {
	let calls = 0;
	const url = await endpoint((_request, response) => { calls += 1; json(response, 200, result()); });
	const cases = [
		{ receipts: [receipts[0]] }, { receipts: [...receipts, receipts[0]] },
		{ receipts: [receipts[0], receipts[0]] },
		{ receipts: [receipts[0], { ...receipts[1], operator_id: receipts[0].operator_id }] },
		{ receipts: [receipts[0], { ...receipts[1], payload_sha256: "0".repeat(64) }] },
		{ receipts: [receipts[0], { ...receipts[1], mac_hex: "AA".repeat(32) }] },
		{ receipts: [receipts[0], { ...receipts[1], tenant_id: provider }] },
		{ receipts: [receipts[0], { ...receipts[1], extra: true }] },
		{ payload: preparePayload({ ...input, reason: "A changed reason must receive fresh operator approvals." }, now) },
		{ payload: preparePayload(input, now - 301) },
		{ development: false }, { serviceKey: "" }, { serviceKey: "fixture\nsecret" },
	];
	for (const options of cases) await assert.rejects(apply(url, options));
	for (const unsafe of ["http://api.example.test", "https://user:secret@example.test", "https://example.test/path", "https://example.test/?token=secret"]) {
		await assert.rejects(apply(unsafe), /HTTPS origin/);
	}
	assert.equal(calls, 0);
});

test("apply sends only exact signed bytes and two MACs and verifies the database receipt", async () => {
	let observed;
	const url = await endpoint(async (request, response) => {
		let body = "";
		for await (const chunk of request) body += chunk;
		observed = { path: request.url, method: request.method, authorization: request.headers.authorization, body: JSON.parse(body) };
		json(response, 200, result({ operator_ids: [...keys.map((key) => key.operator_id)].reverse() }));
	});
	assert.equal((await apply(url)).status, "recovered");
	assert.deepEqual(observed, { path: "/rest/v1/rpc/recover_tenant_saml_outage", method: "POST", authorization: "Bearer fixture-service-key",
		body: { p_payload: payload, p_approvals: receipts.map(({ key_id, mac_hex }) => ({ key_id, mac_hex })) } });
	assert.equal(JSON.stringify(observed.body).includes("operator_id"), false);
	assert.equal(JSON.stringify(observed.body).includes(keys[0].secret_hex), false);
});

test("a structurally valid forged MAC requires database authentication and cannot claim recovery", async () => {
	let calls = 0;
	const url = await endpoint(async (request, response) => {
		calls += 1;
		let body = "";
		for await (const chunk of request) body += chunk;
		const submitted = JSON.parse(body);
		const authentic = submitted.p_approvals.every((approval) => {
			const key = keys.find((entry) => entry.key_id === approval.key_id);
			return key && approval.mac_hex === createHmac("sha256", Buffer.from(key.secret_hex, "hex")).update(submitted.p_payload).digest("hex");
		});
		json(response, authentic ? 200 : 403, authentic ? result() : { code: "42501", message: "private error details must not escape" });
	});
	await assert.rejects(apply(url, { receipts: [receipts[0], { ...receipts[1], mac_hex: "00".repeat(32) }] }), (error) => {
		assert.match(error.message, /403 42501/);
		assert.doesNotMatch(error.message, /private error/);
		return true;
	});
	assert.equal(calls, 1);
});

test("unbound or malformed success responses cannot claim recovery", async () => {
	let body = result();
	const url = await endpoint((_request, response) => json(response, 200, body));
	for (const change of [
		{ tenant_id: provider }, { nonce: owner }, { recovery_owner_id: provider }, { old_provider_id: owner },
		{ new_provider_id: provider }, { change_ref: "other" }, { operator_ids: [keys[0].operator_id, keys[0].operator_id] },
		{ operator_ids: [keys[0].operator_id, owner] }, { audit_log_id: 123 }, { applied_at: "bad" },
		{ applied_at: new Date((now - 1) * 1000).toISOString() },
		{ applied_at: new Date((now + 300) * 1000).toISOString() },
		{ secret: "never print this" }, { status: "pending" },
	]) {
		body = result(change);
		await assert.rejects(apply(url), /Recovery result|does not bind/);
	}
});

test("redirects are refused without forwarding a service credential", async () => {
	let calls = 0;
	const url = await endpoint((_request, response) => {
		calls += 1;
		response.writeHead(302, { Location: "/different-route" });
		response.end();
	});
	await assert.rejects(apply(url), /reconcile the nonce/);
	assert.equal(calls, 1);
});

function privateFile(path) {
	if (process.platform !== "win32") { chmodSync(path, 0o600); return; }
	const command = `
$ErrorActionPreference = 'Stop'
$item = [System.IO.FileInfo]::new([Environment]::GetEnvironmentVariable('AIDR_TEST_CUSTODY_FILE'))
$acl = $item.GetAccessControl()
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) { $acl.PurgeAccessRules($entry.IdentityReference) }
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.SetOwner($owner)
foreach ($sid in @($owner, [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
}
$item.SetAccessControl($acl)
`;
	execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(command, "utf16le").toString("base64")], {
		stdio: "ignore", windowsHide: true, env: { ...process.env, AIDR_TEST_CUSTODY_FILE: path },
	});
}

test("custody key reads enforce native private permissions and reject linked files", () => {
	const directory = temporary();
	const file = join(directory, "operator.json");
	writeFileSync(file, JSON.stringify(keys[0]), { mode: 0o600 });
	privateFile(file);
	assert.deepEqual(readCustodyKey(file), keys[0]);
	const link = join(directory, "linked.json");
	linkSync(file, link);
	assert.throws(() => readCustodyKey(file), /without links/);
	const broad = join(directory, "broad.json");
	writeFileSync(broad, JSON.stringify(keys[0]), { mode: 0o644 });
	if (process.platform === "win32") {
		const command = `$item = [System.IO.FileInfo]::new([Environment]::GetEnvironmentVariable('AIDR_TEST_CUSTODY_FILE')); $acl = $item.GetAccessControl(); $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Read', 'Allow')); $item.SetAccessControl($acl)`;
		execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(command, "utf16le").toString("base64")], { stdio: "ignore", windowsHide: true, env: { ...process.env, AIDR_TEST_CUSTODY_FILE: broad } });
	}
	assert.throws(() => readCustodyKey(broad), /Windows ACL|mode 0600/);
});

test("CLI prepares reviewable bytes and signs without overwriting files or printing secrets", () => {
	const directory = temporary();
	const prepared = join(directory, "payload.json");
	const approval = join(directory, "approval.json");
	const keyFile = join(directory, "operator.json");
	writeFileSync(keyFile, JSON.stringify(keys[0]), { mode: 0o600 });
	privateFile(keyFile);
	const script = resolve("scripts/saml-outage-recovery.mjs");
	const prepareArgs = [script, "prepare", "--tenant", tenant, "--current-provider", provider, "--recovery-owner", owner, "--change-ref", "INC-18", "--reason", input.reason, "--out", prepared];
	const preparedResult = spawnSync(process.execPath, prepareArgs, { encoding: "utf8" });
	assert.equal(preparedResult.status, 0, preparedResult.stderr);
	const text = readFileSync(prepared, "utf8");
	assert.equal(validatePayload(text).tenant_id, tenant);
	const signed = spawnSync(process.execPath, [script, "sign", "--payload", prepared, "--key-file", keyFile, "--out", approval], { encoding: "utf8" });
	assert.equal(signed.status, 0, signed.stderr);
	assert.equal(JSON.parse(readFileSync(approval, "utf8")).payload_sha256, createHash("sha256").update(text).digest("hex"));
	assert.equal(`${preparedResult.stdout}${preparedResult.stderr}${signed.stdout}${signed.stderr}`.includes(keys[0].secret_hex), false);
	assert.notEqual(spawnSync(process.execPath, prepareArgs, { encoding: "utf8" }).status, 0);
	assert.equal(readFileSync(prepared, "utf8"), text);
});
