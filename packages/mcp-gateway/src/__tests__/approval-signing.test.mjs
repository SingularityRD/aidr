import "./helpers/isolated-home.mjs";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, createHmac, createPrivateKey, generateKeyPairSync } from "node:crypto";
import {
	chmodSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { FileMcpAttestationStore } from "@singularityrd/aidr-core";
import { validateGatewayConfig } from "../config.mjs";
import { approveQuarantinedToolset } from "../operator-approval.mjs";
import { testStateDir } from "./helpers/approval-key.mjs";
import { fixture, rpc } from "./helpers/gateway-fixture.mjs";

const src = resolve(import.meta.dirname, "..");
const PASSPHRASE = "operator passphrase for tests";

function tenantDir(stateDir, tenantId) {
	return join(stateDir, createHash("sha256").update(tenantId).digest("hex"));
}

/** A gateway fixture whose attestation state lives in real files, like the CLI's. */
function fileBackedFixture(overrides = {}) {
	const stateDir = testStateDir();
	const stores = new Map(
		["tenant-a", "tenant-b"].map((tenant) => [
			tenant,
			new FileMcpAttestationStore(tenantDir(stateDir, tenant)),
		]),
	);
	const f = fixture({
		...overrides,
		stores,
		gatewayConfig: { stateDir, ...overrides.gatewayConfig },
	});
	return { f, stateDir, dir: tenantDir(stateDir, "tenant-a") };
}

function stateFile(dir) {
	const name = readdirSync(dir).find((entry) => entry.endsWith(".json"));
	assert.ok(name, "attestation state file exists");
	return { name, path: join(dir, name) };
}

function canonical(value) {
	if (Array.isArray(value)) return value.map(canonical);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.keys(value)
			.sort()
			.map((key) => [key, canonical(value[key])]),
	);
}

/** The entry the auditor's probe appended: copied from the quarantine, no operator key. */
function selfApproval(state) {
	const q = state.quarantine;
	return {
		toolsetHash: q.toolsetHash,
		keyId: q.keyId,
		signerKeySha256: q.signerKeySha256,
		bindingSha256: q.bindingSha256,
		approvedAt: new Date().toISOString(),
		approvedBy: "agent",
		reason: "self",
	};
}

/** Run the approval CLI without blocking the event loop (the gateway under test keeps serving). */
function run(args, input = "") {
	return new Promise((resolveRun, rejectRun) => {
		const child = spawn(process.execPath, [join(src, "approve.mjs"), ...args], {
			env: { ...process.env },
		});
		let stdout = "";
		let stderr = "";
		const timer = setTimeout(() => child.kill(), 20_000);
		child.stdout.setEncoding("utf8").on("data", (chunk) => {
			stdout += chunk;
		});
		child.stderr.setEncoding("utf8").on("data", (chunk) => {
			stderr += chunk;
		});
		child.once("error", rejectRun);
		child.once("close", (status) => {
			clearTimeout(timer);
			resolveRun({ status, stdout, stderr });
		});
		child.stdin.end(input);
	});
}

describe("MSC-1: a same-user process cannot approve a quarantined toolset", () => {
	it("keeps the toolset blocked after the state file is edited to self-approve (auditor probe)", async () => {
		const { f, dir } = fileBackedFixture();
		const base = await f.start();
		const before = await rpc(base, f.tokenA, "tools/call", 1);
		assert.match(before.body.error.message, /manifest_quarantined/);

		// "Agent" step: plain file edit, no operator command, no key.
		const { path } = stateFile(dir);
		const state = JSON.parse(readFileSync(path, "utf8"));
		state.approvedToolsets.push(selfApproval(state));
		writeFileSync(path, JSON.stringify(state));

		const after = await rpc(base, f.tokenA, "tools/call", 2);
		assert.ok(after.body.error, "a self-approved toolset must not be delivered");
		assert.match(after.body.error.message, /manifest_rejected/);
		assert.equal(f.toolCalls, 0);
	});

	it("ignores and reports an unsigned entry even when the seal is recomputed with the readable key", async () => {
		const { f, dir } = fileBackedFixture();
		const base = await f.start();
		await rpc(base, f.tokenA, "tools/call", 1);
		const { name, path } = stateFile(dir);
		const { stateMac: _seal, ...state } = JSON.parse(readFileSync(path, "utf8"));
		state.approvedToolsets.push(selfApproval(state));
		const key = readFileSync(join(dir, ".state-integrity.key"));
		const stateMac = createHmac("sha256", key)
			.update("AIDR-MCP-ATTESTATION-STATE-V1\0")
			.update(name)
			.update("\0")
			.update(JSON.stringify(canonical(state)))
			.digest("hex");
		writeFileSync(path, JSON.stringify({ ...state, stateMac }));

		const after = await rpc(base, f.tokenA, "tools/call", 2);
		assert.match(after.body.error.message, /manifest_quarantined/);
		assert.equal(f.toolCalls, 0);
		assert.ok(
			f.events.some(
				(event) =>
					event.reason === "approval_entry_ignored" &&
					event.approvalRejection === "unsigned_approval" &&
					event.decision === "deny",
			),
		);

		// The operator path still works: a signed approval releases the toolset.
		assert.equal((await f.approve()).approved, true);
		const approved = await rpc(base, f.tokenA, "tools/call", 3);
		assert.equal(approved.body.result.content[0].text, "Normal result");
	});

	it("refuses an approval for a toolset or binding the configuration does not produce", async () => {
		const { f } = fileBackedFixture();
		const base = await f.start();
		await rpc(base, f.tokenA, "tools/call", 1);
		const state = await f.gateway.storeFor("tenant-a").read("server-a");
		const common = {
			tenantId: "tenant-a",
			serverId: "server-a",
			approvedBy: "operator",
			reason: "test",
		};
		await assert.rejects(
			approveQuarantinedToolset(f.gateway, {
				...common,
				toolsetHash: state.quarantine.toolsetHash,
				bindingSha256: state.quarantine.bindingSha256,
			}),
			/approval key required/,
		);
		assert.deepEqual(
			await approveQuarantinedToolset(f.gateway, {
				...common,
				toolsetHash: "0".repeat(64),
				bindingSha256: state.quarantine.bindingSha256,
				approvalKey: { keyId: "x", privateKey: "unused" },
			}),
			{ approved: false, reason: "toolset_mismatch" },
		);
	});
});

describe("MSC-14: the state directory is absolute and private", () => {
	it("rejects a relative stateDir in the configuration", () => {
		const { f } = fileBackedFixture();
		const config = {
			stateDir: "relative/state",
			approvalKeys: f.gateway.config.approvalKeys,
			clients: f.clients,
			servers: f.servers,
		};
		assert.throws(() => validateGatewayConfig(config), { code: "statedir_must_be_absolute" });
		assert.throws(
			() =>
				validateGatewayConfig({
					...config,
					stateDir: "/var/lib/aidr/state",
					approvalKeys: undefined,
				}),
			{ code: "missing_approvalkeys" },
		);
	});

	it("refuses to start on a group- or world-writable state directory", {
		skip: process.platform === "win32",
	}, async () => {
		const stateDir = testStateDir();
		chmodSync(stateDir, 0o777);
		const f = fixture({ gatewayConfig: { stateDir } });
		await assert.rejects(f.start(), { code: "state_dir_group_or_world_writable" });
		chmodSync(stateDir, 0o700);
	});
});

describe("aidr-mcp-approve signs approvals with a passphrase-protected operator key", () => {
	it("generates a key, approves only with the right passphrase and a configured key", async () => {
		const work = mkdtempSync(join(testStateDir(), "operator-"));
		const keyFile = join(work, "approval-key.pem");
		const generated = await run(["--generate-key", keyFile, "ops-key-1"], `${PASSPHRASE}\n`);
		assert.equal(generated.status, 0, generated.stderr);
		const { approvalKeys } = JSON.parse(generated.stdout);
		assert.deepEqual(Object.keys(approvalKeys), ["ops-key-1"]);
		const keyPem = readFileSync(keyFile, "utf8");
		assert.throws(() => createPrivateKey(keyPem), "the operator key is encrypted");
		assert.equal(
			createPrivateKey({ key: keyPem, passphrase: PASSPHRASE }).asymmetricKeyType,
			"ed25519",
		);
		if (process.platform !== "win32") assert.equal(statSync(keyFile).mode & 0o077, 0);
		assert.equal(
			(await run(["--generate-key", keyFile, "ops-key-1"], `${PASSPHRASE}\n`)).status,
			1,
		);
		assert.equal(
			(await run(["--generate-key", join(work, "short.pem"), "ops-key-2"], "short\n")).stderr,
			"AIDR MCP approval key generation failed: approval_key_generation_failed:approval_passphrase_too_short\n",
		);

		const { f, stateDir } = fileBackedFixture({ gatewayConfig: { approvalKeys } });
		const base = await f.start();
		assert.match(
			(await rpc(base, f.tokenA, "tools/call", 1)).body.error.message,
			/manifest_quarantined/,
		);
		const state = await f.gateway.storeFor("tenant-a").read("server-a");
		const configPath = join(work, "gateway.json");
		writeFileSync(
			configPath,
			JSON.stringify({ stateDir, approvalKeys, port: 0, clients: f.clients, servers: f.servers }),
		);
		const args = [
			configPath,
			"tenant-a",
			"server-a",
			state.quarantine.toolsetHash,
			state.quarantine.bindingSha256,
			"security-operator",
			"ticket CR-1",
		];

		const usage = await run(args, `${PASSPHRASE}\n`);
		assert.equal(usage.status, 2);
		assert.match(usage.stderr, /--key <keyFile>/);

		const wrong = await run(["--key", keyFile, ...args], "not the passphrase\n");
		assert.equal(wrong.status, 1);
		assert.equal(
			wrong.stderr,
			"AIDR MCP toolset approval failed: approval_key_unavailable:approval_key_passphrase_rejected\n",
		);

		const otherKey = join(work, "other-key.pem");
		assert.equal(
			(await run(["--generate-key", otherKey, "ops-key-9"], `${PASSPHRASE}\n`)).status,
			0,
		);
		assert.equal(
			(await run(["--key", otherKey, ...args], `${PASSPHRASE}\n`)).stderr,
			"AIDR MCP toolset approval failed: approval_key_unavailable:approval_key_not_configured\n",
		);
		assert.match(
			(await rpc(base, f.tokenA, "tools/call", 2)).body.error.message,
			/manifest_quarantined/,
		);

		const approved = await run(
			["--key", keyFile, "--expires-in-days", "30", ...args],
			`${PASSPHRASE}\n`,
		);
		assert.equal(approved.status, 0, approved.stderr);
		assert.equal(approved.stdout, `Approved MCP toolset ${state.quarantine.toolsetHash}\n`);
		const entry = (await f.gateway.storeFor("tenant-a").read("server-a")).approvedToolsets.at(-1);
		assert.equal(entry.approvalKeyId, "ops-key-1");
		assert.ok(entry.signatureB64);
		const lifetime = Date.parse(entry.expiresAt) - Date.parse(entry.approvedAt);
		assert.equal(lifetime, 30 * 24 * 60 * 60 * 1000);
		const delivered = await rpc(base, f.tokenA, "tools/call", 3);
		assert.equal(delivered.body.result.content[0].text, "Normal result");
	});

	it("refuses an unencrypted or group-readable key file", {
		skip: process.platform === "win32",
	}, async () => {
		const work = mkdtempSync(join(testStateDir(), "operator-"));
		const keyFile = join(work, "approval-key.pem");
		const generated = await run(["--generate-key", keyFile, "ops-key-1"], `${PASSPHRASE}\n`);
		const { approvalKeys } = JSON.parse(generated.stdout);
		const { f, stateDir } = fileBackedFixture({ gatewayConfig: { approvalKeys } });
		const configPath = join(work, "gateway.json");
		writeFileSync(
			configPath,
			JSON.stringify({ stateDir, approvalKeys, clients: f.clients, servers: f.servers }),
		);
		const args = (key) => [
			"--key",
			key,
			configPath,
			"tenant-a",
			"server-a",
			"a".repeat(64),
			"b".repeat(64),
			"op",
			"reason",
		];
		chmodSync(keyFile, 0o640);
		assert.equal(
			(await run(args(keyFile), `${PASSPHRASE}\n`)).stderr,
			"AIDR MCP toolset approval failed: approval_key_unavailable:approval_key_permissions_too_open\n",
		);
		const plain = join(work, "plain.pem");
		const { privateKey } = generateKeyPairSync("ed25519", {
			privateKeyEncoding: { type: "pkcs8", format: "pem" },
			publicKeyEncoding: { type: "spki", format: "pem" },
		});
		writeFileSync(plain, privateKey, { mode: 0o600 });
		assert.equal(
			(await run(args(plain), "\n")).stderr,
			"AIDR MCP toolset approval failed: approval_key_unavailable:approval_key_not_encrypted\n",
		);
	});
});
