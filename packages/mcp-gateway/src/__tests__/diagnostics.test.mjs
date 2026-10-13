import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, describe, it } from "node:test";
import { GatewayConfigError } from "../config.mjs";
import { McpGatewayRefusal } from "../coverage.mjs";
import { diagnosticReason, OperatorStageError, stage } from "../diagnostics.mjs";

const src = resolve(import.meta.dirname, "..");
const TOKEN = "t".repeat(40);
const PASSPHRASE = "diagnostics operator passphrase";
const approvalKeyPair = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: {
		type: "pkcs8",
		format: "pem",
		cipher: "aes-256-cbc",
		passphrase: PASSPHRASE,
	},
});
let root;
let home;

function validConfig() {
	return {
		stateDir: join(root, "state"),
		approvalKeys: { operator: approvalKeyPair.publicKey },
		port: 0,
		clients: [
			{
				id: "client-a",
				tenantId: "tenant-a",
				tokenSha256: createHash("sha256").update(TOKEN).digest("hex"),
				allowedTools: { "server-a": ["search"] },
			},
		],
		servers: [
			{
				tenantId: "tenant-a",
				id: "server-a",
				url: "https://mcp.example.test/mcp",
				transport: "json",
				sessionMode: "stateless",
				signedManifest: { manifest: { tools: [{ name: "search" }] } },
				trustedSigners: { publisher: "pem" },
			},
		],
	};
}

function run(entry, args, env = {}, input = "") {
	return spawnSync(process.execPath, [join(src, entry), ...args], {
		env: { ...process.env, HOME: home, USERPROFILE: home, ...env },
		encoding: "utf8",
		input,
		timeout: 20_000,
	});
}

async function writeConfig(name, value) {
	const path = join(root, name);
	await writeFile(path, typeof value === "string" ? value : JSON.stringify(value));
	return path;
}

before(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-mcp-diagnostics-"));
	home = join(root, "home");
});

after(async () => {
	await rm(root, { recursive: true, force: true });
});

describe("operator CLI diagnostics", () => {
	it("maps failures to stage and detail codes without free-text messages", async () => {
		const secret = "/secret/path/with-token-abc123";
		const tagged = await stage("config_unreadable", async () => {
			const error = new Error(`ENOENT: no such file ${secret}`);
			error.code = "ENOENT";
			throw error;
		}).catch((error) => error);
		assert.ok(tagged instanceof OperatorStageError);
		assert.equal(diagnosticReason(tagged), "config_unreadable:enoent");
		assert.equal(
			diagnosticReason(
				new OperatorStageError("config_invalid", new GatewayConfigError("invalid port")),
			),
			"config_invalid:invalid_port",
		);
		assert.equal(
			diagnosticReason(
				new OperatorStageError(
					"startup_failed",
					new McpGatewayRefusal("direct_upstream_bypass_detected", "refused"),
				),
			),
			"startup_failed:direct_upstream_bypass_detected",
		);
		assert.equal(
			diagnosticReason(new OperatorStageError("approval_failed", new Error(`bad ${secret}`))),
			"approval_failed",
		);
		assert.equal(diagnosticReason(new Error(secret)), "unexpected_failure");
	});

	it("reports gateway configuration failures with a reason code and exit 1", async () => {
		const missing = run("cli.mjs", [join(root, "absent.json")]);
		assert.equal(missing.status, 1);
		assert.equal(missing.stderr, "AIDR MCP gateway failed: config_unreadable:enoent\n");

		const malformed = run("cli.mjs", [await writeConfig("malformed.json", "{ not json")]);
		assert.equal(malformed.status, 1);
		assert.equal(malformed.stderr, "AIDR MCP gateway failed: config_parse_failed:invalid_json\n");

		const invalid = { ...validConfig(), port: -1 };
		const rejected = run("cli.mjs", [await writeConfig("invalid.json", invalid)]);
		assert.equal(rejected.status, 1);
		assert.equal(rejected.stderr, "AIDR MCP gateway failed: config_invalid:invalid_port\n");

		const usage = run("cli.mjs", []);
		assert.equal(usage.status, 2);
		assert.match(usage.stderr, /^usage: aidr-mcp-gateway <config\.json>/);
	});

	it("reports approval and stdio binding failures without echoing arguments", async () => {
		const config = await writeConfig("valid.json", validConfig());
		const keyFile = join(root, "approval-key.pem");
		await writeFile(keyFile, approvalKeyPair.privateKey, { mode: 0o600 });
		const approval = run(
			"approve.mjs",
			[
				"--key",
				keyFile,
				config,
				"tenant-z",
				"server-a",
				"a".repeat(64),
				"b".repeat(64),
				"operator",
				"ticket SECRET-REASON",
			],
			{},
			`${PASSPHRASE}\n`,
		);
		assert.equal(approval.status, 1);
		assert.equal(
			approval.stderr,
			"AIDR MCP toolset approval failed: approval_failed:unknown_tenant_server\n",
		);
		assert.ok(!approval.stderr.includes("SECRET-REASON"));

		const bridge = run(
			"stdio-cli.mjs",
			[config, "tenant-a", "client-a", "server-a", "AIDR_TEST_TOKEN"],
			{
				AIDR_TEST_TOKEN: "w".repeat(40),
			},
		);
		assert.equal(bridge.status, 1);
		assert.equal(
			bridge.stderr,
			"AIDR MCP stdio bridge failed: bridge_stopped:stdio_client_binding_rejected\n",
		);
		assert.ok(!bridge.stderr.includes("w".repeat(40)));
	});
});
