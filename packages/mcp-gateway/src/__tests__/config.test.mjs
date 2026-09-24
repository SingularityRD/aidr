import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { authenticateBearer, GatewayConfigError, validateGatewayConfig } from "../config.mjs";

const packageRoot = resolve(fileURLToPath(new URL("../../", import.meta.url)));

function config() {
	const token = "a".repeat(40);
	return {
		stateDir: ".test-mcp",
		port: 7789,
		clients: [
			{
				id: "client-a",
				tenantId: "tenant-a",
				tokenSha256: createHash("sha256").update(token).digest("hex"),
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

describe("MCP gateway configuration and bearer authentication", () => {
	it("accepts only a bearer token matching its fixed-length SHA-256 digest", () => {
		const clients = validateGatewayConfig(config()).clients;
		assert.equal(authenticateBearer(`Bearer ${"a".repeat(40)}`, clients)?.id, "client-a");
		assert.equal(authenticateBearer(`Bearer ${"b".repeat(40)}`, clients), null);
		assert.equal(authenticateBearer("Basic abc", clients), null);
		assert.equal(authenticateBearer(`Bearer ${"a".repeat(40)}\r\nX-Evil: yes`, clients), null);
	});

	it("refuses tenant crossing and unsigned tools in a client allowlist", () => {
		const crossing = config();
		crossing.clients[0].tenantId = "tenant-b";
		assert.throws(() => validateGatewayConfig(crossing), /another tenant/);
		const unsigned = config();
		unsigned.clients[0].allowedTools["server-a"] = ["delete"];
		assert.throws(() => validateGatewayConfig(unsigned), /unsigned tool/);
	});

	it("refuses insecure or credential-bearing upstream URLs and ambiguous fields", () => {
		for (const url of [
			"http://mcp.example.test",
			"https://user:pass@mcp.example.test",
			"https://mcp.example.test/path?token=x",
		]) {
			const candidate = config();
			candidate.servers[0].url = url;
			assert.throws(() => validateGatewayConfig(candidate));
		}
		const candidate = config();
		candidate.clients[0].allowAll = true;
		assert.throws(() => validateGatewayConfig(candidate));
	});

	it("requires explicit tool scope, unique token hashes and bounded body configuration", () => {
		const noScope = config();
		noScope.clients[0].allowedTools = {};
		assert.throws(() => validateGatewayConfig(noScope));
		const duplicate = config();
		duplicate.clients.push({ ...duplicate.clients[0], id: "client-b" });
		assert.throws(() => validateGatewayConfig(duplicate), /duplicate/);
		const tooLarge = config();
		tooLarge.maxBodyBytes = 2 * 1024 * 1024;
		assert.throws(() => validateGatewayConfig(tooLarge), /maxBodyBytes/);
	});

	it("takes an immutable config snapshot so caller mutation cannot change authorization", () => {
		const source = config();
		const validated = validateGatewayConfig(source);

		source.clients[0].allowedTools["server-a"][0] = "delete";
		source.servers[0].url = "https://attacker.example.test/mcp";
		assert.deepEqual(validated.clients[0].allowedTools["server-a"], ["search"]);
		assert.equal(validated.servers[0].url, "https://mcp.example.test/mcp");
		assert.throws(() => validated.clients[0].allowedTools["server-a"].push("delete"));
		assert.throws(() => {
			validated.servers[0].url = "https://attacker.example.test/mcp";
		});
	});
});

describe("MCP gateway detection, binary output and server-initiated policy config", () => {
	function dlpPolicy(tenantId = "tenant-a") {
		return {
			version: 1,
			tenantId,
			labels: [{ id: "label-secret", tenantId, name: "Secret", sensitivity: "restricted" }],
			rules: [
				{
					id: "rule-project",
					tenantId,
					labelId: "label-secret",
					name: "Project codename",
					directions: ["input"],
					action: "block",
					matchers: [{ type: "keyword", values: ["BLUEHERON"] }],
				},
			],
		};
	}

	it("applies fail-closed defaults when the optional sections are absent", () => {
		const validated = validateGatewayConfig(config());
		assert.deepEqual(validated.detection, {});
		assert.deepEqual(validated.serverInitiated, {
			sampling: "deny",
			elicitation: "deny",
			roots: "deny",
			notifications: "deny",
		});
		assert.deepEqual(validated.binaryOutput.allowedMimeTypes, [
			"image/png",
			"image/jpeg",
			"image/gif",
			"image/webp",
		]);
		assert.equal(validated.binaryOutput.maxDecodedBytes, 256 * 1024);
	});

	it("accepts only sniffable binary types and a size limit within the body limit", () => {
		const accepted = config();
		accepted.binaryOutput = { maxDecodedBytes: 1024, allowedMimeTypes: ["application/pdf"] };
		assert.deepEqual(validateGatewayConfig(accepted).binaryOutput, {
			maxDecodedBytes: 1024,
			allowedMimeTypes: ["application/pdf"],
		});
		for (const binaryOutput of [
			{ allowedMimeTypes: ["application/octet-stream"] },
			{ allowedMimeTypes: ["image/png", "image/png"] },
			{ maxDecodedBytes: 2 * 1024 * 1024 },
			{ maxDecodedBytes: -1 },
			{ unknown: true },
		]) {
			const candidate = config();
			candidate.binaryOutput = binaryOutput;
			assert.throws(() => validateGatewayConfig(candidate), GatewayConfigError);
		}
	});

	it("accepts deny or ignore per server-initiated category and nothing else", () => {
		const accepted = config();
		accepted.serverInitiated = { notifications: "ignore" };
		assert.equal(validateGatewayConfig(accepted).serverInitiated.notifications, "ignore");
		assert.equal(validateGatewayConfig(accepted).serverInitiated.sampling, "deny");
		for (const serverInitiated of [{ sampling: "allow" }, { tools: "ignore" }]) {
			const candidate = config();
			candidate.serverInitiated = serverInitiated;
			assert.throws(() => validateGatewayConfig(candidate), /server initiated policy/);
		}
	});

	it("requires absolute detection paths", () => {
		const accepted = config();
		accepted.detection = { threatsDir: "/opt/aidr/threats", agentConfigPath: "/etc/aidr.json" };
		assert.deepEqual(validateGatewayConfig(accepted).detection, {
			threatsDir: "/opt/aidr/threats",
			agentConfigPath: "/etc/aidr.json",
		});
		const relative = config();
		relative.detection = { threatsDir: "threats" };
		assert.throws(() => validateGatewayConfig(relative), /detection paths must be absolute/);
	});

	it("binds a validated DLP policy to its own tenant only", () => {
		const accepted = config();
		accepted.servers[0].dlpPolicy = dlpPolicy();
		const validated = validateGatewayConfig(accepted);
		assert.equal(validated.servers[0].dlpPolicy.tenantId, "tenant-a");
		assert.equal(validated.servers[0].dlpPolicy.unavailableAction, "block");

		const foreign = config();
		foreign.servers[0].dlpPolicy = dlpPolicy("tenant-b");
		assert.throws(() => validateGatewayConfig(foreign), /dlp policy tenant mismatch/);
		const malformed = config();
		malformed.servers[0].dlpPolicy = { version: 1 };
		assert.throws(
			() => validateGatewayConfig(malformed),
			(error) => error instanceof GatewayConfigError && error.code === "invalid_server_dlp_policy",
		);
	});
});

describe("MCP gateway runtime contract", () => {
	it("keeps the manifest, bundle target and deployment guide on Node 22.12", () => {
		const manifest = JSON.parse(readFileSync(resolve(packageRoot, "package.json"), "utf8"));
		const build = readFileSync(resolve(packageRoot, "scripts/bundle-options.mjs"), "utf8");
		const readme = readFileSync(resolve(packageRoot, "README.md"), "utf8");

		assert.equal(manifest.engines?.node, ">=22.12.0");
		assert.match(build, /target:\s*"node22\.12"/);
		assert.match(readme, /Node\.js 22\.12\+ is required/);
	});
});
