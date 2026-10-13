import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
	authenticateBearer,
	GATEWAY_CAPACITY,
	GatewayConfigError,
	validateGatewayConfig,
} from "../config.mjs";
import { tenantAdmissionRefusal } from "../gateway.mjs";
import { TEST_APPROVAL_KEYS } from "./helpers/approval-key.mjs";

const packageRoot = resolve(fileURLToPath(new URL("../../", import.meta.url)));

function config() {
	const token = "a".repeat(40);
	return {
		stateDir: "/var/lib/aidr/test-mcp",
		approvalKeys: TEST_APPROVAL_KEYS,
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

describe("MCP gateway tenant fair-share capacity", () => {
	const pools = Object.keys(GATEWAY_CAPACITY);

	it("defaults every pool and bounds configured quotas to a share that leaves the reserve free", () => {
		const defaults = validateGatewayConfig(config()).tenantQuotas;
		assert.deepEqual(defaults, GATEWAY_CAPACITY);
		for (const pool of pools) {
			const { global, reserved, guaranteed } = GATEWAY_CAPACITY[pool];
			assert.ok(reserved >= guaranteed && reserved < global);
			for (const perTenant of [guaranteed, global - reserved])
				assert.equal(
					validateGatewayConfig({ ...config(), tenantQuotas: { [pool]: perTenant } }).tenantQuotas[
						pool
					].perTenant,
					perTenant,
				);
			for (const perTenant of [guaranteed - 1, global - reserved + 1, global, 1.5, "8", null])
				assert.throws(
					() => validateGatewayConfig({ ...config(), tenantQuotas: { [pool]: perTenant } }),
					GatewayConfigError,
				);
		}
		assert.throws(
			() => validateGatewayConfig({ ...config(), tenantQuotas: { sessions: 8 } }),
			/invalid tenant quotas/,
		);
		assert.throws(
			() => validateGatewayConfig({ ...config(), tenantQuotas: [] }),
			/invalid tenant quotas/,
		);
	});

	/** Simulated pool: `acquire(tenant)` returns the refusal code or null when admitted. */
	function simulatedPool(quotas) {
		const held = new Map();
		const state = { total: 0, held };
		state.acquire = (tenant) => {
			const refusal = tenantAdmissionRefusal(quotas, state.total, held.get(tenant) ?? 0);
			if (refusal) return refusal;
			held.set(tenant, (held.get(tenant) ?? 0) + 1);
			state.total++;
			return null;
		};
		return state;
	}

	function assertQuietTenantsServed(limits, quotas) {
		const pool = simulatedPool(quotas);
		// Four noisy tenants (enough to exhaust the former 4 x quota = global design)
		// each try to take the whole pool.
		const noisy = Array.from({ length: 4 }, (_, index) => `noisy-${index}`);
		for (const tenant of noisy) for (let k = 0; k < limits.global; k++) pool.acquire(tenant);
		for (const count of pool.held.values()) assert.ok(count <= quotas.perTenant);
		// Beyond the shared pool, a noisy tenant can take at most its guaranteed floor.
		assert.ok(pool.total <= limits.global - limits.reserved + noisy.length * limits.guaranteed);
		// Every noisy tenant stays refused while capacity is still free for others.
		assert.ok(pool.total < limits.global);
		for (const tenant of noisy) assert.equal(pool.acquire(tenant), "tenant_busy");
		// Quiet tenants each still receive their guaranteed floor until the pool is full.
		let quiet = 0;
		while (pool.total < limits.global) {
			for (let k = 0; k < limits.guaranteed; k++)
				assert.equal(pool.acquire(`quiet-${quiet}`), null);
			quiet++;
		}
		assert.ok(quiet >= limits.reserved / limits.guaranteed - noisy.length);
		for (let tenant = 0; tenant < quiet; tenant++)
			assert.equal(pool.held.get(`quiet-${tenant}`), limits.guaranteed);
		assert.equal(pool.acquire("late"), "gateway_busy");
	}

	it("keeps the reserve for quiet tenants however many tenants run at their maximum quota", () => {
		for (const pool of pools) {
			const limits = GATEWAY_CAPACITY[pool];
			assertQuietTenantsServed(limits, limits);
			assertQuietTenantsServed(limits, { ...limits, perTenant: limits.global - limits.reserved });
		}
	});

	it("refuses a quiet tenant beyond its guaranteed floor while only the reserve is left", () => {
		const limits = GATEWAY_CAPACITY.pendingReplies;
		const shared = limits.global - limits.reserved;
		assert.equal(tenantAdmissionRefusal(limits, shared - 1, limits.perTenant - 1), null);
		assert.equal(tenantAdmissionRefusal(limits, shared, limits.guaranteed - 1), null);
		assert.equal(tenantAdmissionRefusal(limits, shared, limits.guaranteed), "tenant_busy");
		assert.equal(tenantAdmissionRefusal(limits, 0, limits.perTenant), "tenant_busy");
		assert.equal(tenantAdmissionRefusal(limits, limits.global, 0), "gateway_busy");
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
		// Paths are normalised with path.resolve (a drive letter is added on Windows).
		assert.deepEqual(validateGatewayConfig(accepted).detection, {
			threatsDir: resolve("/opt/aidr/threats"),
			agentConfigPath: resolve("/etc/aidr.json"),
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
