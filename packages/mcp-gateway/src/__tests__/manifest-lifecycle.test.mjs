import "./helpers/isolated-home.mjs";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { signMcpToolManifest } from "@singularityrd/aidr-core";
import { createMcpGateway } from "../gateway.mjs";
import { watchGatewayConfig } from "../reload.mjs";
import { fixture, rpc } from "./helpers/gateway-fixture.mjs";

const DAY = 24 * 60 * 60 * 1000;

function times(issuedOffset, expiresOffset) {
	return {
		issuedAt: new Date(Date.now() + issuedOffset).toISOString(),
		expiresAt: new Date(Date.now() + expiresOffset).toISOString(),
	};
}

function manifestEvents(f, status) {
	return f.events.filter(
		(event) => event.type === "mcp_gateway_manifest" && event.status === status,
	);
}

/** A config for `reloadManifests` with server-a re-signed by `keyPair`. */
function resigned(f, keyPair, manifest) {
	const signedManifest = signMcpToolManifest({
		manifest: { ...f.signedManifest.manifest, ...manifest },
		keyId: "publisher",
		privateKey: keyPair.privateKey,
	});
	return {
		...f.input,
		servers: f.input.servers.map((server) => ({ ...server, signedManifest })),
	};
}

async function approvedBase(f) {
	const base = await f.start();
	await rpc(base, f.tokenA);
	await f.approve();
	return base;
}

describe("signed manifest lifecycle", () => {
	it("refuses to start with an expired manifest and names the reason", async () => {
		const f = fixture(times(-2 * DAY, -DAY));
		await assert.rejects(f.start(), { code: "manifest_expired" });
		assert.equal(f.upstreamCalls, 0);
		assert.equal(manifestEvents(f, "rejected")[0].reasonCode, "manifest_expired");
	});

	it("applies the default seven-day lifetime and an operator-configured maximum", async () => {
		const eightDays = times(-60_000, 8 * DAY - 60_000);
		await assert.rejects(fixture(eightDays).start(), { code: "manifest_lifetime_too_long" });

		const allowed = fixture({
			...eightDays,
			gatewayConfig: { manifestPolicy: { maxLifetimeDays: 30 } },
		});
		const base = await approvedBase(allowed);
		assert.equal((await rpc(base, allowed.tokenA)).body.result.content[0].text, "Normal result");

		const tooLong = fixture({
			...times(-60_000, 31 * DAY),
			gatewayConfig: { manifestPolicy: { maxLifetimeDays: 30 } },
		});
		await assert.rejects(tooLong.start(), { code: "manifest_lifetime_too_long" });
	});

	it("validates the manifest policy", () => {
		const f = fixture();
		const base = f.input;
		for (const manifestPolicy of [
			{ maxLifetimeDays: 0 },
			{ maxLifetimeDays: 91 },
			{ maxLifetimeDays: 1.5 },
			{ maxLifetimeDays: 7, expiryWarningDays: 8 },
			{ maxLifetimeDays: 7, unknown: true },
		]) {
			assert.throws(() => createMcpGateway({ ...base, manifestPolicy }), {
				name: "GatewayConfigError",
			});
		}
		assert.deepEqual(f.gateway.config.manifestPolicy, { maxLifetimeDays: 7, expiryWarningDays: 2 });
	});

	it("warns when a manifest is inside the expiry warning window", async () => {
		const soon = fixture(times(-6 * DAY, DAY));
		await soon.start();
		const warnings = manifestEvents(soon, "expiring");
		assert.equal(warnings.length, 2);
		assert.equal(warnings[0].reasonCode, "manifest_expiring_soon");
		assert.ok(warnings[0].expiresAt);

		const quiet = fixture({
			...times(-6 * DAY, DAY),
			gatewayConfig: { manifestPolicy: { expiryWarningDays: 0 } },
		});
		await quiet.start();
		assert.equal(manifestEvents(quiet, "expiring").length, 0);

		const fresh = fixture(times(-60_000, 5 * DAY));
		await fresh.start();
		assert.equal(manifestEvents(fresh, "expiring").length, 0);
	});

	it("reports the precise reason when a manifest expires while running", async () => {
		let offset = 0;
		const f = fixture({
			...times(-60_000, 60 * 60_000),
			now: () => new Date(Date.now() + offset),
		});
		const base = await approvedBase(f);
		assert.equal((await rpc(base, f.tokenA)).body.result.content[0].text, "Normal result");
		offset = 2 * 60 * 60_000;
		const calls = f.upstreamCalls;
		const result = await rpc(base, f.tokenA);
		assert.match(result.body.error.message, /manifest_rejected/);
		assert.equal(f.upstreamCalls, calls);
		const denied = f.events.findLast((event) => event.decision === "deny");
		assert.equal(denied.reason, "manifest_rejected");
		assert.equal(denied.manifestReason, "expired");
	});

	it("hot-reloads a re-signed manifest and keeps serving", async () => {
		const keyPair = generateKeyPairSync("ed25519");
		const f = fixture({ keyPair });
		const base = await approvedBase(f);
		const expiresAt = new Date(Date.now() + 3 * DAY).toISOString();
		assert.deepEqual(
			await f.gateway.reloadManifests(resigned(f, keyPair, { sequence: 2, expires_at: expiresAt })),
			{ reloaded: 2 },
		);
		assert.equal(f.gateway.config.servers[0].signedManifest.manifest.expires_at, expiresAt);
		assert.equal(manifestEvents(f, "reloaded").length, 2);
		assert.equal((await rpc(base, f.tokenA)).body.result.content[0].text, "Normal result");
	});

	it("refuses a reload with an invalid manifest or a non-manifest change and keeps the old one", async () => {
		const keyPair = generateKeyPairSync("ed25519");
		const f = fixture({ keyPair });
		const base = await approvedBase(f);
		const before = f.gateway.config;
		const expired = resigned(f, keyPair, {
			sequence: 2,
			issued_at: new Date(Date.now() - 2 * DAY).toISOString(),
			expires_at: new Date(Date.now() - DAY).toISOString(),
		});
		await assert.rejects(f.gateway.reloadManifests(expired), { code: "manifest_expired" });
		await assert.rejects(f.gateway.reloadManifests({ ...f.input, maxBodyBytes: 8192 }), {
			code: "configuration_change_requires_restart",
		});
		assert.equal(f.gateway.config, before);
		assert.equal((await rpc(base, f.tokenA)).body.result.content[0].text, "Normal result");
	});

	it("reloads from the watched configuration file and reports refusals", async () => {
		const keyPair = generateKeyPairSync("ed25519");
		const f = fixture({ keyPair });
		await approvedBase(f);
		const directory = await mkdtemp(join(tmpdir(), "aidr-mcp-reload-"));
		const path = join(directory, "gateway.json");
		const lines = [];
		const stderr = { write: (line) => lines.push(line) };
		await writeFile(path, JSON.stringify(f.input));
		const watcher = watchGatewayConfig(f.gateway, path, { stderr, intervalMs: 20 });
		try {
			const expiresAt = new Date(Date.now() + 2 * DAY).toISOString();
			await writeFile(
				path,
				JSON.stringify(resigned(f, keyPair, { sequence: 2, expires_at: expiresAt })),
			);
			for (let count = 0; lines.length === 0 && count < 250; count++)
				await new Promise((resolve) => setTimeout(resolve, 20));
			assert.deepEqual(lines, ["AIDR MCP gateway reloaded 2 signed manifest(s)\n"]);
			assert.equal(f.gateway.config.servers[0].signedManifest.manifest.expires_at, expiresAt);

			await writeFile(path, "{");
			await watcher.reload();
			assert.match(
				lines.at(-1),
				/^AIDR MCP gateway reload refused: config_parse_failed:invalid_json;/,
			);
		} finally {
			watcher.stop();
			await rm(directory, { recursive: true, force: true });
		}
	});
});
