import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { isInvalidConfig, loadConfig } from "../config.js";
import { loadManagedState, saveManagedState } from "../managed.js";
import type { SecretStore } from "../secret-store.js";

const priorCommercial = process.env.AIDR_COMMERCIAL;
const dirs: string[] = [];
const keys = new Map<string, string>();
const vault: SecretStore = {
	kind: "windows-dpapi",
	location: "os-vault",
	osProtected: true,
	isAvailable: () => true,
	put: (id, secret) => {
		keys.set(id, secret);
	},
	get: (id) => keys.get(id) ?? null,
	revoke: (id) => {
		keys.delete(id);
	},
};

function fixturePath(name: string): string {
	const directory = mkdtempSync(join(tmpdir(), "aidr-managed-vault-"));
	dirs.push(directory);
	return join(directory, name);
}

afterEach(() => {
	if (priorCommercial === undefined) delete process.env.AIDR_COMMERCIAL;
	else process.env.AIDR_COMMERCIAL = priorCommercial;
	keys.clear();
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("commercial managed credential storage", () => {
	it("writes only a vault reference and migrates a legacy managed state", async () => {
		process.env.AIDR_COMMERCIAL = "1";
		const path = fixturePath("managed.json");
		writeFileSync(path, JSON.stringify({ api_key: "synthetic-managed-secret" }));
		const migrated = await loadManagedState(path, { secretStore: vault });
		expect(migrated.api_key).toBe("synthetic-managed-secret");
		expect(readFileSync(path, "utf8")).not.toContain("synthetic-managed-secret");
		expect(migrated.api_key_ref?.store).toBe("windows-dpapi");
		await saveManagedState(path, { ...migrated, seat_status: "ok" }, vault);
		expect(readFileSync(path, "utf8")).not.toContain("synthetic-managed-secret");
	});

	it("fails closed if its referenced vault entry disappears", async () => {
		process.env.AIDR_COMMERCIAL = "1";
		const path = fixturePath("managed.json");
		await saveManagedState(path, { api_key: "synthetic-managed-secret" }, vault);
		keys.clear();
		await expect(loadManagedState(path, { secretStore: vault })).rejects.toThrow(/vault/);
	});

	it("requires durable issuance storage even outside a commercial build", async () => {
		process.env.AIDR_COMMERCIAL = "0";
		const path = fixturePath("managed.json");
		writeFileSync(path, "blocked directory");
		await expect(
			saveManagedState(join(path, "state.json"), { api_key: "synthetic-key" }),
		).resolves.toBeUndefined();
		await expect(
			saveManagedState(join(path, "state.json"), { api_key: "synthetic-key" }, undefined, {
				requirePersistence: true,
			}),
		).rejects.toThrow();
	});

	it("rejects a plaintext config credential and resolves an OS-vault reference", async () => {
		process.env.AIDR_COMMERCIAL = "1";
		const path = fixturePath("config.json");
		writeFileSync(
			path,
			JSON.stringify({ mode: "managed", auth: { api_key: "synthetic-config-secret" } }),
		);
		expect(isInvalidConfig(await loadConfig(path))).toBe(true);
		keys.set("synthetic-ref", "synthetic-config-secret");
		writeFileSync(
			path,
			JSON.stringify({
				mode: "managed",
				auth: {
					api_key_ref: {
						store: "windows-dpapi",
						id: "synthetic-ref",
						created_at: new Date().toISOString(),
					},
				},
			}),
		);
		const resolved = await loadConfig(path, undefined, vault);
		expect(isInvalidConfig(resolved)).toBe(false);
		expect(resolved.auth.api_key).toBe("synthetic-config-secret");
		expect(readFileSync(path, "utf8")).not.toContain("synthetic-config-secret");
	});
});
