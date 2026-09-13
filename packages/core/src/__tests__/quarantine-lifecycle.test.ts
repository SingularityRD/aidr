/**
 * Regression tests for the AutoQuarantine constructor.
 *
 * The constructor used to call `this.ensureQuarantineDir()` and
 * `this.loadManifest()` without `await` even though both were `async`, so a
 * freshly constructed instance reported an empty item list until an unrelated
 * microtask happened to run, and any failure surfaced as an unhandled rejection
 * rather than an error. These tests pin the corrected behaviour: a new instance
 * is fully usable the moment its constructor returns.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AutoQuarantine } from "../quarantine.js";

const MANIFEST = "manifest.json";

let dir: string;

function configFor(quarantineDir: string) {
	return {
		enabled: true,
		quarantineDir,
		retentionDays: 30,
		notifyOnQuarantine: false,
		notifyChannels: [] as never[],
	};
}

beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "aidr-quarantine-ctor-"));
});

afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

describe("AutoQuarantine constructor is synchronous and complete", () => {
	it("has the quarantine directory on disk as soon as it is constructed", async () => {
		new AutoQuarantine(configFor(dir));
		// No await, no flush: the directory must already exist.
		await expect(readFile(join(dir, "..", "nonexistent"), "utf8")).rejects.toThrow();
		const { statSync } = await import("node:fs");
		expect(statSync(dir).isDirectory()).toBe(true);
	});

	it("sees persisted items immediately on a fresh instance (restart survival)", async () => {
		// Write a manifest with one item, then construct a new manager pointing at
		// the same directory. A pre-fix implementation would report zero items
		// here until a microtask ran.
		const manifest = {
			version: 1,
			lastUpdated: new Date().toISOString(),
			items: [
				{
					id: "11111111-1111-4111-8111-111111111111",
					originalPath: "/tmp/original.sh",
					quarantinePath: join(dir, "11111111-1111-4111-8111-111111111111"),
					threatId: "CLT-CMD-001",
					timestamp: new Date().toISOString(),
					metadata: {},
					fileSize: 10,
					fileHash: "0".repeat(64),
				},
			],
		};
		await writeFile(join(dir, MANIFEST), JSON.stringify(manifest), "utf8");

		const manager = new AutoQuarantine(configFor(dir));
		// Synchronously, with no await between construction and use.
		const items = manager.list();
		expect(items).toHaveLength(1);
		expect(items[0]?.threatId).toBe("CLT-CMD-001");
	});

	it("starts empty and usable when no manifest exists yet", () => {
		const manager = new AutoQuarantine(configFor(dir));
		expect(manager.list()).toEqual([]);
	});

	it("does not throw when the manifest is corrupt", async () => {
		await writeFile(join(dir, MANIFEST), "{ this is not json", "utf8");
		const manager = new AutoQuarantine(configFor(dir));
		expect(manager.list()).toEqual([]);
	});

	it("ignores a manifest whose version is unknown", async () => {
		await writeFile(
			join(dir, MANIFEST),
			JSON.stringify({ version: 999, items: [], lastUpdated: new Date().toISOString() }),
			"utf8",
		);
		const manager = new AutoQuarantine(configFor(dir));
		expect(manager.list()).toEqual([]);
	});
});

describe("AutoQuarantine round trip", () => {
	it("quarantines a real file and restores it", async () => {
		const victim = join(dir, "suspicious.sh");
		await writeFile(victim, "#!/bin/sh\necho suspicious\n", "utf8");

		const manager = new AutoQuarantine(configFor(join(dir, "vault")));
		const item = await manager.quarantine(victim, "CLT-CMD-001");

		expect(item.threatId).toBe("CLT-CMD-001");
		// The original must be gone and the copy must be in the vault.
		const { existsSync } = await import("node:fs");
		expect(existsSync(victim)).toBe(false);
		expect(existsSync(item.quarantinePath)).toBe(true);

		await manager.restore(item.id);
		expect(existsSync(victim)).toBe(true);
		expect(manager.list()).toHaveLength(0);
	});

	it("persists across a rebuild of the manager", async () => {
		const victim = join(dir, "suspicious2.sh");
		await writeFile(victim, "payload\n", "utf8");

		const vault = join(dir, "vault2");
		const first = new AutoQuarantine(configFor(vault));
		const item = await first.quarantine(victim, "CLT-CMD-002");

		const second = new AutoQuarantine(configFor(vault));
		expect(second.get(item.id)?.threatId).toBe("CLT-CMD-002");
	});
});
