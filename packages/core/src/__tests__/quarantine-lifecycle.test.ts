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

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, utimes, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
					quarantinePath: join(
						dir,
						"2026",
						"09",
						"23",
						"11111111-1111-4111-8111-111111111111_original.sh",
					),
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

	it("fails closed when the manifest is corrupt", async () => {
		await writeFile(join(dir, MANIFEST), "{ this is not json", "utf8");
		expect(() => new AutoQuarantine(configFor(dir))).toThrow("Quarantine manifest is corrupt");
	});

	it("fails closed when the manifest version is unknown", async () => {
		await writeFile(
			join(dir, MANIFEST),
			JSON.stringify({ version: 999, items: [], lastUpdated: new Date().toISOString() }),
			"utf8",
		);
		expect(() => new AutoQuarantine(configFor(dir))).toThrow("unsupported or invalid format");
	});

	it("fails closed when a manifest points outside the quarantine vault", async () => {
		const vault = join(dir, "vault-outside-path");
		await mkdir(vault);
		const canary = join(dir, "outside-vault-canary.txt");
		await writeFile(canary, "must remain untouched", "utf8");
		await writeFile(
			join(vault, MANIFEST),
			JSON.stringify({
				version: 1,
				lastUpdated: new Date().toISOString(),
				items: [
					{
						id: "11111111-1111-4111-8111-111111111111",
						originalPath: join(dir, "original.txt"),
						quarantinePath: canary,
						threatId: "CLT-CMD-001",
						timestamp: new Date().toISOString(),
						metadata: {},
						fileSize: 10,
						fileHash: "0".repeat(64),
					},
				],
			}),
			"utf8",
		);

		expect(() => new AutoQuarantine(configFor(vault))).toThrow(
			"Quarantine manifest contains an invalid item",
		);
		expect(await readFile(canary, "utf8")).toBe("must remain untouched");
	});

	it("fails closed when a manifest path targets another file inside the vault", async () => {
		const vault = join(dir, "vault-internal-path");
		await mkdir(vault);
		const canary = join(vault, "other-item.txt");
		await writeFile(canary, "must remain untouched", "utf8");
		await writeFile(
			join(vault, MANIFEST),
			JSON.stringify({
				version: 1,
				lastUpdated: new Date().toISOString(),
				items: [
					{
						id: "11111111-1111-4111-8111-111111111111",
						originalPath: join(dir, "original.txt"),
						quarantinePath: canary,
						threatId: "CLT-CMD-001",
						timestamp: new Date().toISOString(),
						metadata: {},
						fileSize: 10,
						fileHash: "0".repeat(64),
					},
				],
			}),
			"utf8",
		);

		expect(() => new AutoQuarantine(configFor(vault))).toThrow(
			"Quarantine manifest contains an invalid item",
		);
		expect(await readFile(canary, "utf8")).toBe("must remain untouched");
	});

	it("recovers a source left in staging by a process interruption", async () => {
		const vault = join(dir, "interrupted-vault");
		const itemId = "11111111-1111-4111-8111-111111111111";
		const originalPath = join(dir, "interrupted.sh");
		const stagingDir = join(dir, `.interrupted.sh.aidr-${itemId}.staging`);
		const stagedPath = join(stagingDir, "interrupted.sh");
		const quarantinePath = join(vault, "2026", "09", "23", `${itemId}_interrupted.sh`);
		const captured = "captured bytes\n";
		const newerSource = "newer source bytes\n";
		await mkdir(stagingDir);
		await mkdir(dirname(quarantinePath), { recursive: true });
		await writeFile(stagedPath, newerSource, "utf8");
		await writeFile(quarantinePath, captured, "utf8");
		await writeFile(
			join(vault, MANIFEST),
			JSON.stringify({
				version: 1,
				lastUpdated: new Date().toISOString(),
				items: [
					{
						id: itemId,
						originalPath,
						quarantinePath,
						threatId: "CLT-CMD-INTERRUPTED",
						timestamp: new Date().toISOString(),
						metadata: {},
						fileSize: Buffer.byteLength(captured),
						fileHash: createHash("sha256").update(captured).digest("hex"),
					},
				],
			}),
			"utf8",
		);

		const manager = new AutoQuarantine(configFor(vault));
		expect(await readFile(stagedPath, "utf8")).toBe(newerSource);
		await expect(readFile(originalPath, "utf8")).rejects.toThrow();
		const trigger = join(dir, "trigger-recovery.sh");
		await writeFile(trigger, "trigger\n", "utf8");
		await manager.quarantine(trigger, "CLT-CMD-TRIGGER-RECOVERY");
		expect(await readFile(originalPath, "utf8")).toBe(newerSource);
		expect(await readFile(quarantinePath, "utf8")).toBe(captured);
		expect(manager.get(itemId)).toBeDefined();
		await expect(readFile(stagedPath, "utf8")).rejects.toThrow();
	});

	it("does not discard a staged source unless the vault really contains its bytes", async () => {
		const vault = join(dir, "unverified-vault-recovery");
		const itemId = "11111111-1111-4111-8111-111111111111";
		const originalPath = join(dir, "unverified-recovery.sh");
		const stagingDir = join(dir, `.unverified-recovery.sh.aidr-${itemId}.staging`);
		const stagedPath = join(stagingDir, "unverified-recovery.sh");
		const claimedBytes = "manifest-claimed bytes\n";
		const wrongVaultBytes = "vault is not the claimed content\n";
		const quarantinePath = join(vault, "2026", "09", "23", `${itemId}_unverified-recovery.sh`);
		await mkdir(stagingDir);
		await mkdir(dirname(quarantinePath), { recursive: true });
		await writeFile(stagedPath, claimedBytes, "utf8");
		await writeFile(quarantinePath, wrongVaultBytes, "utf8");
		await writeFile(
			join(vault, MANIFEST),
			JSON.stringify({
				version: 1,
				lastUpdated: new Date().toISOString(),
				items: [
					{
						id: itemId,
						originalPath,
						quarantinePath,
						threatId: "CLT-CMD-UNVERIFIED-VAULT",
						timestamp: new Date().toISOString(),
						metadata: {},
						fileSize: Buffer.byteLength(claimedBytes),
						fileHash: createHash("sha256").update(claimedBytes).digest("hex"),
					},
				],
			}),
			"utf8",
		);

		const manager = new AutoQuarantine(configFor(vault));
		expect(await readFile(stagedPath, "utf8")).toBe(claimedBytes);
		const trigger = join(dir, "trigger-unverified-recovery.sh");
		await writeFile(trigger, "trigger\n", "utf8");
		await manager.quarantine(trigger, "CLT-CMD-TRIGGER-UNVERIFIED-RECOVERY");
		expect(await readFile(originalPath, "utf8")).toBe(claimedBytes);
		expect(await readFile(quarantinePath, "utf8")).toBe(wrongVaultBytes);
		await expect(readFile(stagedPath, "utf8")).rejects.toThrow();
	});

	it("does not overwrite a recreated original while recovering an interrupted move", async () => {
		const vault = join(dir, "collision-vault-recovery");
		const itemId = "11111111-1111-4111-8111-111111111111";
		const originalPath = join(dir, "collision-recovery.sh");
		const stagingDir = join(dir, `.collision-recovery.sh.aidr-${itemId}.staging`);
		const stagedPath = join(stagingDir, "collision-recovery.sh");
		const quarantinePath = join(vault, "2026", "09", "23", `${itemId}_collision-recovery.sh`);
		await mkdir(stagingDir);
		await mkdir(dirname(quarantinePath), { recursive: true });
		await writeFile(originalPath, "recreated bytes\n", "utf8");
		await writeFile(stagedPath, "staged original bytes\n", "utf8");
		await writeFile(quarantinePath, "vault bytes\n", "utf8");
		await writeFile(
			join(vault, MANIFEST),
			JSON.stringify({
				version: 1,
				lastUpdated: new Date().toISOString(),
				items: [
					{
						id: itemId,
						originalPath,
						quarantinePath,
						threatId: "CLT-CMD-RECOVERY-COLLISION",
						timestamp: new Date().toISOString(),
						metadata: {},
						fileSize: 11,
						fileHash: createHash("sha256").update("vault bytes\n").digest("hex"),
					},
				],
			}),
			"utf8",
		);

		const manager = new AutoQuarantine(configFor(vault));
		const trigger = join(dir, "trigger-collision-recovery.sh");
		await writeFile(trigger, "trigger\n", "utf8");
		await expect(manager.quarantine(trigger, "CLT-CMD-TRIGGER-COLLISION-RECOVERY")).rejects.toThrow(
			"found both an original and staged source",
		);
		expect(await readFile(originalPath, "utf8")).toBe("recreated bytes\n");
		expect(await readFile(stagedPath, "utf8")).toBe("staged original bytes\n");
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

	it("does not remove the original when quarantine manifest persistence fails", async () => {
		const victim = join(dir, "persist-failure.sh");
		const vault = join(dir, "persist-failure-vault");
		await writeFile(victim, "keep this file\n", "utf8");
		const manager = new AutoQuarantine(configFor(vault));
		Reflect.set(manager, "saveManifest", async () => {
			throw new Error("injected manifest persistence failure");
		});
		await expect(manager.quarantine(victim, "CLT-CMD-PERSIST-FAILURE")).rejects.toThrow(
			"Failed to persist quarantine before removing original",
		);

		expect(await readFile(victim, "utf8")).toBe("keep this file\n");
		expect(manager.list()).toHaveLength(0);
	});

	it("does not discard newer source bytes changed after the vault copy was committed", async () => {
		const victim = join(dir, "changed-after-copy.sh");
		const vault = join(dir, "changed-after-copy-vault");
		await writeFile(victim, "original bytes\n", "utf8");
		const manager = new AutoQuarantine(configFor(vault));
		const persist = Reflect.get(manager, "persistQuarantineRecord") as (
			...args: unknown[]
		) => Promise<void>;
		Reflect.set(manager, "persistQuarantineRecord", async (...args: unknown[]) => {
			await persist.apply(manager, args);
			await writeFile(victim, "newer bytes must survive\n", "utf8");
		});

		await expect(manager.quarantine(victim, "CLT-CMD-TOCTOU")).rejects.toThrow("Original file");
		const item = manager.list()[0];
		if (!item) throw new Error("Expected the quarantine record to remain tracked");
		expect(await readFile(victim, "utf8")).toBe("newer bytes must survive\n");
		expect(await readFile(item.quarantinePath, "utf8")).toBe("original bytes\n");
	});

	it("preserves bytes changed between staged-source verification and removal", async () => {
		const victim = join(dir, "changed-during-final-verification.sh");
		const vault = join(dir, "changed-during-final-verification-vault");
		await writeFile(victim, "original bytes\n", "utf8");
		const manager = new AutoQuarantine(configFor(vault));
		const computeFileHash = Reflect.get(manager, "computeFileHash") as (
			path: string,
		) => Promise<string>;
		let changedStagedSource = false;
		Reflect.set(manager, "computeFileHash", async (path: string) => {
			const hash = await computeFileHash.call(manager, path);
			if (
				!changedStagedSource &&
				path.includes(".aidr-") &&
				path.endsWith("final-verification.sh")
			) {
				changedStagedSource = true;
				await writeFile(path, "modified bytes\n", "utf8");
			}
			return hash;
		});

		await expect(manager.quarantine(victim, "CLT-CMD-FINAL-VERIFY-TOCTOU")).rejects.toThrow(
			"final quarantine verification",
		);
		const item = manager.list()[0];
		if (!item) throw new Error("Expected the committed quarantine copy to remain tracked");
		expect(await readFile(victim, "utf8")).toBe("modified bytes\n");
		expect(await readFile(item.quarantinePath, "utf8")).toBe("original bytes\n");
	});

	it("serializes concurrent quarantines across managers sharing one manifest", async () => {
		const vault = join(dir, "shared-vault");
		const firstPath = join(dir, "first-concurrent.sh");
		const secondPath = join(dir, "second-concurrent.sh");
		await Promise.all([
			writeFile(firstPath, "first\n", "utf8"),
			writeFile(secondPath, "second\n", "utf8"),
		]);
		const first = new AutoQuarantine(configFor(vault));
		const second = new AutoQuarantine(configFor(vault));
		await Promise.all([
			first.quarantine(firstPath, "CLT-CMD-CONCURRENT-1"),
			second.quarantine(secondPath, "CLT-CMD-CONCURRENT-2"),
		]);

		const restarted = new AutoQuarantine(configFor(vault));
		expect(
			restarted
				.list()
				.map((item) => item.threatId)
				.sort(),
		).toEqual(["CLT-CMD-CONCURRENT-1", "CLT-CMD-CONCURRENT-2"]);
	});

	it("recovers a stale manifest lock only when its process generation is gone", async () => {
		const vault = join(dir, "stale-lock-vault");
		const manager = new AutoQuarantine(configFor(vault));
		const lockDir = join(vault, `${MANIFEST}.lock`);
		const acquire = (
			Reflect.get(manager, "acquireManifestLock") as () => Promise<{
				lockPath: string;
				ownerPath: string;
				token: string;
			}>
		).bind(manager);
		const release = (
			Reflect.get(manager, "releaseManifestLock") as (lock: {
				lockPath: string;
				ownerPath: string;
				token: string;
			}) => Promise<void>
		).bind(manager);
		const recover = (
			Reflect.get(manager, "recoverAbandonedManifestLock") as (path: string) => Promise<boolean>
		).bind(manager);
		const activeLock = await acquire();
		const old = new Date(Date.now() - 60_000);
		await utimes(activeLock.lockPath, old, old);
		expect(await recover(activeLock.lockPath)).toBe(false);
		await release(activeLock);

		const token = "11111111-1111-4111-8111-111111111111";
		await mkdir(lockDir);
		await writeFile(
			join(lockDir, `owner-${token}.json`),
			JSON.stringify({
				v: 1,
				token,
				pid: process.pid,
				host: hostname(),
				acquiredAt: Date.now() - 60_000,
				processStartedAtMs: 1,
			}),
			"utf8",
		);
		await utimes(lockDir, old, old);
		const victim = join(dir, "after-stale-lock.sh");
		await writeFile(victim, "stale lock recovered\n", "utf8");

		await manager.quarantine(victim, "CLT-CMD-STALE-LOCK");
		expect((await manager.list()).map((item) => item.threatId)).toContain("CLT-CMD-STALE-LOCK");
		const { existsSync } = await import("node:fs");
		expect(existsSync(lockDir)).toBe(false);
	});

	it("retains both copies and tracking when restore persistence fails, then allows retry", async () => {
		const victim = join(dir, "restore-persist-failure.sh");
		const vault = join(dir, "restore-persist-failure-vault");
		await writeFile(victim, "restore me\n", "utf8");
		const manager = new AutoQuarantine(configFor(vault));
		const item = await manager.quarantine(victim, "CLT-CMD-RESTORE-PERSIST-FAILURE");

		const saveManifest = Reflect.get(manager, "saveManifest") as () => Promise<void>;
		Reflect.set(manager, "saveManifest", async () => {
			throw new Error("injected manifest persistence failure");
		});
		await expect(manager.restore(item.id)).rejects.toThrow("retry is safe");
		expect(await readFile(victim, "utf8")).toBe("restore me\n");
		const { existsSync } = await import("node:fs");
		expect(existsSync(item.quarantinePath)).toBe(false);
		expect(manager.get(item.id)).toBeDefined();

		Reflect.set(manager, "saveManifest", saveManifest.bind(manager));
		await manager.restore(item.id);
		expect(manager.list()).toHaveLength(0);
		expect(await readFile(victim, "utf8")).toBe("restore me\n");
	});

	it("keeps restored files tracked if vault-payload cleanup fails", async () => {
		const victim = join(dir, "restore-cleanup-failure.sh");
		const manager = new AutoQuarantine(configFor(join(dir, "restore-cleanup-vault")));
		await writeFile(victim, "restore and keep tracked\n", "utf8");
		const item = await manager.quarantine(victim, "CLT-CMD-RESTORE-CLEANUP-FAILURE");
		const removePayload = Reflect.get(manager, "unlinkPayloadFile") as (
			path: string,
		) => Promise<void>;
		Reflect.set(manager, "unlinkPayloadFile", async () => {
			throw new Error("injected payload cleanup failure");
		});

		await expect(manager.restore(item.id)).rejects.toThrow("injected payload cleanup failure");
		expect(manager.get(item.id)).toBeDefined();
		expect(await readFile(victim, "utf8")).toBe("restore and keep tracked\n");
		expect(await readFile(item.quarantinePath, "utf8")).toBe("restore and keep tracked\n");

		Reflect.set(manager, "unlinkPayloadFile", removePayload.bind(manager));
		await manager.restore(item.id);
		expect(manager.list()).toHaveLength(0);
	});

	it("keeps delete tracking when manifest persistence fails and completes on retry", async () => {
		const victim = join(dir, "delete-persist-failure.sh");
		const vault = join(dir, "delete-persist-failure-vault");
		await writeFile(victim, "delete me\n", "utf8");
		const manager = new AutoQuarantine(configFor(vault));
		const item = await manager.quarantine(victim, "CLT-CMD-DELETE-PERSIST-FAILURE");

		const saveManifest = Reflect.get(manager, "saveManifest") as () => Promise<void>;
		Reflect.set(manager, "saveManifest", async () => {
			throw new Error("injected manifest persistence failure");
		});
		await expect(manager.delete(item.id)).rejects.toThrow("retry the delete");
		expect(manager.get(item.id)).toBeDefined();
		const { existsSync } = await import("node:fs");
		expect(existsSync(item.quarantinePath)).toBe(false);

		Reflect.set(manager, "saveManifest", saveManifest.bind(manager));
		await manager.delete(item.id);
		expect(manager.list()).toHaveLength(0);
	});

	it("does not overwrite a file recreated at the original path", async () => {
		const victim = join(dir, "recreated.sh");
		await writeFile(victim, "quarantined content\n", "utf8");

		const manager = new AutoQuarantine(configFor(join(dir, "collision-vault")));
		const item = await manager.quarantine(victim, "CLT-CMD-003");
		await writeFile(victim, "newer content\n", "utf8");

		await expect(manager.restore(item.id)).rejects.toThrow("Failed to restore file");
		expect(await readFile(victim, "utf8")).toBe("newer content\n");
		expect(await readFile(item.quarantinePath, "utf8")).toBe("quarantined content\n");
		expect(manager.get(item.id)).toBeDefined();
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
