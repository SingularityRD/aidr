/**
 * Tests for Auto-Rollback module.
 *
 * ISOLATION: `AutoRollback` resolves its snapshot root from HOME, and
 * `pruneOlderThan` scans that directory. Without redirecting HOME these tests
 * write into the developer's real `~/.singularity-aidr/snapshots` and the prune
 * assertions count *every snapshot ever taken on the machine* — so they pass on a
 * clean checkout and fail on any machine that has run AIDR or this suite before.
 * HOME is redirected here; no assertion was changed.
 */
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AutoRollback, createAutoRollback } from "../rollback.js";
import { makeTmpDir } from "./test-utils.js";

describe("createAutoRollback", () => {
	it("returns an AutoRollback instance", () => {
		const rollback = createAutoRollback();
		expect(rollback).toBeInstanceOf(AutoRollback);
	});
});

describe("AutoRollback", () => {
	let tmpDir: string;
	let testFile1: string;
	let testFile2: string;
	let nestedDir: string;
	let nestedFile: string;
	let home: string;
	let previousHome: string | undefined;
	let previousUserProfile: string | undefined;

	beforeEach(async () => {
		tmpDir = await makeTmpDir();
		testFile1 = join(tmpDir, "test1.txt");
		testFile2 = join(tmpDir, "test2.txt");
		nestedDir = join(tmpDir, "nested");
		nestedFile = join(nestedDir, "nested.txt");

		// Keep snapshots inside this test's temp tree instead of the real HOME.
		home = await makeTmpDir();
		previousHome = process.env.HOME;
		previousUserProfile = process.env.USERPROFILE;
		process.env.HOME = home;
		process.env.USERPROFILE = home;

		await writeFile(testFile1, "original content 1");
		await writeFile(testFile2, "original content 2");
		await mkdir(nestedDir);
		await writeFile(nestedFile, "original nested content");
	});

	afterEach(async () => {
		if (previousHome === undefined) delete process.env.HOME;
		else process.env.HOME = previousHome;
		if (previousUserProfile === undefined) delete process.env.USERPROFILE;
		else process.env.USERPROFILE = previousUserProfile;
		await rm(home, { recursive: true, force: true });
		await rm(tmpDir, { recursive: true, force: true });
	});

	describe("createSnapshot", () => {
		it("creates a snapshot of existing files", async () => {
			const rollback = createAutoRollback();
			const snapshot = await rollback.createSnapshot([testFile1, testFile2], "test-op");

			expect(snapshot.id).toMatch(/^test-op-/);
			expect(snapshot.files.size).toBe(2);
			expect(snapshot.files.has(testFile1)).toBe(true);
			expect(snapshot.files.has(testFile2)).toBe(true);
		});

		it("skips non-existent files gracefully", async () => {
			const rollback = createAutoRollback();
			const nonExistent = join(tmpDir, "does-not-exist.txt");
			const snapshot = await rollback.createSnapshot([testFile1, nonExistent], "test-op");

			expect(snapshot.files.size).toBe(1);
			expect(snapshot.files.has(testFile1)).toBe(true);
		});

		it("skips directories", async () => {
			const rollback = createAutoRollback();
			const snapshot = await rollback.createSnapshot([tmpDir, testFile1], "test-op");

			// Should only have the file, not the directory
			expect(snapshot.files.size).toBe(1);
			expect(snapshot.files.has(testFile1)).toBe(true);
		});
	});

	describe("executeWithRollback", () => {
		it("returns result on success and cleans up snapshot", async () => {
			const rollback = createAutoRollback();
			const operation = vi.fn().mockResolvedValue("success");

			const result = await rollback.executeWithRollback(operation, [testFile1], {
				onFailure: "rollback",
			});

			expect(result).toBe("success");
			expect(operation).toHaveBeenCalled();

			// Snapshot should be cleaned up
			const snapshots = await rollback.listSnapshots();
			expect(snapshots.length).toBe(0);
		});

		it("throws on failure and rolls back when onFailure=rollback", async () => {
			const rollback = createAutoRollback();
			const operation = vi.fn().mockImplementation(async () => {
				await writeFile(testFile1, "modified content");
				throw new Error("Operation failed");
			});

			await expect(
				rollback.executeWithRollback(operation, [testFile1], { onFailure: "rollback" }),
			).rejects.toThrow("Operation failed");

			// File should be rolled back
			const content = await readFile(testFile1, "utf-8");
			expect(content).toBe("original content 1");
		});

		it("throws on failure without rollback when onFailure=notify", async () => {
			const rollback = createAutoRollback();
			const operation = vi.fn().mockRejectedValue(new Error("Operation failed"));

			// Modify the file before the failing operation
			await writeFile(testFile1, "modified content");

			await expect(
				rollback.executeWithRollback(operation, [testFile1], { onFailure: "notify" }),
			).rejects.toThrow("Operation failed");

			// File should NOT be rolled back
			const content = await readFile(testFile1, "utf-8");
			expect(content).toBe("modified content");
		});
	});

	describe("rollback", () => {
		it("restores files from snapshot", async () => {
			const rollback = createAutoRollback();
			const snapshot = await rollback.createSnapshot([testFile1, testFile2], "test-op");

			// Modify files
			await writeFile(testFile1, "modified 1");
			await writeFile(testFile2, "modified 2");

			// Rollback. `expectTargetChanged` is the caller vouching that the change it
			// is about to overwrite is its own: a restore with no such authorization
			// refuses with `target_changed` instead of silently clobbering the target
			// (see rollback-precondition.test.ts).
			await rollback.rollback(snapshot.id, { expectTargetChanged: true });

			// Verify restoration
			const content1 = await readFile(testFile1, "utf-8");
			const content2 = await readFile(testFile2, "utf-8");
			expect(content1).toBe("original content 1");
			expect(content2).toBe("original content 2");
		});

		it("handles nested directory files", async () => {
			const rollback = createAutoRollback();
			const snapshot = await rollback.createSnapshot([nestedFile], "test-op");

			// Modify file
			await writeFile(nestedFile, "modified nested");

			// Rollback, authorizing the overwrite of this test's own change. Without the
			// authorization the restore refuses (`target_changed`): the snapshot cannot
			// tell this change from anyone else's.
			await rollback.rollback(snapshot.id, { expectTargetChanged: true });

			// Verify restoration
			const content = await readFile(nestedFile, "utf-8");
			expect(content).toBe("original nested content");
		});

		it("throws for non-existent snapshot", async () => {
			const rollback = createAutoRollback();
			await expect(rollback.rollback("non-existent-00000000")).rejects.toThrow("Snapshot not found");
		});
	});

	describe("cleanup", () => {
		it("removes snapshot directory", async () => {
			const rollback = createAutoRollback();
			const snapshot = await rollback.createSnapshot([testFile1], "test-op");

			// Verify snapshot exists
			const backupPath = snapshot.files.get(testFile1);
			expect(backupPath).toBeDefined();
			if (!backupPath) return;
			await stat(backupPath); // Should not throw

			// Cleanup
			await rollback.cleanup(snapshot.id);

			// Verify snapshot removed
			await expect(stat(backupPath)).rejects.toThrow();
		});
	});

	describe("listSnapshots", () => {
		it("returns empty array when no snapshots", async () => {
			const rollback = createAutoRollback();
			const snapshots = await rollback.listSnapshots();
			expect(snapshots).toEqual([]);
		});

		it("returns created snapshots", async () => {
			const rollback = createAutoRollback();
			const snapshot = await rollback.createSnapshot([testFile1], "test-op");

			const snapshots = await rollback.listSnapshots();
			expect(snapshots.length).toBe(1);
			expect(snapshots[0].id).toBe(snapshot.id);
			expect(snapshots[0].fileCount).toBe(1);
			expect(snapshots[0].timestamp).toBeInstanceOf(Date);
		});
	});

	describe("prune", () => {
		it("removes snapshots older than threshold", async () => {
			const rollback = createAutoRollback();

			// Create a snapshot
			await rollback.createSnapshot([testFile1], "test-op");

			// No snapshots should be pruned if threshold is large
			let pruned = await rollback.prune(3600 * 1000); // 1 hour
			expect(pruned).toBe(0);

			// All snapshots should be pruned if threshold is 0. "Older than" is strict,
			// so let the clock move past the snapshot's millisecond first; otherwise a
			// fast run creates and prunes within one millisecond and nothing is older.
			await new Promise((resolve) => setTimeout(resolve, 5));
			pruned = await rollback.prune(0);
			expect(pruned).toBe(1);

			const snapshots = await rollback.listSnapshots();
			expect(snapshots.length).toBe(0);
		});
	});
});
