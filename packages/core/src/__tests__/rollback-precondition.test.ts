/**
 * A blind rollback is a second destructive act.
 *
 * `rollbackSnapshot` used to `copyFile(backupPath, originalPath)` unconditionally,
 * so a target that changed after the snapshot was silently replaced with stale
 * content. The snapshot now records a SHA-256 per copied file in its on-disk
 * metadata, and a restore refuses with `target_changed` unless the caller
 * explicitly vouches that the change it is overwriting is its own.
 *
 * The same suite pins the second half: a snapshot that could not preserve a named
 * path must be visible to the caller and must stop the operation (`not_found` is
 * the one benign skip — there was nothing there to protect).
 *
 * ISOLATION: snapshots are written to a temp directory handed to the constructor,
 * and the audit chain to a temp file, so no test touches the real
 * `~/.singularity-aidr`.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ResponseAuditor } from "../response-audit.js";
import { AutoRollback, RollbackRefusedError, SnapshotIncompleteError } from "../rollback.js";
import { nullLogger, type Verdict } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

const PRIOR_CONTENT = "the version the snapshot was taken from\n";
const NEWER_CONTENT = "content written after the snapshot was taken\n";

let tmpDir: string;
let target: string;
let snapshotsDir: string;
let auditPath: string;

function sha256(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function testVerdict(): Verdict {
	return {
		decision: "allow",
		category: "destructive",
		confidence: 0.9,
		severity: "warning",
		source: "test",
		artifacts: [target],
		matchedThreatId: "TEST-ROLLBACK-001",
		reasons: ["destructive operation"],
	};
}

async function readJsonl(path: string): Promise<Array<Record<string, unknown>>> {
	const raw = await readFile(path, "utf8");
	return raw
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

beforeEach(async () => {
	tmpDir = await makeTmpDir();
	target = join(tmpDir, "artifact.bin");
	// A file where the snapshot root needs to be a directory would make every
	// snapshot fail; the root is a sibling of the target so it stays hermetic.
	snapshotsDir = join(tmpDir, "snapshots");
	auditPath = join(tmpDir, "response-audit.jsonl");
	await writeFile(target, PRIOR_CONTENT);
});

afterEach(async () => {
	await rm(tmpDir, { recursive: true, force: true });
});

describe("snapshot paths stay inside the configured vault", () => {
	it("rejects traversal IDs before rollback, creation, or recursive cleanup", async () => {
		const rollback = new AutoRollback(nullLogger, undefined, snapshotsDir);
		const outsideDir = join(tmpDir, "outside-snapshot");
		const marker = join(outsideDir, "keep.txt");
		await mkdir(outsideDir);
		await writeFile(marker, "keep this file\n");

		await expect(rollback.rollback("../outside-snapshot")).rejects.toThrow("Invalid snapshot ID");
		await expect(rollback.cleanup("../outside-snapshot")).rejects.toThrow("Invalid snapshot ID");
		await expect(rollback.createSnapshot([target], "../outside-snapshot")).rejects.toThrow(
			"Invalid snapshot ID",
		);

		expect(await readFile(marker, "utf8")).toBe("keep this file\n");
		expect((await readdir(tmpDir)).some((name) => name.startsWith("outside-snapshot-"))).toBe(false);
	});

	it("rejects metadata whose ID does not match the selected snapshot", async () => {
		const rollback = new AutoRollback(nullLogger, undefined, snapshotsDir);
		const snapshot = await rollback.createSnapshot([target], "test-op");
		await writeFile(target, NEWER_CONTENT);

		const metadataPath = join(snapshotsDir, snapshot.id, "metadata.json");
		const metadata = JSON.parse(await readFile(metadataPath, "utf8")) as {
			id: string;
		};
		metadata.id = "another-snapshot-1234abcd";
		await writeFile(metadataPath, JSON.stringify(metadata));

		const reopened = new AutoRollback(nullLogger, undefined, snapshotsDir);
		await expect(reopened.rollback(snapshot.id, { expectTargetChanged: true })).rejects.toThrow(
			`Snapshot not found: ${snapshot.id}`,
		);
		expect(await readFile(target, "utf8")).toBe(NEWER_CONTENT);
	});

	it("rejects metadata that points a backup outside its snapshot directory", async () => {
		const rollback = new AutoRollback(nullLogger, undefined, snapshotsDir);
		const snapshot = await rollback.createSnapshot([target], "test-op");
		const outsideBackup = join(tmpDir, "outside-backup.bin");
		const outsideContent = "must not be restored\n";
		await writeFile(outsideBackup, outsideContent);
		await writeFile(target, NEWER_CONTENT);

		const metadataPath = join(snapshotsDir, snapshot.id, "metadata.json");
		const metadata = JSON.parse(await readFile(metadataPath, "utf8")) as {
			files: Record<string, string>;
			digests: Record<string, { sha256: string; size: number }>;
		};
		metadata.files[target] = outsideBackup;
		metadata.digests[target] = {
			sha256: sha256(outsideContent),
			size: Buffer.byteLength(outsideContent),
		};
		await writeFile(metadataPath, JSON.stringify(metadata));

		const reopened = new AutoRollback(nullLogger, undefined, snapshotsDir);
		await expect(reopened.rollback(snapshot.id, { expectTargetChanged: true })).rejects.toThrow(
			`Snapshot not found: ${snapshot.id}`,
		);
		expect(await readFile(target, "utf8")).toBe(NEWER_CONTENT);
	});
});

describe("a restore verifies the target before it overwrites it", () => {
	it("refuses to restore a target that changed after the snapshot", async () => {
		const rollback = new AutoRollback(nullLogger, undefined, snapshotsDir);
		const snapshot = await rollback.createSnapshot([target], "test-op");

		// The snapshot itself must carry the digest a later restore is checked
		// against, or there is nothing to verify with.
		const metadata = JSON.parse(
			await readFile(join(snapshotsDir, snapshot.id, "metadata.json"), "utf8"),
		) as { digests?: Record<string, { sha256: string }> };
		expect(metadata.digests?.[target]?.sha256).toBe(sha256(PRIOR_CONTENT));

		await writeFile(target, NEWER_CONTENT);

		const error = await rollback.rollback(snapshot.id).catch((err: unknown) => err);
		expect(error).toBeInstanceOf(RollbackRefusedError);
		expect(error).toMatchObject({ code: "target_changed" });
		expect((error as RollbackRefusedError).refusals).toEqual([
			expect.objectContaining({ path: target, reason: "target_changed" }),
		]);

		// The refusal is only meaningful because nothing was written: the newer
		// content is still there, byte for byte.
		expect(await readFile(target, "utf8")).toBe(NEWER_CONTENT);
	});

	it("refuses it from a later process, using the digest recorded on disk", async () => {
		// Process A takes the snapshot and goes away...
		const first = new AutoRollback(nullLogger, undefined, snapshotsDir);
		const snapshot = await first.createSnapshot([target], "test-op");

		await writeFile(target, NEWER_CONTENT);

		// ...process B only has the vault on disk. It cannot know who changed the
		// target, so it must not clobber it.
		const second = new AutoRollback(nullLogger, undefined, snapshotsDir);
		const error = await second.rollback(snapshot.id).catch((err: unknown) => err);
		expect(error).toBeInstanceOf(RollbackRefusedError);
		expect(error).toMatchObject({ code: "target_changed" });
		expect(await readFile(target, "utf8")).toBe(NEWER_CONTENT);
	});

	it("refuses a target that is no longer a regular file instead of following it", async () => {
		const rollback = new AutoRollback(nullLogger, undefined, snapshotsDir);
		const snapshot = await rollback.createSnapshot([target], "test-op");

		// A directory in the target's place: copyFile would fail, but a symlink would
		// be FOLLOWED, so the target's type is checked before anything is written.
		await rm(target);
		await mkdir(target);

		const error = await rollback
			.rollback(snapshot.id, { expectTargetChanged: true })
			.catch((err: unknown) => err);
		expect(error).toBeInstanceOf(RollbackRefusedError);
		expect((error as RollbackRefusedError).refusals[0]?.reason).toBe("not_a_file");
	});

	it("restores a target that matches the snapshot, and one that is simply gone", async () => {
		const rollback = new AutoRollback(nullLogger, undefined, snapshotsDir);

		// Unchanged target: the precondition holds, so a restore is allowed.
		const unchanged = await rollback.createSnapshot([target], "test-op");
		await rollback.rollback(unchanged.id);
		expect(await readFile(target, "utf8")).toBe(PRIOR_CONTENT);

		// Deleted target: overwriting nothing destroys nothing, so a delete can always
		// be undone. This is the case the guard's rollback relies on.
		const deleted = await rollback.createSnapshot([target], "test-op");
		await rm(target);
		await rollback.rollback(deleted.id);
		expect(await readFile(target, "utf8")).toBe(PRIOR_CONTENT);
	});

	it("restores when the caller vouches for the change, and records the operator", async () => {
		const auditor = new ResponseAuditor(auditPath, { signEntries: true });
		const rollback = new AutoRollback(nullLogger, auditor, snapshotsDir);

		// The wrapper took the snapshot and ran the operation, so the half-written
		// content it is undoing is its own: it may authorize the overwrite.
		await expect(
			rollback.executeWithRollback(
				async () => {
					await writeFile(target, "half-written by the failed operation");
					throw new Error("operation failed");
				},
				[target],
				{
					onFailure: "rollback",
					tool: "Bash",
					input: "rm artifact.bin",
					verdict: testVerdict(),
					threatId: "TEST-ROLLBACK-001",
					authorizedBy: "operator:on-call",
				},
			),
		).rejects.toThrow("operation failed");

		expect(await readFile(target, "utf8")).toBe(PRIOR_CONTENT);

		const entries = await readJsonl(auditPath);
		expect(entries.map((entry) => entry.action)).toEqual(["contain", "rollback"]);
		expect(entries[0]).toMatchObject({ authorized_by: "operator:on-call" });
		expect(entries[1]).toMatchObject({
			action: "rollback",
			outcome: "success",
			authorized_by: "operator:on-call",
		});
	});

	it("persists the operator identity on the snapshot itself, not only in the audit log", async () => {
		const auditor = new ResponseAuditor(auditPath, { signEntries: true });
		const rollback = new AutoRollback(nullLogger, auditor, snapshotsDir);

		const result = await rollback.createSnapshotDetailed([target], "test-op", {
			tool: "Bash",
			input: "rm artifact.bin",
			verdict: testVerdict(),
			threatId: "TEST-ROLLBACK-001",
			authorizedBy: "operator:on-call",
		});

		expect(result.snapshot.authorizedBy).toBe("operator:on-call");
		// On disk too: a rollback run by a later process has to be able to say who
		// authorized the copy it is restoring.
		const metadata = JSON.parse(
			await readFile(join(snapshotsDir, result.snapshot.id, "metadata.json"), "utf8"),
		) as { authorizedBy?: string };
		expect(metadata.authorizedBy).toBe("operator:on-call");

		const entries = await readJsonl(auditPath);
		expect(entries[0]).toMatchObject({ action: "contain", authorized_by: "operator:on-call" });
	});

	it("does not invent an operator when none was supplied", async () => {
		const auditor = new ResponseAuditor(auditPath, { signEntries: true });
		const rollback = new AutoRollback(nullLogger, auditor, snapshotsDir);

		// A blank or implausibly short identity is not an identity, and must not be
		// recorded as one.
		const result = await rollback.createSnapshotDetailed([target], "test-op", {
			tool: "Bash",
			input: "rm artifact.bin",
			verdict: testVerdict(),
			threatId: "TEST-ROLLBACK-001",
			authorizedBy: "  ",
		});

		expect(result.snapshot.authorizedBy).toBeUndefined();
		const entries = await readJsonl(auditPath);
		expect(entries[0]).not.toHaveProperty("authorized_by");
	});
});

describe("a snapshot that could not protect a path is never invisible", () => {
	it("fails closed when a snapshot copy was skipped for a reason other than a missing path", async () => {
		const rollback = new AutoRollback(nullLogger, undefined, snapshotsDir);
		// A directory can never be snapshotted as a file: the skip reason is
		// `not_a_file`, which is NOT the benign "the path does not exist yet" case.
		const notAFile = join(tmpDir, "a-directory");
		await mkdir(notAFile);

		let ran = false;
		const error = await rollback
			.executeWithRollback(
				async () => {
					ran = true;
					return "should never run";
				},
				[notAFile],
				{ onFailure: "rollback", operationId: "test-op" },
			)
			.catch((err: unknown) => err);

		expect(error).toBeInstanceOf(SnapshotIncompleteError);
		expect(error).toMatchObject({ code: "snapshot_incomplete" });
		expect((error as SnapshotIncompleteError).skipped).toEqual([
			expect.objectContaining({ path: notAFile, reason: "not_a_file" }),
		]);
		// The operation must not have run: it would have destroyed a file the caller
		// was told is recoverable.
		expect(ran).toBe(false);
	});

	it("reports a benign missing-path skip to the caller and still runs the operation", async () => {
		const rollback = new AutoRollback(nullLogger, undefined, snapshotsDir);
		const missing = join(tmpDir, "not-created-yet.txt");
		const skipped: Array<{ path: string; reason: string }> = [];

		let ran = false;
		const result = await rollback.executeWithRollback(
			async () => {
				ran = true;
				return "done";
			},
			[target, missing],
			{
				onFailure: "rollback",
				operationId: "test-op",
				onSnapshotSkipped: (report) => skipped.push(...report),
			},
		);

		expect(result).toBe("done");
		expect(ran).toBe(true);
		// A path that does not exist has nothing to preserve, but the caller is told
		// rather than left believing it was snapshotted.
		expect(skipped).toEqual([expect.objectContaining({ path: missing, reason: "not_found" })]);
	});
});
