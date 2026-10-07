/**
 * Item 69 (snapshot half): connectors that evaluate with `evaluateToolCall`
 * directly (Claude Code, Cursor, VS Code) take the same pre-operation snapshot
 * `guardToolCall` takes, so a protected path can be restored by the operator
 * (`aidr restore`). The snapshot store is bounded by size as well as age.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { snapshotBeforeAllowedToolCall } from "../guard.js";
import { AutoRollback } from "../rollback.js";
import { type Config, ConfigSchema, type Verdict } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const allow: Verdict = {
	decision: "allow",
	category: "file_write",
	confidence: 1,
	severity: "info",
	source: "heuristic",
	reasons: [],
	artifacts: [],
	matchedThreatId: null,
};

let work: string;
let snapshots: string;

function config(actions: Record<string, unknown>): Config {
	return ConfigSchema.parse({
		logging: { enabled: true, log_clean: true, path: join(work, "audit.jsonl") },
		response: { actions: { snapshot_root_dir: snapshots, ...actions } },
	});
}

beforeEach(async () => {
	work = await makeTmpDir();
	snapshots = join(work, "snapshots");
});

afterEach(async () => {
	await removeTmpDir(work);
});

describe("snapshotBeforeAllowedToolCall", () => {
	it("snapshots a protected file before an allowed overwrite, restorable later", async () => {
		const target = join(work, "project", "settings.json");
		const { mkdirSync } = await import("node:fs");
		mkdirSync(join(work, "project"), { recursive: true });
		writeFileSync(target, '{"original":true}');

		const result = await snapshotBeforeAllowedToolCall(
			{ toolName: "Write", toolInput: { file_path: target, content: "{}" }, sessionId: "s" },
			allow,
			{
				config: config({
					snapshot_before_destructive: true,
					protect_paths: [join(work, "project")],
				}),
			},
		);
		expect(result.snapshot?.target).toBe(target);
		expect(result.records[0]?.outcome).toBe("success");
		expect(readFileSync(join(work, "audit.jsonl"), "utf8")).toContain(
			result.snapshot?.id as string,
		);

		// The call runs and destroys the content; the operator restores it.
		writeFileSync(target, "{}");
		const rollback = new AutoRollback(undefined, undefined, snapshots);
		const stored = await rollback.listStoredSnapshots();
		expect(stored.map((s) => s.id)).toEqual([result.snapshot?.id]);
		expect(stored[0]?.files[0]?.path).toBe(target);
		await rollback.rollbackSnapshot(result.snapshot?.id as string, {
			expectTargetChanged: true,
			authorizedBy: "operator:test",
		});
		expect(readFileSync(target, "utf8")).toBe('{"original":true}');
	});

	it("does nothing when the feature is off, the path is unprotected or the call is not allowed", async () => {
		const target = join(work, "file.txt");
		writeFileSync(target, "x");
		const request = { toolName: "Write", toolInput: { file_path: target }, sessionId: "s" };
		expect(
			(await snapshotBeforeAllowedToolCall(request, allow, { config: config({}) })).snapshot,
		).toBeNull();
		expect(
			(
				await snapshotBeforeAllowedToolCall(request, allow, {
					config: config({ snapshot_before_destructive: true, protect_paths: [] }),
				})
			).snapshot,
		).toBeNull();
		expect(
			(
				await snapshotBeforeAllowedToolCall(
					request,
					{ ...allow, decision: "deny" },
					{ config: config({ snapshot_before_destructive: true, protect_paths: [work] }) },
				)
			).snapshot,
		).toBeNull();
		expect(
			(
				await snapshotBeforeAllowedToolCall(
					{ toolName: "Read", toolInput: { file_path: target }, sessionId: "s" },
					allow,
					{ config: config({ snapshot_before_destructive: true, protect_paths: [work] }) },
				)
			).snapshot,
		).toBeNull();
	});
});

describe("snapshot store size bound", () => {
	it("prunes the oldest snapshots first and never the one just taken", async () => {
		const rollback = new AutoRollback(undefined, undefined, snapshots);
		const ids: string[] = [];
		for (const name of ["a", "b", "c"]) {
			const path = join(work, `${name}.bin`);
			writeFileSync(path, Buffer.alloc(1000, name));
			ids.push((await rollback.createSnapshot([path], `op-${name}`)).id);
			await new Promise((r) => setTimeout(r, 5));
		}
		expect(await rollback.pruneToTotalBytes(2000)).toBe(1);
		const remaining = (
			await new AutoRollback(undefined, undefined, snapshots).listStoredSnapshots()
		).map((s) => s.id);
		expect(remaining.sort()).toEqual([ids[1], ids[2]].sort());
		// A bound smaller than the newest snapshot still keeps the protected one.
		await rollback.pruneToTotalBytes(10, ids[2]);
		const kept = (
			await new AutoRollback(undefined, undefined, snapshots).listStoredSnapshots()
		).map((s) => s.id);
		expect(kept).toEqual([ids[2]]);
	});
});
