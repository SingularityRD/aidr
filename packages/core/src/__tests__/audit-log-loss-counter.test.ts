import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	getAuditLogLossState,
	logVerdict,
	recordAuditRotationDrop,
	recordAuditWriteFailure,
	resetAuditLogLossState,
} from "../audit-log.js";
import type { LoggingConfig, Verdict } from "../types.js";

/**
 * An audit write that fails is fail-open by design â€” the verdict must not change
 * â€” but it used to be silent, so a full disk lost records with no trace. These
 * tests pin the accounting that makes the loss visible.
 */
const denial: Verdict = {
	decision: "deny",
	confidence: 1,
	severity: "high",
	source: "heuristic",
	reasons: ["test"],
	artifacts: [],
	matchedThreatId: "CLT-TEST-001",
};

describe("audit log loss accounting", () => {
	beforeEach(() => resetAuditLogLossState());
	afterEach(() => resetAuditLogLossState());

	it("starts clean", () => {
		const state = getAuditLogLossState();
		expect(state.writeFailures).toBe(0);
		expect(state.rotationDrops).toBe(0);
		expect(state.lastError).toBeNull();
	});

	it("counts an unwritable audit append instead of reporting a clean log", async () => {
		const directory = mkdtempSync(join(tmpdir(), "aidr-audit-loss-"));
		try {
			// A directory where the log file is expected: appendFile fails with
			// EISDIR, which is the same class of failure a full disk produces.
			const asDirectory = join(directory, "audit.jsonl");
			mkdirSync(asDirectory);
			const config: LoggingConfig = {
				enabled: true,
				path: asDirectory,
				max_bytes: 5_000_000,
				max_files: 3,
				log_clean: true,
			};

			await logVerdict(config, "session-1", "Bash", { command: "rm -rf /" }, denial);

			const state = getAuditLogLossState();
			expect(state.writeFailures).toBe(1);
			expect(state.lastError).not.toBeNull();
			expect(state.lastErrorAt).not.toBeNull();
		} finally {
			rmSync(directory, { recursive: true, force: true });
		}
	});

	it("keeps enforcement unchanged when the audit log cannot be written", async () => {
		const directory = mkdtempSync(join(tmpdir(), "aidr-audit-loss-"));
		try {
			const asDirectory = join(directory, "audit.jsonl");
			mkdirSync(asDirectory);
			const config: LoggingConfig = {
				enabled: true,
				path: asDirectory,
				max_bytes: 5_000_000,
				max_files: 3,
				log_clean: true,
			};

			// The call resolves rather than throwing, and the verdict the caller
			// already computed is untouched.
			await expect(
				logVerdict(config, "session-1", "Bash", { command: "rm -rf /" }, denial),
			).resolves.toBeUndefined();
		} finally {
			rmSync(directory, { recursive: true, force: true });
		}
	});

	it("counts a rotation that drops the oldest file", async () => {
		const directory = mkdtempSync(join(tmpdir(), "aidr-audit-loss-"));
		try {
			const logPath = join(directory, "audit.jsonl");
			// Fill the active file past max_bytes and create the oldest backup so
			// rotation has something real to drop.
			writeFileSync(logPath, `${"x".repeat(200)}\n`, "utf8");
			writeFileSync(`${logPath}.2`, "oldest\n", "utf8");
			const config: LoggingConfig = {
				enabled: true,
				path: logPath,
				max_bytes: 100,
				max_files: 2,
				log_clean: true,
			};

			await logVerdict(config, "session-1", "Bash", { command: "rm -rf /" }, denial);

			expect(getAuditLogLossState().rotationDrops).toBe(1);
			// The entry still lands: rotation is not allowed to lose the record it
			// was writing.
			expect(readFileSync(logPath, "utf8")).toContain("CLT-TEST-001");
		} finally {
			rmSync(directory, { recursive: true, force: true });
		}
	});

	it("records the reason for a loss", () => {
		recordAuditWriteFailure(new Error("ENOSPC: no space left on device"), 1_700_000_000_000);
		const state = getAuditLogLossState();
		expect(state.lastError).toContain("ENOSPC");
		expect(state.lastErrorAt).toBe(1_700_000_000_000);
		recordAuditRotationDrop();
		expect(state.rotationDrops + 1).toBe(getAuditLogLossState().rotationDrops);
	});
});

