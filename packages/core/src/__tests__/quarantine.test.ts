import { randomUUID } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { AutoQuarantine, type QuarantineConfig } from "../quarantine.js";
import { ResponseAuditor } from "../response-audit.js";
import type { Verdict } from "../types.js";

function tmpDir(name: string): string {
	return path.join(process.cwd(), ".tmp-test", name);
}

function testVerdict(): Verdict {
	return {
		decision: "deny",
		category: "malware",
		confidence: 0.99,
		severity: "critical",
		source: "test",
		artifacts: ["payload"],
		matchedThreatId: "TEST-QUARANTINE-001",
		reasons: ["test quarantine"],
	};
}

async function readAuditEntries(auditLogPath: string): Promise<Array<Record<string, unknown>>> {
	const raw = await readFile(auditLogPath, "utf8");
	return raw
		.trim()
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>);
}

function quarantineConfig(dir: string): QuarantineConfig {
	return {
		quarantineDir: path.join(dir, "quarantine"),
		retentionDays: 30,
		notifyChannels: [],
	};
}

describe("AutoQuarantine", () => {
	it("moves a file into quarantine and writes success response audit evidence", async () => {
		const dir = tmpDir(`quarantine-${randomUUID()}`);
		await mkdir(dir, { recursive: true });
		const sourcePath = path.join(dir, "payload.txt");
		await writeFile(sourcePath, "danger", "utf8");

		const auditLogPath = path.join(dir, "response-audit.jsonl");
		const auditor = new ResponseAuditor(auditLogPath);
		const quarantine = new AutoQuarantine(quarantineConfig(dir), undefined, undefined, auditor);

		const item = await quarantine.quarantine(sourcePath, "TEST-QUARANTINE-001", undefined, {
			tool: "Bash",
			input: "cat payload.txt",
			verdict: testVerdict(),
		});

		await expect(stat(sourcePath)).rejects.toThrow();
		await expect(readFile(item.quarantinePath, "utf8")).resolves.toBe("danger");

		const entries = await readAuditEntries(auditLogPath);
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({
			action: "quarantine",
			threat_id: "TEST-QUARANTINE-001",
			outcome: "success",
			response_taken: "quarantine",
			metadata: {
				quarantineId: item.id,
				notificationSent: false,
			},
		});
	});

	it("writes failure response audit evidence when the target file is missing", async () => {
		const dir = tmpDir(`quarantine-missing-${randomUUID()}`);
		await mkdir(dir, { recursive: true });

		const auditLogPath = path.join(dir, "response-audit.jsonl");
		const auditor = new ResponseAuditor(auditLogPath);
		const quarantine = new AutoQuarantine(quarantineConfig(dir), undefined, undefined, auditor);
		const missingPath = path.join(dir, "missing.txt");

		await expect(
			quarantine.quarantine(missingPath, "TEST-QUARANTINE-001", undefined, {
				tool: "Bash",
				input: "cat missing.txt",
				verdict: testVerdict(),
			}),
		).rejects.toThrow("File not found or not accessible");

		const entries = await readAuditEntries(auditLogPath);
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({
			action: "quarantine",
			threat_id: "TEST-QUARANTINE-001",
			outcome: "failure",
			response_taken: "quarantine",
			metadata: {},
		});
		expect(entries[0]?.error).toContain("File not found or not accessible");
	});
});
