/**
 * `aidr audit verify`: offline verification of the signed response-action chain.
 *
 * Pins that a good chain passes, that the FIRST broken link is reported (not
 * just a boolean), that any failure exits non-zero, and that verification never
 * mints a signing key for a chain that has none.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ResponseAuditor, type Verdict } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	AUDIT_VERIFY_BROKEN,
	AUDIT_VERIFY_UNVERIFIABLE,
	auditVerifyResponseChainCommand as auditVerifyCommand,
} from "../commands/audit.js";

const verdict: Verdict = {
	decision: "deny",
	severity: "critical",
	category: "test",
	reasons: ["test"],
	source: "heuristic",
	confidence: 0.99,
} as Verdict;

let dir: string;
let chainPath: string;
let out: string[];
let err: string[];

async function writeChain(count: number): Promise<void> {
	const auditor = new ResponseAuditor(chainPath, { signEntries: true });
	for (let i = 0; i < count; i++) {
		await auditor.log({
			action: "block",
			threatId: `T-${i}`,
			tool: "bash",
			input: `echo ${i}`,
			verdict,
			responseTaken: "block",
			metadata: {},
			outcome: "success",
		});
	}
}

function chainLines(): string[] {
	return readFileSync(chainPath, "utf8").trim().split("\n");
}

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-audit-verify-"));
	chainPath = join(dir, "response-audit.jsonl");
	out = [];
	err = [];
	vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		out.push(args.join(" "));
	});
	vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
		err.push(args.join(" "));
	});
	process.exitCode = undefined;
});

afterEach(() => {
	vi.restoreAllMocks();
	process.exitCode = undefined;
	rmSync(dir, { recursive: true, force: true });
});

describe("aidr audit verify", () => {
	it("passes an intact chain and exits zero", async () => {
		await writeChain(3);
		const result = await auditVerifyCommand(chainPath);
		expect(result?.valid).toBe(true);
		expect(result?.verifiedEntries).toBe(3);
		expect(process.exitCode).toBeUndefined();
		expect(out.join("\n")).toContain("3 signed entries verified");
	});

	it("reports the first broken link when an entry is edited", async () => {
		await writeChain(4);
		const lines = chainLines();
		const second = JSON.parse(lines[1] as string) as Record<string, unknown>;
		second.tool = "tampered";
		lines[1] = JSON.stringify(second);
		writeFileSync(chainPath, `${lines.join("\n")}\n`);

		const result = await auditVerifyCommand(chainPath);
		expect(result?.valid).toBe(false);
		expect(result?.firstBrokenLink).toMatchObject({
			line: 2,
			entryId: second.id,
			reason: "entry_hash_mismatch",
		});
		expect(result?.verifiedEntries).toBe(1);
		expect(process.exitCode).toBe(AUDIT_VERIFY_BROKEN);
		expect(err.join("\n")).toContain("First broken link: line 2");
	});

	it("reports a deleted middle entry as a prev-hash break", async () => {
		await writeChain(3);
		const lines = chainLines();
		writeFileSync(chainPath, `${[lines[0], lines[2]].join("\n")}\n`);
		const result = await auditVerifyCommand(chainPath, { json: true });
		expect(result?.firstBrokenLink?.reason).toBe("prev_hash_mismatch");
		expect(result?.firstBrokenLink?.line).toBe(2);
		expect(process.exitCode).toBe(AUDIT_VERIFY_BROKEN);
		const json = JSON.parse(out[0] as string) as Record<string, unknown>;
		expect(json.valid).toBe(false);
	});

	it("detects a truncated tail through the head checkpoint", async () => {
		await writeChain(3);
		const lines = chainLines();
		writeFileSync(chainPath, `${lines.slice(0, 2).join("\n")}\n`);
		const result = await auditVerifyCommand(chainPath);
		expect(result?.firstBrokenLink?.reason).toBe("audit_log_tail_deleted");
		expect(process.exitCode).toBe(AUDIT_VERIFY_BROKEN);
	});

	it("rejects a forged signature", async () => {
		await writeChain(2);
		const lines = chainLines();
		const first = JSON.parse(lines[0] as string) as Record<string, unknown>;
		first._signature = Buffer.alloc(64, 1).toString("base64");
		lines[0] = JSON.stringify(first);
		writeFileSync(chainPath, `${lines.join("\n")}\n`);
		const result = await auditVerifyCommand(chainPath);
		expect(result?.firstBrokenLink).toMatchObject({ line: 1, reason: "signature_invalid" });
	});

	it("is unverifiable (exit 2) without the signing key and never creates one", async () => {
		await writeChain(1);
		const keyPath = join(dir, ".response-audit-key");
		rmSync(keyPath);
		const result = await auditVerifyCommand(chainPath);
		expect(result?.valid).toBe(false);
		expect(result?.reason).toBe("signing_key_missing");
		expect(process.exitCode).toBe(AUDIT_VERIFY_UNVERIFIABLE);
		expect(existsSync(keyPath)).toBe(false);
	});

	it("is unverifiable (exit 2), not broken, when verification itself throws", async () => {
		await writeChain(1);
		vi.spyOn(ResponseAuditor.prototype, "verifyChain").mockRejectedValueOnce(
			new Error("EACCES: permission denied"),
		);
		const result = await auditVerifyCommand(chainPath);
		expect(result).toBeNull();
		expect(process.exitCode).toBe(AUDIT_VERIFY_UNVERIFIABLE);
		expect(err.join("\n")).toContain("EACCES");
	});

	it("is unverifiable (exit 2) when the log does not exist", async () => {
		await writeChain(1);
		rmSync(chainPath);
		const result = await auditVerifyCommand(chainPath);
		expect(result?.reason).toBe("audit_log_missing");
		expect(process.exitCode).toBe(AUDIT_VERIFY_UNVERIFIABLE);
	});
});
