/**
 * Item 72: the signed, hash-chained verdict log.
 *
 * Every record written to audit.jsonl with `logging.signed_chain` carries a
 * sequence number, the previous record's hash, its own hash and an Ed25519
 * signature by an epoch key that a vault-held root certified. The verifier must
 * name the FIRST broken, missing or reordered record, and a record that could
 * not be signed is written anyway but never reported as verified.
 *
 * No real OS vault is touched: the vault is an in-memory store.
 */

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	auditChainDir,
	rotateAuditChainRootKey,
	setAuditChainTestHooks,
	verifyAuditChain,
} from "../audit-chain.js";
import { logIncident, logVerdict } from "../audit-log.js";
import { resolveAuditSignedChain } from "../config.js";
import type { SecretStore } from "../secret-store.js";
import type { LoggingConfig, Verdict } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const denial: Verdict = {
	decision: "deny",
	category: "destructive_command",
	confidence: 1,
	severity: "critical",
	source: "heuristic",
	reasons: ["Recursive delete of the root filesystem"],
	artifacts: ["rm -rf /"],
	matchedThreatId: "CLT-CMD-001",
};

function memoryVault(): SecretStore & { entries: Map<string, string> } {
	const entries = new Map<string, string>();
	return {
		kind: "windows-dpapi",
		location: "os-vault",
		osProtected: true,
		entries,
		isAvailable: () => true,
		put: (id, secret) => {
			entries.set(id, secret);
		},
		get: (id) => entries.get(id) ?? null,
		revoke: (id) => {
			entries.delete(id);
		},
	};
}

let dir: string;
let vault: ReturnType<typeof memoryVault>;

function logging(overrides: Partial<LoggingConfig> = {}): LoggingConfig {
	return {
		enabled: true,
		log_clean: true,
		path: join(dir, "audit.jsonl"),
		max_bytes: 5_000_000,
		max_files: 3,
		signed_chain: true,
		...overrides,
	};
}

function files(config: LoggingConfig): string[] {
	const out: string[] = [];
	for (let i = config.max_files; i >= 1; i--) out.push(`${config.path}.${i}`);
	out.push(config.path);
	return out;
}

async function writeRecords(config: LoggingConfig, count: number, offset = 0): Promise<void> {
	for (let i = 0; i < count; i++) {
		await logVerdict(
			config,
			`session-${offset + i}`,
			"Bash",
			{ command: `rm -rf /tmp/x${offset + i}` },
			denial,
		);
	}
}

function lines(path: string): string[] {
	return readFileSync(path, "utf8").split("\n").filter(Boolean);
}

beforeEach(async () => {
	dir = await makeTmpDir();
	vault = memoryVault();
	setAuditChainTestHooks({ vault: () => vault });
});

afterEach(async () => {
	setAuditChainTestHooks(null);
	delete process.env.AIDR_AUDIT_CHAIN_KEY_STORAGE;
	await removeTmpDir(dir);
});

describe("signed verdict chain", () => {
	it("chains and signs every record, and verifies clean", async () => {
		const config = logging();
		await writeRecords(config, 5);
		await logIncident(config, {
			type: "quarantine",
			timestamp: new Date().toISOString(),
			item_id: "x",
		});

		const records = lines(config.path).map((line) => JSON.parse(line));
		expect(records).toHaveLength(6);
		records.forEach((record, index) => {
			expect(record._chain.seq).toBe(index + 1);
			expect(record._chain.sig).toMatch(/^[A-Za-z0-9+/]+=*$/);
			expect(record._chain.unsigned).toBeUndefined();
		});
		expect(records[0]._chain.prev).toBe("GENESIS");
		expect(records[1]._chain.prev).toBe(records[0]._chain.hash);

		const result = await verifyAuditChain(config.path, files(config));
		expect(result.problems).toEqual([]);
		expect(result.ok).toBe(true);
		expect(result.verified).toBe(6);
		expect(result.firstSeq).toBe(1);
		expect(result.lastSeq).toBe(6);
		expect(result.roots).toHaveLength(1);
		expect(result.roots[0]?.fingerprint).toMatch(/^SHA256:[0-9a-f]{64}$/);
	});

	it("keeps the root key in the vault only; no private key reaches the log", async () => {
		const config = logging();
		await writeRecords(config, 2);
		expect([...vault.entries.keys()].some((id) => id.startsWith("aidr-audit-chain-root-"))).toBe(
			true,
		);
		const chainFiles = readdirSync(auditChainDir(config.path));
		expect(chainFiles.some((name) => name.startsWith("root-"))).toBe(false);
		const log = readFileSync(config.path, "utf8");
		expect(log).not.toMatch(/PRIVATE KEY/);
		for (const name of ["keys.json", "epochs.jsonl", "head.json"]) {
			expect(readFileSync(join(auditChainDir(config.path), name), "utf8")).not.toMatch(
				/PRIVATE KEY/,
			);
		}
	});

	it("redacts credential-shaped values before they are hashed and written", async () => {
		const config = logging();
		await logIncident(config, {
			type: "incident",
			timestamp: new Date().toISOString(),
			detail: "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123' https://x.test",
			note: "key sk-ant-abcdefghijklmnopqrstuvwxyz",
		});
		const log = readFileSync(config.path, "utf8");
		expect(log).not.toContain("abcdefghijklmnopqrstuvwxyz0123");
		expect(log).not.toContain("sk-ant-abcdefghijklmnopqrstuvwxyz");
		expect((await verifyAuditChain(config.path, files(config))).ok).toBe(true);
	});

	it("reports a modified record as the first problem, at its line", async () => {
		const config = logging();
		await writeRecords(config, 5);
		const all = lines(config.path);
		const third = JSON.parse(all[2] as string);
		third.verdict = "allow";
		all[2] = JSON.stringify(third);
		writeFileSync(config.path, `${all.join("\n")}\n`);

		const result = await verifyAuditChain(config.path, files(config));
		expect(result.ok).toBe(false);
		expect(result.problems[0]).toMatchObject({ kind: "hash_mismatch", line: 3, seq: 3 });
	});

	it("reports a deleted record as missing", async () => {
		const config = logging();
		await writeRecords(config, 5);
		const all = lines(config.path);
		all.splice(1, 1);
		writeFileSync(config.path, `${all.join("\n")}\n`);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.problems[0]).toMatchObject({ kind: "missing_records", seq: 3, line: 2 });
	});

	it("reports reordered records", async () => {
		const config = logging();
		await writeRecords(config, 5);
		const all = lines(config.path);
		[all[2], all[3]] = [all[3] as string, all[2] as string];
		writeFileSync(config.path, `${all.join("\n")}\n`);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.ok).toBe(false);
		expect(["missing_records", "reordered_record"]).toContain(result.problems[0]?.kind);
		expect(result.problems.some((p) => p.kind === "reordered_record")).toBe(true);
	});

	it("reports a truncated tail through the signed head", async () => {
		const config = logging();
		await writeRecords(config, 5);
		const all = lines(config.path);
		writeFileSync(config.path, `${all.slice(0, 3).join("\n")}\n`);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.problems[0]).toMatchObject({ kind: "tail_truncated", seq: 4 });
	});

	it("reports deleted head-of-log records", async () => {
		const config = logging();
		await writeRecords(config, 4);
		const all = lines(config.path);
		writeFileSync(config.path, `${all.slice(2).join("\n")}\n`);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.problems[0]).toMatchObject({ kind: "missing_head_records", seq: 3, line: 1 });
	});

	it("reports a record whose _chain was stripped", async () => {
		const config = logging();
		await writeRecords(config, 3);
		const all = lines(config.path);
		const second = JSON.parse(all[1] as string);
		delete second._chain;
		all[1] = JSON.stringify(second);
		writeFileSync(config.path, `${all.join("\n")}\n`);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.problems[0]).toMatchObject({ kind: "unchained_record", line: 2 });
	});

	it("rejects a forged record re-hashed without the signing key", async () => {
		const config = logging();
		await writeRecords(config, 2);
		const all = lines(config.path);
		const forged = JSON.parse(all[1] as string);
		forged._chain.sig = Buffer.alloc(64, 1).toString("base64");
		all[1] = JSON.stringify(forged);
		writeFileSync(config.path, `${all.join("\n")}\n`);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.problems[0]).toMatchObject({ kind: "bad_signature", line: 2 });
	});

	it("counts records written before signing was enabled as legacy, not failures", async () => {
		const config = logging();
		await writeRecords({ ...config, signed_chain: false }, 2);
		await writeRecords(config, 2, 10);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.ok).toBe(true);
		expect(result.legacyUnchained).toBe(2);
		expect(result.verified).toBe(2);
	});

	it("survives rotation: dropped files leave signed anchors, the rest verifies", async () => {
		const config = logging({ max_bytes: 1_200, max_files: 2 });
		await writeRecords(config, 12);
		const anchors = readFileSync(join(auditChainDir(config.path), "anchors.jsonl"), "utf8");
		expect(anchors.trim().length).toBeGreaterThan(0);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.problems).toEqual([]);
		expect(result.firstSeq).toBeGreaterThan(1);
		expect(result.lastSeq).toBe(12);
	});

	it("writes an unsigned-but-chained record when the vault fails, and verify reports it", async () => {
		setAuditChainTestHooks({
			vault: () => {
				throw new Error("no vault");
			},
		});
		const config = logging();
		await writeRecords(config, 1);
		const record = JSON.parse(lines(config.path)[0] as string);
		// The record itself is never dropped (the audit write fails open).
		expect(record.verdict ?? record.decision).toBe("deny");
		expect(record._chain.sig).toBeUndefined();
		expect(record._chain.unsigned).toMatch(/signing_key_unavailable/);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.ok).toBe(false);
		expect(result.problems[0]?.kind).toBe("unsigned_record");
	});

	it("rotates the root key; old and new records both verify through the endorsement", async () => {
		const config = logging();
		await writeRecords(config, 2);
		const rotation = await rotateAuditChainRootKey(config.path);
		expect(rotation.previousRootKid).not.toBeNull();
		expect(rotation.endorsed).toBe(true);
		// The retired root's private key is removed from the vault.
		expect(vault.entries.has(`aidr-audit-chain-root-${rotation.previousRootKid}`)).toBe(false);
		await writeRecords(config, 2, 5);
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.problems).toEqual([]);
		expect(result.verified).toBe(4);
		expect(result.roots.map((root) => root.retired)).toEqual([true, false]);
	});

	it("pins the first root with --expect-root", async () => {
		const config = logging();
		await writeRecords(config, 1);
		const good = await verifyAuditChain(config.path, files(config));
		const fingerprint = good.roots[0]?.fingerprint as string;
		expect(
			(await verifyAuditChain(config.path, files(config), { expectRoot: fingerprint })).ok,
		).toBe(true);
		const pinned = await verifyAuditChain(config.path, files(config), {
			expectRoot: `SHA256:${"0".repeat(64)}`,
		});
		expect(pinned.problems[0]?.kind).toBe("untrusted_root");
	});

	it("supports the explicit file key storage", async () => {
		process.env.AIDR_AUDIT_CHAIN_KEY_STORAGE = "file";
		const config = logging();
		await writeRecords(config, 2);
		expect(vault.entries.size).toBe(0);
		expect(readdirSync(auditChainDir(config.path)).some((name) => name.startsWith("root-"))).toBe(
			true,
		);
		expect((await verifyAuditChain(config.path, files(config))).ok).toBe(true);
	});

	it("writes plain records when signing is off", async () => {
		const config = logging({ signed_chain: false });
		await writeRecords(config, 1);
		expect(JSON.parse(lines(config.path)[0] as string)._chain).toBeUndefined();
		const result = await verifyAuditChain(config.path, files(config));
		expect(result.noChain).toBe(true);
	});
});

describe("audit.signed_chain default", () => {
	it("is off in local mode, on in managed mode, and an explicit value wins", () => {
		expect(resolveAuditSignedChain({ mode: "local" })).toBe(false);
		expect(resolveAuditSignedChain({ mode: "managed" })).toBe(true);
		expect(resolveAuditSignedChain({ mode: "managed", audit: { signed_chain: false } })).toBe(
			false,
		);
		expect(resolveAuditSignedChain({ mode: "local", audit: { signed_chain: true } })).toBe(true);
	});
});
