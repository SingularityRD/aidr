/**
 * Built-bundle test: a commercial-flavoured run of an artifact that ships an
 * unsigned manifest (what `pnpm build:release` produces before release signing)
 * must fail closed at both Claude Code boundaries and record INTEGRITY-001.
 *
 * Regression: un-enrolled commercial installs were allowed to start on verified
 * digests when no integrity keys were provisioned, and that allowance also
 * covered artifacts that were never signed, so the hooks allowed every call.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const DIST_DIR = resolve(__dirname, "..", "..", "dist");

let root: string;
let dist: string;
let home: string;

function run(script: string, stdin: string): Promise<{ stdout: string; code: number | null }> {
	const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home };
	for (const key of Object.keys(env)) if (key.startsWith("AIDR_")) delete env[key];
	env.AIDR_COMMERCIAL = "1";
	return new Promise((done) => {
		const child = execFile(
			process.execPath,
			[join(dist, script)],
			{ timeout: 30_000, env, maxBuffer: 16 * 1024 * 1024 },
			(error, stdout) => done({ stdout, code: error?.code ? Number(error.code) : child.exitCode }),
		);
		child.stdin?.end(stdin);
	});
}

async function integrityIncidents(): Promise<Array<Record<string, unknown>>> {
	const raw = await readFile(join(home, ".singularity-aidr", "audit.jsonl"), "utf8").catch(
		() => "",
	);
	return raw
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line) as Record<string, unknown>)
		.filter((entry) => entry.matched_threat_id === "INTEGRITY-001");
}

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-cc-commercial-integrity-"));
	dist = join(root, "dist");
	home = join(root, "home");
	await cp(DIST_DIR, dist, {
		recursive: true,
		filter: (source) => !/aidr-artifact\.manifest\.(json|sig)$/.test(source),
	});
	// Digests match the copied bytes exactly: only the signature is absent.
	const files: Array<{ path: string; sha256: string }> = [];
	for (const entry of await readdir(dist, { recursive: true, withFileTypes: true })) {
		if (!entry.isFile()) continue;
		const rel = relative(dist, join(entry.parentPath, entry.name)).split(sep).join("/");
		const digest = createHash("sha256")
			.update(await readFile(join(dist, rel)))
			.digest("hex");
		files.push({ path: rel, sha256: digest });
	}
	await writeFile(
		join(dist, "aidr-artifact.manifest.json"),
		JSON.stringify({
			schema_version: 1,
			artifact_id: "claude-code/dist",
			artifact_version: "0.0.0-test",
			created_at: new Date().toISOString(),
			files,
		}),
	);
}, 120_000);

afterAll(async () => {
	if (root) await rm(root, { recursive: true, force: true });
});

describe("Claude Code commercial integrity (unsigned artifact)", () => {
	it("denies a tool call and records INTEGRITY-001", async () => {
		const result = await run(
			"pre-tool-use.cjs",
			JSON.stringify({
				session_id: "integrity-test",
				hook_event_name: "PreToolUse",
				tool_name: "Bash",
				tool_input: { command: "echo hello" },
				cwd: root,
			}),
		);
		const output = JSON.parse(result.stdout) as {
			hookSpecificOutput?: { permissionDecision?: string };
		};
		expect(output.hookSpecificOutput?.permissionDecision).toBe("deny");
		const incidents = await integrityIncidents();
		expect(incidents.length).toBeGreaterThan(0);
		expect(JSON.stringify(incidents)).toContain("no_public_keys");
	});

	it("blocks a prompt before it reaches the model", async () => {
		const result = await run(
			"user-prompt-submit.cjs",
			JSON.stringify({
				session_id: "integrity-test",
				hook_event_name: "UserPromptSubmit",
				prompt: "add a unit test for the parser",
				cwd: root,
			}),
		);
		const output = JSON.parse(result.stdout) as { decision?: string };
		expect(output.decision).toBe("block");
		expect((await integrityIncidents()).length).toBeGreaterThan(0);
	});
});
