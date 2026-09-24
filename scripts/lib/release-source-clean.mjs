import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDistDirs = [
	"core", "claude-code", "extension", "openclaw", "opencode",
	"cli", "sdk", "dashboard", "codex", "mcp-gateway",
].map((name) => `packages/${name}/dist/`);

function releaseOutputName(value) {
	if (typeof value !== "string" || !/^release-output(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?$/u.test(value)) {
		throw new Error("release output must be a direct child directory named release-output or release-output-<suffix>");
	}
	return value;
}

function generatedOutput(path, outputRelative) {
	return packageDistDirs.some((directory) => path.startsWith(directory)) ||
		path === "packages/claude-code/aidr-artifact.manifest.json" ||
		path === "packages/claude-code/aidr-artifact.manifest.sig" ||
		path.startsWith(".release-evidence/") ||
		path.startsWith(`${outputRelative}/`);
}

/** Reject every source change while allowing only known release build outputs. */
export function assertReleaseSourceClean(root, { outputRelative = "release-output" } = {}) {
	releaseOutputName(outputRelative);
	const result = spawnSync("git", ["status", "--porcelain=v1", "-z", "--untracked-files=all"], {
		cwd: resolve(root),
		maxBuffer: 64 * 1024 * 1024,
	});
	if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
		throw new Error(`unable to verify release source worktree: ${result.error?.message ?? result.stderr?.toString("utf8").trim() ?? "git status failed"}`);
	}
	const entries = result.stdout.toString("utf8").split("\0");
	if (entries.at(-1) === "") entries.pop();
	const dirty = [];
	for (let index = 0; index < entries.length; index += 1) {
		const entry = entries[index];
		if (entry.length < 4 || entry[2] !== " ") throw new Error("invalid Git porcelain status record");
		const status = entry.slice(0, 2);
		const path = entry.slice(3);
		// A rename/copy can conceal a changed source path behind an allowed output path.
		if (/[RCU]/u.test(status)) {
			if (/[RC]/u.test(status)) index += 1; // Porcelain -z includes the old path as the next record.
			dirty.push(path);
			continue;
		}
		if (!generatedOutput(path, outputRelative)) dirty.push(path);
	}
	if (dirty.length > 0) {
		const shown = dirty.slice(0, 20).map((path) => JSON.stringify(path)).join(", ");
		throw new Error(`release requires a clean source worktree: ${shown}${dirty.length > 20 ? ` (+${dirty.length - 20} more)` : ""}`);
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		assertReleaseSourceClean(resolve(dirname(fileURLToPath(import.meta.url)), "../.."), {
			outputRelative: process.argv[2],
		});
		console.log("Release source worktree is clean (known generated outputs excluded).");
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
