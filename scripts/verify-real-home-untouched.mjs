/**
 * CI guard: the test suites must never write the runner's real agent configuration.
 *
 * The hook-installer tests (Cursor, VS Code/Claude settings) and the connector
 * tests resolve paths through `os.homedir()`. They stub HOME/USERPROFILE to a
 * temporary directory; this guard proves it from the outside by fingerprinting
 * every agent configuration file an installer can write under the real home
 * before the tests run, and failing if any of them was created, changed or
 * deleted afterwards.
 *
 *   node scripts/verify-real-home-untouched.mjs --record <snapshot.json>
 *   node scripts/verify-real-home-untouched.mjs --verify <snapshot.json>
 *
 * The home directory is taken from AIDR_REAL_HOME when set (so the check can be
 * exercised in tests), otherwise from `os.homedir()` of this process, which in
 * CI is the runner's real home because this script is never run under a stub.
 */

import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

/** Agent configuration files AIDR installers write, relative to the home directory. */
export const GUARDED_HOME_PATHS = Object.freeze([
	".claude/settings.json",
	".claude/plugins/installed_plugins.json",
	".cursor/hooks.json",
	".codex/config.toml",
	".codex/hooks.json",
	".openclaw/openclaw.json",
	".config/opencode/opencode.json",
	".vscode/settings.json",
]);

/** Map each guarded path to its sha256, or null when absent. */
export function snapshotHome(home) {
	const entries = {};
	for (const relative of GUARDED_HOME_PATHS) {
		const file = path.join(home, relative);
		if (!existsSync(file)) {
			entries[relative] = null;
			continue;
		}
		const info = lstatSync(file);
		entries[relative] = info.isFile()
			? createHash("sha256").update(readFileSync(file)).digest("hex")
			: `non-file:${info.isSymbolicLink() ? "symlink" : "other"}`;
	}
	return { home, entries };
}

/** Human-readable differences between two snapshots; empty when unchanged. */
export function diffSnapshots(before, after) {
	if (before.home !== after.home) return [`home directory changed: ${before.home} -> ${after.home}`];
	const changes = [];
	for (const relative of GUARDED_HOME_PATHS) {
		const was = before.entries[relative] ?? null;
		const now = after.entries[relative] ?? null;
		if (was === now) continue;
		if (was === null) changes.push(`created ~/${relative}`);
		else if (now === null) changes.push(`deleted ~/${relative}`);
		else changes.push(`modified ~/${relative}`);
	}
	return changes;
}

function main(argv) {
	const [mode, snapshotPath] = argv;
	if (!["--record", "--verify"].includes(mode) || !snapshotPath) {
		console.error("usage: verify-real-home-untouched.mjs --record|--verify <snapshot.json>");
		return 2;
	}
	const home = process.env.AIDR_REAL_HOME || homedir();
	const current = snapshotHome(home);
	if (mode === "--record") {
		writeFileSync(snapshotPath, `${JSON.stringify(current, null, 2)}\n`, "utf8");
		console.log(`Recorded ${GUARDED_HOME_PATHS.length} agent configuration paths under ${home}`);
		return 0;
	}
	if (!existsSync(snapshotPath)) {
		console.error(`No home snapshot at ${snapshotPath}; the --record step did not run.`);
		return 1;
	}
	const changes = diffSnapshots(JSON.parse(readFileSync(snapshotPath, "utf8")), current);
	if (changes.length > 0) {
		console.error("Tests wrote the runner's real home directory:");
		for (const change of changes) console.error(`  ${change}`);
		return 1;
	}
	console.log(`Real home ${home} untouched (${GUARDED_HOME_PATHS.length} agent configuration paths)`);
	return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
	process.exitCode = main(process.argv.slice(2));
}
