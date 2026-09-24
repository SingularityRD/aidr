import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { GUARDED_HOME_PATHS, diffSnapshots, snapshotHome } from "./verify-real-home-untouched.mjs";

const script = fileURLToPath(new URL("./verify-real-home-untouched.mjs", import.meta.url));

function withFakeHome(run) {
	const home = mkdtempSync(path.join(tmpdir(), "aidr-real-home-guard-"));
	try {
		return run(home);
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
}

function guard(home, ...args) {
	return spawnSync(process.execPath, [script, ...args], {
		encoding: "utf8",
		env: { ...process.env, AIDR_REAL_HOME: home },
	});
}

function write(home, relative, content) {
	mkdirSync(path.dirname(path.join(home, relative)), { recursive: true });
	writeFileSync(path.join(home, relative), content);
}

test("guards the configuration files every hook installer writes", () => {
	for (const required of [".cursor/hooks.json", ".claude/settings.json", ".codex/hooks.json", ".openclaw/openclaw.json"]) {
		assert.ok(GUARDED_HOME_PATHS.includes(required), `${required} must be guarded`);
	}
});

test("an untouched home passes and created, modified or deleted files fail", () => {
	withFakeHome((home) => {
		write(home, ".claude/settings.json", "{}\n");
		write(home, ".cursor/hooks.json", "{}\n");
		const snapshot = path.join(home, "snapshot.json");
		assert.equal(guard(home, "--record", snapshot).status, 0);
		const clean = guard(home, "--verify", snapshot);
		assert.equal(clean.status, 0, clean.stderr);
		assert.match(clean.stdout, /untouched/);

		write(home, ".claude/settings.json", '{"hooks":{}}\n');
		rmSync(path.join(home, ".cursor/hooks.json"));
		write(home, ".codex/hooks.json", "{}\n");
		const dirty = guard(home, "--verify", snapshot);
		assert.equal(dirty.status, 1);
		assert.match(dirty.stderr, /modified ~\/\.claude\/settings\.json/);
		assert.match(dirty.stderr, /deleted ~\/\.cursor\/hooks\.json/);
		assert.match(dirty.stderr, /created ~\/\.codex\/hooks\.json/);
	});
});

test("verification fails closed without a recorded snapshot or with bad arguments", () => {
	withFakeHome((home) => {
		const missing = guard(home, "--verify", path.join(home, "absent.json"));
		assert.equal(missing.status, 1);
		assert.match(missing.stderr, /did not run/);
		assert.equal(guard(home).status, 2);
	});
});

test("a changed home directory is reported instead of compared file by file", () => {
	withFakeHome((home) => {
		const before = snapshotHome(home);
		const after = { ...snapshotHome(home), home: path.join(home, "other") };
		assert.deepEqual(diffSnapshots(before, after), [`home directory changed: ${home} -> ${path.join(home, "other")}`]);
	});
});
