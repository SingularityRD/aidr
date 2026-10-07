import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const gitBash = "C:\\Program Files\\Git\\bin\\bash.exe";
const bash = process.platform === "win32" && existsSync(gitBash) ? gitBash : "bash";
const bashAvailable = spawnSync(bash, ["-c", "exit 0"]).status === 0;
const gitAvailable = spawnSync("git", ["--version"]).status === 0;
const skip = !bashAvailable || !gitAvailable ? "bash and git are required" : false;

function git(cwd, ...args) {
	const result = spawnSync("git", ["-c", "user.name=AIDR Test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", ...args], { cwd, encoding: "utf8" });
	assert.equal(result.status, 0, result.stderr);
}

/** A throwaway repo with the real script and PATH stubs that only log their arguments. */
function fixture(t, { tagged = true, dirty = false } = {}) {
	const root = mkdtempSync(join(tmpdir(), "aidr-deploy-dashboard-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	mkdirSync(join(root, "scripts"));
	mkdirSync(join(root, "packages/dashboard"), { recursive: true });
	copyFileSync(fileURLToPath(new URL("./deploy-dashboard.sh", import.meta.url)), join(root, "scripts/deploy-dashboard.sh"));
	writeFileSync(join(root, "packages/dashboard/package.json"), "{}\n");
	writeFileSync(join(root, ".gitignore"), "stub-bin/\ncalls.log\n");
	const bin = join(root, "stub-bin");
	mkdirSync(bin);
	for (const name of ["pnpm", "npx", "vercel", "supabase"]) {
		writeFileSync(join(bin, name), `#!/usr/bin/env bash\necho "${name} $*" >> "$AIDR_TEST_LOG"\n`);
		chmodSync(join(bin, name), 0o755);
	}
	git(root, "init", "-q");
	git(root, "add", "-A");
	git(root, "commit", "-q", "-m", "fixture");
	if (tagged) git(root, "tag", "v1.2.3");
	if (dirty) writeFileSync(join(root, "untracked.txt"), "local change\n");
	const log = join(root, "calls.log").replace(/\\/g, "/");
	return {
		run(args, extraEnv = {}) {
			const env = { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`, AIDR_TEST_LOG: log, ...extraEnv };
			if (!("AIDR_DEPLOY_CONFIRM" in extraEnv)) delete env.AIDR_DEPLOY_CONFIRM;
			const result = spawnSync(bash, [join(root, "scripts/deploy-dashboard.sh"), ...args], { cwd: root, encoding: "utf8", env, stdio: ["pipe", "pipe", "pipe"] });
			assert.equal(result.error, undefined);
			return { ...result, calls: existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [] };
		},
	};
}

test("rejects unknown environments before doing anything", { skip }, (t) => {
	const repo = fixture(t);
	for (const args of [["staging"], ["Production"], ["prod"], ["preview", "extra"]]) {
		const result = repo.run(args);
		assert.equal(result.status, 2, `${args.join(" ")}: ${result.stderr}`);
		assert.deepEqual(result.calls, []);
	}
});

test("production refuses a dirty working tree, including untracked files", { skip }, (t) => {
	const result = fixture(t, { dirty: true }).run(["production"], { AIDR_DEPLOY_CONFIRM: "production" });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /not clean/);
	assert.deepEqual(result.calls, []);
});

test("production refuses a HEAD that is not exactly at a tag", { skip }, (t) => {
	const result = fixture(t, { tagged: false }).run(["production"], { AIDR_DEPLOY_CONFIRM: "production" });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /not exactly at a tag/);
	assert.deepEqual(result.calls, []);
});

test("production refuses to deploy without an explicit confirmation", { skip }, (t) => {
	const repo = fixture(t);
	for (const extraEnv of [{}, { AIDR_DEPLOY_CONFIRM: "yes" }, { AIDR_DEPLOY_CONFIRM: "PRODUCTION" }]) {
		const result = repo.run(["production"], extraEnv);
		assert.notEqual(result.status, 0, JSON.stringify(extraEnv));
		assert.match(result.stderr, /not confirmed/);
		assert.deepEqual(result.calls, []);
	}
});

test("a confirmed, clean, tagged production deploy uses the frozen lockfile", { skip }, (t) => {
	const result = fixture(t).run(["production"], { AIDR_DEPLOY_CONFIRM: "production" });
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(result.calls, ["pnpm install --frozen-lockfile", "pnpm build", "vercel --prod"]);
});

test("preview deploys use the frozen lockfile and never the production target", { skip }, (t) => {
	const result = fixture(t, { tagged: false }).run([]);
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(result.calls, ["pnpm install --frozen-lockfile", "pnpm build", "vercel"]);
});
