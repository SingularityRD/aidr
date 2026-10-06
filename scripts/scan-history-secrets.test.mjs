import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { isPartialScan, summarize } from "./scan-history-secrets.mjs";

test("a partial gitleaks run is never treated as a result", () => {
	assert.equal(isPartialScan("WRN partial scan completed in 2m19s\nWRN 180 leaks found in partial scan"), true);
	assert.equal(isPartialScan("ERR failed to scan Git repository error=\"stderr is not empty\""), true);
	assert.equal(isPartialScan("INF 618 commits scanned.\nWRN leaks found: 184"), false);
});

test("summary counts findings without carrying any match text", () => {
	const summary = summarize([
		{ RuleID: "github-pat", Commit: "a", File: "x", Secret: "REDACTED", Match: "REDACTED" },
		{ RuleID: "github-pat", Commit: "b", File: "x" },
		{ RuleID: "jwt", Commit: "b", File: "y" },
	]);
	assert.deepEqual(summary, { findings: 3, commits: 2, files: 2, byRule: { "github-pat": 2, jwt: 1 } });
	assert.equal(JSON.stringify(summary).includes("REDACTED"), false);
});

function audit(t, { history = 0, current = 0, version = "8.30.1" } = {}) {
	const root = mkdtempSync(join(tmpdir(), "aidr-pre-release-audit-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	mkdirSync(join(root, "scripts"));
	copyFileSync(fileURLToPath(new URL("./pre-release-audit.sh", import.meta.url)), join(root, "scripts/pre-release-audit.sh"));
	writeFileSync(join(root, ".gitleaks.toml"), 'title = "fixture"\n');
	const scanner = join(root, "gitleaks");
	writeFileSync(scanner, '#!/usr/bin/env bash\n[[ "$1" == "version" ]] || exit 99\nprintf "%s\\n" "$AIDR_TEST_SCANNER_VERSION"\n');
	chmodSync(scanner, 0o755);
	for (const [name, status] of [["history", history], ["current", current]]) {
		writeFileSync(join(root, `scripts/scan-${name}-secrets.mjs`), `import { isAbsolute } from "node:path"; if (!isAbsolute(process.env.GITLEAKS_BIN)) process.exit(2); console.log("${name} scan executed"); process.exit(${status});\n`);
	}
	const gitBash = "C:\\Program Files\\Git\\bin\\bash.exe";
	const bash = process.platform === "win32" && existsSync(gitBash) ? gitBash : "bash";
	const result = spawnSync(bash, [join(root, "scripts/pre-release-audit.sh")], {
		encoding: "utf8",
		env: { ...process.env, GITLEAKS_BIN: scanner, AIDR_TEST_SCANNER_VERSION: version },
	});
	assert.equal(result.error, undefined);
	return result;
}

test("pre-release audit uses the redacted all-ref wrapper and consistent pinned version", () => {
	const script = readFileSync(new URL("./pre-release-audit.sh", import.meta.url), "utf8");
	const wrapper = readFileSync(new URL("./scan-history-secrets.mjs", import.meta.url), "utf8");
	assert.match(script, /REQUIRED_GITLEAKS_VERSION="8\.30\.1"/u);
	assert.match(script, /node "\$REPO_ROOT\/scripts\/scan-history-secrets\.mjs"/u);
	assert.match(wrapper, /--log-opts=--all --no-textconv/u);
	assert.match(wrapper, /--redact=100/u);
	assert.doesNotMatch(script, /"\$GITLEAKS_BIN" git|gitleaks:allow/u);
});

test("pre-release audit passes only after both checked wrappers pass", (t) => {
	const result = audit(t);
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /history scan executed/u);
	assert.match(result.stdout, /current scan executed/u);
	assert.match(result.stdout, /PASS/u);
});

test("pre-release audit scans the current checkout even when history has findings", (t) => {
	const result = audit(t, { history: 1 });
	assert.equal(result.status, 1);
	assert.match(result.stdout, /history scan executed/u);
	assert.match(result.stdout, /current scan executed/u);
	assert.doesNotMatch(result.stdout, /PASS/u);
});

test("pre-release audit preserves scan errors over finding-only results", (t) => {
	for (const [history, current] of [[2, 0], [1, 2]]) {
		const result = audit(t, { history, current });
		assert.equal(result.status, 2);
		assert.match(result.stdout, /current scan executed/u);
		assert.doesNotMatch(result.stdout, /PASS/u);
	}
});

test("pre-release audit rejects an obsolete scanner before either scan runs", (t) => {
	const result = audit(t, { version: "8.30.0" });
	assert.equal(result.status, 2);
	assert.match(result.stdout, /gitleaks 8\.30\.1 is required/u);
	assert.doesNotMatch(result.stdout, /scan executed/u);
});
