import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const verifier = fileURLToPath(new URL("./verify-codex-hook.mjs", import.meta.url));

test("Codex verifier accepts only an evaluated empty-stdout allow", (context) => {
	const root = mkdtempSync(join(tmpdir(), "aidr-codex-verifier-test-"));
	context.after(() => rmSync(root, { recursive: true, force: true }));
	const script = join(root, "scripts", "verify-codex-hook.mjs");
	const dist = join(root, "packages", "codex", "dist");
	mkdirSync(dirname(script), { recursive: true });
	mkdirSync(dist, { recursive: true });
	copyFileSync(verifier, script);
	writeFileSync(join(dist, "aidr-artifact.manifest.json"), "{}\n");
	writeFileSync(join(dist, "pre-tool-use.cjs"), `
const { readFileSync } = require("node:fs");
function deny() {
  process.stdout.write(JSON.stringify({ hookSpecificOutput: {
    hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "blocked"
  } }));
}
let input;
try { input = JSON.parse(readFileSync(0, "utf8")); } catch { input = null; }
const command = String(input?.tool_input?.command ?? "");
if (!input || input.hook_event_name !== "PreToolUse" ||
    /evil\\.test|rm -rf \\/|dev\\/tcp|authorized_keys/.test(command)) {
  deny();
} else if (process.env.AIDR_TEST_BAD_ALLOW === "1") {
  process.stdout.write(" ");
}
`);

	function run(badAllow) {
		return spawnSync(process.execPath, [script], {
			cwd: root,
			encoding: "utf8",
			timeout: 30_000,
			env: { ...process.env, AIDR_TEST_BAD_ALLOW: badAllow ? "1" : "0" },
		});
	}

	const valid = run(false);
	assert.equal(valid.status, 0, valid.stderr || valid.error?.message);
	assert.match(valid.stdout, /ALL PASS - 11\/11 cases behaved correctly/);
	const invalid = run(true);
	assert.equal(invalid.status, 1, invalid.stderr || invalid.error?.message);
	assert.match(invalid.stdout, /4 FAILURE\(S\) - 7\/11 cases behaved correctly/);
});
