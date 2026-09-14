import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const root = new URL("..", import.meta.url);
const verifierPath = new URL("./verify-aig-source.mjs", import.meta.url);

test("verifier source pin matches the superproject gitlink", async () => {
	const verifier = await readFile(verifierPath, "utf8");
	const expectedCommit = verifier.match(/const expectedCommit = "([0-9a-f]{40})";/)?.[1];
	assert.ok(expectedCommit, "verify-aig-source.mjs must declare a full expectedCommit SHA");

	const gitlink = execFileSync(
		"git",
		["ls-tree", "HEAD", "vendor/ai-infra-guard"],
		{ cwd: root, encoding: "utf8" },
	).trim();
	const match = gitlink.match(/^160000 commit ([0-9a-f]{40})\tvendor\/ai-infra-guard$/);
	assert.ok(match, "vendor/ai-infra-guard must be a checked-in gitlink");
	assert.equal(expectedCommit, match[1]);
});
