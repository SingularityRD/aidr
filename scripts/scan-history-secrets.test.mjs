import assert from "node:assert/strict";
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
