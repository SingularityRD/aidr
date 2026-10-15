/**
 * Customer-facing documentation claims must match the repository.
 *
 *   node --test scripts/check-doc-claims.test.mjs
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { checkDocClaims, customerSurfaces, failClosedWithoutCaveat, staleRuleClaims, staleRuleTables } from "./check-doc-claims.mjs";
import { loadRuleFacts } from "./lib/rule-facts.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const facts = loadRuleFacts(root);

test("rule facts agree with a plain count of the rule files", () => {
	const ids = execFileSync("bash", ["-c", "cat threats/*.yaml | grep -c '^- id:'"], { cwd: root, encoding: "utf8" });
	assert.equal(facts.total, Number(ids.trim()));
	const actions = Object.values(facts.byAction).reduce((a, b) => a + b, 0);
	assert.equal(actions, facts.total, "every rule has exactly one action");
	assert.equal(Object.values(facts.byCategory).reduce((a, b) => a + b, 0), facts.total);
});

test("stale totals, splits and file counts are reported (the 494/351 regression)", () => {
	const text = [
		"- **Local heuristics** — 494 YAML threat rules in 29 files",
		"| YAML threat heuristics — **351 rules across 23 files** |",
		"Of the 494 rules, 211 block, 255 require approval",
		"and 28 log; 168 are critical, 299 high and 27 medium.",
		"veridir: **29 dosyada 494 kural** bulunur",
		"494 kuralın 211'i engeller, 255'i onay ister,",
		"28'i yalnızca kayıt tutar; 168'i critical, 299'u high, 27'si medium",
		"CLT-FILE-002 kuralı eşleşir; 2,000+ CVE rules; 13 new rules.",
	].join("\n");
	const kinds = staleRuleClaims(text, facts).map((p) => `${p.kind}:${p.claimed}`);
	for (const expected of ["rule total:494", "rule total:351", "rule file count:23", "block rules:211", "require_approval rules:255", "critical rules:168", "high rules:299"]) {
		assert.ok(kinds.includes(expected), `expected ${expected} in ${kinds.join(", ")}`);
	}
	assert.ok(!kinds.some((k) => k.endsWith(":2") || k.endsWith(":13") || k.endsWith(":2000")), "rule ids, CVE counts and small numbers are not totals");
	const current = `${facts.total} YAML threat rules in ${facts.fileCount} files. Of the ${facts.total} rules, ${facts.byAction.block} block, ${facts.byAction.require_approval} require approval and ${facts.byAction.log} log.`;
	assert.deepEqual(staleRuleClaims(current, facts), []);
});

test("rule tables are checked per file and per category", () => {
	const stale = ["| File | Scope | Rules |", "| --- | --- | --- |", "| `commands.yaml` | Dangerous | 1 |", "| **Total** | 29 files | **494** |"].join("\n");
	const kinds = staleRuleTables(stale, facts).map((p) => p.kind);
	assert.ok(kinds.includes("rules in commands.yaml"));
	assert.ok(kinds.includes("table total"));
	assert.ok(kinds.some((k) => k.startsWith("rule file ") && k.endsWith("missing from the table")));
	const categories = ["| Group | Categories | Rules |", "| --- | --- | --- |", "| Tool abuse | `tool` | 1 |"].join("\n");
	assert.ok(staleRuleTables(categories, facts).some((p) => p.kind === "category tool across the table"));
});

test("a connector fail-closed claim needs the host caveat in the same paragraph", () => {
	assert.equal(failClosedWithoutCaveat("44 Fail-closed connectors — an internal error denies the call instead of passing it.").length, 1);
	assert.equal(failClosedWithoutCaveat("Connector entry points remain fail-closed as always.").length, 1);
	assert.deepEqual(failClosedWithoutCaveat("Connector entry points fail closed; a disabled, untrusted or killed hook is outside that."), []);
	assert.deepEqual(failClosedWithoutCaveat("### Fail-closed behaviour per connector\n\nSee the table."), [], "headings are not claims");
	assert.deepEqual(failClosedWithoutCaveat("Authentication fails closed."), [], "security controls are out of scope");
});

test("dated and internal records are not customer surfaces", () => {
	const surfaces = customerSurfaces(root);
	assert.ok(surfaces.includes("README.md"));
	assert.ok(surfaces.includes("docs/product/overview.md"));
	assert.ok(!surfaces.some((file) => file.startsWith("docs/production-readiness/") || file.includes("historical")));
});

test("the customer-facing documentation matches the repository", () => {
	const { problems } = checkDocClaims(root);
	assert.deepEqual(
		problems.map(({ file, line, kind, claimed, expected }) => `${file}:${line} ${kind}${claimed !== undefined ? ` (says ${claimed}, repository ${expected})` : ""}`),
		[],
		"run node scripts/check-doc-claims.mjs and fix the listed documents",
	);
});
