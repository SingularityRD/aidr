import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
	DECLARATION_PATTERN,
	INCLUDED_ROOTS,
	checkRepo,
	collectedTestFiles,
	scanSource,
} from "./check-mandatory-skips.mjs";

/** A repository-shaped scratch tree with one test file. */
function fixture(source) {
	const root = mkdtempSync(join(tmpdir(), "aidr-skips-"));
	const directory = join(root, "packages", "demo", "src", "__tests__");
	mkdirSync(directory, { recursive: true });
	writeFileSync(join(directory, "demo.test.ts"), source, "utf8");
	return root;
}

test("an undeclared skip fails the gate", () => {
	const root = fixture(`import { it } from "vitest";
${"it"}.skip("not run here", () => { doSomething(); });
`);
	try {
		const { violations } = checkRepo(root);
		assert.equal(violations.length, 1);
		assert.equal(violations[0].declared, false);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("a skip with a backlog id and owner passes while remaining visible", () => {
	const root = fixture(`import { it } from "vitest";
// AIDR-SKIP: AIDR-049 qa-owner - the extension host is not installed on this machine
${"it"}.skip("needs an editor host", () => { doSomething(); });
`);
	try {
		const { findings, violations } = checkRepo(root);
		assert.equal(violations.length, 0);
		// Still reported: declared is not the same as invisible.
		assert.equal(findings.length, 1);
		assert.equal(findings[0].declared, true);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("an empty skip body is always a failure", () => {
	const root = fixture(`import { it } from "vitest";
// AIDR-SKIP: AIDR-020 qa-owner - requires a reachable reputation endpoint
${"it"}.skip("denies a malicious URL", () => {});
`);
	try {
		const { violations } = checkRepo(root);
		assert.equal(violations.length, 1);
		assert.equal(violations[0].empty, true);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("conditional skip forms are skip sites too", () => {
	const root = fixture(`import { describe, it } from "vitest";
${"it"}.skipIf(process.platform !== "win32")("Windows behavior", () => { doSomething(); });
${"describe"}.skipIf(process.platform !== "win32")("Windows suite", () => { doSomething(); });
`);
	try {
		const { findings, violations } = checkRepo(root);
		assert.equal(findings.length, 2);
		assert.equal(violations.length, 2);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("the scripts root is included in the scan", () => {
	const root = fixture("import { it } from \"vitest\";\nit(\"package test\", () => {});\n");
	try {
		const scripts = join(root, "scripts");
		mkdirSync(scripts, { recursive: true });
		writeFileSync(join(scripts, "script.test.mjs"), "it(\\\"script test\\\", () => {});\\n", "utf8");
		const files = collectedTestFiles(root).map((file) => file.replaceAll("\\", "/"));
		assert.equal(INCLUDED_ROOTS.includes("scripts"), true);
		assert.equal(files.some((file) => file.endsWith("/scripts/script.test.mjs")), true);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("a todo is a skip site too", () => {
	const root = fixture(`import { it } from "vitest";
${"it"}.todo("write this later");
`);
	try {
		const { findings, violations } = checkRepo(root);
		assert.equal(findings.length, 1);
		assert.equal(violations.length, 1);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("the gate does not match a skip call written as a comment", () => {
	const source = `import { it } from "vitest";
// we used to call it.skip("this assertion here", () => {});
it("does the real thing", () => {
	doSomething();
});
`;
	assert.equal(scanSource(source, "demo.test.ts").length, 0);
});

test("a skip call inside a string literal is reported, not silently ignored", () => {
	// Documented behaviour: a `it.skip(` occurring inside a quoted string is
	// indistinguishable from a call without a parser, so the gate reports it
	// rather than pretending it is not there. A false positive is visible and
	// fixable; a false negative would hide a skip.
	const source = `import { it } from "vitest";
const message = "${"it"}.skip( is not a call";
it("does the real thing", () => {
	doSomething(message);
});
`;
	assert.equal(scanSource(source, "demo.test.ts").length, 1);
});

test("the declaration form requires a backlog id, an owner and a reason", () => {
	assert.equal(DECLARATION_PATTERN.test("// AIDR-SKIP: AIDR-049 qa-owner - host missing"), true);
	assert.equal(DECLARATION_PATTERN.test("// AIDR-SKIP: AIDR-049 qa-owner — host missing"), true);
	// No backlog id, and no owner, are both rejected.
	assert.equal(DECLARATION_PATTERN.test("// AIDR-SKIP: no-id qa-owner - host missing"), false);
	assert.equal(DECLARATION_PATTERN.test("// AIDR-SKIP: AIDR-049 - host missing"), false);
	// A bare mention of the marker is not a declaration either.
	assert.equal(DECLARATION_PATTERN.test("// AIDR-SKIP: because it needs a host"), false);
});

test("an empty body is detected for both the arrow and the function form", () => {
	const arrow = `${"it"}.skip("a", () => {});`;
	const fn = `${"it"}.skip("b", function () {});`;
	const real = `${"it"}.skip("c", () => { run(); });`;
	assert.equal(scanSource(arrow, "a").length, 1);
	assert.equal(scanSource(fn, "b").length, 1);
	assert.equal(scanSource(real, "c")[0]?.empty, false);
});
