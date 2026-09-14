#!/usr/bin/env node
/**
 * verify-repo-hygiene.test.mjs — `node --test` coverage for the AIDR-012 gate.
 *
 * Every fixture is built in a temporary directory OUTSIDE the repository, so the tests never
 * depend on, and never mutate, the real working tree. Each fixture is a throwaway git
 * repository: the gate reads the index (`git ls-files`), so a fixture must really stage its
 * files for the check to be meaningful.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { after, describe, it } from "node:test";

import {
	ALLOWLIST,
	HOST_PATH_PATTERNS,
	checkAllowlistSelfCheck,
	classifyScratchPattern,
	isBinaryBuffer,
	listTrackedFiles,
	main,
	matchAllowlistEntry,
	parseGitignoreScratchPatterns,
	runGate,
	scanHostPaths,
} from "./verify-repo-hygiene.mjs";

const SCRIPT_PATH = fileURLToPath(import.meta.url).replace(/\.test\.mjs$/, ".mjs");
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Owner-tagged allowlist entry with a real written reason, for fixture use. */
const FIXTURE_ALLOWLIST = [
	{
		path: "vendor/upstream/embedded-path.txt",
		owner: "AIDR-012",
		reason: "Vendored upstream file legitimately embeds the build machine path recorded by its own release tooling.",
	},
];

const created = [];
after(() => {
	for (const dir of created) {
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			/* best effort */
		}
	}
});

/**
 * Create a temporary git repository OUTSIDE the repository under test, stage every fixture
 * file (forced, so .gitignore cannot silently hide it), and return its root.
 */
function makeFixture(files) {
	const root = mkdtempSync(join(tmpdir(), "aidr-repo-hygiene-"));
	created.push(root);
	execFileSync("git", ["init", "--quiet", "-b", "main"], { cwd: root, stdio: "ignore" });
	for (const [name, content] of Object.entries(files)) {
		const target = join(root, name);
		mkdirSync(dirname(target), { recursive: true });
		writeFileSync(target, content);
	}
	execFileSync("git", ["add", "-A", "-f"], { cwd: root, stdio: "ignore" });
	return root;
}

/** Run the gate against a fixture repo, using the fixture allowlist unless one is given. */
function runFixture(root, allowlist = []) {
	return runGate({ repoRoot: root, allowlist, now: "1970-01-01T00:00:00.000Z" });
}

const CLEAN_GITIGNORE = ["node_modules/", "*.log", "coverage/", ".tmp-test/", "test_output*"].join("\n");

/** Every violation whose check/kind pair matches, for readable assertions. */
function violationsOfKind(report, kind) {
	return report.violations.filter((violation) => violation.kind === kind);
}

describe("verify-repo-hygiene: root scratch check", () => {
	it("passes a clean tree", () => {
		const root = makeFixture({
			".gitignore": `${CLEAN_GITIGNORE}\n`,
			"README.md": "# fixture\n\nNo scratch output here.\n",
			"src/index.ts": "export const answer = 42;\n",
		});
		const report = runFixture(root);
		assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
		assert.equal(report.violations.length, 0);
		assert.equal(report.summary.trackedFiles, 3);
		assert.equal(report.summary.scratchPatternsFromGitignore, 4);
	});

	it("fails when a root *.log file is tracked", () => {
		const root = makeFixture({
			".gitignore": `${CLEAN_GITIGNORE}\n`,
			"README.md": "# fixture\n",
			"debug.log": "lint finished\n",
		});
		const report = runFixture(root);
		assert.equal(report.ok, false);
		const offenders = violationsOfKind(report, "tracked-scratch-at-root").map((entry) => entry.file);
		assert.deepEqual(offenders, ["debug.log"]);
		assert.equal(violationsOfKind(report, "tracked-scratch-at-root")[0].pattern, "*.log");
	});

	it("fails when root test_output.txt is tracked", () => {
		const root = makeFixture({
			".gitignore": `${CLEAN_GITIGNORE}\n`,
			"test_output.txt": "noise\n",
		});
		const report = runFixture(root);
		assert.equal(report.ok, false);
		assert.deepEqual(
			violationsOfKind(report, "tracked-scratch-at-root").map((entry) => entry.file),
			["test_output.txt"],
		);
	});

	it("fails when a tracked tmp-test file sits below the root", () => {
		const root = makeFixture({
			".gitignore": `${CLEAN_GITIGNORE}\n`,
			".tmp-test/integrity-1/a.txt": "scratch\n",
		});
		const report = runFixture(root);
		assert.equal(report.ok, false);
		assert.deepEqual(
			violationsOfKind(report, "tracked-scratch-below-root").map((entry) => entry.file),
			[".tmp-test/integrity-1/a.txt"],
		);
	});

	it("does not flag a scratch-looking name that is not declared in .gitignore", () => {
		const root = makeFixture({
			".gitignore": "node_modules/\n",
			"notes.log": "an intentional tracked fixture\n",
		});
		const report = runFixture(root);
		assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
	});

	it("classifies gitignore patterns and drops negations", () => {
		assert.equal(classifyScratchPattern("*.log"), "diagnostic-log");
		assert.equal(classifyScratchPattern("coverage/"), "coverage-report");
		assert.equal(classifyScratchPattern("/lint*.txt"), "text-dump");
		assert.equal(classifyScratchPattern("diagnostics/"), "diagnostics-dir");
		assert.equal(classifyScratchPattern("*.cpuprofile"), "diagnostic-log");
		assert.equal(classifyScratchPattern("node_modules/"), null);
		assert.equal(classifyScratchPattern("!keep-me.log"), "diagnostic-log");
		const parsed = parseGitignoreScratchPatterns("*.log\n!important.log\ncoverage/\n# comment\n");
		assert.deepEqual(parsed.map((entry) => entry.pattern), ["*.log", "coverage/"]);
	});
});

describe("verify-repo-hygiene: host-path scan", () => {
	it("fails on a Windows drive path in a tracked text file", () => {
		const root = makeFixture({
			".gitignore": "node_modules/\n",
			"notes.md": "line one\nleaked at C:\\Users\\someone\\secret\n",
		});
		const report = runFixture(root);
		assert.equal(report.ok, false);
		const entry = violationsOfKind(report, "personal-windows-home")[0];
		assert.equal(entry.file, "notes.md");
		assert.equal(entry.line, 2);
		assert.match(entry.match, /^C:\\Users\\someone$/);
		assert.equal(entry.patternId, "windows_drive_path");
	});

	it("fails on a POSIX /home/<name>/ path in a tracked text file", () => {
		const root = makeFixture({
			".gitignore": "node_modules/\n",
			"config.yaml": "home: /home/someone/\n",
		});
		const report = runFixture(root);
		assert.equal(report.ok, false);
		const entry = violationsOfKind(report, "absolute-posix-home")[0];
		assert.equal(entry.file, "config.yaml");
		assert.equal(entry.match, "/home/someone");
	});

	it("fails on a macOS /Users/<name>/ path and on an escaped Windows path", () => {
		const root = makeFixture({
			".gitignore": "node_modules/\n",
			"a.json": '{"plan":"C:\\\\Users\\\\someone\\\\plan.md"}\n',
			"b.sh": "cd /Users/someone/project\n",
		});
		const report = runFixture(root);
		assert.equal(report.ok, false);
		assert.deepEqual(
			report.violations.filter((entry) => entry.check === "host-path").map((entry) => entry.file),
			["a.json", "b.sh"],
		);
	});

	it("does not mistake regex escapes for host paths", () => {
		const root = makeFixture({
			".gitignore": "node_modules/\n",
			"deploy.sh": 'psql -c "\\\\gset"\n',
			"batch.cmd": "if defined X (\\endif)\n",
			"rules.ts": 'export const rule = /\\\\bexport\\\\s+PATH/;\n',
			"rules.yaml": 'pattern: "\\\\bBun\\\\.shell\\\\b"\n',
		});
		const report = runFixture(root);
		assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
	});

	it("treats anonymous placeholder identities as non-identifying", () => {
		const root = makeFixture({
			".gitignore": "node_modules/\n",
			"fixture.ts": 'const a = "/home/user/.ssh/id_rsa";\nconst b = "/Users/user/project";\nconst c = "/home/u/.claude/hooks.json";\n',
		});
		const report = runFixture(root);
		assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
	});

	it("exempts a vendored file listed in the allowlist with a reason", () => {
		const root = makeFixture({
			".gitignore": "node_modules/\n",
			"vendor/upstream/embedded-path.txt": "built at /home/builder/ci\n",
			"notes.md": "clean\n",
		});
		const report = runFixture(root, FIXTURE_ALLOWLIST);
		assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
		assert.deepEqual(report.allowlistedFiles, ["vendor/upstream/embedded-path.txt"]);
	});

	it("fails the allowlist self-check when a reason is empty", () => {
		const root = makeFixture({
			".gitignore": "node_modules/\n",
			"vendor/upstream/embedded-path.txt": "built at /home/builder/ci\n",
		});
		const report = runFixture(root, [{ path: "vendor/upstream/embedded-path.txt", owner: "AIDR-012", reason: "" }]);
		assert.equal(report.ok, false);
		assert.equal(report.allowlistProblems.length, 1);
		assert.equal(report.allowlistProblems[0].kind, "allowlist-missing-reason");
		// The self-check failure alone is enough to fail the gate even with no path violations.
		assert.equal(report.violations.length, 1); // the vendored file is no longer exempt
	});

	it("fails the allowlist self-check on a whitespace-only reason and on a missing owner", () => {
		const problems = checkAllowlistSelfCheck([
			{ path: "vendor/a.txt", owner: "AIDR-012", reason: "   \n  " },
			{ path: "vendor/b.txt", reason: "A properly written reason that clears the minimum length." },
		]);
		assert.deepEqual(
			problems.map((problem) => problem.kind).sort(),
			["allowlist-missing-owner", "allowlist-missing-reason"],
		);
	});

	it("fails the allowlist self-check on a duplicate path", () => {
		const problems = checkAllowlistSelfCheck([
			{ path: "docs/x.md", owner: "AIDR-012", reason: "First written reason that is long enough to count." },
			{ path: "docs/x.md", owner: "AIDR-012", reason: "Second written reason that is long enough to count." },
		]);
		assert.deepEqual(problems.map((problem) => problem.kind), ["allowlist-duplicate-path"]);
	});

	it("keeps every shipped allowlist entry self-check clean", () => {
		assert.deepEqual(checkAllowlistSelfCheck(ALLOWLIST), []);
		assert.ok(ALLOWLIST.length > 0);
	});

	it("skips binary content without a false positive", () => {
		const root = mkdtempSync(join(tmpdir(), "aidr-repo-hygiene-bin-"));
		created.push(root);
		const withNul = Buffer.from("leak C:\\Users\\someone\\secret\u0000tail", "utf8");
		const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01]);
		const fakePng = Buffer.concat([
			png,
			Buffer.from("/home/someone/pictures/identity.png", "latin1"),
		]);
		writeFileSync(join(root, "blob.bin"), withNul);
		writeFileSync(join(root, "picture.png"), fakePng);
		const text = Buffer.from("plain text, no leak\n", "utf8");
		writeFileSync(join(root, "plain.txt"), text);

		assert.equal(isBinaryBuffer(withNul, "blob.bin"), true, "NUL probe must mark the blob binary");
		assert.equal(isBinaryBuffer(fakePng, "picture.png"), true, "extension must mark the PNG binary");
		assert.equal(isBinaryBuffer(text, "plain.txt"), false);

		// Drive the scanner directly so the assertion is about scanning, not about git.
		const result = scanHostPaths({
			repoRoot: root,
			trackedFiles: ["blob.bin", "picture.png", "plain.txt"],
			allowlist: [],
		});
		assert.deepEqual(result.violations, []);
		assert.deepEqual(result.scanned, ["plain.txt"]);
	});

	it("is deterministic across two runs", () => {
		const root = makeFixture({
			".gitignore": `${CLEAN_GITIGNORE}\n`,
			"a.log": "scratch\n",
			"notes.md": String.raw`C:\Users\someone\secret` + "\n",
			"src/b.ts": "const p = '/home/someone/x';\n",
		});
		const first = runGate({ repoRoot: root, allowlist: [], now: "1970-01-01T00:00:00.000Z" });
		const second = runGate({ repoRoot: root, allowlist: [], now: "1970-01-01T00:00:00.000Z" });
		assert.deepEqual(second, first, "two runs over identical inputs must produce identical reports");
		assert.equal(first.ok, false);
		const kinds = first.violations.map((entry) => `${entry.check}:${entry.kind}:${entry.file}`);
		assert.ok(kinds.includes("root-scratch:tracked-scratch-at-root:a.log"), kinds.join(", "));
		assert.ok(kinds.includes("host-path:personal-windows-home:notes.md"), kinds.join(", "));
		assert.ok(kinds.includes("host-path:absolute-posix-home:src/b.ts"), kinds.join(", "));
		assert.equal(new Set(kinds).size, kinds.length, "no duplicate violations");
	});
});

describe("verify-repo-hygiene: helpers", () => {
	it("matches allowlist prefixes and exact paths", () => {
		const allowlist = [{ path: "docs/**", owner: "o", reason: "a reason long enough to satisfy self check" }];
		assert.ok(matchAllowlistEntry("docs/a/b.md", allowlist));
		assert.ok(matchAllowlistEntry("docs/a.md", allowlist));
		assert.equal(matchAllowlistEntry("docsomething/a.md", allowlist), null);
		assert.equal(matchAllowlistEntry("src/a.ts", allowlist), null);
	});

	it("lists tracked files from git, not from the filesystem", () => {
		const root = makeFixture({
			".gitignore": "*.log\n",
			"tracked.md": "hello\n",
		});
		// Present on disk but deliberately not staged: an index read must not see it.
		writeFileSync(join(root, "untracked.log"), "not tracked\n");
		const tracked = listTrackedFiles(root);
		assert.deepEqual(tracked.sort(), [".gitignore", "tracked.md"]);
	});

	it("exposes host-path patterns able to match every declared kind", () => {
		const samples = {
			windows_drive_path: String.raw`C:\Users\someone\x`,
			posix_home_path: "/home/someone/x",
		};
		assert.deepEqual(
			HOST_PATH_PATTERNS.map((pattern) => pattern.id),
			Object.keys(samples),
		);
		for (const pattern of HOST_PATH_PATTERNS) {
			pattern.re.lastIndex = 0;
			assert.ok(pattern.re.test(samples[pattern.id]), `${pattern.id} must match its sample`);
		}
	});

	it("returns exit code 0 when clean and 1 with a machine-readable report when dirty", () => {
		const clean = makeFixture({ ".gitignore": "node_modules/\n", "README.md": "# ok\n" });
		const dirty = makeFixture({
			".gitignore": "node_modules/\n",
			"notes.md": "C:\\Users\\someone\\secret\n",
		});

		const cleanRun = execFileSync(process.execPath, [SCRIPT_PATH, "--json", "--repo", clean], { encoding: "utf8" });
		const cleanReport = JSON.parse(cleanRun);
		assert.equal(cleanReport.ok, true);
		assert.equal(cleanReport.gate, "verify-repo-hygiene");
		assert.equal(cleanReport.finding, "AIDR-012");

		let dirtyReport = null;
		try {
			execFileSync(process.execPath, [SCRIPT_PATH, "--json", "--repo", dirty], { encoding: "utf8" });
			assert.fail("gate must exit non-zero on a violation");
		} catch (error) {
			assert.equal(error.status, 1);
			dirtyReport = JSON.parse(error.stdout);
		}
		assert.equal(dirtyReport.ok, false);
		assert.equal(dirtyReport.violations[0].kind, "personal-windows-home");
		assert.ok(dirtyReport.summary.violations >= 1);
	});

	it("exposes main() for in-process use and reports the real repository as clean", () => {
		assert.equal(typeof main, "function");
		const report = runGate({ repoRoot: REPO_ROOT });
		assert.equal(report.ok, true, JSON.stringify(report.violations.slice(0, 5), null, 2));
		assert.equal(report.summary.violations, 0);
		assert.equal(report.allowlistProblems.length, 0);
	});
});
