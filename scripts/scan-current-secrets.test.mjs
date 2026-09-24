import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
	existsSync,
	mkdtempSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
	scanStagedCheckout,
	stageCurrentCheckout,
	verifyGitleaksCanary,
} from "./scan-current-secrets.mjs";

const git = (cwd, ...args) => execFileSync("git", args, { cwd, stdio: "ignore" });

test("stages only tracked and non-ignored regular checkout files", () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-current-scan-test-"));
	const destination = mkdtempSync(join(tmpdir(), "aidr-current-scan-stage-"));
	try {
		git(root, "init", "-q");
		git(root, "config", "user.email", "fixture@example.invalid");
		git(root, "config", "user.name", "Fixture");
		writeFileSync(join(root, ".gitignore"), "ignored/\n");
		writeFileSync(join(root, ".gitleaks.toml"), "title = \"fixture\"\n");
		writeFileSync(join(root, "tracked.txt"), "tracked\n");
		git(root, "add", ".gitignore", ".gitleaks.toml", "tracked.txt");
		git(root, "commit", "-qm", "fixture");
		writeFileSync(join(root, "untracked.txt"), "untracked\n");
		mkdirSync(join(root, "ignored"));
		writeFileSync(join(root, "ignored", "artifact.txt"), "ignored\n");

		const nested = join(root, "nested");
		mkdirSync(nested);
		git(nested, "init", "-q");
		git(nested, "config", "user.email", "fixture@example.invalid");
		git(nested, "config", "user.name", "Fixture");
		writeFileSync(join(nested, "source.txt"), "nested\n");
		git(nested, "add", "source.txt");
		git(nested, "commit", "-qm", "nested");
		git(root, "add", "nested");

		const staged = stageCurrentCheckout(root, destination).sort();
		assert.deepEqual(staged, [
			".gitignore",
			".gitleaks.toml",
			"tracked.txt",
			"untracked.txt",
		]);
		assert.equal(existsSync(join(destination, "ignored", "artifact.txt")), false);
		assert.equal(existsSync(join(destination, "nested", "source.txt")), false);
	} finally {
		rmSync(root, { recursive: true, force: true });
		rmSync(destination, { recursive: true, force: true });
	}
});

test("rejects a scanner that silently passes the synthetic credential canary", () => {
	assert.throws(
		() => verifyGitleaksCanary("stub-gitleaks", new URL("../.gitleaks.toml", import.meta.url), () => ({ status: 0 })),
		/scanner did not reject its synthetic credential canary/,
	);
});

test("accepts only the expected default-rule canary finding", () => {
	const fakeScanner = (_executable, args) => {
		const reportIndex = args.indexOf("--report-path");
		writeFileSync(args[reportIndex + 1], JSON.stringify([{ RuleID: "github-pat", File: "canary.txt" }]));
		return { status: 1 };
	};
	assert.equal(
		verifyGitleaksCanary("stub-gitleaks", new URL("../.gitleaks.toml", import.meta.url), fakeScanner),
		undefined,
	);
});

test("rejects unrelated findings as a canary false negative", () => {
	const fakeScanner = (_executable, args) => {
		const reportIndex = args.indexOf("--report-path");
		writeFileSync(args[reportIndex + 1], JSON.stringify([{ RuleID: "generic-api-key", File: "canary.txt" }]));
		return { status: 1 };
	};
	assert.throws(
		() => verifyGitleaksCanary("stub-gitleaks", new URL("../.gitleaks.toml", import.meta.url), fakeScanner),
		/scanner did not report the expected canary rule/,
	);
});

test("scans clean and finding reports while redacting secret fields", () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-current-scan-regression-"));
	try {
		assert.equal(
			existsSync(new URL("../.gitleaksignore", import.meta.url)),
			false,
			"mutable path/rule/line ignores must not be reintroduced",
		);
		git(root, "init", "-q");
		git(root, "config", "user.email", "fixture@example.invalid");
		git(root, "config", "user.name", "Fixture");
		writeFileSync(
			join(root, ".gitleaks.toml"),
			readFileSync(new URL("../.gitleaks.toml", import.meta.url)),
		);
		mkdirSync(join(root, "fixtures"));
		const fixture = join(root, "fixtures", "credential.txt");
		const lines = ["one", "two", "three", "four", "five", "six", "clean"];
		writeFileSync(fixture, `${lines.join("\n")}\n`);
		git(root, "add", ".gitleaks.toml", "fixtures/credential.txt");
		git(root, "commit", "-qm", "fixture");

		const runScan = (finding) => {
			const staging = mkdtempSync(join(tmpdir(), "aidr-current-scan-stub-"));
			const files = stageCurrentCheckout(root, staging);
			const output = [];
			const sensitiveValue = "SYNTHETIC-SENTINEL-NEVER-LOG";
			const run = (_executable, args) => {
				const reportPath = args[args.indexOf("--report-path") + 1];
				if (reportPath.endsWith("canary-report.json")) {
					writeFileSync(reportPath, JSON.stringify([{ RuleID: "github-pat", File: "canary.txt" }]));
					return { status: 1 };
				}
				if (!finding) return { status: 0 };
				writeFileSync(
					reportPath,
					JSON.stringify([{
						RuleID: "fixture-rule",
						File: "fixtures/credential.txt",
						StartLine: 7,
						Commit: "",
						Secret: sensitiveValue,
						Match: sensitiveValue,
					}]),
				);
				return { status: 1 };
			};
			try {
				const status = scanStagedCheckout({
					staging,
					files,
					gitleaks: "stub-gitleaks",
					version: "8.30.1",
					run,
					log: { log: (message) => output.push(message), error: (message) => output.push(message) },
				});
				return { status, output: output.join("\n"), sensitiveValue };
			} finally {
				rmSync(staging, { recursive: true, force: true });
			}
		};

		const clean = runScan(false);
		assert.equal(clean.status, 0);
		assert.match(clean.output, /Current-checkout secret scan passed/);

		const finding = runScan(true);
		assert.equal(finding.status, 1);
		assert.match(finding.output, /fixtures\/credential\.txt/);
		assert.match(finding.output, /fixture-rule/);
		assert.match(finding.output, /"line":7/);
		assert.ok(!finding.output.includes(finding.sensitiveValue));
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
