import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
	existsSync,
	mkdtempSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

const nativeGitleaks = process.env.GITLEAKS_BIN || "gitleaks";
const nativeVersion = spawnSync(nativeGitleaks, ["version"], { encoding: "utf8" });
const nativeOptions = {
	skip: nativeVersion.error?.code === "ENOENT" ? "native Gitleaks is not installed" : false,
};
const publicEvidence = [
	{
		path: "docs/production-readiness/evidence/bridge-high-zero-archive-audit-2026-10-06.json",
		property: "app/auth.py",
		value: "07fdde3dfb5a30988c02af5d9e97b369cf446ea250e56c532103e7106bdaa9b2",
	},
	{
		path: "docs/production-readiness/evidence/bridge-high-zero-security-2026-10-06.json",
		property: "app/auth.py",
		value: "07fdde3dfb5a30988c02af5d9e97b369cf446ea250e56c532103e7106bdaa9b2",
	},
	{
		path: "docs/production-readiness/evidence/bridge-high-zero-full-image-scan-2026-10-06.json",
		property: "GPG_KEY",
		value: "7169605F62C751356D054A26A821E680E5FA6305",
	},
	{
		path: "packages/privacy/docs/MODEL_CANDIDATE_EVIDENCE.json",
		property: "tokenizer_sha256",
		value: "0614fe83cadab421296e664e1f48f4261fa8fef6e03e63bb75c20f38e37d07d3",
	},
	{
		path: "packages/privacy/docs/MODEL_QUALITY_DIAGNOSTICS.json",
		property: "packages/privacy/reports/platform/t38-alternative-models/en-deberta/tokenizer.json",
		value: "fa3cbe7ce1be7311df6b43a5a5cca547a2e86ce6c604b0505638ff054dfbe952",
		additional: [
			["packages/privacy/reports/platform/t38-alternative-models/en-deberta/tokenizer_config.json",
				"2d4cb82493b36f48593a41fbcbd4a37c87e7dcf49d15a328d919847c5aced76c"],
			[".tmp-test/model-quality-2026-10-06/privacy/compare-tokenizer-contract.py",
				"f448983f72e61fb95a735228343ea5cb5112010de2b386f89f91c60898ac51bb"],
		],
	},
];

function scanNativeFixture(root, config, name) {
	assert.equal(nativeVersion.status, 0, "native scanner version command must succeed");
	assert.equal(nativeVersion.stdout.trim(), "8.30.1", "native scanner must use the pinned version");
	if (process.platform === "win32" && process.arch === "x64") {
		assert.equal(
			createHash("sha256").update(readFileSync(nativeGitleaks)).digest("hex"),
			"17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c",
			"native scanner must be the verified official Windows executable",
		);
	}
	const report = join(root, `${name}.json`);
	const result = spawnSync(nativeGitleaks, [
		"dir", ".", "--config", config, "--redact", "--report-format", "json", "--report-path", report,
	], { cwd: join(root, "scan"), encoding: "utf8", stdio: ["ignore", "ignore", "ignore"] });
	assert.ifError(result.error);
	return { status: result.status, findings: JSON.parse(readFileSync(report, "utf8")) };
}

for (const evidence of publicEvidence) {
	test(`native scanner preserves credential detection in ${evidence.path}`, nativeOptions, () => {
		const root = mkdtempSync(join(tmpdir(), "aidr-public-evidence-scan-"));
		try {
			const target = join(root, "scan", evidence.path);
			mkdirSync(dirname(target), { recursive: true });
			const defaultConfig = join(root, "default.toml");
			const projectConfig = join(root, "project.toml");
			writeFileSync(defaultConfig, "[extend]\nuseDefault = true\n");
			writeFileSync(projectConfig, readFileSync(new URL("../.gitleaks.toml", import.meta.url)));
			const original = JSON.stringify(Object.fromEntries([
				[evidence.property, evidence.value], ...(evidence.additional ?? []),
			]));
			writeFileSync(target, original);
			const baseline = scanNativeFixture(root, defaultConfig, "baseline");
			assert.equal(baseline.status, 1, "default scanner must reproduce the public-value false positive");
			assert.equal(baseline.findings.filter((finding) => finding.RuleID === "generic-api-key").length,
				1 + (evidence.additional?.length ?? 0));
			const publicOnly = scanNativeFixture(root, projectConfig, "public-only");
			assert.equal(publicOnly.status, 0, "the exact verified public value must pass");
			assert.deepEqual(publicOnly.findings, []);

			writeFileSync(target, `${original}\napi_key = "${randomBytes(32).toString("hex")}"\n`);
			const credential = scanNativeFixture(root, projectConfig, "credential");
			assert.equal(credential.status, 1, "an actual random credential in the same file must fail");
			assert.ok(credential.findings.some((finding) =>
				finding.RuleID === "generic-api-key" && finding.File === evidence.path));

			writeFileSync(target, JSON.stringify({ [evidence.property]: randomBytes(32).toString("hex") }));
			const changedValue = scanNativeFixture(root, projectConfig, "changed-value");
			assert.equal(changedValue.status, 1, "a different value at the allowed property must fail");
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});
}

test("native scanner rejects the same public values outside their exact evidence paths", nativeOptions, () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-public-evidence-boundary-"));
	try {
		mkdirSync(join(root, "scan"));
		const projectConfig = join(root, "project.toml");
		writeFileSync(projectConfig, readFileSync(new URL("../.gitleaks.toml", import.meta.url)));
		verifyGitleaksCanary(nativeGitleaks, projectConfig);
		for (const [index, evidence] of publicEvidence.entries()) {
			writeFileSync(join(root, "scan", `unrelated-${index}.json`),
				JSON.stringify(Object.fromEntries([
					[evidence.property, evidence.value], ...(evidence.additional ?? []),
				])));
		}
		const result = scanNativeFixture(root, projectConfig, "outside-paths");
		assert.equal(result.status, 1);
		assert.equal(result.findings.filter((finding) => finding.RuleID === "generic-api-key").length,
			publicEvidence.reduce((count, evidence) => count + 1 + (evidence.additional?.length ?? 0), 0));
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
