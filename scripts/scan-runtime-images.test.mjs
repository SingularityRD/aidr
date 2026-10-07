import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildSummary, compactFindings, compareImages, countFindings } from "./scan-runtime-images.mjs";

const script = join(import.meta.dirname, "scan-runtime-images.mjs");
const vuln = (id, severity, pkg, fixed = "") => ({ VulnerabilityID: id, Severity: severity, PkgName: pkg, InstalledVersion: "1.0.0", FixedVersion: fixed, Status: fixed ? "fixed" : "affected" });
const fixtureReport = {
	Metadata: { OS: { Family: "debian", Name: "12.15" } },
	Results: [
		{ Target: "img (debian 12.15)", Type: "debian", Vulnerabilities: [vuln("CVE-2026-0001", "CRITICAL", "openssl", "3.0.18"), vuln("CVE-2026-0002", "HIGH", "zlib"), vuln("CVE-2026-0009", "MEDIUM", "bash", "5.2")] },
		{ Target: "app/package-lock.json", Type: "npm", Vulnerabilities: [vuln("CVE-2026-0002", "HIGH", "zlib-js", "2.0.0"), vuln("GHSA-aaaa-bbbb-cccc", "HIGH", "lodash", "4.17.22")] },
		{ Target: "usr/bin/tool", Type: "gobinary" },
	],
};

test("compactFindings keeps only HIGH/CRITICAL with compact fields, CRITICAL first", () => {
	const findings = compactFindings(fixtureReport);
	assert.equal(findings.length, 4);
	assert.deepEqual(findings[0], { id: "CVE-2026-0001", severity: "CRITICAL", pkg: "openssl", installed: "1.0.0", fixed: "3.0.18", status: "fixed", target: "img (debian 12.15)", type: "debian" });
	assert.equal(findings.some((f) => f.severity === "MEDIUM"), false);
	assert.equal(findings.find((f) => f.pkg === "zlib").fixed, null);
	assert.deepEqual(compactFindings({}), []);
});

test("countFindings separates occurrences, unique ids and fixed-available", () => {
	const counts = countFindings(compactFindings(fixtureReport));
	assert.deepEqual(counts.CRITICAL, { findings: 1, unique_ids: 1, fixed_available: 1, fixed_available_unique_ids: 1 });
	assert.deepEqual(counts.HIGH, { findings: 3, unique_ids: 2, fixed_available: 2, fixed_available_unique_ids: 2 });
	assert.equal(counts.total_findings, 4);
});

const record = (name, service, role, report) => {
	const findings = compactFindings(report);
	return { name, service, role, ref: `x/${service}:${role}@sha256:${"a".repeat(64)}`, succeeded: true, findings, counts: countFindings(findings) };
};

test("compareImages requires a strict reduction and no new CRITICAL id", () => {
	const current = record("s-current", "s", "current", fixtureReport);
	const fewer = record("s-candidate", "s", "candidate", { Results: [{ Target: "t", Vulnerabilities: [vuln("CVE-2026-0001", "CRITICAL", "openssl")] }] });
	assert.equal(compareImages(current, fewer).eligible, true);
	assert.equal(compareImages(current, fewer).delta_critical_high, -3);
	const newCritical = record("s-candidate", "s", "candidate", { Results: [{ Target: "t", Vulnerabilities: [vuln("CVE-2026-7777", "CRITICAL", "glibc")] }] });
	assert.deepEqual(compareImages(current, newCritical), { eligible: false, delta_critical_high: -3, new_critical_ids: ["CVE-2026-7777"], reason: "introduces new CRITICAL: CVE-2026-7777" });
	assert.equal(compareImages(current, current).eligible, false);
	assert.equal(compareImages(current, { succeeded: false }).eligible, false);
});

test("buildSummary aggregates totals, strips findings and never marks failures complete", () => {
	const current = record("s-current", "s", "current", fixtureReport);
	const candidate = record("s-candidate", "s", "candidate", { Results: [] });
	const failed = { name: "t-current", service: "t", role: "current", ref: "r", succeeded: false, failure: "boom" };
	const summary = buildSummary({ scanner: { version: "0.0.0" }, platform: "linux/amd64", startedAt: "a", finishedAt: "b", images: [current, candidate, failed] });
	assert.equal(summary.completed, false);
	assert.deepEqual(summary.totals, { current: { images: 1, CRITICAL: 1, HIGH: 3 }, candidate: { images: 1, CRITICAL: 0, HIGH: 0 } });
	assert.equal(summary.images.some((i) => "findings" in i), false);
	assert.equal(summary.comparisons.length, 1);
	assert.equal(summary.comparisons[0].eligible, true);
	assert.equal(buildSummary({ scanner: {}, platform: "p", startedAt: "a", finishedAt: "b", images: [current] }).completed, true);
});

test("scan rejects plans whose refs are not digest-pinned", () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-scan-test-"));
	try {
		const plan = join(directory, "plan.json");
		writeFileSync(plan, JSON.stringify({ images: [{ name: "x-current", service: "x", role: "current", ref: "supabase/realtime:v2.142.0" }] }));
		const result = spawnSync(process.execPath, [script, "scan", "--plan", plan, "--output", join(directory, "out"), "--engine", "trivy"], { encoding: "utf8" });
		assert.equal(result.status, 2);
		assert.match(result.stderr, /must be repo:tag@sha256/);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
});
