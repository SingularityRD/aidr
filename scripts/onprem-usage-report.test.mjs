import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { publicKeyEntry, signLicense } from "./license-issue.mjs";
import { canonicalJson, parsePublicKeyRegistry, verifyLicense } from "./license-verify.mjs";
import { buildUsageReport, licenseStateAt, USAGE_REPORT_FORMAT, verifyUsageReport } from "./onprem-usage-report.mjs";

const script = resolve(dirname(fileURLToPath(import.meta.url)), "onprem-usage-report.mjs");
const NOW = Date.parse("2027-03-01T12:00:00Z");
const appliedLicense = {
	license_id: "LIC-2026-0042",
	customer_id: "example-ag",
	not_before: "2026-09-01T00:00:00+00:00",
	expires_at: "2027-09-01T00:00:00+00:00",
	grace_ends_at: "2027-09-15T00:00:00+00:00",
};
const facts = (overrides = {}) => ({
	seats_licensed: 250,
	devices_enrolled: 180,
	devices_active_30d: 150,
	license: appliedLicense,
	admission: { kind: "licensed", seats: 250, reference: "LIC-2026-0042" },
	...overrides,
});

test("the report carries exactly the contract fields and a digest of the canonical JSON", () => {
	const report = buildUsageReport(facts(), { now: NOW, deploymentVersion: "0.6.0+abc123" });
	assert.deepEqual(Object.keys(report), [
		"format", "customer_id", "license_id", "generated_at", "seats_licensed", "devices_enrolled",
		"devices_active_30d", "license_state", "updates_until", "deployment_version", "report_sha256",
	]);
	assert.equal(report.format, USAGE_REPORT_FORMAT);
	assert.equal(report.customer_id, "example-ag");
	assert.equal(report.license_state, "valid");
	assert.equal(report.updates_until, "2027-09-15T00:00:00.000Z");
	assert.equal(report.generated_at, "2027-03-01T12:00:00.000Z");
	const { report_sha256: digest, ...fields } = report;
	assert.equal(digest, createHash("sha256").update(canonicalJson(fields)).digest("hex"));
	assert.deepEqual(verifyUsageReport(report), []);
});

test("any edit after generation is detected (customer-attested, not signed)", () => {
	const report = buildUsageReport(facts(), { now: NOW, deploymentVersion: "0.6.0" });
	assert.match(verifyUsageReport({ ...report, devices_enrolled: 10 }).join(" "), /report_sha256 does not match/);
	assert.match(verifyUsageReport({ ...report, extra: 1 }).join(" "), /fields must be exactly/);
	assert.match(verifyUsageReport({ ...report, license_state: "great" }).join(" "), /license_state/);
});

test("license state follows the reporting clock and the source of the terms", () => {
	assert.equal(licenseStateAt(appliedLicense, Date.parse("2026-08-01T00:00:00Z")), "not_yet_valid");
	assert.equal(licenseStateAt(appliedLicense, Date.parse("2027-09-05T00:00:00Z")), "grace");
	assert.equal(licenseStateAt(appliedLicense, Date.parse("2027-10-01T00:00:00Z")), "expired");
	const unverified = buildUsageReport(facts({ license: null }), { now: NOW, deploymentVersion: "0.6.0" });
	assert.equal(unverified.license_state, "unverified");
	assert.equal(unverified.license_id, "LIC-2026-0042");
	assert.equal(unverified.updates_until, null);
	const unlicensed = buildUsageReport(facts({ license: null, admission: null, seats_licensed: 0 }), { now: NOW, deploymentVersion: "0.6.0" });
	assert.equal(unlicensed.license_state, "unlicensed");
	assert.throws(() => buildUsageReport(facts({ devices_enrolled: -1 }), { now: NOW, deploymentVersion: "0.6.0" }), /devices_enrolled/);
	assert.throws(() => buildUsageReport(facts(), { now: NOW, deploymentVersion: "" }), /deployment_version/);
});

test("a locally verified license file wins over the stored terms", () => {
	// DEV test key only, generated in memory.
	const key = generateKeyPairSync("ed25519").privateKey;
	const license = signLicense({
		license_id: "LIC-2027-0007", customer: "Example Customer AG", customer_id: "example-ag", plan_id: "enterprise",
		seats: 300, features: [], deployment: "airgap", issued_at: "2027-01-01T00:00:00Z",
		not_before: "2027-01-01T00:00:00Z", expires_at: "2028-01-01T00:00:00Z", grace_days: 30,
	}, { privateKey: key, keyId: "dev-1" });
	const publicKeys = parsePublicKeyRegistry({ format: "aidr-license-public-keys-v1", schema_version: 1,
		keys: [publicKeyEntry(key, { keyId: "dev-1", notBefore: "2026-01-01T00:00:00Z" })] });
	const verifiedLicense = verifyLicense(license, { publicKeys, now: NOW });
	const report = buildUsageReport(facts(), { verifiedLicense, now: NOW, deploymentVersion: "0.6.0" });
	assert.equal(report.license_id, "LIC-2027-0007");
	assert.equal(report.updates_until, "2028-01-31T00:00:00.000Z");
});

test("the CLI reads facts with the deployment's service credential, writes a private report and verifies it", async (t) => {
	const dir = mkdtempSync(join(tmpdir(), "aidr-usage-report-"));
	const calls = [];
	const server = createServer(async (req, res) => {
		let text = "";
		for await (const chunk of req) text += chunk;
		calls.push({ url: req.url, auth: req.headers.authorization, body: text ? JSON.parse(text) : null });
		res.writeHead(req.url === "/rest/v1/rpc/usage_report_facts" ? 200 : 404, { "Content-Type": "application/json" });
		res.end(JSON.stringify(req.url === "/rest/v1/rpc/usage_report_facts" ? facts() : { message: "nope" }));
	});
	await new Promise((done) => server.listen(0, "127.0.0.1", done));
	t.after(async () => {
		await new Promise((done) => server.close(done));
		rmSync(dir, { recursive: true, force: true });
	});
	writeFileSync(join(dir, "deployment.json"), JSON.stringify({ development: true,
		supabase_url: `http://127.0.0.1:${server.address().port}`, source_commit: "0123456789abcdef0123" }));
	writeFileSync(join(dir, ".env"), "SERVICE_ROLE_KEY=private-fixture-key\n");
	const run = (args) => new Promise((done) => {
		const child = spawn(process.execPath, [script, ...args], { stdio: ["ignore", "pipe", "pipe"], timeout: 20_000 });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => { stdout += chunk; });
		child.stderr.on("data", (chunk) => { stderr += chunk; });
		child.on("close", (code) => done({ code, stdout, stderr }));
	});
	const result = await run([dir]);
	assert.equal(result.code, 0, result.stderr);
	assert.match(result.stderr, /customer-attested/);
	assert.equal(calls.length, 1);
	assert.equal(calls[0].auth, "Bearer private-fixture-key");
	assert.deepEqual(calls[0].body, { p_tenant_id: null });
	const file = readdirSync(dir).find((name) => name.startsWith("aidr-usage-report-"));
	assert.ok(file, "report file written");
	const report = JSON.parse(readFileSync(join(dir, file), "utf8"));
	assert.equal(report.devices_enrolled, 180);
	assert.match(report.deployment_version, /^\d+\.\d+\.\d+\+0123456789ab$/);
	assert.equal(result.stdout.includes("private-fixture-key"), false, "credential printed");
	assert.equal((await run(["--verify", join(dir, file)])).code, 0);
	writeFileSync(join(dir, file), JSON.stringify({ ...report, devices_enrolled: 1 }));
	const tampered = await run(["--verify", join(dir, file)]);
	assert.equal(tampered.code, 1);
	assert.match(tampered.stderr, /report_sha256 does not match/);
	assert.equal((await run([dir, "--tenant", "not-a-uuid"])).code, 1);
});
