import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildPack, exactHostOfPattern, exportRelease, PackReleaseError, verifyRelease } from "./intel-pack-release.mjs";
import { canonicalJson } from "./license-verify.mjs";

const releaseScript = fileURLToPath(new URL("./intel-pack-release.mjs", import.meta.url));
const signScript = fileURLToPath(new URL("./sign-intel-pack-manifest.mjs", import.meta.url));
const keysScript = fileURLToPath(new URL("./intel-pack-keys.mjs", import.meta.url));
const importScript = fileURLToPath(new URL("./import-offline-pack.mjs", import.meta.url));
const revocationsScript = fileURLToPath(new URL("./license-revocations-issue.mjs", import.meta.url));

// DEV keys generated per run; never persisted outside the temp directory.
const publisher = generateKeyPairSync("ed25519");
const licenseSigner = generateKeyPairSync("ed25519");
const ISSUED_AT = "2026-10-12T05:47:00Z";
const DAY = 24 * 60 * 60 * 1000;
const iso = (ms) => new Date(ms).toISOString().replace(".000Z", "Z");

function workdir(t) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-intel-release-test-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	return directory;
}

/** A threats dir with one exact-host block rule, plus rules that must not become intel. */
function threatsDir(root) {
	const dir = join(root, "threats");
	mkdirSync(dir);
	const rule = (id, pattern, extra = "") => `- id: "${id}"\n  category: network_egress\n  severity: critical\n  confidence: 0.9\n  action: block\n  pattern: "${pattern}"\n  match_on: url\n  title: "t"\n  expires_at: null\n  revoked: false\n${extra}`;
	writeFileSync(
		join(dir, "urls.yaml"),
		[
			rule("T-URL-1", "^https?://drop\\\\.release-test\\\\.example(?:/|$)"),
			rule("T-URL-2", "paste\\\\.release-test\\\\.example/raw/"),
			rule("T-URL-3", "old\\\\.release-test\\\\.example").replace("revoked: false", "revoked: true"),
			rule("T-URL-4", "ask\\\\.release-test\\\\.example").replace("action: block", "action: require_approval"),
		].join("\n"),
	);
	return dir;
}

function intelDir(root, files = {}) {
	const dir = join(root, "intel");
	mkdirSync(dir);
	const defaults = {
		"url_denylist.txt": "# curated\nhttps://exfil.release-test.example/upload\nc2.release-test.example\n",
		"package_hash_denylist.txt": `${"ab".repeat(32)}\n`,
		"domain_risk.json": JSON.stringify([{ domain: "risky.release-test.example", action: "ask", severity: "high", reason: "test" }]),
	};
	for (const [name, content] of Object.entries({ ...defaults, ...files })) if (content !== null) writeFileSync(join(dir, name), content);
	return dir;
}

function writeKey(root, name, key) {
	const path = join(root, name);
	writeFileSync(path, key.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
	return path;
}

function trustedKeys(root) {
	const path = join(root, "trusted-keys.json");
	writeFileSync(path, JSON.stringify({ "aidr-intel-test-1": publisher.publicKey.export({ type: "spki", format: "pem" }).toString() }));
	return path;
}

function run(script, args, env = {}) {
	const result = spawnSync(process.execPath, [script, ...args], { encoding: "utf8", env: { ...process.env, ...env } });
	let json = null;
	try {
		json = JSON.parse(result.stdout.trim().split("\n").at(-1));
	} catch {}
	return { ...result, json };
}

async function signedPack(root, { audience = ["example-co"], encrypt = false, version = "2026.1012.1", name = "pack" } = {}) {
	const out = join(root, name);
	const source = join(root, `${name}-src`);
	mkdirSync(source);
	const built = await buildPack({ out, packId: "aidr-intel", version, keyId: "aidr-intel-test-1", threatsDir: threatsDir(source), intelDir: intelDir(source), audience, issuedAt: ISSUED_AT, expiresInDays: 45 });
	assert.equal(built.outcome, "built");
	let sharedKeyFile;
	if (encrypt) {
		sharedKeyFile = join(root, `${name}-shared.key`);
		assert.equal(run(keysScript, ["new-shared-key", "--label", "release-test", "--out", sharedKeyFile]).status, 0);
		const encrypted = run(keysScript, ["encrypt-pack", "--pack", out, "--shared-key-file", sharedKeyFile]);
		assert.equal(encrypted.status, 0, encrypted.stderr);
	}
	const signed = run(signScript, ["--manifest", join(out, "manifest.json"), "--private-key", writeKey(root, `${name}-publisher.pem`, publisher.privateKey), "--audience", audience.length ? audience.join(",") : "none"]);
	assert.equal(signed.status, 0, signed.stderr);
	return { dir: out, manifest: built.manifest, sharedKeyFile };
}

/** A DEV license around the pack's issued_at, signed per run, plus the registry that trusts it. */
function licenseFiles(root, { name, licenseId, customerId = "example-co", from, to }) {
	const payload = { license_id: licenseId, customer: "Example Customer", customer_id: customerId, plan_id: "enterprise", seats: 10, features: ["premium_intel"], deployment: "airgap", issued_at: iso(from), not_before: iso(from), expires_at: iso(to), grace_days: 14 };
	const license = { format: "aidr-license-v1", key_id: "aidr-license-dev-1", payload, sig: sign(null, Buffer.from(`aidr-license-v1\n${canonicalJson(payload)}`, "utf8"), licenseSigner.privateKey).toString("base64") };
	const path = join(root, `${name}.json`);
	writeFileSync(path, JSON.stringify(license));
	return path;
}

function licenseRegistry(root) {
	const path = join(root, "license-public-keys.json");
	writeFileSync(path, JSON.stringify({ format: "aidr-license-public-keys-v1", schema_version: 1, keys: [{ key_id: "aidr-license-dev-1", algorithm: "ed25519", public_key_pem: licenseSigner.publicKey.export({ type: "spki", format: "pem" }).toString(), not_before: "2025-01-01T00:00:00Z", not_after: null, status: "active" }] }));
	return path;
}

test("exactHostOfPattern only accepts patterns that are an escaped host literal", () => {
	assert.equal(exactHostOfPattern("^https?://drop\\.release-test\\.example(?:/|$)"), "drop.release-test.example");
	assert.equal(exactHostOfPattern("Evil\\.Example\\.COM$"), "evil.example.com");
	for (const pattern of ["paste\\.ee/r/", "evil.example.com", "raw\\.githubusercontent\\.com/.*/malware", "https?://\\d{1,3}\\.\\d{1,3}", "a|b\\.com", 42]) {
		assert.equal(exactHostOfPattern(pattern), null, String(pattern));
	}
});

test("build -> encrypt -> sign -> verify -> export -> import: license term, audience and revocation are enforced", async (t) => {
	const root = workdir(t);
	const { dir, manifest, sharedKeyFile } = await signedPack(root, { encrypt: true });
	assert.deepEqual(manifest.audience, { customer_ids: ["example-co"] });
	assert.deepEqual(manifest.source.derived_rule_ids, ["T-URL-1"], "only the exact-host block rule becomes intel");
	assert.deepEqual(manifest.source.entries, { url_denylist: 3, domain_risk: 1, package_hash_denylist: 1 });

	const registry = licenseRegistry(root);
	const issued = Date.parse(ISSUED_AT);
	const revocations = join(root, "license-revocations.json");
	const issuedList = run(revocationsScript, ["--key-id", "aidr-license-dev-1", "--sequence", "4", "--license-id", "LIC-REVOKED", "--issued-at", ISSUED_AT, "--public-keys", registry, "--out", revocations], { AIDR_LICENSE_SIGNING_KEY: licenseSigner.privateKey.export({ type: "pkcs8", format: "pem" }).toString() });
	assert.equal(issuedList.status, 0, issuedList.stderr);

	const report = await verifyRelease({ packDir: dir, trustedKeysPath: trustedKeys(root), sharedKeyFile, licensePublicKeysPath: registry, revocationsPath: revocations, now: issued });
	assert.equal(report.outcome, "verified");
	assert.equal(report.encrypted_files, 3);
	assert.deepEqual(report.loader.entries, { url_denylist: 3, url_allowlist: 0, domain_risk: 1, package_name_denylist: 0, package_hash_denylist: 1, plugin_signature_denylist: 0 });
	assert.equal(report.loader.tampered_copy, "refused");
	assert.deepEqual(report.acceptance, { in_term: "accepted", out_of_term: "license_term_ended", other_customer: "pack_audience_mismatch", revoked_license: "license_revoked" });
	assert.deepEqual(report.license_revocations, { sequence: 4, issued_at: ISSUED_AT, revoked_licenses: 1 });

	const offline = join(root, "offline");
	const exported = await exportRelease({ packDir: dir, trustedKeysPath: trustedKeys(root), out: offline, revocationsPath: revocations, licensePublicKeysPath: registry, now: issued });
	assert.deepEqual(exported.files, ["IMPORT.txt", "SHA256SUMS", "aidr-intel-2026.1012.1.aidrpack.json", "intel-trusted-keys.json", "license-revocations.json"]);
	assert.match(readFileSync(join(offline, "SHA256SUMS"), "utf8"), /[0-9a-f]{64} {2}aidr-intel-2026\.1012\.1\.aidrpack\.json/);
	assert.match(readFileSync(join(offline, "IMPORT.txt"), "utf8"), /TR {2}Önce dosyaları doğrulayın/);

	// The customer side: the existing offline importer, against real license files.
	const bundle = join(offline, exported.bundle);
	const home = join(root, "home");
	mkdirSync(home);
	const importAs = (license, extra = [], packsDir = join(root, `packs-${Math.random().toString(16).slice(2)}`)) =>
		run(importScript, ["--pack", bundle, "--trusted-keys", join(offline, "intel-trusted-keys.json"), "--target", "local", "--packs-dir", packsDir, "--license", license, "--license-public-keys", registry, ...extra], { HOME: home });
	const inTerm = licenseFiles(root, { name: "in-term", licenseId: "LIC-OK", from: issued - 100 * DAY, to: issued + 200 * DAY });
	const outOfTerm = licenseFiles(root, { name: "out-of-term", licenseId: "LIC-OLD", from: issued - 400 * DAY, to: issued - 20 * DAY });
	const otherCustomer = licenseFiles(root, { name: "other", licenseId: "LIC-OTHER", customerId: "other-co", from: issued - 100 * DAY, to: issued + 200 * DAY });
	const revoked = licenseFiles(root, { name: "revoked", licenseId: "LIC-REVOKED", from: issued - 100 * DAY, to: issued + 200 * DAY });

	const accepted = importAs(inTerm, ["--license-revocations", join(offline, "license-revocations.json")]);
	assert.equal(accepted.status, 0, accepted.stderr);
	assert.equal(accepted.json.outcome, "installed");
	assert.deepEqual(accepted.json.license_revocations, { sequence: 4, issued_at: ISSUED_AT });
	assert.match(importAs(outOfTerm).stderr, /license_term_ended/);
	assert.match(importAs(otherCustomer).stderr, /pack_audience_mismatch/);
	// The list stored by the first import keeps binding later imports without --license-revocations.
	assert.ok(existsSync(join(home, ".singularity-aidr", "license-revocations.json")));
	const refused = importAs(revoked);
	assert.equal(refused.status, 1);
	assert.match(refused.stderr, /license_revoked: .*LIC-REVOKED is revoked.*Installed rules keep enforcing/);
});

test("an older revocation list cannot replace a newer stored one, and a forged list refuses the import", async (t) => {
	const root = workdir(t);
	const { dir } = await signedPack(root, { audience: [] });
	const registry = licenseRegistry(root);
	const issued = Date.parse(ISSUED_AT);
	const env = { AIDR_LICENSE_SIGNING_KEY: licenseSigner.privateKey.export({ type: "pkcs8", format: "pem" }).toString() };
	const list = (name, sequence, ids) => {
		const path = join(root, `${name}.json`);
		const result = run(revocationsScript, ["--key-id", "aidr-license-dev-1", "--sequence", String(sequence), ...ids.flatMap((id) => ["--license-id", id]), "--issued-at", ISSUED_AT, "--out", path], env);
		assert.equal(result.status, 0, result.stderr);
		return path;
	};
	const newer = list("newer", 7, ["LIC-A"]);
	const older = list("older", 6, []);
	const home = join(root, "home");
	mkdirSync(home);
	const license = licenseFiles(root, { name: "a", licenseId: "LIC-A", from: issued - 100 * DAY, to: issued + 200 * DAY });
	const importWith = (extra) => run(importScript, ["--pack", dir, "--trusted-keys", trustedKeys(root), "--target", "local", "--packs-dir", join(root, "packs"), "--license", license, "--license-public-keys", registry, ...extra], { HOME: home });
	assert.match(importWith(["--license-revocations", newer]).stderr, /license_revoked/);
	assert.match(importWith(["--license-revocations", older]).stderr, /license_revoked/, "sequence 6 must not un-revoke sequence 7");

	const forged = JSON.parse(readFileSync(newer, "utf8"));
	forged.payload.license_ids = [];
	forged.payload.sequence = 99;
	const forgedPath = join(root, "forged.json");
	writeFileSync(forgedPath, JSON.stringify(forged));
	assert.match(importWith(["--license-revocations", forgedPath]).stderr, /revocation list .* is not valid: .*does not verify/);
});

test("verify refuses a pack the loader would not load as declared, or signed by another key", async (t) => {
	const root = workdir(t);
	const out = join(root, "pack");
	const built = await buildPack({ out, packId: "aidr-intel", version: "2026.1012.2", keyId: "aidr-intel-test-1", threatsDir: threatsDir(root), intelDir: intelDir(root), issuedAt: ISSUED_AT, expiresInDays: 30 });
	// Declare more entries than the files carry, then sign: the loader cross-check must catch it.
	const manifest = { ...built.manifest, source: { ...built.manifest.source, entries: { ...built.manifest.source.entries, url_denylist: 99 } } };
	writeFileSync(join(out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	assert.equal(run(signScript, ["--manifest", join(out, "manifest.json"), "--private-key", writeKey(root, "p.pem", publisher.privateKey)]).status, 0);
	await assert.rejects(verifyRelease({ packDir: out, trustedKeysPath: trustedKeys(root), now: Date.parse(ISSUED_AT) }), /loaded 3 url_denylist entries, the signed manifest declares 99/);

	const strangerOut = join(root, "stranger");
	await buildPack({ out: strangerOut, packId: "aidr-intel", version: "2026.1012.3", keyId: "aidr-intel-test-1", threatsDir: join(root, "threats"), intelDir: join(root, "intel"), issuedAt: ISSUED_AT });
	assert.equal(run(signScript, ["--manifest", join(strangerOut, "manifest.json"), "--private-key", writeKey(root, "s.pem", generateKeyPairSync("ed25519").privateKey)]).status, 0);
	await assert.rejects(verifyRelease({ packDir: strangerOut, trustedKeysPath: trustedKeys(root), now: Date.parse(ISSUED_AT) }), /signature does not verify/);
});

test("build refuses unknown or invalid intel data, conflicting lists, an existing output and an empty pack", async (t) => {
	const root = workdir(t);
	const threats = threatsDir(root);
	const base = { packId: "aidr-intel", version: "1.0.0", keyId: "k1", threatsDir: threats, issuedAt: ISSUED_AT };
	const attempt = async (name, files) => {
		const dir = join(root, `intel-${name}`);
		mkdirSync(dir);
		for (const [file, content] of Object.entries(files)) writeFileSync(join(dir, file), content);
		return buildPack({ ...base, out: join(root, `out-${name}`), intelDir: dir });
	};
	await assert.rejects(attempt("unknown", { "rules.yaml": "x" }), /unknown file rules\.yaml/);
	await assert.rejects(attempt("host", { "url_denylist.txt": "not a host!\n" }), /line 1: "not a host!" is not a host name/);
	await assert.rejects(attempt("hash", { "package_hash_denylist.txt": "1234\n" }), /SHA-256/);
	await assert.rejects(attempt("risk", { "domain_risk.json": JSON.stringify([{ domain: "a.example", action: "block", severity: "high" }]) }), /action must be allow, ask or deny/);
	await assert.rejects(attempt("conflict", { "url_denylist.txt": "x.example\n", "url_allowlist.txt": "x.example\n" }), /both the URL denylist and the URL allowlist/);
	await assert.rejects(buildPack({ ...base, out: join(root, "aud"), audience: ["Not_A_Customer"] }), /--audience/);

	const emptyThreats = join(root, "empty-threats");
	mkdirSync(emptyThreats);
	writeFileSync(join(emptyThreats, "a.yaml"), "[]\n");
	await assert.rejects(buildPack({ ...base, threatsDir: emptyThreats, out: join(root, "empty") }), PackReleaseError);
	assert.deepEqual((await buildPack({ ...base, threatsDir: emptyThreats, out: join(root, "empty"), ifEmpty: "skip" })).outcome, "empty");
	assert.equal(existsSync(join(root, "empty")), false);

	const first = await buildPack({ ...base, out: join(root, "once") });
	assert.equal(first.outcome, "built");
	await assert.rejects(buildPack({ ...base, out: join(root, "once") }), /already exists/);
});

test("the CLI builds a pack from the repository's own threats directory", (t) => {
	const root = workdir(t);
	const intel = intelDir(root);
	const built = run(releaseScript, ["build", "--out", join(root, "cli"), "--pack-id", "aidr-intel", "--version", "2026.1012.9", "--key-id", "k1", "--intel-dir", intel, "--expires-in-days", "45", "--source-ref", "abc123"]);
	assert.equal(built.status, 0, built.stderr);
	assert.equal(built.json.outcome, "built");
	const manifest = JSON.parse(readFileSync(join(root, "cli", "manifest.json"), "utf8"));
	assert.ok(manifest.source.threat_rules > 100);
	assert.equal(manifest.source.ref, "abc123");
	assert.equal(Date.parse(manifest.expires_at) - Date.parse(manifest.issued_at), 45 * DAY);
	assert.equal(manifest.audience, undefined);
});
