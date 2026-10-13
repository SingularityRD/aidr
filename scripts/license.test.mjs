import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildPayload, publicKeyEntry, signLicense } from "./license-issue.mjs";
import {
	canonicalJson,
	DEFAULT_PUBLIC_KEYS_PATH,
	LICENSE_FORMAT,
	LicenseError,
	licenseSigningMessage,
	loadPublicKeyRegistry,
	MAX_LICENSE_TERM_DAYS,
	parsePublicKeyRegistry,
	PUBLIC_KEYS_FORMAT,
	RETIRED_KEY_ACCEPTANCE_DAYS,
	verifyLicense,
} from "./license-verify.mjs";

// DEV test keys only: generated in memory for every run, never written to the
// shipped registry and never persisted outside the per-test temp directory.
const issueScript = fileURLToPath(new URL("./license-issue.mjs", import.meta.url));
const verifyScript = fileURLToPath(new URL("./license-verify.mjs", import.meta.url));
const DAY = 24 * 60 * 60 * 1000;
const devKey = generateKeyPairSync("ed25519").privateKey;
const otherKey = generateKeyPairSync("ed25519").privateKey;

function payload(overrides = {}) {
	return {
		license_id: "LIC-2026-0001",
		customer: "Example Customer AG",
		plan_id: "enterprise",
		seats: 250,
		features: ["managed_policy", "premium_intel", "siem_export"],
		deployment: "onprem",
		issued_at: "2026-09-01T00:00:00Z",
		not_before: "2026-09-01T00:00:00Z",
		expires_at: "2027-09-01T00:00:00Z",
		grace_days: 14,
		...overrides,
	};
}

function registry(entries) {
	return parsePublicKeyRegistry({ format: PUBLIC_KEYS_FORMAT, schema_version: 1, keys: entries });
}

const devEntry = (overrides = {}) => ({
	...publicKeyEntry(devKey, { keyId: "aidr-license-dev-1", notBefore: "2026-01-01T00:00:00Z" }),
	...overrides,
});
const inTerm = Date.parse("2027-03-01T00:00:00Z");

test("a vendor-signed license verifies and exposes its terms", () => {
	const license = signLicense(payload(), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	const result = verifyLicense(license, { publicKeys: registry([devEntry()]), now: inTerm });
	assert.equal(result.status, "valid");
	assert.equal(result.payload.seats, 250);
	assert.equal(result.managed_features, "enabled");
	assert.equal(result.local_detection, "enforced");
	assert.equal(result.grace_ends_at, "2027-09-15T00:00:00.000Z");
	// Reformatting the file does not change the signed canonical payload.
	const reformatted = JSON.parse(JSON.stringify(license, null, 4));
	reformatted.payload = Object.fromEntries(Object.entries(reformatted.payload).reverse());
	assert.equal(verifyLicense(reformatted, { publicKeys: registry([devEntry()]), now: inTerm }).status, "valid");
	assert.equal(canonicalJson({ b: 1, a: [2, { d: 1, c: 0 }] }), '{"a":[2,{"c":0,"d":1}],"b":1}');
});

test("a tampered license is refused", () => {
	const license = signLicense(payload(), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	for (const change of [{ seats: 5000 }, { expires_at: "2030-01-01T00:00:00Z" }, { grace_days: 90 }, { features: ["managed_policy"] }]) {
		const tampered = { ...license, payload: { ...license.payload, ...change } };
		assert.throws(
			() => verifyLicense(tampered, { publicKeys: registry([devEntry()]), now: inTerm }),
			(error) => error instanceof LicenseError && error.code === "bad_signature",
		);
	}
	const addedField = { ...license, payload: { ...license.payload, unlimited: true } };
	assert.throws(() => verifyLicense(addedField, { publicKeys: registry([devEntry()]), now: inTerm }), /bad_signature|does not verify/);
	const flipped = Buffer.from(license.sig, "base64");
	flipped[0] ^= 1;
	assert.throws(
		() => verifyLicense({ ...license, sig: flipped.toString("base64") }, { publicKeys: registry([devEntry()]), now: inTerm }),
		/does not verify/,
	);
});

test("a license signed by a different key is refused, including a spoofed key_id", () => {
	const spoofed = signLicense(payload(), { privateKey: otherKey, keyId: "aidr-license-dev-1" });
	assert.throws(
		() => verifyLicense(spoofed, { publicKeys: registry([devEntry()]), now: inTerm }),
		(error) => error.code === "bad_signature",
	);
	const unknown = signLicense(payload(), { privateKey: otherKey, keyId: "attacker-key" });
	assert.throws(
		() => verifyLicense(unknown, { publicKeys: registry([devEntry()]), now: inTerm }),
		(error) => error.code === "unknown_key",
	);
});

test("expired, not-yet-valid and grace states are reported, never as valid", () => {
	const license = signLicense(payload({ not_before: "2026-10-01T00:00:00Z" }), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	const keys = registry([devEntry()]);
	const early = verifyLicense(license, { publicKeys: keys, now: Date.parse("2026-09-15T00:00:00Z") });
	assert.equal(early.status, "not_yet_valid");
	assert.equal(early.managed_features, "degraded");

	const grace = verifyLicense(license, { publicKeys: keys, now: Date.parse("2027-09-01T00:00:00Z") + 3 * DAY });
	assert.equal(grace.status, "grace");
	assert.equal(grace.managed_features, "enabled");
	assert.equal(grace.days_remaining, 11);

	const expired = verifyLicense(license, { publicKeys: keys, now: Date.parse("2027-09-15T00:00:00Z") });
	assert.equal(expired.status, "expired");
	assert.equal(expired.managed_features, "degraded");
	// Expiry degrades managed features only: local detection is never switched off.
	assert.equal(expired.local_detection, "enforced");

	const noGrace = signLicense(payload({ grace_days: 0 }), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.equal(verifyLicense(noGrace, { publicKeys: keys, now: Date.parse("2027-09-01T00:00:00Z") }).status, "expired");
});

test("key rotation: retired keys verify licenses from their window, revoked keys verify nothing", () => {
	const old = signLicense(payload(), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	const rotated = registry([
		devEntry({ status: "retired", not_after: "2026-12-31T00:00:00Z", retired_at: "2026-12-31T00:00:00Z" }),
		publicKeyEntry(otherKey, { keyId: "aidr-license-dev-2", notBefore: "2026-12-01T00:00:00Z" }),
	]);
	assert.equal(verifyLicense(old, { publicKeys: rotated, now: inTerm }).status, "valid");
	const lateOld = signLicense(payload({ issued_at: "2027-02-01T00:00:00Z", not_before: "2027-02-01T00:00:00Z" }), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.throws(() => verifyLicense(lateOld, { publicKeys: rotated, now: inTerm }), (error) => error.code === "key_window");
	const fresh = signLicense(payload({ issued_at: "2027-01-05T00:00:00Z", not_before: "2027-01-05T00:00:00Z" }), { privateKey: otherKey, keyId: "aidr-license-dev-2" });
	assert.equal(verifyLicense(fresh, { publicKeys: rotated, now: inTerm }).status, "valid");
	const revoked = registry([devEntry({ status: "revoked" })]);
	assert.throws(() => verifyLicense(old, { publicKeys: revoked, now: inTerm }), (error) => error.code === "revoked_key");
});

test("a retired key is capped by its retired_at, on the verifier's clock, not by signer-chosen issued_at", () => {
	const retiredAt = "2026-11-01T00:00:00Z";
	const keys = registry([
		publicKeyEntry(devKey, { keyId: "aidr-license-dev-1", notBefore: "2026-01-01T00:00:00Z", status: "retired", retiredAt }),
	]);
	const beforeRetirement = signLicense(payload(), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	const result = verifyLicense(beforeRetirement, { publicKeys: keys, now: inTerm });
	assert.equal(result.status, "valid");
	assert.equal(result.key_status, "retired");
	assert.equal(result.key_retired_at, "2026-11-01T00:00:00.000Z");

	// A license claiming issuance after retirement was signed by a key that no longer signs.
	const afterRetirement = signLicense(payload({ issued_at: "2026-11-02T00:00:00Z", not_before: "2026-11-02T00:00:00Z" }), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.throws(() => verifyLicense(afterRetirement, { publicKeys: keys, now: inTerm }), (error) => error.code === "key_window");

	// A leaked retired key cannot back-date issued_at into a license that outlives
	// retired_at + the longest license life: the term cap refuses it at signing and
	// at verification, and the verifier's clock ends the key's acceptance.
	assert.throws(
		() => signLicense(payload({ issued_at: "2026-10-01T00:00:00Z", not_before: "2026-10-01T00:00:00Z", expires_at: "2099-01-01T00:00:00Z" }), { privateKey: devKey, keyId: "k" }),
		/at most 1830 days after issued_at/,
	);
	const longest = signLicense(
		payload({
			issued_at: "2026-10-01T00:00:00Z",
			not_before: "2026-10-01T00:00:00Z",
			expires_at: new Date(Date.parse("2026-10-01T00:00:00Z") + MAX_LICENSE_TERM_DAYS * DAY).toISOString().replace(".000Z", "Z"),
			grace_days: 90,
		}),
		{ privateKey: devKey, keyId: "aidr-license-dev-1" },
	);
	const cutoff = Date.parse(retiredAt) + RETIRED_KEY_ACCEPTANCE_DAYS * DAY;
	assert.equal(verifyLicense(longest, { publicKeys: keys, now: cutoff - DAY }).status, "expired");
	assert.throws(() => verifyLicense(longest, { publicKeys: keys, now: cutoff }), (error) => error.code === "retired_key_expired");
	// The same license under an active key is judged by its own terms only.
	assert.equal(verifyLicense(longest, { publicKeys: registry([devEntry()]), now: cutoff }).status, "expired");
});

test("a retired key must record retired_at inside its window, and only a retired key may", () => {
	assert.throws(() => registry([devEntry({ status: "retired" })]), /retired_at must be an ISO-8601/);
	assert.throws(() => registry([devEntry({ status: "retired", retired_at: "2025-06-01T00:00:00Z" })]), /within its not_before\.\.not_after window/);
	assert.throws(
		() => registry([devEntry({ status: "retired", not_after: "2026-06-01T00:00:00Z", retired_at: "2026-07-01T00:00:00Z" })]),
		/within its not_before\.\.not_after window/,
	);
	assert.throws(() => registry([devEntry({ retired_at: "2026-07-01T00:00:00Z" })]), /has retired_at but status active/);
	assert.equal(registry([devEntry({ status: "revoked", retired_at: null })]).get("aidr-license-dev-1").status, "revoked");
});

test("the shipped registry is a placeholder that refuses every license", () => {
	const shipped = JSON.parse(readFileSync(DEFAULT_PUBLIC_KEYS_PATH, "utf8"));
	assert.equal(shipped.format, PUBLIC_KEYS_FORMAT);
	assert.deepEqual(shipped.keys, [], "no key — and never a development key — may ship in the registry");
	assert.ok(shipped.instructions.join(" ").includes("docs/operations/licensing.md"));
	assert.ok(!readFileSync(DEFAULT_PUBLIC_KEYS_PATH, "utf8").includes("PRIVATE KEY"));
	const license = signLicense(payload(), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.throws(
		() => verifyLicense(license, { publicKeys: loadPublicKeyRegistry(), now: inTerm }),
		(error) => error.code === "no_trusted_keys",
	);
});

test("malformed documents and registries fail closed", () => {
	const keys = registry([devEntry()]);
	const license = signLicense(payload(), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.throws(() => verifyLicense({ ...license, format: "aidr-license-v0" }, { publicKeys: keys, now: inTerm }), /format/);
	assert.throws(() => verifyLicense({ ...license, extra: 1 }, { publicKeys: keys, now: inTerm }), /unknown field/);
	assert.throws(() => verifyLicense(license, { now: inTerm }), /public-key registry is required/);
	assert.throws(() => signLicense(payload({ seats: 0 }), { privateKey: devKey, keyId: "k" }), /seats/);
	assert.throws(() => signLicense(payload({ deployment: "cloud" }), { privateKey: devKey, keyId: "k" }), /deployment/);
	assert.throws(() => signLicense(payload({ expires_at: "2026-08-01T00:00:00Z" }), { privateKey: devKey, keyId: "k" }), /expires_at/);
	assert.throws(() => registry([devEntry(), devEntry()]), /duplicate/);
	assert.throws(() => registry([devEntry({ algorithm: "rsa" })]), /ed25519/);
	assert.throws(() => registry([{ ...devEntry(), public_key_pem: "not a key" }]), /not a PEM public key/);
	assert.throws(() => parsePublicKeyRegistry({ keys: [] }), /format/);
});

test("CLI issues from a restricted key file and never accepts a key on argv", (t) => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-license-cli-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	const keyPath = join(directory, "license-signing.pem");
	writeFileSync(keyPath, devKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
	const registryPath = join(directory, "license-public-keys.json");
	const entry = spawnSync(process.execPath, [issueScript, "--print-public-key-entry", "--key-id", "aidr-license-dev-1", "--not-before", "2026-01-01T00:00:00Z", "--private-key-file", keyPath], { encoding: "utf8" });
	assert.equal(entry.status, 0, entry.stderr);
	writeFileSync(registryPath, JSON.stringify({ format: PUBLIC_KEYS_FORMAT, schema_version: 1, keys: [JSON.parse(entry.stdout)] }));

	const licensePath = join(directory, "license.json");
	const terms = ["--key-id", "aidr-license-dev-1", "--license-id", "LIC-CLI-1", "--customer", "Example Customer AG", "--plan-id", "enterprise", "--seats", "40", "--features", "managed_policy,premium_intel", "--deployment", "airgap", "--issued-at", "2026-09-01T00:00:00Z", "--expires-at", "2027-09-01T00:00:00Z", "--public-keys", registryPath, "--out", licensePath];
	const issued = spawnSync(process.execPath, [issueScript, ...terms, "--private-key-file", keyPath], { encoding: "utf8" });
	assert.equal(issued.status, 0, issued.stderr);
	assert.ok(!issued.stdout.includes("PRIVATE KEY"));
	const again = spawnSync(process.execPath, [issueScript, ...terms, "--private-key-file", keyPath], { encoding: "utf8" });
	assert.notEqual(again.status, 0, "an existing license file must never be overwritten");

	const fromEnv = spawnSync(process.execPath, [issueScript, ...terms.slice(0, -1), join(directory, "license-env.json")], {
		encoding: "utf8",
		env: { ...process.env, AIDR_LICENSE_SIGNING_KEY: devKey.export({ type: "pkcs8", format: "pem" }).toString() },
	});
	assert.equal(fromEnv.status, 0, fromEnv.stderr);

	const argvKey = spawnSync(process.execPath, [issueScript, ...terms.slice(0, -1), join(directory, "argv.json"), "--private-key", devKey.export({ type: "pkcs8", format: "pem" }).toString()], { encoding: "utf8", env: { ...process.env, AIDR_LICENSE_SIGNING_KEY: "", AIDR_LICENSE_SIGNING_KEY_FILE: "" } });
	assert.notEqual(argvKey.status, 0, "a private key must never be accepted as a command argument");

	if (process.platform !== "win32") {
		const loosePath = join(directory, "loose.pem");
		writeFileSync(loosePath, devKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o644 });
		const loose = spawnSync(process.execPath, [issueScript, ...terms.slice(0, -1), join(directory, "loose.json"), "--private-key-file", loosePath], { encoding: "utf8" });
		assert.notEqual(loose.status, 0);
		assert.match(loose.stderr, /owner-only/);
	}

	const run = (now, registryFile = registryPath) => spawnSync(process.execPath, [verifyScript, "--license-file", licensePath, "--public-keys", registryFile, "--now", now], { encoding: "utf8" });
	const valid = run("2027-01-01T00:00:00Z");
	assert.equal(valid.status, 0, valid.stderr);
	const summary = JSON.parse(valid.stdout);
	assert.equal(summary.status, "valid");
	assert.equal(summary.seats, 40);
	assert.equal(summary.deployment, "airgap");
	assert.equal(summary.local_detection, "enforced");
	assert.equal(run("2027-09-05T00:00:00Z").status, 2, "grace exits 2");
	assert.equal(run("2027-10-01T00:00:00Z").status, 3, "expired exits 3");
	assert.equal(run("2026-08-01T00:00:00Z").status, 4, "not yet valid exits 4");
	const shipped = run("2027-01-01T00:00:00Z", DEFAULT_PUBLIC_KEYS_PATH);
	assert.equal(shipped.status, 1, "the empty shipped registry must fail closed");
	assert.match(shipped.stderr, /no license public keys are configured/);
});

test("an air-gapped license requires the enterprise plan (catalog feature air_gapped_deployment)", () => {
	const keys = registry([devEntry()]);
	for (const plan_id of ["free", "team", "business"]) {
		assert.throws(
			() => signLicense(payload({ plan_id, deployment: "airgap" }), { privateKey: devKey, keyId: "aidr-license-dev-1" }),
			(error) => error instanceof LicenseError && error.code === "plan_feature_required" && /requires the enterprise plan/.test(error.message),
		);
		// The same plan may still be licensed for a connected on-prem deployment.
		const onprem = signLicense(payload({ plan_id, deployment: "onprem" }), { privateKey: devKey, keyId: "aidr-license-dev-1" });
		assert.equal(verifyLicense(onprem, { publicKeys: keys, now: inTerm }).status, "valid");
	}
	assert.throws(
		() => buildPayload({ licenseId: "LIC-1", customer: "Example", planId: "business", seats: "10", deployment: "airgap", issuedAt: "2026-09-01T00:00:00Z", expiresAt: "2027-09-01T00:00:00Z" }),
		(error) => error.code === "plan_feature_required",
	);
	const airgap = signLicense(payload({ deployment: "airgap" }), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.equal(verifyLicense(airgap, { publicKeys: keys, now: inTerm }).payload.deployment, "airgap");

	// A license signed outside the issuer's validation is still refused by the verifier.
	const forgedTerms = payload({ plan_id: "team", deployment: "airgap" });
	const forged = {
		format: LICENSE_FORMAT,
		key_id: "aidr-license-dev-1",
		payload: forgedTerms,
		sig: sign(null, licenseSigningMessage(forgedTerms), devKey).toString("base64"),
	};
	assert.throws(() => verifyLicense(forged, { publicKeys: keys, now: inTerm }), (error) => error.code === "plan_feature_required");
});

test("plan_id must be a catalog plan", () => {
	for (const plan_id of ["pro", "enterprise-plus", "Enterprise"]) {
		assert.throws(
			() => signLicense(payload({ plan_id }), { privateKey: devKey, keyId: "k" }),
			(error) => error.code === "invalid_payload" && /plan_id/.test(error.message),
		);
	}
});

test("CLI refuses to issue an air-gapped license for a non-enterprise plan", (t) => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-license-airgap-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	const keyPath = join(directory, "license-signing.pem");
	writeFileSync(keyPath, devKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
	const out = join(directory, "license.json");
	const issued = spawnSync(process.execPath, [issueScript, "--key-id", "aidr-license-dev-1", "--license-id", "LIC-CLI-2", "--customer", "Example Customer AG", "--plan-id", "business", "--seats", "40", "--deployment", "airgap", "--issued-at", "2026-09-01T00:00:00Z", "--expires-at", "2027-09-01T00:00:00Z", "--out", out, "--private-key-file", keyPath], { encoding: "utf8" });
	assert.equal(issued.status, 1);
	assert.match(issued.stderr, /air-gapped deployment \(air_gapped_deployment\) requires the enterprise plan/);
	assert.equal(existsSync(out), false, "no license file is written");
});

test("customer_id is an optional signed term: absent stays valid, present must match its pattern", () => {
	const keys = registry([devEntry()]);
	const legacy = signLicense(payload(), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.equal(verifyLicense(legacy, { publicKeys: keys, now: inTerm }).payload.customer_id, undefined);

	const bound = signLicense(payload({ customer_id: "bilgem" }), { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.equal(verifyLicense(bound, { publicKeys: keys, now: inTerm }).payload.customer_id, "bilgem");
	// customer_id is covered by the signature: changing or dropping it breaks verification.
	const dropped = Object.fromEntries(Object.entries(bound.payload).filter(([key]) => key !== "customer_id"));
	for (const changed of [{ ...bound.payload, customer_id: "havelsan" }, dropped]) {
		assert.throws(() => verifyLicense({ ...bound, payload: changed }, { publicKeys: keys, now: inTerm }), (error) => error.code === "bad_signature");
	}
	for (const customer_id of ["", "a", "Bilgem", "-bilgem", "bil gem", "bilgem_1", "x".repeat(33), 7, null]) {
		assert.throws(
			() => signLicense(payload({ customer_id }), { privateKey: devKey, keyId: "aidr-license-dev-1" }),
			(error) => error.code === "invalid_payload" && /customer_id/.test(error.message),
			`customer_id ${JSON.stringify(customer_id)} must be refused`,
		);
	}
	for (const customer_id of ["ab", "bilgem", "havelsan-2", "9lives", "x".repeat(32)]) {
		assert.equal(signLicense(payload({ customer_id }), { privateKey: devKey, keyId: "aidr-license-dev-1" }).payload.customer_id, customer_id);
	}
	const terms = { licenseId: "LIC-1", customer: "Example", planId: "enterprise", seats: "10", deployment: "onprem", issuedAt: "2026-09-01T00:00:00Z", expiresAt: "2027-09-01T00:00:00Z" };
	assert.equal(buildPayload({ ...terms, customerId: "bilgem" }).customer_id, "bilgem");
	assert.equal("customer_id" in buildPayload(terms), false);
});

test("CLI --customer-id signs the customer id into the license and the verifier reports it", (t) => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-license-customer-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	const keyPath = join(directory, "license-signing.pem");
	writeFileSync(keyPath, devKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
	const registryPath = join(directory, "license-public-keys.json");
	writeFileSync(registryPath, JSON.stringify({ format: PUBLIC_KEYS_FORMAT, schema_version: 1, keys: [devEntry()] }));
	const out = join(directory, "license.json");
	const base = ["--key-id", "aidr-license-dev-1", "--license-id", "LIC-CLI-3", "--customer", "TÜBİTAK BİLGEM", "--plan-id", "enterprise", "--seats", "40", "--deployment", "onprem", "--issued-at", "2026-09-01T00:00:00Z", "--expires-at", "2027-09-01T00:00:00Z", "--public-keys", registryPath, "--private-key-file", keyPath];
	const bad = spawnSync(process.execPath, [issueScript, ...base, "--customer-id", "BILGEM", "--out", out], { encoding: "utf8" });
	assert.equal(bad.status, 1);
	assert.match(bad.stderr, /customer_id must be/);
	assert.equal(existsSync(out), false);
	const issued = spawnSync(process.execPath, [issueScript, ...base, "--customer-id", "bilgem", "--out", out], { encoding: "utf8" });
	assert.equal(issued.status, 0, issued.stderr);
	assert.match(issued.stdout, /customer id bilgem/);
	assert.equal(JSON.parse(readFileSync(out, "utf8")).payload.customer_id, "bilgem");
	const verified = spawnSync(process.execPath, [verifyScript, "--license-file", out, "--public-keys", registryPath, "--now", "2027-01-01T00:00:00Z"], { encoding: "utf8" });
	assert.equal(verified.status, 0, verified.stderr);
	assert.equal(JSON.parse(verified.stdout).customer_id, "bilgem");
});
