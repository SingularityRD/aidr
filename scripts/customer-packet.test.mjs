import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildPacketPayload, selfVerifyCustomerPacket, signCustomerPacket } from "./customer-packet-issue.mjs";
import {
	CUSTOMER_PACKET_FORMAT,
	CustomerPacketError,
	customerPacketSigningMessage,
	summarizeCustomerPacket,
	verifyCustomerPacket,
} from "./customer-packet-verify.mjs";
import { publicKeyEntry, signLicense } from "./license-issue.mjs";
import {
	DEFAULT_PUBLIC_KEYS_PATH,
	LICENSE_FORMAT,
	licenseSigningMessage,
	loadPublicKeyRegistry,
	parsePublicKeyRegistry,
	PUBLIC_KEYS_FORMAT,
	RETIRED_KEY_ACCEPTANCE_DAYS,
	verifyLicense,
} from "./license-verify.mjs";

// DEV test keys only: generated in memory for every run, never written to the
// shipped registry and never persisted outside the per-test temp directory.
const issueScript = fileURLToPath(new URL("./customer-packet-issue.mjs", import.meta.url));
const verifyScript = fileURLToPath(new URL("./customer-packet-verify.mjs", import.meta.url));
const DAY = 24 * 60 * 60 * 1000;
const devKey = generateKeyPairSync("ed25519").privateKey;
const secondKey = generateKeyPairSync("ed25519").privateKey;
const strangerKey = generateKeyPairSync("ed25519").privateKey;
const inTerm = Date.parse("2027-03-01T00:00:00Z");

const devEntry = (overrides = {}) => ({
	...publicKeyEntry(devKey, { keyId: "aidr-license-dev-1", notBefore: "2026-01-01T00:00:00Z" }),
	...overrides,
});
const secondEntry = () => publicKeyEntry(secondKey, { keyId: "aidr-license-dev-2", notBefore: "2026-01-01T00:00:00Z" });
const registry = (entries = [devEntry()]) => parsePublicKeyRegistry({ format: PUBLIC_KEYS_FORMAT, schema_version: 1, keys: entries });

function licenseTerms(overrides = {}) {
	return {
		license_id: "LIC-2026-0042",
		customer: "TÜBİTAK BİLGEM",
		customer_id: "bilgem",
		plan_id: "enterprise",
		seats: 500,
		features: ["managed_policy", "premium_intel"],
		deployment: "airgap",
		issued_at: "2026-09-01T00:00:00Z",
		not_before: "2026-09-01T00:00:00Z",
		expires_at: "2027-09-01T00:00:00Z",
		grace_days: 14,
		...overrides,
	};
}

const license = (overrides = {}, privateKey = devKey, keyId = "aidr-license-dev-1") => signLicense(licenseTerms(overrides), { privateKey, keyId });

function packetTerms(overrides = {}) {
	return {
		customer_id: "bilgem",
		packet_id: "PKT-bilgem-2026-09",
		issued_at: "2026-09-02T00:00:00Z",
		license: license(),
		control_plane_url: "https://aidr.bilgem.example.internal/",
		sensitivity: "paranoid",
		display_name: "TÜBİTAK BİLGEM",
		...overrides,
	};
}

/** Sign without the issuer's validation, to prove the verifier refuses on its own. */
function rawPacket(payload, privateKey = devKey, keyId = "aidr-license-dev-1") {
	return { format: CUSTOMER_PACKET_FORMAT, key_id: keyId, payload, sig: sign(null, customerPacketSigningMessage(payload), privateKey).toString("base64") };
}

const packet = (overrides = {}) => signCustomerPacket(packetTerms(overrides), { privateKey: devKey, keyId: "aidr-license-dev-1" });
const refusedWith = (code) => (error) => error instanceof CustomerPacketError && error.code === code;

test("a vendor-signed packet verifies and exposes its terms and the license state", () => {
	const result = verifyCustomerPacket(packet(), { publicKeys: registry(), now: inTerm });
	assert.equal(result.customer_id, "bilgem");
	assert.equal(result.packet_id, "PKT-bilgem-2026-09");
	assert.equal(result.control_plane_url, "https://aidr.bilgem.example.internal/");
	assert.equal(result.sensitivity, "paranoid");
	assert.equal(result.display_name, "TÜBİTAK BİLGEM");
	assert.equal(result.license_state, "active");
	assert.equal(result.license.payload.license_id, "LIC-2026-0042");
	assert.equal(result.license.grace_ends_at, "2027-09-15T00:00:00.000Z");
	assert.equal(result.local_detection, "enforced");
	assert.deepEqual(result.license_document, packet().payload.license);
	// Optional fields may be omitted.
	const minimal = signCustomerPacket(
		{ customer_id: "bilgem", packet_id: "p1", issued_at: "2026-09-02T00:00:00Z", license: license() },
		{ privateKey: devKey, keyId: "aidr-license-dev-1" },
	);
	const plain = verifyCustomerPacket(minimal, { publicKeys: registry(), now: inTerm });
	assert.equal("control_plane_url" in plain || "sensitivity" in plain || "display_name" in plain, false);
	// Reformatting the file does not change the signed canonical payload.
	const reformatted = JSON.parse(JSON.stringify(packet(), null, 3));
	reformatted.payload = Object.fromEntries(Object.entries(reformatted.payload).reverse());
	assert.equal(verifyCustomerPacket(reformatted, { publicKeys: registry(), now: inTerm }).customer_id, "bilgem");
	// The CLI summary carries no license signature or document, only terms.
	const summary = summarizeCustomerPacket(result);
	assert.equal(summary.updates_until, "2027-09-15T00:00:00.000Z");
	assert.equal(JSON.stringify(summary).includes(result.license_document.sig), false);
});

test("an expired or not-yet-valid license still verifies the packet; the state is reported, never hidden", () => {
	const doc = packet();
	assert.equal(verifyCustomerPacket(doc, { publicKeys: registry(), now: Date.parse("2027-09-05T00:00:00Z") }).license_state, "grace");
	const expired = verifyCustomerPacket(doc, { publicKeys: registry(), now: Date.parse("2028-06-01T00:00:00Z") });
	assert.equal(expired.license_state, "expired");
	assert.equal(expired.local_detection, "enforced");
	assert.equal(verifyCustomerPacket(doc, { publicKeys: registry(), now: Date.parse("2026-08-01T00:00:00Z") }).license_state, "not_yet_valid");
});

test("a tampered packet is refused, including a swapped embedded license", () => {
	const doc = packet();
	const keys = registry();
	for (const change of [
		{ control_plane_url: "https://attacker.example/" },
		{ sensitivity: "relaxed" },
		{ display_name: "Someone Else" },
		{ packet_id: "PKT-other" },
		{ license: license({ seats: 5000 }) },
	]) {
		assert.throws(() => verifyCustomerPacket({ ...doc, payload: { ...doc.payload, ...change } }, { publicKeys: keys, now: inTerm }), refusedWith("bad_signature"));
	}
	const { sensitivity: _dropped, ...withoutSensitivity } = doc.payload;
	assert.throws(() => verifyCustomerPacket({ ...doc, payload: withoutSensitivity }, { publicKeys: keys, now: inTerm }), refusedWith("bad_signature"));
	const flipped = Buffer.from(doc.sig, "base64");
	flipped[10] ^= 1;
	assert.throws(() => verifyCustomerPacket({ ...doc, sig: flipped.toString("base64") }, { publicKeys: keys, now: inTerm }), refusedWith("bad_signature"));
	// A license tampered inside a validly re-signed packet is still refused by the license check.
	const forgedLicense = { ...license(), payload: { ...license().payload, seats: 9999 } };
	assert.throws(() => verifyCustomerPacket(rawPacket(packetTerms({ license: forgedLicense })), { publicKeys: keys, now: inTerm }), (error) => {
		return refusedWith("invalid_license")(error) && /bad_signature/.test(error.message);
	});
});

test("domain separation: a license signature never verifies as a packet, and a packet signature never as a license", () => {
	const keys = registry();
	const terms = packetTerms();
	// Sign the packet payload with the license domain: the packet verifier refuses it.
	const crossSigned = { format: CUSTOMER_PACKET_FORMAT, key_id: "aidr-license-dev-1", payload: terms, sig: sign(null, licenseSigningMessage(terms), devKey).toString("base64") };
	assert.throws(() => verifyCustomerPacket(crossSigned, { publicKeys: keys, now: inTerm }), refusedWith("bad_signature"));
	// Present a valid license as a packet and a valid packet as a license.
	const lic = license();
	assert.throws(() => verifyCustomerPacket({ ...lic, format: CUSTOMER_PACKET_FORMAT }, { publicKeys: keys, now: inTerm }), refusedWith("bad_signature"));
	const doc = packet();
	assert.throws(() => verifyLicense({ ...doc, format: LICENSE_FORMAT }, { publicKeys: keys, now: inTerm }), (error) => error.code === "bad_signature");
	assert.throws(() => verifyCustomerPacket(lic, { publicKeys: keys, now: inTerm }), refusedWith("invalid_document"));
});

test("wrong, unknown, revoked and retired keys fail closed under the license registry rules", () => {
	const spoofed = signCustomerPacket(packetTerms(), { privateKey: strangerKey, keyId: "aidr-license-dev-1" });
	assert.throws(() => verifyCustomerPacket(spoofed, { publicKeys: registry(), now: inTerm }), refusedWith("bad_signature"));
	const unknown = signCustomerPacket(packetTerms(), { privateKey: strangerKey, keyId: "attacker-key" });
	assert.throws(() => verifyCustomerPacket(unknown, { publicKeys: registry(), now: inTerm }), refusedWith("unknown_key"));
	assert.throws(() => verifyCustomerPacket(packet(), { publicKeys: registry([devEntry({ status: "revoked" })]), now: inTerm }), refusedWith("revoked_key"));
	assert.throws(() => verifyCustomerPacket(packet(), { publicKeys: registry([]), now: inTerm }), refusedWith("no_trusted_keys"));
	assert.throws(() => verifyCustomerPacket(packet(), { now: inTerm }), refusedWith("invalid_public_keys"));

	// The packet and its license may be signed by different registry keys.
	const mixed = signCustomerPacket(packetTerms(), { privateKey: secondKey, keyId: "aidr-license-dev-2" });
	assert.equal(verifyCustomerPacket(mixed, { publicKeys: registry([devEntry(), secondEntry()]), now: inTerm }).key_id, "aidr-license-dev-2");
	// ...but the embedded license's key must be trusted too.
	assert.throws(() => verifyCustomerPacket(mixed, { publicKeys: registry([secondEntry()]), now: inTerm }), (error) => refusedWith("invalid_license")(error) && /unknown_key/.test(error.message));

	// Retired key: packets claiming issuance after retirement are refused; the verifier's clock ends acceptance.
	const retiredAt = "2026-11-01T00:00:00Z";
	const retired = registry([publicKeyEntry(devKey, { keyId: "aidr-license-dev-1", notBefore: "2026-01-01T00:00:00Z", status: "retired", retiredAt })]);
	assert.equal(verifyCustomerPacket(packet(), { publicKeys: retired, now: inTerm }).key_status, "retired");
	assert.throws(() => verifyCustomerPacket(packet({ issued_at: "2026-11-02T00:00:00Z" }), { publicKeys: retired, now: inTerm }), refusedWith("key_window"));
	assert.throws(() => verifyCustomerPacket(packet({ issued_at: "2025-06-01T00:00:00Z" }), { publicKeys: registry(), now: inTerm }), refusedWith("key_window"));
	const cutoff = Date.parse(retiredAt) + RETIRED_KEY_ACCEPTANCE_DAYS * DAY;
	assert.throws(() => verifyCustomerPacket(packet(), { publicKeys: retired, now: cutoff }), refusedWith("retired_key_expired"));
});

test("the customer id must match the license, which must carry one", () => {
	const keys = registry();
	assert.throws(() => verifyCustomerPacket(rawPacket(packetTerms({ customer_id: "havelsan" })), { publicKeys: keys, now: inTerm }), refusedWith("customer_mismatch"));
	const { customer_id: _none, ...legacyTerms } = licenseTerms();
	const legacy = signLicense(legacyTerms, { privateKey: devKey, keyId: "aidr-license-dev-1" });
	assert.throws(() => verifyCustomerPacket(rawPacket(packetTerms({ license: legacy })), { publicKeys: keys, now: inTerm }), (error) => {
		return refusedWith("customer_mismatch")(error) && /carries no customer_id/.test(error.message);
	});
	assert.throws(() => verifyCustomerPacket(packet(), { publicKeys: keys, now: inTerm, expectedCustomerId: "havelsan" }), refusedWith("customer_mismatch"));
	assert.equal(verifyCustomerPacket(packet(), { publicKeys: keys, now: inTerm, expectedCustomerId: "bilgem" }).customer_id, "bilgem");
	// The issuer refuses the same mistakes before signing.
	assert.throws(() => buildPacketPayload({ license: legacy, packetId: "p" }), refusedWith("customer_mismatch"));
	assert.throws(() => buildPacketPayload({ license: license(), customerId: "havelsan", packetId: "p" }), refusedWith("customer_mismatch"));
});

test("malformed packets and unknown or invalid terms fail closed", () => {
	const keys = registry();
	const verifyRaw = (overrides) => verifyCustomerPacket(rawPacket(packetTerms(overrides)), { publicKeys: keys, now: inTerm });
	const credentialUrl = ["https://", "admin", ":", "pw", "@aidr.example/"].join("");
	const invalidTerms = [
		{ customer_id: "BILGEM" },
		{ customer_id: "b" },
		{ packet_id: "" },
		{ packet_id: "-starts-with-dash" },
		{ packet_id: "x".repeat(129) },
		{ issued_at: "2026-09-02" },
		{ issued_at: "2026-09-02T00:00:00+03:00" },
		{ license: "not a document" },
		{ control_plane_url: "http://aidr.example/" },
		{ control_plane_url: "aidr.example" },
		{ control_plane_url: credentialUrl },
		{ control_plane_url: "https://aidr.example/#frag" },
		{ control_plane_url: " https://aidr.example/" },
		{ control_plane_url: `https://aidr.example/${"a".repeat(2048)}` },
		{ sensitivity: "lenient" },
		{ display_name: "" },
		{ display_name: " BILGEM" },
		{ display_name: "x".repeat(61) },
		{ display_name: "BIL\u0007GEM" },
		{ display_name: "BIL‮GEM" },
		{ enrollment_code: "secret" },
		{ api_key: "secret" },
	];
	for (const overrides of invalidTerms) {
		assert.throws(() => verifyRaw(overrides), refusedWith("invalid_payload"), `must refuse ${JSON.stringify(overrides).slice(0, 80)}`);
		assert.throws(() => signCustomerPacket(packetTerms(overrides), { privateKey: devKey, keyId: "aidr-license-dev-1" }), refusedWith("invalid_payload"));
	}
	const { packet_id: _missing, ...noPacketId } = packetTerms();
	assert.throws(() => verifyCustomerPacket(rawPacket(noPacketId), { publicKeys: keys, now: inTerm }), refusedWith("invalid_payload"));
	assert.equal(verifyRaw({ display_name: "x".repeat(60), control_plane_url: "https://aidr.example:8443/api?tenant=1" }).display_name.length, 60);

	const doc = packet();
	assert.throws(() => verifyCustomerPacket({ ...doc, format: "aidr-customer-packet-v0" }, { publicKeys: keys, now: inTerm }), refusedWith("invalid_document"));
	assert.throws(() => verifyCustomerPacket({ ...doc, extra: 1 }, { publicKeys: keys, now: inTerm }), refusedWith("invalid_document"));
	assert.throws(() => verifyCustomerPacket({ ...doc, sig: "!!" }, { publicKeys: keys, now: inTerm }), refusedWith("invalid_document"));
	assert.throws(() => verifyCustomerPacket({ ...doc, sig: Buffer.alloc(32).toString("base64") }, { publicKeys: keys, now: inTerm }), refusedWith("invalid_document"));
	assert.throws(() => verifyCustomerPacket({ ...doc, key_id: "" }, { publicKeys: keys, now: inTerm }), refusedWith("invalid_document"));
	assert.throws(() => verifyCustomerPacket([doc], { publicKeys: keys, now: inTerm }), refusedWith("invalid_document"));
	assert.throws(() => verifyCustomerPacket(null, { publicKeys: keys, now: inTerm }), refusedWith("invalid_document"));
	const huge = { ...doc, payload: { ...doc.payload, display_name: "x".repeat(70 * 1024) } };
	assert.throws(() => verifyCustomerPacket(huge, { publicKeys: keys, now: inTerm }), (error) => refusedWith("invalid_document")(error) && /larger than/.test(error.message));
});

test("issuer self-verification refuses a key that is not active in the customer registry", () => {
	const doc = packet();
	assert.equal(selfVerifyCustomerPacket(doc, { privateKey: devKey, publicKeys: registry(), now: inTerm }).customer_id, "bilgem");
	assert.throws(() => selfVerifyCustomerPacket(doc, { privateKey: secondKey, publicKeys: registry(), now: inTerm }), refusedWith("bad_signature"));
	const retired = registry([devEntry({ status: "retired", retired_at: "2026-11-01T00:00:00Z" })]);
	assert.throws(() => selfVerifyCustomerPacket(doc, { privateKey: devKey, publicKeys: retired, now: inTerm }), refusedWith("unknown_key"));
	assert.throws(() => selfVerifyCustomerPacket(doc, { privateKey: devKey, publicKeys: registry([secondEntry()]), now: inTerm }), refusedWith("unknown_key"));
});

test("the shipped registry is empty, so no packet verifies until the vendor publishes a key", () => {
	assert.throws(() => verifyCustomerPacket(packet(), { publicKeys: loadPublicKeyRegistry(), now: inTerm }), refusedWith("no_trusted_keys"));
});

test("CLI issues from a restricted key file, never takes a key on argv, and the verifier CLI checks the result", (t) => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-packet-cli-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	const pem = devKey.export({ type: "pkcs8", format: "pem" }).toString();
	const keyPath = join(directory, "license-signing.pem");
	writeFileSync(keyPath, pem, { mode: 0o600 });
	const registryPath = join(directory, "license-public-keys.json");
	writeFileSync(registryPath, JSON.stringify({ format: PUBLIC_KEYS_FORMAT, schema_version: 1, keys: [devEntry()] }));
	const licensePath = join(directory, "license.json");
	writeFileSync(licensePath, JSON.stringify(license()));
	const out = join(directory, "customer-packet.json");
	const clearEnv = { ...process.env, AIDR_LICENSE_SIGNING_KEY: "", AIDR_LICENSE_SIGNING_KEY_FILE: "" };
	const terms = ["--key-id", "aidr-license-dev-1", "--license-file", licensePath, "--packet-id", "PKT-bilgem-1", "--issued-at", "2026-09-02T00:00:00Z", "--control-plane-url", "https://aidr.bilgem.example.internal/", "--sensitivity", "balanced", "--display-name", "TÜBİTAK BİLGEM", "--public-keys", registryPath];
	const issue = (extra, env = clearEnv) => spawnSync(process.execPath, [issueScript, ...terms, ...extra], { encoding: "utf8", env });

	const missingRegistry = spawnSync(process.execPath, [issueScript, ...terms.slice(0, -2), "--out", out, "--private-key-file", keyPath], { encoding: "utf8", env: clearEnv });
	assert.equal(missingRegistry.status, 1);
	assert.match(missingRegistry.stderr, /--public-keys is required/);

	const issued = issue(["--out", out, "--private-key-file", keyPath, "--customer-id", "bilgem"]);
	assert.equal(issued.status, 0, issued.stderr);
	assert.match(issued.stdout, /Issued customer packet PKT-bilgem-1 for bilgem/);
	assert.ok(!`${issued.stdout}${issued.stderr}`.includes("PRIVATE KEY"));
	const written = JSON.parse(readFileSync(out, "utf8"));
	assert.equal(written.format, CUSTOMER_PACKET_FORMAT);
	assert.equal(written.payload.sensitivity, "balanced");

	assert.notEqual(issue(["--out", out, "--private-key-file", keyPath]).status, 0, "an existing packet must never be overwritten");
	const mismatch = issue(["--out", join(directory, "mismatch.json"), "--private-key-file", keyPath, "--customer-id", "havelsan"]);
	assert.equal(mismatch.status, 1);
	assert.match(mismatch.stderr, /does not match the license customer_id bilgem/);
	const fromEnv = issue(["--out", join(directory, "env.json")], { ...clearEnv, AIDR_LICENSE_SIGNING_KEY: pem });
	assert.equal(fromEnv.status, 0, fromEnv.stderr);
	const argvKey = issue(["--out", join(directory, "argv.json"), "--private-key", pem]);
	assert.notEqual(argvKey.status, 0, "a private key must never be accepted as a command argument");
	assert.equal(existsSync(join(directory, "argv.json")), false);
	if (process.platform !== "win32") {
		const loosePath = join(directory, "loose.pem");
		writeFileSync(loosePath, pem, { mode: 0o644 });
		const loose = issue(["--out", join(directory, "loose.json"), "--private-key-file", loosePath]);
		assert.equal(loose.status, 1);
		assert.match(loose.stderr, /owner-only/);
	}
	const unregistered = join(directory, "other-registry.json");
	writeFileSync(unregistered, JSON.stringify({ format: PUBLIC_KEYS_FORMAT, schema_version: 1, keys: [devEntry(), secondEntry()] }));
	const wrongKey = spawnSync(process.execPath, [issueScript, ...terms.slice(0, -1), unregistered, "--key-id", "aidr-license-dev-2", "--out", join(directory, "wrong.json"), "--private-key-file", keyPath], { encoding: "utf8", env: clearEnv });
	assert.equal(wrongKey.status, 1, "a key id that does not match the private key is caught by self-verification");
	assert.equal(existsSync(join(directory, "wrong.json")), false);

	const verifyCli = (extra = []) => spawnSync(process.execPath, [verifyScript, "--packet-file", out, "--public-keys", registryPath, ...extra], { encoding: "utf8" });
	const ok = verifyCli(["--now", "2027-01-01T00:00:00Z", "--expect-customer-id", "bilgem"]);
	assert.equal(ok.status, 0, ok.stderr);
	const summary = JSON.parse(ok.stdout);
	assert.deepEqual([summary.verified, summary.customer_id, summary.license_state, summary.updates_until], [true, "bilgem", "active", "2027-09-15T00:00:00.000Z"]);
	assert.match(summary.document_sha256, /^[0-9a-f]{64}$/);
	const expired = verifyCli(["--now", "2028-01-01T00:00:00Z"]);
	assert.equal(expired.status, 0, "an expired license still verifies the packet");
	assert.equal(JSON.parse(expired.stdout).license_state, "expired");
	assert.match(expired.stderr, /Installed detection keeps enforcing/);
	const otherCustomer = verifyCli(["--expect-customer-id", "havelsan"]);
	assert.equal(otherCustomer.status, 1);
	assert.match(otherCustomer.stderr, /not havelsan/);
	const shipped = spawnSync(process.execPath, [verifyScript, "--packet-file", out, "--public-keys", DEFAULT_PUBLIC_KEYS_PATH], { encoding: "utf8" });
	assert.equal(shipped.status, 1, "the empty shipped registry must fail closed");
	assert.match(shipped.stderr, /no license public keys are configured/);
	const tamperedPath = join(directory, "tampered.json");
	writeFileSync(tamperedPath, JSON.stringify({ ...written, payload: { ...written.payload, sensitivity: "relaxed" } }));
	const tampered = spawnSync(process.execPath, [verifyScript, "--packet-file", tamperedPath, "--public-keys", registryPath], { encoding: "utf8" });
	assert.equal(tampered.status, 1);
	assert.match(tampered.stderr, /signature does not verify/);
	assert.equal(spawnSync(process.execPath, [verifyScript], { encoding: "utf8" }).status, 1);
});
