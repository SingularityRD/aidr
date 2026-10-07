import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parseHashLockedRequirements } from "./python-requirements-sbom.mjs";

const hash = "a".repeat(64);
const continuation = String.fromCharCode(92);

test("includes every pinned AIG runtime package with distribution hashes", () => {
	const lock = readFileSync(new URL("../../services/aig-bridge/requirements-runtime.lock", import.meta.url), "utf8");
	const packages = parseHashLockedRequirements(lock);
	assert.ok(packages.length >= 30);
	assert.ok(packages.every((pkg) => pkg.hashes.length > 0));
	assert.ok(packages.some((pkg) => pkg.name === "uvicorn"));
});

test("rejects a missing hash or an unpinned Python runtime dependency", () => {
	assert.throws(() => parseHashLockedRequirements("fastapi==1.2.3\n"), /no SHA-256 hash/);
	assert.throws(
		() => parseHashLockedRequirements([
			"fastapi==1.2.3 " + continuation,
			"    --hash=sha256:" + hash,
			"uvicorn>=1",
		].join("\n")),
		/Unsupported Python runtime lock entry/,
	);
});

test("normalizes package identities and rejects duplicates", () => {
	assert.throws(
		() => parseHashLockedRequirements([
			"typing_extensions==1 " + continuation,
			"    --hash=sha256:" + hash,
			"typing-extensions==2 " + continuation,
			"    --hash=sha256:" + hash,
		].join("\n")),
		/Duplicate Python runtime package/,
	);
});

test("accepts hashes on the pin line (privacy worker locks)", () => {
	const other = "b".repeat(64);
	const packages = parseHashLockedRequirements([
		"torch==2.14.1+cpu --hash=sha256:" + hash,
		"Pillow==12.3.0 --hash=sha256:" + other + " --hash=sha256:" + hash,
	].join("\n"));
	assert.deepEqual(packages, [
		{ name: "torch", version: "2.14.1+cpu", hashes: [hash] },
		{ name: "pillow", version: "12.3.0", hashes: [hash, other] },
	]);
	assert.throws(() => parseHashLockedRequirements("torch==2 --index-url=https://example.test\n"), /Unsupported/);
	assert.throws(() => parseHashLockedRequirements("torch==2 --hash=md5:abc\n"), /Unsupported/);
});

test("parses every privacy worker lock", () => {
	for (const lock of [
		"packages/privacy/ner/requirements.linux-py311.lock.txt",
		"packages/privacy/ner/requirements.windows-py312.lock.txt",
		"packages/privacy/vision/requirements.lock.txt",
		"packages/privacy/parsers/requirements.lock.txt",
	]) {
		const packages = parseHashLockedRequirements(readFileSync(new URL(`../../${lock}`, import.meta.url), "utf8"));
		assert.ok(packages.length > 0, lock);
		assert.ok(packages.every((pkg) => pkg.hashes.length > 0), lock);
	}
});
