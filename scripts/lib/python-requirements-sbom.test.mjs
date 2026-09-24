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
