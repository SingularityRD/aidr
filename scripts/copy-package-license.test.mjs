import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { copyPackageLicense } from "./copy-package-license.mjs";
import { removePath } from "./verify-package-install.mjs";

function fixture() {
	const repositoryRoot = path.join(tmpdir(), `aidr-license-test-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	const packageRoot = path.join(repositoryRoot, "packages", "fixture");
	mkdirSync(packageRoot, { recursive: true });
	writeFileSync(path.join(repositoryRoot, "LICENSE"), "repository license\n", "utf8");
	return { repositoryRoot, packageRoot };
}

test("copies the repository license into dist when the package has none", async () => {
	const f = fixture();
	try {
		const result = await copyPackageLicense(f);
		assert.equal(result.copied, true);
		assert.equal(readFileSync(path.join(f.packageRoot, "dist", "LICENSE"), "utf8"), "repository license\n");
	} finally {
		removePath(f.repositoryRoot);
	}
});

test("does not duplicate a package-local license inside dist", async () => {
	const f = fixture();
	try {
		writeFileSync(path.join(f.packageRoot, "LICENSE"), "package license\n", "utf8");
		const result = await copyPackageLicense(f);
		assert.equal(result.copied, false);
		assert.equal(existsSync(path.join(f.packageRoot, "dist", "LICENSE")), false);
	} finally {
		removePath(f.repositoryRoot);
	}
});
