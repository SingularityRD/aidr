import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { cpSync } from "./deployment-input-copy.mjs";

function fixture(t) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-public-input-modes-"));
	t.after(() => {
		assert.equal(dirname(realpathSync(directory)), realpathSync(tmpdir()));
		rmSync(directory, { recursive: true, force: true });
	});
	return directory;
}

test("public input copying clears POSIX group/world write without adding owner permissions", { skip: process.platform === "win32" }, (t) => {
	const directory = fixture(t);
	for (const mode of [0o777, 0o666, 0o600, 0o400, 0o750]) {
		const source = join(directory, `source-${mode.toString(8)}`);
		const destination = join(directory, `destination-${mode.toString(8)}`);
		writeFileSync(source, "public recovery-template fixture\n");
		chmodSync(source, mode);
		cpSync(source, destination);
		assert.equal(statSync(destination).mode & 0o777, mode & ~0o022);
		assert.equal(statSync(source).mode & 0o777, mode, "source permissions must remain unchanged");
		assert.equal(readFileSync(destination, "utf8"), readFileSync(source, "utf8"));
	}
});

test("recursive public copies retain the private output root and filter semantics", (t) => {
	const directory = fixture(t);
	const source = join(directory, "source");
	const destination = join(directory, "private-root");
	mkdirSync(source);
	mkdirSync(destination, { mode: 0o700 });
	writeFileSync(join(source, "keep.txt"), "kept\n");
	writeFileSync(join(source, "omit.test.txt"), "omitted\n");
	cpSync(source, destination, { filter: (path) => !path.endsWith("omit.test.txt") });
	assert.equal(readFileSync(join(destination, "keep.txt"), "utf8"), "kept\n");
	assert.equal(existsSync(join(destination, "omit.test.txt")), false);
	if (process.platform !== "win32") assert.equal(statSync(destination).mode & 0o777, 0o700);
});
