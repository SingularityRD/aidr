import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { inspectReleaseArchive } from "./lib/release-archive-inspection.mjs";
import { createTempWorkspace } from "./verify-package-install.mjs";

function archiveFixture(name, { listing, source = "console.log('ok');\n" }) {
	const workspace = createTempWorkspace(`aidr-release-archive-${name}-`);
	const archive = path.join(workspace.root, `${name}.tar.gz`);
	writeFileSync(archive, gzipSync(Buffer.from("fixture tar bytes")));
	const run = (_command, args) => args[0] === "-tf"
		? { status: 0, stdout: listing, stderr: "" }
		: { status: 0, stdout: source, stderr: "" };
	return { workspace, archive, run };
}

test("tar.gz inspection requires signed evidence and scans packaged JavaScript", () => {
	const f = archiveFixture("clean", {
		listing: "package/dist/index.js\npackage/dist/aidr-artifact.manifest.json\npackage/dist/aidr-artifact.manifest.sig\n",
	});
	try {
		const result = inspectReleaseArchive(f.archive, {
			run: f.run,
			requiredEntries: ["package/dist/aidr-artifact.manifest.json", "package/dist/aidr-artifact.manifest.sig"],
		});
		assert.equal(result.entries.has("package/dist/index.js"), true);
	} finally {
		f.workspace.dispose();
	}
});

test("archive inspection rejects source directives and debug files", () => {
	const directive = archiveFixture("directive", { listing: "package/dist/index.js\n", source: "//# sourceURL=leak.js\n" });
	const map = archiveFixture("map", { listing: "package/dist/index.js.map\n" });
	try {
		assert.throws(() => inspectReleaseArchive(directive.archive, { run: directive.run }), /sourceURL/);
		assert.throws(() => inspectReleaseArchive(map.archive, { run: map.run }), /forbidden files/);
	} finally {
		directive.workspace.dispose();
		map.workspace.dispose();
	}
});
