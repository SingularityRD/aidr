import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { coreBuildReason, ensureCoreBuild } from "./ensure-core-build.mjs";

function fixture(flavor = "development") {
	const root = path.join(tmpdir(), `aidr-core-ensure-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
	const core = path.join(root, "packages", "core");
	mkdirSync(path.join(core, "src", "generated"), { recursive: true });
	mkdirSync(path.join(core, "dist", "generated"), { recursive: true });
	writeFileSync(path.join(core, "src", "index.ts"), "export {};\n");
	writeFileSync(path.join(core, "src", "generated", "rules.json"), "{}\n");
	writeFileSync(path.join(core, "dist", "generated", "rules.json"), "{}\n");
	writeFileSync(path.join(core, "dist", "index.js"), "export {};\n");
	writeFileSync(path.join(core, "dist", "index.d.ts"), "export {};\n");
	writeFileSync(path.join(core, "dist", "build-flavor.js"), `const EMBEDDED_BUILD_FLAVOR = "${flavor}";\n`);
	const old = new Date(Date.now() - 10_000);
	const fresh = new Date();
	utimesSync(path.join(core, "src", "index.ts"), old, old);
	for (const name of ["index.js", "index.d.ts", "build-flavor.js"]) utimesSync(path.join(core, "dist", name), fresh, fresh);
	return { root, core };
}

test("standalone release ensure rejects development core and runs the commercial build", () => {
	const { root, core } = fixture();
	try {
		assert.match(coreBuildReason(root, "commercial"), /not commercial/);
		let script;
		const status = ensureCoreBuild({
			repoRoot: root,
			release: true,
			runBuild: (_coreDir, selected) => {
				script = selected;
				writeFileSync(path.join(core, "dist", "build-flavor.js"), 'const EMBEDDED_BUILD_FLAVOR = "commercial";\n');
			},
		});
		assert.equal(status, 0);
		assert.equal(script, "build:release");
		assert.equal(coreBuildReason(root, "commercial"), null);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("standalone release ensure fails when the release build does not produce a commercial core", () => {
	const { root } = fixture();
	try {
		assert.equal(ensureCoreBuild({ repoRoot: root, release: true, runBuild: () => {} }), 1);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("OpenClaw standalone build:release requests a commercial core before cleaning", () => {
	const manifest = JSON.parse(
		readFileSync(new URL("../packages/openclaw/package.json", import.meta.url), "utf8"),
	);
	assert.match(
		manifest.scripts["build:release"],
		/^node \.\.\/\.\.\/scripts\/ensure-core-build\.mjs --release && pnpm run clean/,
	);
});
