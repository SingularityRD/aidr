import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { createDependencyAuditor, evaluateReport, parseVersionedDenoNpm } from "./knip-dependency-audit.mjs";

const denoFile = "supabase/functions/new-handler/index.ts";
const nodeFile = "scripts/generator.mjs";
const fixtureRoots = new WeakMap();

// Explicit removal also works on Windows runtimes where recursive rmSync can
// silently leave fixture trees behind (which would pollute the next Knip run).
function removeFixture(path) {
	for (const entry of readdirSync(path, { withFileTypes: true })) {
		const child = join(path, entry.name);
		if (entry.isDirectory()) removeFixture(child);
		else unlinkSync(child);
	}
	rmdirSync(path);
}

function fixture(t, file, source, dependencies = { yaml: "2.8.3", zod: "3.25.76" }) {
	const root = mkdtempSync(join(fileURLToPath(new URL(".", import.meta.url)), ".knip-fixture-"));
	let roots = fixtureRoots.get(t);
	if (!roots) {
		roots = [];
		fixtureRoots.set(t, roots);
		t.after(() => { for (const path of roots) removeFixture(path); });
	}
	roots.push(root);
	const put = (path, text) => {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), text);
	};
	put(file, source);
	put("packages/core/package.json", JSON.stringify({ dependencies }));
	for (const name of ["yaml", "zod", "npm"]) {
		put(`packages/core/node_modules/${name}/package.json`, JSON.stringify({ name, version: "1.0.0", main: "index.js" }));
		put(`packages/core/node_modules/${name}/index.js`, "module.exports = {};\n");
	}
	return { approve: createDependencyAuditor(root), root };
}

function finding(source, literal, name, occurrence = 0) {
	let pos = -1;
	for (let index = 0; index <= occurrence; index++) pos = source.indexOf(JSON.stringify(literal), pos + 1);
	assert.notEqual(pos, -1);
	const lines = source.slice(0, pos).split("\n");
	return { name, pos, line: lines.length, col: lines.at(-1).length + 2 };
}

const requireSetup = 'import { createRequire } from "node:module";\nconst require = createRequire(new URL("../packages/core/package.json", import.meta.url));\n';

test("numeric versioned scoped/unscoped Deno URLs and safe subpaths parse", () => {
	for (const specifier of ["npm:yaml@2.8.3", "npm:@supabase/supabase-js@2", "npm:yaml@2.8", "npm:@supabase/supabase-js@2.57.4", "npm:pkg@1.2.3-beta.1+build/sub/path.js"]) {
		assert.ok(parseVersionedDenoNpm(specifier), specifier);
	}
});

test("bare, nonnumeric ranges, tagged, malformed and spoofed Deno specifiers do not parse", () => {
	for (const specifier of ["npm", "npm:yaml", "npm:yaml@^2.8.3", "npm:yaml@latest", "npm:yaml@02.8.3", "npm:yaml@2.8.3-01", "npm:@/yaml@2.8.3", "npm:../yaml@2.8.3", "npm:yaml@2.8.3/../npm", "npm:yaml@2.8.3/%2e%2e/npm", "npm:yaml@2.8.3//file", "npm:yaml@2.8.3/", "npm:yaml@2.8.3?x", "npm:yaml@2.8.3#x", "npm:yaml@2.8.3\\x", "npm:node_modules@1.2.3", "npm:UPPER@1.2.3", "npm:yaml@2.8.3\n", "npm:yaml@9007199254740992.0.0"]) {
		assert.equal(parseVersionedDenoNpm(specifier), null, specifier);
	}
});

test("new Deno files are interpreted per exact import location, not enumerated", (t) => {
	const source = '// π unicode\r\nimport type { Client } from "npm:@supabase/supabase-js@2.57.4";\r\n';
	const { approve } = fixture(t, denoFile, source);
	const value = finding(source, "npm:@supabase/supabase-js@2.57.4", "npm");
	assert.equal(approve({ file: denoFile }, "unlisted", value), true);
	for (const change of [{ pos: value.pos + 1 }, { line: value.line + 1 }, { col: value.col + 1 }, { name: "yaml" }]) {
		assert.equal(approve({ file: denoFile }, "unlisted", { ...value, ...change }), false);
	}
	assert.equal(approve({ file: denoFile }, "dependencies", value), false);
	assert.equal(approve({ file: `scripts/../${denoFile}` }, "unlisted", value), false);
	assert.equal(approve({ file: `../${denoFile}` }, "unlisted", value), false);
	assert.equal(approve({ file: denoFile }, "unlisted", { name: "npm" }), false);
});

test("pinned URLs in comments, ordinary strings, mocks or Node files are not imports", (t) => {
	for (const source of ['// import "npm:yaml@2.8.3";', 'const doc = "npm:yaml@2.8.3";', 'vi.mock("npm:yaml@2.8.3", () => ({}));', 'require("npm:yaml@2.8.3");']) {
		const { approve } = fixture(t, denoFile, source);
		assert.equal(approve({ file: denoFile }, "unlisted", finding(source, "npm:yaml@2.8.3", "npm")), false);
	}
	const source = 'import "npm:yaml@2.8.3";';
	const { approve } = fixture(t, nodeFile, source);
	assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, "npm:yaml@2.8.3", "npm")), false);
});

test("genuine npm/yaml/zod imports block even in previously exempt files", (t) => {
	for (const file of [denoFile, "supabase/functions/policy-management/index.ts", "supabase/functions/__tests__/policy-management-contract.test.ts", nodeFile]) {
		for (const name of ["npm", "yaml", "zod"]) {
			const source = `import ${JSON.stringify(name)};`;
			const { approve } = fixture(t, file, source);
			assert.equal(approve({ file }, "unlisted", finding(source, name, name)), false, `${file}: ${name}`);
		}
	}
});

test("mixed report filters only proven references and retains real violations", (t) => {
	const source = 'import "npm:yaml@2.8.3";\nimport "zod";\nimport "yaml";';
	const { approve } = fixture(t, denoFile, source);
	const report = { files: ["unused.ts"], issues: [{ file: denoFile, unlisted: [finding(source, "npm:yaml@2.8.3", "npm"), finding(source, "zod", "zod"), finding(source, "yaml", "yaml")] }] };
	const result = evaluateReport(report, approve);
	assert.equal(result.blocking.length, 2);
	assert.ok(result.blocking.every((line) => !line.includes('"name":"npm"')));
	assert.equal(result.counts.files, 1);
});

test("Knip package deduplication cannot conceal an unsafe sibling reference", (t) => {
	for (const bad of ["npm", "npm:yaml", "npm:yaml@^2"]) {
		const source = `import "npm:yaml@2.8.3";\nimport ${JSON.stringify(bad)};`;
		const { approve } = fixture(t, denoFile, source);
		assert.equal(approve({ file: denoFile }, "unlisted", finding(source, "npm:yaml@2.8.3", "npm")), false);
	}
	const source = `${requireSetup}require("yaml");\nimport "yaml";`;
	const { approve } = fixture(t, nodeFile, source);
	assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, "yaml", "yaml")), false);
});

test("core-anchored createRequire proves declared and installed packages", (t) => {
	for (const literal of ["yaml", "zod", "zod/package.json"]) {
		const source = `${requireSetup}require(${JSON.stringify(literal)});`;
		const { approve } = fixture(t, nodeFile, source);
		assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, literal, literal.split("/")[0])), true);
	}
	const source = 'import { createRequire as makeRequire } from "node:module";\nconst core = new URL("../packages/core/package.json", import.meta.url);\nconst load = makeRequire(core);\nload("yaml");';
	const { approve } = fixture(t, nodeFile, source);
	assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, "yaml", "yaml")), true);
});

test("Knip require member locations map only to the immediate audited call", (t) => {
	for (const setup of [requireSetup, ""]) {
		const source = `${setup}const version = require("zod/package.json").version;\nconst decoy = other.version;`;
		const { approve } = fixture(t, nodeFile, source);
		const at = (pos) => {
			const lines = source.slice(0, pos).split("\n");
			return { name: "zod", pos, line: lines.length, col: lines.at(-1).length + 2 };
		};
		const position = source.indexOf(").version") + 2;
		assert.equal(approve({ file: nodeFile }, "unlisted", at(position)), !!setup);
		assert.equal(approve({ file: nodeFile }, "unlisted", at(position + 1)), false);
		assert.equal(approve({ file: nodeFile }, "unlisted", at(source.indexOf("other.version") + 6)), false);
	}
});

test("undeclared, missing, wrong-anchor, shadowed and raw path imports still block", (t) => {
	const sources = [
		'require("yaml");',
		'import "../packages/core/node_modules/yaml/index.js";',
		`${requireSetup.replace("core/package.json", "core/src/policy.ts")}require("yaml");`,
		`${requireSetup.replace("core/package.json", "core-spoof/package.json")}require("yaml");`,
		`${requireSetup}function f(require) { return require("yaml"); }`,
		'import { createRequire } from "node:module";\nfunction f(createRequire) { const require = createRequire(new URL("../packages/core/package.json", import.meta.url)); require("yaml"); }',
		`const URL = class {};\n${requireSetup}require("yaml");`,
		`${requireSetup.replace("const require", "let require")}require("yaml");`,
	];
	for (const source of sources) {
		const literal = source.includes("node_modules") ? "../packages/core/node_modules/yaml/index.js" : "yaml";
		const { approve } = fixture(t, nodeFile, source);
		assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, literal, "yaml")), false, source);
	}
	for (const name of ["yaml", "zod", "npm"]) {
		const source = `${requireSetup}require(${JSON.stringify(name)});`;
		const { approve } = fixture(t, nodeFile, source, {});
		assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, name, name)), false);
	}
	const source = `${requireSetup}require("yaml/missing.js");`;
	const { approve } = fixture(t, nodeFile, source);
	assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, "yaml/missing.js", "yaml")), false);
});

test("unsupported and malformed sibling references cannot disappear in deduplication", (t) => {
	for (const sibling of ['import(`npm`);', 'import x = require("npm");', 'require.resolve("npm");']) {
		const source = `import "npm:yaml@2.8.3";\n${sibling}`;
		const { approve } = fixture(t, denoFile, source);
		assert.equal(approve({ file: denoFile }, "unlisted", finding(source, "npm:yaml@2.8.3", "npm")), false);
	}
	for (const sibling of ['import(`yaml`);', 'import "yaml/%2e%2e/zod";', 'other.require("yaml");']) {
		const source = `${requireSetup}require("yaml");\n${sibling}`;
		const { approve } = fixture(t, nodeFile, source);
		assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, "yaml", "yaml")), false);
	}
});

test("URL const aliases cannot be mutated or escape", (t) => {
	for (const mutation of ['core.pathname = "/other/package.json";', 'alter(core);', 'const alias = core; alias.pathname = "/other/package.json";']) {
		const source = `import { createRequire } from "node:module";\nconst core = new URL("../packages/core/package.json", import.meta.url);\n${mutation}\nconst require = createRequire(core);\nrequire("yaml");`;
		const { approve } = fixture(t, nodeFile, source);
		assert.equal(approve({ file: nodeFile }, "unlisted", finding(source, "yaml", "yaml")), false);
	}
});

test("invalid report shapes fail closed", () => {
	for (const report of [{}, [], null, { files: [], issues: [{ file: "x.ts", unlisted: { name: "yaml" } }] }, { files: [], issues: [], errors: ["error"] }]) {
		assert.throws(() => evaluateReport(report, () => false), /Invalid Knip/);
	}
});
