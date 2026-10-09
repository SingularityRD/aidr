import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { test } from "node:test";
import { KOFFI_WINDOWS_ARCHES, koffiNativeBinary, stageWindowsKoffi } from "./stage-windows-koffi.mjs";

// Koffi 3.3.2's dynamic lookup, exercising both untrusted fallback locations.
function loaderSource(esm) {
	return `${esm ? 'import fs from "node:fs";\nimport { createRequire } from "node:module";\nconst require2 = createRequire(import.meta.url);\nimport { loadStatic } from "./src/static.js";' : 'const fs = require("node:fs");\nconst require2 = require;\nvar { loadStatic } = require("./src/static.cjs");'}
function loadDynamic(dirname, pkg2, triplets2) {
  let suffix = "/../../build/koffi";
  let root = dirname + suffix;
  let roots = [root];
  let native2 = null;
  let err = null;
  if (process["resourcesPath"] != null) {
    let suffixes = [
      "/koffi",
      "/koffi/build",
      "/node_modules/koffi/build"
    ];
    for (let suffix2 of suffixes)
      roots.push(process["resourcesPath"] + suffix2);
  }
  let names = [
    \`\${${esm ? "import.meta.dirname" : "__dirname"}}/../../../@koromix/koffi-\${pkg2}\`,
    ...triplets2.flatMap((triplet) => roots.map((dir) => \`\${dir}/\${triplet}/koffi.node\`))
  ];
  for (let name of names) {
    if (!fs.existsSync(name))
      continue;
    try {
      native2 = require2(name);
      break;
    } catch (e) {
      err ??= e;
    }
  }
  if (native2 == null && err != null)
    throw err;
  return native2;
}
const pkg = process.platform + "-" + process.arch;
const triplets = [process.platform + "_" + process.arch];
const native = loadStatic(pkg) ?? loadDynamic(${esm ? "import.meta.dirname" : "__dirname"}, pkg, triplets);
if (native == null) throw new Error("Cannot find the native Koffi module");
${esm ? "export default native;" : "module.exports = native;"}
`;
}

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "aidr-koffi-staging-"));
	function write(file, contents) {
		mkdirSync(dirname(file), { recursive: true });
		writeFileSync(file, contents);
	}
	const source = join(root, "node_modules", "koffi");
	write(join(root, "package.json"), JSON.stringify({ type: "module" }));
	write(join(source, "package.json"), JSON.stringify({ name: "koffi", version: "3.3.2", main: "index.cjs", type: "module" }));
	write(join(source, "index.cjs"), "module.exports = {};\n");
	write(join(source, "LICENSE.txt"), "MIT fixture\n");
	for (const [ext, esm] of [["js", true], ["cjs", false]]) {
		write(join(source, "src", "koffi", `index.${ext}`), loaderSource(esm));
	}
	for (const arch of KOFFI_WINDOWS_ARCHES) {
		const native = join(root, "node_modules", "@koromix", `koffi-${arch.replace("_", "-")}`);
		write(join(native, "package.json"), JSON.stringify({ version: "3.3.2" }));
		write(join(native, arch, "koffi.node"), 'module.exports = { source: "staged" };\n');
	}
	const vendor = join(root, "dist", "vendor", "koffi");
	const resourceRoot = join(root, "electron-resources");
	const marker = join(root, "uncovered-code-executed");
	const uncovered = `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed"); throw new Error("Uncovered native module executed");\n`;
	write(join(root, "dist", "vendor", "@koromix", "koffi-win32-x64", "package.json"), JSON.stringify({ type: "commonjs" }));
	write(join(root, "dist", "vendor", "@koromix", "koffi-win32-x64", "index.js"), uncovered);
	write(join(resourceRoot, "koffi", "win32_x64", "koffi.node"), uncovered);
	return { root, source, vendor, resourceRoot, marker };
}

function cleanup(root) {
	const location = relative(resolve(tmpdir()), resolve(root));
	assert.ok(location.startsWith("aidr-koffi-staging-") && !location.includes(".."));
	rmSync(root, { recursive: true, force: true });
}

function probe(f, ext, missing) {
	const script = `
const assert = require("node:assert/strict");
const { pathToFileURL } = require("node:url");
Object.defineProperty(process, "platform", { value: "win32" });
Object.defineProperty(process, "arch", { value: "x64" });
process.resourcesPath = ${JSON.stringify(f.resourceRoot)};
// Fixture native bytes are JS; exercise lookup paths without requiring a host ABI.
require.extensions[".node"] = require.extensions[".js"];
(async () => {
  const load = async () => ${ext === "js" ? `import(pathToFileURL(${JSON.stringify(join(f.vendor, "index.js"))}).href)` : `require(${JSON.stringify(join(f.vendor, "index.cjs"))})`};
  ${missing ? 'await assert.rejects(load, /Cannot find the native Koffi module/);' : 'const loaded = await load(); assert.equal((loaded.default ?? loaded).source, "staged");'}
})().catch(error => { console.error(error); process.exitCode = 1; });
`;
	const result = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 10_000 });
	assert.equal(result.status, 0, result.stderr || result.error?.message);
	assert.equal(existsSync(f.marker), false, "A loader executed code outside the staged payload");
}

test("staged ESM and CJS native loaders ignore an adjacent package", () => {
	const f = fixture();
	try {
		assert.equal(stageWindowsKoffi(f.root, { isRelease: true }), true);
		for (const ext of ["js", "cjs"]) probe(f, ext, false);
	} finally {
		cleanup(f.root);
	}
});

test("missing staged binaries fail closed without trying adjacent or Electron resources", () => {
	const f = fixture();
	try {
		stageWindowsKoffi(f.root, { isRelease: true });
		rmSync(join(f.vendor, koffiNativeBinary("win32_x64")));
		for (const ext of ["js", "cjs"]) probe(f, ext, true);
	} finally {
		cleanup(f.root);
	}
});

test("changed upstream lookup fails staging before any payload is written", () => {
	const f = fixture();
	try {
		const path = join(f.source, "src", "koffi", "index.js");
		writeFileSync(path, readFileSync(path, "utf8").replace('process["resourcesPath"] != null', 'process["resourcesPath"] !== undefined'));
		assert.throws(() => stageWindowsKoffi(f.root, { isRelease: true }), /cannot restrict native lookup/);
		assert.equal(existsSync(f.vendor), false);
	} finally {
		cleanup(f.root);
	}
});
