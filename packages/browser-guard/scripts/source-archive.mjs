#!/usr/bin/env node
/**
 * Writes the source package addons.mozilla.org asks for when an add-on ships bundled or
 * minified code: dist/aidr-browser-guard-source-<version>.zip, and adds it to
 * dist/SHA256SUMS. Run after `node scripts/build.mjs --release --zip`.
 *
 *   node scripts/source-archive.mjs [--out <dist dir>]
 *
 * The file list is not hand-maintained: esbuild's metafile names every source file the
 * five bundles are built from (including the shared packages/privacy and packages/core
 * modules), and every tsconfig.json / package.json esbuild consults for them is added, so
 * a reviewer who unpacks the archive and follows AMO-REVIEWER-NOTES.md rebuilds a
 * byte-identical Firefox package. The archive is deterministic (sorted entries, fixed
 * timestamps), so two release builds of the same commit give the same SHA-256.
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { ENTRIES, PACKAGE_ROOT, TARGETS, manifestVersion } from "./build.mjs";
import { createZip } from "./zip.mjs";

export const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
const PACKAGE_DIR = relative(REPO_ROOT, PACKAGE_ROOT).split(sep).join("/");

/** Build inputs that are not bundle sources. */
const BUILD_FILES = ["package.json", "tsconfig.json", "README.md", "scripts/build.mjs", "scripts/zip.mjs"];
const BUILD_DIRS = ["static", "_locales"];

const toPosix = (path) => path.split(sep).join("/");

function listFiles(dir) {
	const out = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...listFiles(full));
		else if (entry.isFile()) out.push(full);
	}
	return out;
}

/** Every tsconfig.json / package.json esbuild may read for `file`, plus tsconfig `extends` targets. */
function configFiles(file, seen = new Set()) {
	const found = [];
	for (let dir = dirname(file); dir.startsWith(REPO_ROOT); dir = dirname(dir)) {
		for (const name of ["tsconfig.json", "jsconfig.json", "package.json"]) {
			const candidate = join(dir, name);
			if (!existsSync(candidate) || seen.has(candidate)) continue;
			seen.add(candidate);
			found.push(candidate);
			if (name !== "package.json") {
				let extendsPath;
				try {
					extendsPath = JSON.parse(readFileSync(candidate, "utf8").replace(/^\s*\/\/.*$/gm, "")).extends;
				} catch (error) {
					throw new Error(`[browser-guard source] cannot read ${candidate}: ${error.message}`);
				}
				if (typeof extendsPath === "string" && extendsPath.startsWith(".")) {
					const target = resolve(dir, extendsPath.endsWith(".json") ? extendsPath : `${extendsPath}.json`);
					if (existsSync(target) && !seen.has(target)) {
						seen.add(target);
						found.push(target);
					}
				}
			}
		}
		if (dir === REPO_ROOT) break;
	}
	return found;
}

/** Absolute paths of every file the release bundles are built from. */
export async function bundleInputs(packageRoot = PACKAGE_ROOT) {
	const esbuild = await import("esbuild");
	const inputs = new Set();
	for (const target of Object.keys(TARGETS)) {
		for (const entry of ENTRIES) {
			const result = await esbuild.build({
				absWorkingDir: packageRoot,
				entryPoints: [join(packageRoot, entry.source)],
				bundle: true,
				write: false,
				metafile: true,
				format: "iife",
				platform: "browser",
				target: [TARGETS[target].esbuildTarget],
				logLevel: "silent",
				define: { __AIDR_VERSION__: '"0"', __AIDR_TARGET__: JSON.stringify(target) },
			});
			for (const input of Object.keys(result.metafile.inputs)) {
				const file = resolve(packageRoot, input);
				if (existsSync(file)) inputs.add(file);
			}
		}
	}
	// The manifest's site list is read from src/sites/index.ts at build time.
	inputs.add(join(packageRoot, "src", "sites", "index.ts"));
	return [...inputs].sort();
}

function reviewerNotes({ version, esbuildVersion, firefoxSha, nodeEngine }) {
	return `# Singularity AIDR Browser Guard ${version}: build instructions for reviewers

This archive holds every source file the extension's bundles are built from
(\`${PACKAGE_DIR}/src\` and the shared modules under \`packages/privacy/src\` and
\`packages/core/src\` that it imports), the build script and the static files.
The bundles are produced by esbuild only: no other code generator, no obfuscation.

Requirements: Node.js ${nodeEngine} and esbuild ${esbuildVersion} (exact).

\`\`\`bash
cd ${PACKAGE_DIR}
npm install --no-save --no-package-lock esbuild@${esbuildVersion}
node scripts/build.mjs --release --zip
sha256sum dist/aidr-browser-guard-firefox-${version}.zip
\`\`\`

Expected SHA-256 of \`dist/aidr-browser-guard-firefox-${version}.zip\` (the uploaded package):

    ${firefoxSha}

The build is deterministic (sorted zip entries, fixed timestamps and permissions), so
the hash matches when the same esbuild version is used. \`dist/firefox/\` holds the
unpacked files. Readable copies of the bundles: \`node scripts/build.mjs\` (no
\`--release\`) writes unminified bundles with inline source maps.
`;
}

/**
 * Writes the source archive next to the release zips and lists it in SHA256SUMS.
 * @returns {{ archive: string; files: string[] }}
 */
export async function writeSourceArchive({ outDir = join(PACKAGE_ROOT, "dist"), log = console.log } = {}) {
	const packageJson = JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8"));
	const { version } = manifestVersion(String(packageJson.version));
	const sumsFile = join(outDir, "SHA256SUMS");
	const firefoxZip = `aidr-browser-guard-firefox-${version}.zip`;
	if (!existsSync(sumsFile) || !existsSync(join(outDir, firefoxZip))) {
		throw new Error(`[browser-guard source] run the release build first: ${firefoxZip} / SHA256SUMS missing in ${outDir}`);
	}

	const files = new Set();
	for (const input of await bundleInputs()) {
		if (input.includes(`${sep}node_modules${sep}`)) {
			throw new Error(`[browser-guard source] bundle input from node_modules is not covered by the reviewer notes: ${input}`);
		}
		files.add(input);
	}
	for (const name of BUILD_FILES) files.add(join(PACKAGE_ROOT, name));
	for (const dir of BUILD_DIRS) for (const file of listFiles(join(PACKAGE_ROOT, dir))) files.add(file);
	const seen = new Set();
	for (const file of [...files]) for (const config of configFiles(file, seen)) files.add(config);

	const esbuildVersion = createRequire(join(PACKAGE_ROOT, "package.json"))("esbuild/package.json").version;
	const firefoxSha = createHash("sha256").update(readFileSync(join(outDir, firefoxZip))).digest("hex");
	const entries = [...files]
		.filter((file) => statSync(file).isFile())
		.map((file) => ({ name: toPosix(relative(REPO_ROOT, file)), data: readFileSync(file) }));
	entries.push({
		name: "AMO-REVIEWER-NOTES.md",
		data: Buffer.from(
			reviewerNotes({ version, esbuildVersion, firefoxSha, nodeEngine: packageJson.engines?.node ?? ">=22.12.0" }),
		),
	});

	const archiveName = `aidr-browser-guard-source-${version}.zip`;
	const archive = createZip(entries);
	writeFileSync(join(outDir, archiveName), archive);
	const digest = createHash("sha256").update(archive).digest("hex");
	const lines = readFileSync(sumsFile, "utf8")
		.split("\n")
		.filter((line) => line.trim() !== "" && !line.endsWith(`  ${archiveName}`));
	lines.push(`${digest}  ${archiveName}`);
	writeFileSync(sumsFile, `${lines.sort().join("\n")}\n`);
	log(`[browser-guard] packaged ${archiveName} (${entries.length} files, ${archive.length} bytes)`);
	return { archive: join(outDir, archiveName), files: entries.map((e) => e.name).sort() };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const args = process.argv.slice(2);
	const outIndex = args.indexOf("--out");
	if (args.length > 0 && (outIndex !== 0 || args.length !== 2)) {
		console.error("usage: source-archive.mjs [--out <dist dir>]");
		process.exit(2);
	}
	try {
		await writeSourceArchive(outIndex === 0 ? { outDir: resolve(args[1]) } : {});
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
