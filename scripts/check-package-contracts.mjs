/**
 * Verify that every release package's declared entry points are present in its
 * generated artifact. Package managers do not validate `main`, `exports`, or
 * `bin` paths when creating a tarball, so a release can otherwise look green
 * while failing on the first consumer import or command invocation.
 *
 * Usage: node scripts/check-package-contracts.mjs [packageDir ...]
 */

import { access, readdir, stat } from "node:fs/promises";
import path from "node:path";

const repoRoot = process.cwd();
const packageDirs = process.argv.slice(2).map((p) => path.resolve(repoRoot, p));

if (packageDirs.length === 0) {
	console.error("Usage: node scripts/check-package-contracts.mjs <packageDir ...>");
	process.exit(2);
}

const failures = [];

for (const packageDir of packageDirs) {
	const packageJsonPath = path.join(packageDir, "package.json");
	const distDir = path.join(packageDir, "dist");
	let pkg;
	try {
		pkg = JSON.parse(await readText(packageJsonPath));
	} catch (error) {
		failures.push(`${packageJsonPath}: cannot read package.json (${formatError(error)})`);
		continue;
	}

	if (!(await isDirectory(distDir))) {
		failures.push(`${pkg.name ?? packageDir}: missing dist/ directory`);
		continue;
	}

	const declared = new Set();
	for (const field of ["main", "module", "types"]) {
		if (typeof pkg[field] === "string") declared.add(pkg[field]);
	}
	collectPathStrings(pkg.bin, declared);
	collectExportPaths(pkg.exports, declared);

	for (const declaredPath of declared) {
		if (!declaredPath.startsWith("./")) continue;
		const resolved = path.resolve(packageDir, declaredPath);
		if (!isWithin(resolved, packageDir)) {
			failures.push(`${pkg.name ?? packageDir}: declared path escapes package: ${declaredPath}`);
			continue;
		}
		if (!(await isFile(resolved))) {
			failures.push(`${pkg.name ?? packageDir}: missing declared artifact ${declaredPath}`);
		}
	}

	const manifestPath = path.join(distDir, "aidr-artifact.manifest.json");
	if (!(await isFile(manifestPath))) {
		failures.push(`${pkg.name ?? packageDir}: missing dist/aidr-artifact.manifest.json`);
	}
}

if (failures.length > 0) {
	console.error("ERROR: release package contracts are incomplete:");
	for (const failure of failures) console.error(`  - ${failure}`);
	process.exit(1);
}

console.log(`Package contract check passed for ${packageDirs.length} package(s).`);

function collectPathStrings(value, output) {
	if (typeof value === "string") {
		output.add(value);
		return;
	}
	if (!value || typeof value !== "object") return;
	for (const child of Object.values(value)) collectPathStrings(child, output);
}

function collectExportPaths(value, output) {
	if (typeof value === "string") {
		output.add(value);
		return;
	}
	if (!value || typeof value !== "object") return;
	for (const [key, child] of Object.entries(value)) {
		// `types`, `import`, `require`, and nested condition keys are handled by
		// recursion; export subpath keys themselves are not filesystem paths.
		if (key.startsWith(".")) collectExportPaths(child, output);
		else collectPathStrings(child, output);
	}
}

async function readText(filePath) {
	const { readFile } = await import("node:fs/promises");
	return readFile(filePath, "utf8");
}

async function isFile(filePath) {
	try {
		return (await stat(filePath)).isFile();
	} catch {
		return false;
	}
}

async function isDirectory(dirPath) {
	try {
		return (await stat(dirPath)).isDirectory();
	} catch {
		return false;
	}
}

function isWithin(candidate, root) {
	const relative = path.relative(root, candidate);
	return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}
