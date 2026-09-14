/**
 * Packaging hardening: fail if release artifacts include sourcemaps or
 * sourceMappingURL references.
 *
 * Usage:
 *   node scripts/check-no-sourcemaps.mjs [path]
 *
 * Defaults to current working directory. Scans any dist/ folders under the
 * provided path.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { IGNORE_DIRS, SOURCE_MAPPING_DIRECTIVE_RE, SOURCE_URL_DIRECTIVE_RE, isDistDir, isSourceMapFile } from "./lib/package-artifact-rules.mjs";

const root = path.resolve(process.argv[2] || ".");

const mapFiles = [];
const mappingUrlHits = [];
const sourceUrlHits = [];
const absPathHits = [];

const forbiddenNeedles = buildForbiddenNeedles(process.cwd());

await scan(root);

if (mapFiles.length || mappingUrlHits.length || sourceUrlHits.length || absPathHits.length) {
	console.error("ERROR: release artifacts must not include debug/sourcemap leakage.");
	if (mapFiles.length) {
		console.error("\nFound .map files:");
		for (const file of mapFiles) console.error(`  ${file}`);
	}
	if (mappingUrlHits.length) {
		console.error("\nFound sourceMappingURL references:");
		for (const hit of mappingUrlHits) console.error(`  ${hit}`);
	}
	if (sourceUrlHits.length) {
		console.error("\nFound sourceURL references:");
		for (const hit of sourceUrlHits) console.error(`  ${hit}`);
	}
	if (absPathHits.length) {
		console.error("\nFound build-machine absolute path leakage:");
		for (const hit of absPathHits) console.error(`  ${hit}`);
		console.error("\nForbidden needles (derived from current working directory):");
		for (const n of forbiddenNeedles) console.error(`  ${n}`);
	}
	process.exit(1);
}

async function scan(startPath) {
	let st;
	try {
		st = await stat(startPath);
	} catch {
		return;
	}

	if (st.isDirectory() && isDistDir(startPath)) {
		await scanDist(startPath);
		return;
	}

	await walkForDistDirs(startPath);
}

async function walkForDistDirs(current) {
	let entries;
	try {
		entries = await readdir(current, { withFileTypes: true });
	} catch {
		return;
	}

	for (const entry of entries) {
		if (!entry.isDirectory()) continue;
		if (IGNORE_DIRS.has(entry.name)) continue;

		const full = path.join(current, entry.name);
		if (isDistDir(full)) {
			await scanDist(full);
			continue;
		}
		await walkForDistDirs(full);
	}
}

async function scanDist(distDir) {
	const stack = [distDir];
	while (stack.length) {
		const dir = stack.pop();
		let entries;
		try {
			entries = await readdir(dir, { withFileTypes: true });
		} catch {
			continue;
		}

		for (const entry of entries) {
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				stack.push(full);
				continue;
			}
			if (!entry.isFile()) continue;

			if (isSourceMapFile(entry.name)) {
				mapFiles.push(full);
				continue;
			}

			const isJsLike = /\.(c|m)?js$/i.test(entry.name);
			const isCss = /\.css$/i.test(entry.name);
			const isJson = /\.json$/i.test(entry.name);

			// Cheap scan for esbuild/tsc "sourceMappingURL=" trailer (JS/CJS/MJS)
			// and CSS sourcemap comments.
			if (isJsLike || isCss || isJson) {
				let data;
				try {
					data = await readFile(full, "utf8");
				} catch {
					continue;
				}
				if (SOURCE_MAPPING_DIRECTIVE_RE.test(data)) {
					mappingUrlHits.push(full);
				}
				if (isJsLike && SOURCE_URL_DIRECTIVE_RE.test(data)) {
					sourceUrlHits.push(full);
				}
				if (containsAnyNeedle(data, forbiddenNeedles)) {
					absPathHits.push(full);
				}
			}
		}
	}
}

function buildForbiddenNeedles(cwd) {
	const p = path.resolve(cwd);
	const win = p.replace(/\//g, "\\");
	const posix = p.replace(/\\/g, "/");
	const fileUrl =
		process.platform === "win32"
			? `file:///${posix.replace(/^([A-Za-z]):/, (_, d) => `${d.toUpperCase()}:`)}`
			: `file://${posix}`;
	return [p, win, posix, fileUrl];
}

function containsAnyNeedle(haystack, needles) {
	const h = haystack.toLowerCase();
	for (const n of needles) {
		if (!n) continue;
		if (h.includes(String(n).toLowerCase())) return true;
	}
	return false;
}
