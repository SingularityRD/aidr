#!/usr/bin/env node
// Deno type-check every Supabase Edge Function entry point.
//
// The list is generated from the supabase/functions directory instead of being
// maintained by hand, so a new function cannot ship without passing the Deno
// type checker (vitest contract suites mock npm: specifiers and Deno globals and
// would not catch a Deno-only type or import error).
//
// Usage: node scripts/check-edge-functions-typed.mjs [--list]
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const DENO_VERSION = "2.5.2";

/** Directories under supabase/functions that are not deployable functions. */
const NON_FUNCTION_DIRS = new Set(["_shared", "__tests__"]);

/**
 * Return every `supabase/functions/<name>/index.ts` (repo-relative, sorted).
 * A function directory without an index.ts is reported as an error so the gate
 * cannot silently skip a mis-shaped function.
 */
export function edgeFunctionEntryPoints(root) {
	const functionsDir = path.join(root, "supabase", "functions");
	const entries = [];
	const missing = [];
	for (const dirent of readdirSync(functionsDir, { withFileTypes: true })) {
		if (!dirent.isDirectory() || NON_FUNCTION_DIRS.has(dirent.name) || dirent.name.startsWith(".")) continue;
		const entry = path.join(functionsDir, dirent.name, "index.ts");
		if (existsSync(entry)) entries.push(`supabase/functions/${dirent.name}/index.ts`);
		else missing.push(dirent.name);
	}
	if (missing.length > 0) {
		throw new Error(`Edge Function directories without index.ts: ${missing.sort().join(", ")}`);
	}
	return entries.sort();
}

export function denoCheckArgs(entryPoints) {
	return [
		"dlx",
		`deno@${DENO_VERSION}`,
		"check",
		"--node-modules-dir=none",
		"--lock=supabase/functions/deno.lock",
		"--frozen",
		...entryPoints,
	];
}

function main() {
	const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
	const entryPoints = edgeFunctionEntryPoints(root);
	if (process.argv.includes("--list")) {
		for (const entry of entryPoints) console.log(entry);
		return;
	}
	console.log(`Deno type-checking ${entryPoints.length} Edge Functions`);
	const result = spawnSync("pnpm", denoCheckArgs(entryPoints), {
		cwd: root,
		stdio: "inherit",
		shell: process.platform === "win32",
	});
	if (result.error) {
		console.error(result.error.message);
		process.exit(1);
	}
	process.exit(result.status ?? 1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
