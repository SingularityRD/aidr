#!/usr/bin/env node
/**
 * Ensure published workspace packages do not install the same command name.
 * npm/pnpm place every package bin in one consumer bin directory, so duplicate
 * names make the last-installed package silently win.
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptRoot, "..");

export function duplicateBins(manifests) {
	const owners = new Map();
	for (const manifest of manifests) {
		for (const name of Object.keys(manifest.package?.bin ?? {})) {
			const list = owners.get(name) ?? [];
			list.push(manifest.name ?? manifest.path ?? "(unnamed package)");
			owners.set(name, list);
		}
	}
	return [...owners.entries()]
		.filter(([, packages]) => packages.length > 1)
		.map(([name, packages]) => ({ name, packages }));
}

export function readWorkspaceBinManifests(root = repoRoot) {
	const packagesDir = path.join(root, "packages");
	const entries = readdirSync(packagesDir, { withFileTypes: true });
	const manifests = [];
	for (const entry of entries) {
		if (!entry.isDirectory()) continue;
		const manifestPath = path.join(packagesDir, entry.name, "package.json");
		if (!existsSync(manifestPath)) continue;
		const packageJson = JSON.parse(readFileSync(manifestPath, "utf8"));
		if (!packageJson.bin || typeof packageJson.bin !== "object") continue;
		manifests.push({ path: path.relative(root, manifestPath), name: packageJson.name, package: packageJson });
	}
	return manifests;
}

export function verifyWorkspaceBins(root = repoRoot) {
	const duplicates = duplicateBins(readWorkspaceBinManifests(root));
	if (duplicates.length > 0) {
		const detail = duplicates.map(({ name, packages }) => `${name}: ${packages.join(", ")}`).join("; ");
		throw new Error(`duplicate published bin name(s): ${detail}`);
	}
	return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		verifyWorkspaceBins();
		console.log("Published package bin names are unique.");
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
}
