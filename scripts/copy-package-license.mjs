#!/usr/bin/env node

import { existsSync } from "node:fs";
import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const modulePath = fileURLToPath(import.meta.url);
const defaultRepositoryRoot = path.resolve(path.dirname(modulePath), "..");

/** Include the repository license only when npm cannot auto-include a package-local one. */
export async function copyPackageLicense({ packageRoot, repositoryRoot = defaultRepositoryRoot }) {
	const resolvedPackageRoot = path.resolve(packageRoot);
	if (existsSync(path.join(resolvedPackageRoot, "LICENSE"))) return { copied: false, reason: "package-local license" };
	const source = path.join(path.resolve(repositoryRoot), "LICENSE");
	if (!existsSync(source)) throw new Error(`repository license is missing: ${source}`);
	const dist = path.join(resolvedPackageRoot, "dist");
	await mkdir(dist, { recursive: true });
	await copyFile(source, path.join(dist, "LICENSE"));
	return { copied: true, target: path.join(dist, "LICENSE") };
}

if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
	const result = await copyPackageLicense({ packageRoot: path.resolve(process.cwd(), process.argv[2] ?? ".") });
	console.log(result.copied ? `Copied repository license to ${result.target}` : "Package-local license already ships; no dist copy needed.");
}
