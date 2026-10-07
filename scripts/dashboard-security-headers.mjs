#!/usr/bin/env node
// Render the dashboard's static-hosting header files from the single source of
// truth in deploy/dashboard/security-headers.mjs.
//
//   node scripts/dashboard-security-headers.mjs          # check, exit 1 on drift
//   node scripts/dashboard-security-headers.mjs --write  # rewrite the files
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderCloudflareHeaders, renderVercelHeaders } from "../deploy/dashboard/security-headers.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const VERCEL_FILE = join(root, "packages/dashboard/vercel.json");
export const CLOUDFLARE_FILE = join(root, "packages/dashboard/public/_headers");

/** Expected file contents; vercel.json keeps every key other than `headers`. */
export function expectedFiles() {
	const vercel = JSON.parse(readFileSync(VERCEL_FILE, "utf8"));
	return {
		[VERCEL_FILE]: `${JSON.stringify({ ...vercel, headers: renderVercelHeaders() }, null, "\t")}\n`,
		[CLOUDFLARE_FILE]: renderCloudflareHeaders(),
	};
}

/** Paths whose committed content differs from the rendered source of truth. */
export function driftedFiles() {
	const drifted = [];
	const expected = expectedFiles();
	const vercel = JSON.parse(readFileSync(VERCEL_FILE, "utf8"));
	if (JSON.stringify(vercel.headers) !== JSON.stringify(renderVercelHeaders())) drifted.push(VERCEL_FILE);
	if (readFileSync(CLOUDFLARE_FILE, "utf8").replace(/\r\n/g, "\n") !== expected[CLOUDFLARE_FILE]) drifted.push(CLOUDFLARE_FILE);
	return drifted;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
	if (process.argv.includes("--write")) {
		for (const [path, content] of Object.entries(expectedFiles())) writeFileSync(path, content);
	} else {
		const drifted = driftedFiles();
		if (drifted.length > 0) {
			console.error(`Security headers drifted from deploy/dashboard/security-headers.mjs:\n${drifted.join("\n")}\nRun: node scripts/dashboard-security-headers.mjs --write`);
			process.exit(1);
		}
	}
}
