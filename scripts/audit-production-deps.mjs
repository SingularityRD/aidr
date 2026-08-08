/**
 * Production dependency security gate.
 *
 * `pnpm audit` intentionally remains the source of truth.  This wrapper only
 * permits a narrowly scoped false-positive exception when the application
 * proves that the affected code path is not part of the product.  Any new
 * advisory, path, or React Router server/RSC usage fails closed.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = resolve(fileURLToPath(new URL(".", import.meta.url)));
const rootDir = resolve(scriptDir, "..");
const pnpmCommand = process.platform === "win32" ? "pnpm.cmd" : "pnpm";

const audit = spawnSync(pnpmCommand, ["audit", "--prod", "--json"], {
	cwd: rootDir,
	encoding: "utf8",
	maxBuffer: 32 * 1024 * 1024,
	shell: process.platform === "win32",
});

const output = (audit.stdout ?? "").trim();
if (!output) {
	console.error("Production dependency audit produced no JSON output.");
	if (audit.error) console.error(audit.error);
	if (audit.stderr) console.error(audit.stderr.trim());
	process.exit(1);
}

let report;
try {
	report = JSON.parse(output);
} catch (error) {
	console.error("Unable to parse pnpm audit JSON:", error);
	if (audit.stderr) console.error(audit.stderr.trim());
	process.exit(1);
}

const advisories = Object.values(report.advisories ?? {});
const allowedRscAdvisoryId = "1124282";

function collectSourceText(directory) {
	const chunks = [];
	const visit = (current) => {
		for (const entry of readdirSync(current, { withFileTypes: true })) {
			if (entry.name === "node_modules" || entry.name === "dist" || entry.name === ".git") {
				continue;
			}
			const path = join(current, entry.name);
			if (entry.isDirectory()) {
				visit(path);
				continue;
			}
			if (/\.(?:ts|tsx|js|jsx|mjs|cjs)$/.test(entry.name)) {
				chunks.push(`${path}\n${readFileSync(path, "utf8")}`);
			}
		}
	};
	visit(directory);
	return chunks.join("\n");
}

function verifyReactRouterIsClientOnly() {
	const dashboardSource = collectSourceText(join(rootDir, "packages", "dashboard", "src"));
	const forbiddenRscPatterns = [
		/unstable[^\n]{0,100}\brsc\b/i,
		/\brsc\b[^\n]{0,100}react-router/i,
		/react-router\/(?:server|node|dom\/server)/i,
		/\b(?:ServerRouter|RSCHydratedRouter|RSCStaticRouter|matchRSC|createRSC)\b/i,
	];
	const hits = forbiddenRscPatterns.flatMap((pattern) => {
		const match = dashboardSource.match(pattern);
		return match ? [match[0]] : [];
	});
	if (hits.length > 0) {
		return `React Router RSC/server marker found in dashboard source: ${hits.join(" | ")}`;
	}
	if (!dashboardSource.includes("createBrowserRouter") || !dashboardSource.includes("RouterProvider")) {
		return "Dashboard router proof is missing createBrowserRouter + RouterProvider client markers.";
	}

	const dashboardManifest = JSON.parse(
		readFileSync(join(rootDir, "packages", "dashboard", "package.json"), "utf8"),
	);
	const declaredRange = dashboardManifest.dependencies?.["react-router-dom"];
	if (typeof declaredRange !== "string" || !/(?:^|[^0-9])7\./.test(declaredRange)) {
		return `Dashboard react-router-dom declaration is not pinned to the v7 client line: ${declaredRange}`;
	}
	return null;
}

const failures = [];
for (const advisory of advisories) {
	const id = String(advisory.id);
	if (id !== allowedRscAdvisoryId) {
		failures.push(`${id} ${advisory.module_name} (${advisory.severity})`);
		continue;
	}

	const paths = advisory.findings?.flatMap((finding) => finding.paths ?? []) ?? [];
	const expectedPath = "packages__dashboard>react-router-dom>react-router";
	if (advisory.module_name !== "react-router" || paths.some((path) => path !== expectedPath)) {
		failures.push(`${id} path/module changed; RSC allowlist no longer applies`);
		continue;
	}
	const clientOnlyFailure = verifyReactRouterIsClientOnly();
	if (clientOnlyFailure) {
		failures.push(`${id} RSC allowlist proof failed: ${clientOnlyFailure}`);
	}
}

const summary = report.metadata?.vulnerabilities ?? {};
console.log(
	`Production dependency audit: ${advisories.length} advisory(ies); ` +
	`critical=${summary.critical ?? 0}, high=${summary.high ?? 0}, ` +
	`moderate=${summary.moderate ?? 0}, low=${summary.low ?? 0}.`,
);

if (failures.length > 0) {
	console.error("Production dependency audit failed:");
	for (const failure of failures) console.error(`- ${failure}`);
	process.exit(1);
}

if (advisories.some((advisory) => String(advisory.id) === allowedRscAdvisoryId)) {
	console.log(
		`Allowed ${allowedRscAdvisoryId}: React Router RSC-only advisory; ` +
		"dashboard source is verified client-only (createBrowserRouter/RouterProvider, no RSC/server APIs).",
	);
}

process.exit(0);
