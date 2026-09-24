#!/usr/bin/env node

/**
 * Deterministic preflight for customer access to a configured deployment.
 *
 * This command checks the customer entry points and writes a redacted local
 * receipt. It never creates a Supabase user, changes a tenant, or contacts a
 * production endpoint.
 */

import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const staticOnly = process.argv.includes("--static");
const failures = [];
const warnings = [];

async function exists(relativePath) {
	try {
		await access(path.join(root, relativePath));
		return true;
	} catch {
		return false;
	}
}

async function requireText(relativePath, patterns) {
	const file = path.join(root, relativePath);
	let source;
	try {
		source = await readFile(file, "utf8");
	} catch {
		failures.push(`missing ${relativePath}`);
		return;
	}
	for (const [pattern, label, forbidden] of patterns) {
		if (forbidden ? pattern.test(source) : !pattern.test(source)) {
			failures.push(`${relativePath}: ${forbidden ? "contains" : "missing"} ${label}`);
		}
	}
}

await requireText("packages/dashboard/src/main.tsx", [
	[/path: "demo", loader: \(\) => redirect\("\/login\?returnTo=%2Fonboarding"\)/, "legacy demo redirects to sign-in"],
	[/\{productionConfigMissing \? \(/, "production configuration guard covers every route"],
	[/DemoPage|isControlledDemoRoute/, "synthetic demo app import or configuration exception", true],
]);
await requireText("packages/dashboard/src/ui/PublicLayout.tsx", [
	[/<NavLink to="\/login">Dashboard<\/NavLink>/, "real dashboard navigation"],
	[/to="\/demo"/, "synthetic demo navigation", true],
]);
await requireText("packages/dashboard/src/ui/pages/public/LandingPage.tsx", [
	[/to="\/login\?returnTo=%2Fonboarding"/, "onboarding sign-in link"],
	[/to="\/demo"|href: "\/demo"/, "synthetic demo CTA", true],
]);
await requireText("scripts/dashboard-route-smoke.mjs", [[/legacyRoutes = \["\/demo"\]/, "legacy route smoke coverage"]]);
await requireText("packages/dashboard/tests/browser-smoke.manifest.json", [[/legacy-demo-redirect/, "browser redirect scenario"]]);

if (!staticOnly) {
	if (!(await exists("packages/dashboard/dist/index.html"))) {
		failures.push("packages/dashboard/dist/index.html is missing; run pnpm -C packages/dashboard build first");
	}
	for (const name of ["VITE_SUPABASE_URL", "VITE_SUPABASE_ANON_KEY", "DASHBOARD_SMOKE_BASE_URL", "DEMO_USER_EMAIL", "DEMO_USER_PASSWORD"]) {
		if (!process.env[name]?.trim()) failures.push(`${name} is required for a live customer walkthrough`);
	}
}

if (process.env.VITE_AIDR_COMMERCIAL_MODE?.trim() === "self-service") {
	failures.push("VITE_AIDR_COMMERCIAL_MODE=self-service is not permitted for the direct-GA demo");
}

if (!process.env.VITE_SALES_URL?.trim() && !process.env.VITE_SALES_EMAIL?.trim()) {
	warnings.push("no sales URL/email configured; the invoice CTA will fail closed");
}
if (staticOnly) warnings.push("source-contract check only; live sign-in and onboarding require a deployed browser test");

if (failures.length) {
	console.error("Demo preflight: NO-GO");
	for (const failure of failures) console.error(`- ${failure}`);
	process.exitCode = 1;
} else {
	const receipt = {
		status: "ready-for-browser-validation",
		mode: staticOnly ? "static-only" : "local-or-deployed",
		generated_at: new Date().toISOString(),
		production_claims_allowed: false,
		live_supabase_configured: Boolean(process.env.VITE_SUPABASE_URL && process.env.VITE_SUPABASE_ANON_KEY),
		credentialed_browser_configured: Boolean(process.env.DEMO_USER_EMAIL && process.env.DEMO_USER_PASSWORD),
		warnings,
	};
	if (!staticOnly) {
		const evidenceDir = path.join(root, ".e2e-artifacts", "demo");
		await mkdir(evidenceDir, { recursive: true });
		const evidencePath = path.join(evidenceDir, "preflight.json");
		await writeFile(evidencePath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
		console.log(`Demo preflight: PASS (controlled evaluation); receipt: ${evidencePath}`);
	} else {
		console.log("Demo preflight: PASS (static-only controlled evaluation surface)");
	}
	for (const warning of warnings) console.warn(`WARN: ${warning}`);
}
