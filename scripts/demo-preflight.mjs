#!/usr/bin/env node

/**
 * Deterministic preflight for the controlled customer/investor demo.
 *
 * This command only checks the demo surface and writes a redacted local
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
	for (const [pattern, label] of patterns) {
		if (!pattern.test(source)) failures.push(`${relativePath}: missing ${label}`);
	}
}

await requireText("packages/dashboard/src/main.tsx", [
	[/path: "demo"/, "demo route"],
	[/isControlledDemoRoute/, "Supabase-free demo escape hatch"],
	[/productionConfigMissing && !isControlledDemoRoute/, "configuration guard preserves demo route"],
]);
await requireText("packages/dashboard/src/ui/pages/public/DemoPage.tsx", [
	[/Controlled evaluation demo/, "controlled evaluation banner"],
	[/synthetic fixtures/, "synthetic-fixture boundary"],
	[/No external command/, "no-external-request warning"],
	[/demo-2026-08-04\.1/, "fixture version"],
]);
await requireText("packages/dashboard/src/ui/PublicLayout.tsx", [
	[/to="\/demo"/, "demo navigation link"],
	[/location\.pathname !== "\/demo"/, "demo configuration warning boundary"],
]);
await requireText("scripts/dashboard-route-smoke.mjs", [[/"\/demo"/, "demo route smoke coverage"]]);
await requireText("packages/dashboard/tests/browser-smoke.manifest.json", [[/"\/demo"/, "browser manifest demo route"]]);

if (!staticOnly && !(await exists("packages/dashboard/dist/index.html"))) {
	failures.push("packages/dashboard/dist/index.html is missing; run pnpm -C packages/dashboard build first");
}

if (process.env.VITE_AIDR_COMMERCIAL_MODE?.trim() === "self-service") {
	failures.push("VITE_AIDR_COMMERCIAL_MODE=self-service is not permitted for the direct-GA demo");
}

if (!process.env.VITE_SALES_URL?.trim() && !process.env.VITE_SALES_EMAIL?.trim()) {
	warnings.push("no sales URL/email configured; the invoice CTA will fail closed");
}
if (!process.env.DASHBOARD_SMOKE_BASE_URL?.trim()) {
	warnings.push("DASHBOARD_SMOKE_BASE_URL is absent; only the local/static demo route is verified");
}
if (!process.env.DEMO_USER_EMAIL?.trim() || !process.env.DEMO_USER_PASSWORD?.trim()) {
	warnings.push("DEMO_USER_EMAIL/DEMO_USER_PASSWORD are absent; credentialed browser onboarding is not ready");
}

if (failures.length) {
	console.error("Demo preflight: NO-GO");
	for (const failure of failures) console.error(`- ${failure}`);
	process.exitCode = 1;
} else {
	const receipt = {
		status: "ready-for-controlled-evaluation",
		mode: staticOnly ? "static-only" : "local-or-deployed",
		fixture_version: "demo-2026-08-04.1",
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
