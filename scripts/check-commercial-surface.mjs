import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { validateCommercialReadiness } from "./check-commercial-readiness.mjs";

const root = process.cwd();
const files = {
	dashboardCommercial: path.join(root, "packages", "dashboard", "src", "billing", "commercial.ts"),
	dashboardBilling: path.join(root, "packages", "dashboard", "src", "ui", "pages", "BillingPage.tsx"),
	legacyRouter: path.join(root, "packages", "dashboard", "src", "billing", "payment-router.ts"),
	providerSelector: path.join(root, "packages", "dashboard", "src", "billing", "provider-selector.tsx"),
	checkout: path.join(root, "supabase", "functions", "billing-checkout", "index.ts"),
	webhook: path.join(root, "supabase", "functions", "paddle-webhook", "index.ts"),
	docs: path.join(root, "docs", "billing.md"),
};

const contents = new Map(await Promise.all(Object.entries(files).map(async ([key, file]) => [key, await readFile(file, "utf8")])))
const failures = [];
const requirePattern = (key, pattern, description) => {
	if (!pattern.test(contents.get(key) ?? "")) failures.push(`${key}: missing ${description}`);
};

requirePattern("dashboardCommercial", /VITE_AIDR_COMMERCIAL_MODE\s*\?\?\s*["']invoice["']/i, "invoice-only default");
requirePattern("dashboardCommercial", /requestedMode\s*===\s*["']self-service["']/i, "explicit self-service opt-in");
requirePattern("dashboardBilling", /selfServiceCheckoutEnabled\s*\?/i, "dashboard checkout gate");
requirePattern("legacyRouter", /if\s*\(!selfServiceCheckoutEnabled\)/i, "legacy payment-router gate");
requirePattern("providerSelector", /if\s*\(!selfServiceCheckoutEnabled\)\s*return\s*\[\]/i, "legacy provider-selector gate");
for (const key of ["checkout", "webhook"]) {
	requirePattern(key, /AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING/i, "legacy billing environment gate");
	requirePattern(key, /disabled_for_direct_ga/i, "direct-GA fail-closed response");
}
requirePattern("docs", /enterprise invoice\/order workflow/i, "invoice/order source-of-truth documentation");

const [inventory, gaps, registry, releaseSource] = await Promise.all([
	readFile(path.join(root, "FEATURE_INVENTORY.json"), "utf8").then(JSON.parse),
	readFile(path.join(root, "PRODUCTION_SALES_GAPS.json"), "utf8").then(JSON.parse),
	readFile(path.join(root, "docs", "production-readiness", "commercial-go-evidence-registry.json"), "utf8").then(JSON.parse),
	readFile(path.join(root, "scripts", "release-artifact-manifests.mjs"), "utf8"),
]);
failures.push(...validateCommercialReadiness({ inventory, gaps, registry, releaseSource }));

if (failures.length) {
	console.error("Commercial surface contract failed:");
	for (const failure of failures) console.error(`- ${failure}`);
	process.exitCode = 1;
} else {
	console.log("Commercial surface contract passed (invoice defaults, release package scope, readiness counts, and claim approval state).");
}
