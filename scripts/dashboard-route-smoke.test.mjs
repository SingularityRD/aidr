import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { assertSecurityHeaders, resolveDocumentAssets } from "./dashboard-route-smoke.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath) {
	return readFileSync(resolve(root, relativePath), "utf8");
}

test("root-based dashboard assets stay at the origin root on nested routes", () => {
	const html = `
		<script type="module" src="/assets/app.js"></script>
		<link rel="stylesheet" href="/assets/app.css">
		<script src="/runtime-config.js"></script>
	`;
	assert.deepEqual(resolveDocumentAssets(html, "https://dashboard.example/auth/callback"), [
		{ url: "https://dashboard.example/assets/app.js", kind: "script" },
		{ url: "https://dashboard.example/assets/app.css", kind: "style" },
		{ url: "https://dashboard.example/runtime-config.js", kind: "script" },
	]);
});

test("local route smoke starts the installed Vite CLI directly, without a shell", () => {
	const smoke = read("scripts/dashboard-route-smoke.mjs");
	assert.match(
		smoke,
		/spawn\(\s*process\.execPath,\s*\[join\(dashboardRoot, "node_modules", "vite", "bin", "vite\.js"\), "preview"/s,
	);
	assert.doesNotMatch(smoke, /shell:\s*process\.platform\s*===\s*"win32"/);
});

test("retired demo address redirects to real onboarding and has no public fixture entry", () => {
	const main = read("packages/dashboard/src/main.tsx");
	const publicLayout = read("packages/dashboard/src/ui/PublicLayout.tsx");
	const landing = read("packages/dashboard/src/ui/pages/public/LandingPage.tsx");
	const manifest = JSON.parse(read("packages/dashboard/tests/browser-smoke.manifest.json"));
	assert.match(main, /path: "demo", loader: \(\) => redirect\("\/login\?returnTo=%2Fonboarding"\)/);
	assert.doesNotMatch(main, /DemoPage|isControlledDemoRoute/);
	assert.doesNotMatch(publicLayout, /to="\/demo"/);
	assert.doesNotMatch(landing, /to="\/demo"|href: "\/demo"/);
	assert.deepEqual(manifest.routes.legacy, ["/demo"]);
	assert.ok(manifest.scenarios.some((scenario) => scenario.id === "legacy-demo-redirect"));
});

test("remote header validation rejects missing or weakened deployment controls", () => {
	const headers = new Headers({
		"strict-transport-security": "max-age=63072000; includeSubDomains; preload",
		"content-security-policy": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; connect-src 'self' https://*.sentry.io https://*.ingest.sentry.io",
		"x-content-type-options": "nosniff",
		"x-frame-options": "DENY",
		"referrer-policy": "strict-origin-when-cross-origin",
		"permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
	});
	assert.doesNotThrow(() => assertSecurityHeaders(headers));

	headers.delete("content-security-policy");
	assert.throws(() => assertSecurityHeaders(headers), /missing content-security-policy/);
});

test("dashboard Sentry configuration has one documented operator namespace", () => {
	const server = read("deploy/dashboard/server.mjs");
	const prepare = read("scripts/deployment-prepare.mjs");
	const vite = read("packages/dashboard/vite.config.ts");
	const environmentExample = read(".env.example");
	const deploymentDocs = read("docs/runbooks/deployment.md");

	for (const name of ["SENTRY_DSN", "SENTRY_ENVIRONMENT", "SENTRY_TRACES_SAMPLE_RATE"]) {
		assert.match(server, new RegExp(`process\\.env\\.${name}\\b`));
		assert.match(prepare, new RegExp(`${name}:`));
		assert.match(vite, new RegExp(`sentry\\.${name}\\b`));
		assert.match(environmentExample, new RegExp(`^${name}=`, "m"));
		assert.match(deploymentDocs, new RegExp(`\\b${name}\\b`));
	}

	assert.doesNotMatch(server, /process\.env\.VITE_SENTRY_/);
	assert.doesNotMatch(deploymentDocs, /\bVITE_SENTRY_/);
	assert.match(environmentExample, /^SENTRY_ENABLED=false$/m);
	assert.match(vite, /"import\.meta\.env\.VITE_SENTRY_DSN": JSON\.stringify\(sentry\.SENTRY_DSN \|\| ""\)/);
	assert.doesNotMatch(vite, /envPrefix\s*:/);
	assert.doesNotMatch(vite, /SENTRY_AUTH_TOKEN/);
});
