#!/usr/bin/env node

/**
 * Fail-closed dashboard smoke gate.
 *
 * This is intentionally dependency-free: it exercises the built SPA through
 * the same HTTP surface a customer sees and verifies the security-sensitive
 * source contracts that a browser test must not silently skip.  A real
 * deployment/base URL or Supabase credentials are required by default.  Use
 * --static only for local structural checks while setting up a demo; that
 * result is explicitly labelled non-production evidence.
 */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve, relative } from "node:path";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const dashboardRoot = join(repoRoot, "packages", "dashboard");
const distRoot = join(dashboardRoot, "dist");
const staticOnly = process.argv.includes("--static");
const configuredBaseUrl = process.env.DASHBOARD_SMOKE_BASE_URL?.trim();
const timeoutMs = Number(process.env.DASHBOARD_SMOKE_TIMEOUT_MS ?? 10_000);

const REQUIRED_SECURITY_HEADERS = [
	"strict-transport-security",
	"content-security-policy",
	"x-content-type-options",
	"x-frame-options",
	"referrer-policy",
	"permissions-policy",
];

const publicRoutes = [
	"/",
	"/pilot",
	"/pricing",
	"/verify",
	"/login",
	"/auth/callback",
	"/auth/recover",
	"/enterprise",
	"/support",
	"/status",
	"/privacy",
	"/security",
	"/terms",
];
const legacyRoutes = ["/demo"];
const protectedRoutes = [
	"/auth/dlp-step-up",
	"/onboarding",
	"/dashboard",
	"/events",
	"/discovery",
	"/settings",
	"/agents",
	"/autosecops",
	"/agents/:agentId",
	"/incidents",
	"/api-keys",
	"/billing",
	"/team",
	"/scim",
	"/policies",
	"/privacy-guard",
];
const routes = [...publicRoutes, ...protectedRoutes, ...legacyRoutes];

function fail(message) {
	throw new Error(`[dashboard-route-smoke] ${message}`);
}

async function read(relativePath) {
	try {
		return await readFile(join(repoRoot, relativePath), "utf8");
	} catch (error) {
		fail(`missing or unreadable ${relativePath}: ${error instanceof Error ? error.message : String(error)}`);
	}
}

function assertIncludes(content, needle, label) {
	if (!content.includes(needle)) fail(`${label}: expected ${JSON.stringify(needle)}`);
}

function assertRegex(content, pattern, label) {
	if (!pattern.test(content)) fail(`${label}: expected ${pattern}`);
}

/** Resolve same-origin scripts and styles exactly as a browser would. */
export function resolveDocumentAssets(html, documentUrl) {
	const document = new URL(documentUrl);
	const assets = [];
	const tags = html.matchAll(/<(script|link)\b[^>]*?\b(src|href)=["']([^"']+)["'][^>]*>/gi);
	for (const match of tags) {
		const tag = match[1].toLowerCase();
		if (tag === "link" && !/\brel=["']stylesheet["']/i.test(match[0])) continue;
		const raw = match[3];
		let resolved;
		try {
			resolved = new URL(raw, document);
		} catch {
			continue;
		}
		if (!/^https?:$/.test(resolved.protocol) || resolved.origin !== document.origin) continue;
		assets.push({
			url: resolved.href,
			kind: tag === "script" ? "script" : "style",
		});
	}
	return assets;
}

export function assertSecurityHeaders(headers, label = "deployment response") {
	for (const name of REQUIRED_SECURITY_HEADERS) {
		if (!headers.get(name)?.trim()) fail(`${label} is missing ${name}`);
	}
	const hsts = headers.get("strict-transport-security") ?? "";
	const maxAge = Number(hsts.match(/(?:^|;)\s*max-age=(\d+)/i)?.[1] ?? 0);
	if (maxAge < 31_536_000) fail(`${label} has an insufficient Strict-Transport-Security max-age`);
	const csp = headers.get("content-security-policy") ?? "";
	for (const directive of ["default-src 'self'", "base-uri 'self'", "object-src 'none'", "frame-ancestors 'none'"]) {
		if (!csp.includes(directive)) fail(`${label} Content-Security-Policy is missing ${directive}`);
	}
	if (!csp.includes("https://*.sentry.io") || !csp.includes("https://*.ingest.sentry.io")) {
		fail(`${label} Content-Security-Policy blocks configured Sentry reporting`);
	}
	if ((headers.get("x-content-type-options") ?? "").toLowerCase() !== "nosniff") {
		fail(`${label} must set X-Content-Type-Options: nosniff`);
	}
	if ((headers.get("x-frame-options") ?? "").toUpperCase() !== "DENY") {
		fail(`${label} must set X-Frame-Options: DENY`);
	}
}

async function structuralChecks() {
	const [main, onboarding, apiKeys, agents, autoSecOps, login, billing, landing, commercial, publicLayout, publicInfo, routeError, returnTo, session, scim, vercel, index, packageJson, browserManifest] = await Promise.all([
		read("packages/dashboard/src/main.tsx"),
		read("packages/dashboard/src/ui/pages/OnboardingPage.tsx"),
		read("packages/dashboard/src/ui/pages/ApiKeysPage.tsx"),
		read("packages/dashboard/src/ui/pages/AgentsPage.tsx"),
		read("packages/dashboard/src/ui/pages/AutoSecOpsPage.tsx"),
		read("packages/dashboard/src/ui/pages/LoginPage.tsx"),
		read("packages/dashboard/src/ui/pages/BillingPage.tsx"),
		read("packages/dashboard/src/ui/pages/public/LandingPage.tsx"),
		read("packages/dashboard/src/billing/commercial.ts"),
		read("packages/dashboard/src/ui/PublicLayout.tsx"),
		read("packages/dashboard/src/ui/pages/public/PublicInfoPage.tsx"),
		read("packages/dashboard/src/ui/RouteErrorPage.tsx"),
		read("packages/dashboard/src/ui/return-to.ts"),
		read("packages/dashboard/src/ui/session.ts"),
		read("packages/dashboard/src/ui/pages/ScimPage.tsx"),
		read("packages/dashboard/vercel.json"),
		read("packages/dashboard/index.html"),
		read("packages/dashboard/package.json"),
		read("packages/dashboard/tests/browser-smoke.manifest.json"),
	]);
	const manifest = JSON.parse(browserManifest);
	if (manifest.version !== 1 || !Array.isArray(manifest.scenarios) || manifest.scenarios.length < 5) {
		fail("browser smoke manifest is missing required release scenarios");
	}
	const manifestRoutes = [...(manifest.routes?.public ?? []), ...(manifest.routes?.protected ?? []), ...(manifest.routes?.legacy ?? [])];
	if (JSON.stringify(manifestRoutes) !== JSON.stringify(routes)) {
		fail("browser smoke manifest routes drifted from the HTTP smoke route matrix");
	}
	const registeredRoutes = [...main.matchAll(/\bpath:\s*"([^"]+)"/g)]
		.map((match) => match[1])
		.filter((route) => route !== "*")
		.map((route) => (route === "/" ? route : `/${route.replace(/^\/+/, "")}`));
	const expectedRoutes = [...new Set(routes)].sort();
	if (JSON.stringify([...new Set(registeredRoutes)].sort()) !== JSON.stringify(expectedRoutes)) {
		fail("browser smoke manifest does not cover every registered dashboard route");
	}

	for (const route of publicRoutes.slice(1)) {
		assertRegex(main, new RegExp(`path: "/?${route.slice(1)}"`), `public route ${route}`);
	}
	for (const route of protectedRoutes) {
		assertRegex(
			main,
			new RegExp(`path: "/?${route.slice(1)}",[\\s\\S]{0,240}?loader: requireSessionLoader`),
			`protected route ${route} must require a session`,
		);
	}
	assertIncludes(main, 'path: "demo", loader: () => redirect("/login?returnTo=%2Fonboarding")', "legacy demo redirects to onboarding sign-in");
	if (main.includes("DemoPage") || publicLayout.includes('to="/demo"') || landing.includes('to="/demo"')) {
		fail("synthetic demo must not be reachable from the customer product");
	}
	assertIncludes(main, 'path: "*"', "404 fallback route");
	assertIncludes(main, "const productionConfigMissing = Boolean(supabaseEnvError) && import.meta.env.PROD;", "production config fail-closed guard");
	if (main.includes("!isControlledDemoRoute")) fail("production config must not exempt the legacy demo route");

	// Device authorization must expire locally even if polling is delayed or the
	// edge function is unavailable.  An incomplete response must never become a
	// usable device record.
	assertIncludes(onboarding, "Date.parse(device.expires_at)", "onboarding expiry guard");
	assertIncludes(onboarding, 'setPoll({ status: "expired" })', "onboarding expired state");
	assertIncludes(onboarding, "!result.device_code", "onboarding response validation");
	assertIncludes(onboarding, "safeVerificationUrl", "authorization URL validation");
	assertIncludes(onboarding, "Date.parse(result.expires_at) <= Date.now()", "authorization expiry validation");
	assertIncludes(onboarding, 'type={showEnrollmentToken ? "text" : "password"}', "enrollment token masking");
	assertIncludes(onboarding, "navigator.clipboard.writeText", "enrollment token copy action");

	// API keys and enrollment tokens are one-time secrets.  The DOM starts in a
	// password/masked state and clipboard failures remain actionable.
	assertIncludes(apiKeys, 'type={showCreatedKey ? "text" : "password"}', "API key masking");
	assertIncludes(apiKeys, 'type={showCreatedEnrollToken ? "text" : "password"}', "enrollment masking");
	assertIncludes(apiKeys, "navigator.clipboard.writeText", "API secret copy action");
	assertIncludes(apiKeys, "setCreatedKey(null)", "API key clear action");
	assertIncludes(apiKeys, "setCreatedEnrollToken(null)", "enrollment token clear action");
	assertIncludes(agents, 'allowed ?? "unavailable"', "agent limit fail-closed rendering");
	assertIncludes(autoSecOps, 'autosecops-runtime', "AutoSecOps dashboard bridge");
	assertIncludes(autoSecOps, "No synthetic or cached AutoSecOps data", "AutoSecOps fail-closed rendering");
	assertIncludes(login, 'id="login-email"', "login email input id");
	assertIncludes(login, "const captchaReady = !captchaConfigured || Boolean(captchaToken)", "optional CAPTCHA login path");
	assertIncludes(await read("packages/dashboard/src/ui/pages/public/VerifyPage.tsx"), "signInReturnTo", "verify code survives sign-in redirect");
	assertIncludes(returnTo, 'candidate.startsWith("//")', "open redirect protection");
	assertRegex(returnTo, /candidate\.includes\(["']\\\\["']\)/, "backslash redirect protection");
	assertIncludes(session, "if (error) throw error", "auth error propagation");
	assertIncludes(commercial, "export function safeCommercialLink", "billing URL validation");
	assertIncludes(commercial, 'VITE_AIDR_COMMERCIAL_MODE ?? "invoice"', "invoice-only commercial default");
	assertIncludes(billing, "selfServiceCheckoutEnabled", "billing checkout gate");
	assertIncludes(billing, "Enterprise / manual invoice", "enterprise invoice workflow");
	assertRegex(
		scim,
		/supabase\.functions\.invoke<unknown>\(\s*query\s*\?\s*`scim-admin\?\$\{query\}`\s*:\s*"scim-admin"/,
		"SCIM owner API integration",
	);
	assertIncludes(scim, "scim_token", "SCIM one-time credential handling");
	assertIncludes(scim, "Group.externalId", "SCIM exact group identifier guidance");

	// A public page must expose support/legal links and never open a new tab
	// without an opener policy.
	assertIncludes(publicLayout, 'aria-label="Support and legal"', "support/legal navigation");
	assertRegex(`${publicLayout}\n${publicInfo}`, /target="_blank"[\s\S]{0,80}rel="noreferrer"/, "external link opener policy");
	assertIncludes(publicInfo, "No live status feed is configured", "status feed fail-closed notice");
	assertIncludes(publicInfo, "Terms URL is not configured", "terms URL fail-closed notice");
	assertIncludes(routeError, "Retry", "route error retry action");

	const vercelConfig = JSON.parse(vercel);
	if (!Array.isArray(vercelConfig.rewrites) || vercelConfig.rewrites.length === 0) {
		fail("Vercel SPA rewrite is missing; deep links would 404 on refresh");
	}
	const headerText = JSON.stringify(vercelConfig.headers ?? []);
	for (const header of [
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	]) assertIncludes(headerText, header, `Vercel security header ${header}`);

	assertRegex(index, /^<html\s+lang="[a-z-]+">/m, "document language");
	assertIncludes(index, 'name="viewport"', "responsive viewport");
	assertIncludes(index, "<title>", "document title");
	const dashboardPackage = JSON.parse(packageJson);
	if (dashboardPackage.scripts?.["test:route-smoke"] !== "node ../../scripts/dashboard-route-smoke.mjs") {
		fail("dashboard package must expose test:route-smoke");
	}

	return { routes: routes.length, checks: 30 };
}

async function reservePort() {
	return await new Promise((resolvePort, reject) => {
		const server = createServer();
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			const port = typeof address === "object" && address ? address.port : 0;
			server.close((error) => (error ? reject(error) : resolvePort(port)));
		});
	});
}

async function waitForHttp(url, child) {
	const deadline = Date.now() + timeoutMs;
	let lastError = "not started";
	while (Date.now() < deadline) {
		try {
			const response = await fetch(url, { signal: AbortSignal.timeout(Math.min(2_000, timeoutMs)) });
			return response;
		} catch (error) {
			lastError = error instanceof Error ? error.message : String(error);
			if (child && child.exitCode !== null) break;
			await new Promise((resolveWait) => setTimeout(resolveWait, 150));
		}
	}
	fail(`dashboard preview did not answer ${url}: ${lastError}`);
}

async function stopProcess(child) {
	if (child.exitCode !== null) return;
	if (process.platform === "win32" && child.pid) {
		await new Promise((resolveStop) => {
			const killer = spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], {
				stdio: "ignore",
			});
			killer.once("close", () => resolveStop());
			killer.once("error", () => resolveStop());
		});
	} else {
		child.kill("SIGTERM");
	}
}

async function routeCrawl(baseUrl) {
	let child = null;
	let base = baseUrl;
	const remote = Boolean(baseUrl);
	if (!base) {
		const port = await reservePort();
		child = spawn(
			process.execPath,
			[join(dashboardRoot, "node_modules", "vite", "bin", "vite.js"), "preview", "--host", "127.0.0.1", "--port", String(port)],
			{
				cwd: dashboardRoot,
				env: { ...process.env, CI: "1" },
				stdio: ["ignore", "pipe", "pipe"],
			},
		);
		base = `http://127.0.0.1:${port}`;
	}
	base = base.replace(/\/$/, "");
	const baseOrigin = new URL(base).origin;
	if (remote) {
		const parsed = new URL(base);
		const localHost =
			parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1";
		if (parsed.protocol !== "https:" && !localHost) fail("remote dashboard smoke requires HTTPS");
	}

	const results = [];
	const checkedAssets = new Set();
	try {
		for (const route of routes) {
			const response = await waitForHttp(`${base}${route}`, child);
			const body = await response.text();
			if (!response.ok) fail(`${route} returned HTTP ${response.status}`);
			if (new URL(response.url).origin !== baseOrigin) fail(`${route} redirected outside the dashboard origin`);
			if (!response.headers.get("content-type")?.toLowerCase().includes("text/html")) {
				fail(`${route} did not return HTML`);
			}
			if (remote) assertSecurityHeaders(response.headers, `${route} response`);
			if (!/id=["']root["']/.test(body)) fail(`${route} did not return the dashboard SPA shell`);
			if (!/type=["']module["'][^>]+src=/.test(body)) fail(`${route} missing module entrypoint`);
			const documentAssets = resolveDocumentAssets(body, response.url);
			if (!documentAssets.some((asset) => asset.kind === "script")) {
				fail(`${route} did not reference a same-origin script`);
			}
			for (const asset of documentAssets) {
				if (checkedAssets.has(asset.url)) continue;
				checkedAssets.add(asset.url);
				const assetResponse = await waitForHttp(asset.url, child);
				if (!assetResponse.ok) fail(`${route} asset ${asset.url} returned HTTP ${assetResponse.status}`);
				if (new URL(assetResponse.url).origin !== baseOrigin) fail(`${route} asset redirected outside the dashboard origin`);
				const contentType = assetResponse.headers.get("content-type")?.toLowerCase() ?? "";
				if (asset.kind === "script" && !contentType.includes("javascript")) {
					fail(`${route} script ${asset.url} returned ${contentType || "no content type"}`);
				}
				if (asset.kind === "style" && !contentType.includes("text/css")) {
					fail(`${route} stylesheet ${asset.url} returned ${contentType || "no content type"}`);
				}
			}
			results.push({ route, status: response.status, contentType: response.headers.get("content-type") });
		}
	} finally {
		if (child) await stopProcess(child);
	}
	return results;
}

async function checkDist() {
	const html = await readFile(join(distRoot, "index.html"), "utf8").catch(() => null);
	if (!html) fail("packages/dashboard/dist/index.html is missing; run pnpm -C packages/dashboard build first");
	const documentAssets = resolveDocumentAssets(html, "https://dashboard.invalid/");
	for (const asset of documentAssets) {
		const entry = new URL(asset.url).pathname;
		const assetPath = join(distRoot, entry.replace(/^\//, ""));
		const relativeAsset = relative(distRoot, assetPath);
		if (relativeAsset.startsWith("..")) fail(`dist asset escapes dashboard bundle: ${entry}`);
		await readFile(assetPath).catch(() => fail(`dist entrypoint is missing: ${entry}`));
	}
	const assetFiles = await (await import("node:fs/promises")).readdir(join(distRoot, "assets")).catch(() => []);
	if (assetFiles.length === 0) fail("dashboard dist/assets is empty");
	const suspicious = [];
	for (const file of assetFiles.filter((name) => /\.(?:js|css)$/.test(name))) {
		const text = await readFile(join(distRoot, "assets", file), "utf8");
		if (/SUPABASE_SERVICE_ROLE_KEY|service_role|-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----/.test(text)) suspicious.push(file);
	}
	if (suspicious.length) fail(`possible secret material found in dashboard bundle: ${suspicious.join(", ")}`);
	return { assets: assetFiles.length };
}

async function main() {
	const missing = ["VITE_SUPABASE_URL", "VITE_SUPABASE_ANON_KEY"].filter(
		(name) => !process.env[name]?.trim(),
	);
	if (!staticOnly && !configuredBaseUrl && missing.length) {
		fail(
			`setup incomplete: ${missing.join(", ")} missing. Provide dashboard credentials or DASHBOARD_SMOKE_BASE_URL; use --static only for non-production structural evidence.`,
		);
	}
	const structural = await structuralChecks();
	const dist = await checkDist();
	const crawled = await routeCrawl(configuredBaseUrl);
	const report = {
		status: "passed",
		mode: staticOnly ? "static-only" : configuredBaseUrl ? "remote" : "local-preview",
		generated_at: new Date().toISOString(),
		structural,
		dist,
		routes: crawled,
	};
	const evidenceDir = join(repoRoot, ".e2e-artifacts", "dashboard");
	await mkdir(evidenceDir, { recursive: true });
	const evidencePath = join(evidenceDir, "route-smoke.json");
	await writeFile(evidencePath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

	// The release gate consumes this suite through its `command` kind and reads
	// the JUnit file named by the `{junit}` placeholder. Without this the gate
	// finds no report from this run and falls back to whatever stale artifact is
	// already on disk, which is how a passing smoke test was recorded as 0/1.
	const junitIndex = process.argv.indexOf("--junit");
	if (junitIndex !== -1 && process.argv[junitIndex + 1]) {
		const junitPath = process.argv[junitIndex + 1];
		await mkdir(dirname(junitPath), { recursive: true });
		await writeFile(
			junitPath,
			`<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="aidr-dashboard-route-smoke" tests="1" failures="0">\n  <testsuite name="dashboard-route-smoke" tests="1" failures="0">\n    <testcase name="dashboard routes and bundle contract" classname="dashboard-route-smoke" time="0"/>\n  </testsuite>\n</testsuites>\n`,
			"utf8",
		);
	}

	console.log(`Dashboard route smoke PASS (${report.mode}); evidence: ${evidencePath}`);
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
	main().catch((error) => {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	});
}
