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

const publicRoutes = [
	"/",
	"/demo",
	"/pilot",
	"/pricing",
	"/verify",
	"/login",
	"/support",
	"/status",
	"/privacy",
	"/security",
	"/terms",
];
const protectedRoutes = ["/onboarding", "/agents", "/autosecops", "/incidents", "/api-keys", "/billing"];
const routes = [...publicRoutes, ...protectedRoutes];

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

async function structuralChecks() {
	const [main, onboarding, apiKeys, agents, autoSecOps, login, billing, demo, commercial, publicLayout, publicInfo, routeError, returnTo, session, vercel, index, packageJson, browserManifest] = await Promise.all([
		read("packages/dashboard/src/main.tsx"),
		read("packages/dashboard/src/ui/pages/OnboardingPage.tsx"),
		read("packages/dashboard/src/ui/pages/ApiKeysPage.tsx"),
		read("packages/dashboard/src/ui/pages/AgentsPage.tsx"),
		read("packages/dashboard/src/ui/pages/AutoSecOpsPage.tsx"),
		read("packages/dashboard/src/ui/pages/LoginPage.tsx"),
		read("packages/dashboard/src/ui/pages/BillingPage.tsx"),
		read("packages/dashboard/src/ui/pages/public/DemoPage.tsx"),
		read("packages/dashboard/src/billing/commercial.ts"),
		read("packages/dashboard/src/ui/PublicLayout.tsx"),
		read("packages/dashboard/src/ui/pages/public/PublicInfoPage.tsx"),
		read("packages/dashboard/src/ui/RouteErrorPage.tsx"),
		read("packages/dashboard/src/ui/return-to.ts"),
		read("packages/dashboard/src/ui/session.ts"),
		read("packages/dashboard/vercel.json"),
		read("packages/dashboard/index.html"),
		read("packages/dashboard/package.json"),
		read("packages/dashboard/tests/browser-smoke.manifest.json"),
	]);
	const manifest = JSON.parse(browserManifest);
	if (manifest.version !== 1 || !Array.isArray(manifest.scenarios) || manifest.scenarios.length < 5) {
		fail("browser smoke manifest is missing required release scenarios");
	}
	const manifestRoutes = [...(manifest.routes?.public ?? []), ...(manifest.routes?.protected ?? [])];
	if (JSON.stringify(manifestRoutes) !== JSON.stringify(routes)) {
		fail("browser smoke manifest routes drifted from the HTTP smoke route matrix");
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
	assertIncludes(main, 'path: "*"', "404 fallback route");
	assertIncludes(main, "const productionConfigMissing = Boolean(supabaseEnvError) && import.meta.env.PROD;", "production config fail-closed guard");

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
	assertIncludes(login, "const captchaReady = !captchaConfigured || captchaVerified", "optional CAPTCHA login path");
	assertIncludes(await read("packages/dashboard/src/ui/pages/public/VerifyPage.tsx"), "signInReturnTo", "verify code survives sign-in redirect");
	assertIncludes(returnTo, 'candidate.startsWith("//")', "open redirect protection");
	assertRegex(returnTo, /candidate\.includes\(["']\\\\["']\)/, "backslash redirect protection");
	assertIncludes(session, "if (error) throw error", "auth error propagation");
	assertIncludes(commercial, "export function safeCommercialLink", "billing URL validation");
	assertIncludes(commercial, 'VITE_AIDR_COMMERCIAL_MODE ?? "invoice"', "invoice-only commercial default");
	assertIncludes(billing, "selfServiceCheckoutEnabled", "billing checkout gate");
	assertIncludes(billing, "Enterprise / manual invoice", "enterprise invoice workflow");
	assertIncludes(demo, "Controlled evaluation demo", "controlled demo boundary");
	assertIncludes(demo, "No external command", "demo no-external-request notice");

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
	if (!base) {
		const port = await reservePort();
		child = spawn(
			process.platform === "win32" ? "pnpm.cmd" : "pnpm",
			["preview", "--host", "127.0.0.1", "--port", String(port)],
			{
				cwd: dashboardRoot,
				env: { ...process.env, CI: "1" },
				stdio: ["ignore", "pipe", "pipe"],
				shell: process.platform === "win32",
			},
		);
		base = `http://127.0.0.1:${port}`;
	}
	base = base.replace(/\/$/, "");

	const results = [];
	try {
		for (const route of routes) {
			const response = await waitForHttp(`${base}${route}`, child);
			const body = await response.text();
			if (!response.ok) fail(`${route} returned HTTP ${response.status}`);
			if (!/id=["']root["']/.test(body)) fail(`${route} did not return the dashboard SPA shell`);
			if (!/type=["']module["'][^>]+src=/.test(body)) fail(`${route} missing module entrypoint`);
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
	const entryMatches = [...html.matchAll(/(?:src|href)=["']([^"']+)["']/g)].map((match) => match[1]);
	for (const entry of entryMatches.filter((value) => value.startsWith("./assets/") || value.startsWith("/assets/"))) {
		const assetPath = join(distRoot, entry.replace(/^\.\//, "").replace(/^\//, ""));
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
	console.log(`Dashboard route smoke PASS (${report.mode}); evidence: ${evidencePath}`);
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : String(error));
	process.exitCode = 1;
});
