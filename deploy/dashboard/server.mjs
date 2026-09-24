import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { extname, isAbsolute, resolve, sep } from "node:path";
import { createHttpRequestMetrics, createReadinessMonitor, loadReadinessConfig } from "./monitoring.mjs";
import { assertHttpsUrl, parseReleaseManifestBytes } from "./release-manifest.mjs";
import { parseSamlRuntimeConfig } from "../saml-config.mjs";

const root = resolve(process.env.AIDR_STATIC_DIR || "/app/public");
const url = new URL(process.env.VITE_SUPABASE_URL);
const loopback = url.hostname === "localhost" || url.hostname === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(url.hostname);
if ((url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) || url.username || url.password) throw new Error("Public Supabase URL must use HTTPS (HTTP is allowed only on loopback)");
const publicKey = process.env.VITE_SUPABASE_ANON_KEY;
if (!publicKey) throw new Error("VITE_SUPABASE_ANON_KEY is required");
try {
	const payload = JSON.parse(Buffer.from(publicKey.split(".")[1], "base64url").toString());
	if (payload.role !== "anon") throw new Error("Not an anonymous key");
} catch { if (!publicKey.startsWith("sb_publishable_")) throw new Error("Only an anonymous or publishable key may be exposed"); }
const authMethods = (process.env.AIDR_AUTH_METHODS || "password").split(",").map((method) => method.trim());
if (authMethods.some((method) => !["password", "magic-link", "google", "github", "azure"].includes(method))) throw new Error("Invalid AIDR_AUTH_METHODS");
const signupMode = process.env.AIDR_SIGNUP_MODE || "closed";
if (!["closed", "cloud"].includes(signupMode)) throw new Error("Invalid AIDR_SIGNUP_MODE");
if (signupMode === "cloud" && !authMethods.includes("password")) throw new Error("Cloud signup requires password auth");
const samlConfig = parseSamlRuntimeConfig({
	providers: process.env.AIDR_SAML_PROVIDERS,
	providerId: process.env.AIDR_SAML_PROVIDER_ID,
	domain: process.env.AIDR_SAML_DOMAIN,
});

let sentryDsn = null;
const configuredSentryDsn = process.env.SENTRY_DSN?.trim();
if (configuredSentryDsn) {
	try {
		sentryDsn = new URL(configuredSentryDsn);
	} catch {
		throw new Error("SENTRY_DSN must be a valid HTTPS Sentry DSN");
	}
	const projectId = sentryDsn.pathname.split("/").filter(Boolean).at(-1);
	if (sentryDsn.protocol !== "https:" || !sentryDsn.username || sentryDsn.password || sentryDsn.search || sentryDsn.hash || !/^\d+$/.test(projectId || "")) {
		throw new Error("SENTRY_DSN must be a valid HTTPS Sentry DSN");
	}
}
const sentryEnvironment = process.env.SENTRY_ENVIRONMENT?.trim() || process.env.NODE_ENV?.trim() || "development";
if (!/^[A-Za-z0-9._-]{1,64}$/.test(sentryEnvironment) || sentryEnvironment === "None") {
	throw new Error("SENTRY_ENVIRONMENT must be a safe Sentry environment name");
}
const configuredSampleRate = process.env.SENTRY_TRACES_SAMPLE_RATE?.trim();
const sentryTracesSampleRate = configuredSampleRate ? Number(configuredSampleRate) : 0;
if (!Number.isFinite(sentryTracesSampleRate) || sentryTracesSampleRate < 0 || sentryTracesSampleRate > 1) {
	throw new Error("SENTRY_TRACES_SAMPLE_RATE must be a number from 0 to 1");
}

let recoveryTemplate = null;
const authTemplateDir = process.env.AIDR_AUTH_TEMPLATE_DIR?.trim();
if (authTemplateDir) {
	if (!isAbsolute(authTemplateDir) || authTemplateDir.includes("\0")) throw new Error("AIDR_AUTH_TEMPLATE_DIR must be an absolute path");
	const templatePath = resolve(authTemplateDir, "recovery.html");
	const templateStat = await stat(templatePath);
	if (!templateStat.isFile()) throw new Error("AIDR recovery email template must be a regular file");
	recoveryTemplate = await readFile(templatePath);
}

// Download center. Either serve a signed-off manifest file from this host
// (AIDR_RELEASE_MANIFEST_PATH, validated at startup and on every request) or
// point the browser at an external HTTPS manifest (VITE_AIDR_RELEASE_MANIFEST_URL).
// Neither configured is a supported state: the dashboard then shows that no
// release manifest is published instead of inventing download links.
let releaseManifestPath = null;
const configuredManifestPath = process.env.AIDR_RELEASE_MANIFEST_PATH?.trim();
if (configuredManifestPath) {
	if (!isAbsolute(configuredManifestPath) || configuredManifestPath.includes("\0")) throw new Error("AIDR_RELEASE_MANIFEST_PATH must be an absolute path");
	const manifestStat = await stat(configuredManifestPath);
	if (!manifestStat.isFile()) throw new Error("AIDR_RELEASE_MANIFEST_PATH must be a regular file");
	parseReleaseManifestBytes(await readFile(configuredManifestPath));
	releaseManifestPath = configuredManifestPath;
}
let externalReleaseManifestUrl = null;
const configuredManifestUrl = process.env.VITE_AIDR_RELEASE_MANIFEST_URL?.trim();
if (configuredManifestUrl) {
	if (releaseManifestPath) throw new Error("Configure only one of AIDR_RELEASE_MANIFEST_PATH or VITE_AIDR_RELEASE_MANIFEST_URL");
	try {
		externalReleaseManifestUrl = new URL(assertHttpsUrl(configuredManifestUrl, "VITE_AIDR_RELEASE_MANIFEST_URL"));
	} catch {
		throw new Error("VITE_AIDR_RELEASE_MANIFEST_URL must be an absolute https: URL without credentials");
	}
}

const config = {
	supabaseUrl: url.href.replace(/\/$/, ""),
	supabaseAnonKey: publicKey,
	authMethods: [...new Set(authMethods)],
	signupMode,
	...samlConfig,
	sentryDsn: sentryDsn?.href ?? null,
	sentryEnvironment,
	sentryTracesSampleRate,
	releaseManifestUrl: releaseManifestPath ? "/release-manifest.json" : (externalReleaseManifestUrl?.href ?? null),
};
await stat(resolve(root, "index.html"));
const types = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2" };
const port = Number(process.env.PORT || 8080);
const socketOrigin = url.origin.replace(/^http/, "ws");
const connectSources = [...new Set(["'self'", url.origin, socketOrigin, "https://challenges.cloudflare.com", sentryDsn?.origin, externalReleaseManifestUrl?.origin].filter(Boolean))].join(" ");
const metricsToken = process.env.AIDR_METRICS_TOKEN?.trim() || null;
const readiness = createReadinessMonitor(loadReadinessConfig());
const requestMetrics = createHttpRequestMetrics();
const operationalPaths = new Set(["/livez", "/healthz", "/readyz", "/metrics"]);

function metricsAuthorized(req) {
	if (!metricsToken) return false;
	const match = (req.headers.authorization ?? "").match(/^Bearer\s+(.+)$/i);
	if (!match) return false;
	const supplied = Buffer.from(match[1]);
	const expected = Buffer.from(metricsToken);
	return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

const server = createServer(async (req, res) => {
	const startedAt = process.hrtime.bigint();
	let observedPath = null;
	try { observedPath = decodeURIComponent(new URL(req.url, "http://localhost").pathname); } catch { /* The request handler returns 400 below. */ }
	if (!operationalPaths.has(observedPath)) {
		res.once("finish", () => requestMetrics.observe(res.statusCode, Number(process.hrtime.bigint() - startedAt) / 1e9));
	}
	res.setHeader("X-Content-Type-Options", "nosniff");
	res.setHeader("Referrer-Policy", "no-referrer");
	res.setHeader("X-Frame-Options", "DENY");
	res.setHeader("Content-Security-Policy", `default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src ${connectSources}; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'`);
	res.setHeader("Cache-Control", "no-store");
	if (!["GET", "HEAD"].includes(req.method)) { res.writeHead(405); res.end(); return; }
	try {
		const path = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
		if (path === "/livez" || path === "/healthz") { res.setHeader("Content-Type", "application/json"); res.end(req.method === "HEAD" ? undefined : '{"status":"ok","component":"dashboard"}'); return; }
		if (path === "/readyz") {
			const health = await readiness.safeSnapshot();
			res.setHeader("Content-Type", "application/json");
			res.writeHead(health.status === "ready" ? 200 : 503);
			res.end(req.method === "HEAD" ? undefined : JSON.stringify(health));
			return;
		}
		if (path === "/metrics") {
			if (!metricsAuthorized(req)) {
				res.setHeader("WWW-Authenticate", 'Bearer realm="metrics"');
				res.writeHead(metricsToken ? 401 : 404);
				res.end();
				return;
			}
			res.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
			res.end(req.method === "HEAD" ? undefined : `${await readiness.metrics()}${requestMetrics.renderPrometheus()}`);
			return;
		}
		if (path === "/auth-templates/recovery.html") {
			if (!recoveryTemplate) { res.writeHead(404); res.end(); return; }
			res.setHeader("Content-Type", "text/html; charset=utf-8");
			res.end(req.method === "HEAD" ? undefined : recoveryTemplate);
			return;
		}
		if (path.startsWith("/auth-templates/")) { res.writeHead(404); res.end(); return; }
		if (path === "/release-manifest.json") {
			if (!releaseManifestPath) { res.writeHead(404); res.end(); return; }
			let manifestBytes;
			try {
				manifestBytes = await readFile(releaseManifestPath);
				parseReleaseManifestBytes(manifestBytes);
			} catch {
				// A manifest replaced with invalid content is withheld, never served.
				res.writeHead(503);
				res.end();
				return;
			}
			const etag = `"sha256-${createHash("sha256").update(manifestBytes).digest("base64url")}"`;
			res.setHeader("Content-Type", "application/json; charset=utf-8");
			res.setHeader("Cache-Control", "public, max-age=60, must-revalidate");
			res.setHeader("ETag", etag);
			const ifNoneMatch = req.headers["if-none-match"] ?? "";
			if (ifNoneMatch.split(",").some((candidate) => candidate.trim().replace(/^W\//, "") === etag)) {
				res.writeHead(304);
				res.end();
				return;
			}
			res.setHeader("Content-Length", manifestBytes.byteLength);
			res.end(req.method === "HEAD" ? undefined : manifestBytes);
			return;
		}
		if (path === "/runtime-config.js") { res.setHeader("Content-Type", "application/javascript"); res.end(req.method === "HEAD" ? undefined : `window.__AIDR_CONFIG__=${JSON.stringify(config)};`); return; }
		const target = resolve(root, path === "/" ? "index.html" : `.${path}`);
		if (!target.startsWith(root + sep) || path.endsWith(".map") || path.split("/").some((part) => part.startsWith("."))) { res.writeHead(404); res.end(); return; }
		let bytes;
		let extension = extname(target);
		try { bytes = await readFile(target); } catch {
			if (extension) { res.writeHead(404); res.end(); return; }
			extension = ".html";
			bytes = await readFile(resolve(root, "index.html"));
		}
		res.setHeader("Content-Type", types[extension] || "application/octet-stream");
		res.end(req.method === "HEAD" ? undefined : bytes);
	} catch { res.writeHead(400); res.end(); }
});
server.listen(port, "0.0.0.0", () => console.log(`AIDR dashboard listening on ${server.address().port}`));
