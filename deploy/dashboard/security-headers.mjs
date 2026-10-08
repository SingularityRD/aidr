/**
 * Single source of truth for the dashboard's HTTP security headers.
 *
 * Consumed directly by `deploy/dashboard/server.mjs` (self-hosted container) and
 * rendered into `packages/dashboard/vercel.json` and
 * `packages/dashboard/public/_headers` (Vercel and Cloudflare static hosting) by
 * `scripts/dashboard-security-headers.mjs`. The drift test
 * `packages/dashboard/src/__tests__/security-headers-drift.test.ts` fails when a
 * rendered file no longer matches this module; run
 * `node scripts/dashboard-security-headers.mjs --write` after changing it.
 *
 * Only `connect-src` differs between targets: the container knows the exact
 * Supabase and Sentry origins at start-up, static hosting has to allow the
 * hosted Supabase and Sentry domains. Every other value is identical.
 *
 * Origins the dashboard actually loads (checked against packages/dashboard/src):
 * - Supabase Auth/PostgREST/Functions via fetch (connect-src). Realtime is not
 *   used, so no wss: source is allowed.
 * - Sentry event ingestion via fetch (connect-src).
 * - Cloudflare Turnstile script and iframe (script-src, frame-src, connect-src).
 * - Google/GitHub/Azure/SAML sign-in are full-page redirects through Supabase
 *   Auth, so no identity-provider script or frame source is needed.
 * - Images are same-origin, the inline data: favicon, or blob: object URLs.
 */

export const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";

/** Two years. No `preload`: customer domains must opt into the preload list themselves. */
const STRICT_TRANSPORT_SECURITY = "max-age=63072000; includeSubDomains";

/** connect-src for static hosting, where the Supabase project and Sentry DSN are not known at build time. */
const STATIC_CONNECT_SOURCES = Object.freeze([
	"'self'",
	"https://*.supabase.co",
	"https://*.sentry.io",
	"https://*.ingest.sentry.io",
	TURNSTILE_ORIGIN,
]);

/**
 * @param {{ connectSources: readonly string[], upgradeInsecureRequests?: boolean }} options
 * @returns {string}
 */
/** @public Loaded dynamically by the dashboard security-headers drift test. */
export function contentSecurityPolicy({ connectSources, upgradeInsecureRequests = true }) {
	if (!Array.isArray(connectSources) || connectSources.length === 0 || connectSources[0] !== "'self'") {
		throw new Error("connect-src must start with 'self'");
	}
	for (const source of connectSources) {
		if (typeof source !== "string" || /[\s;,]/.test(source) || !source) throw new Error("Invalid connect-src source");
	}
	const directives = [
		"default-src 'self'",
		"base-uri 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		`script-src 'self' ${TURNSTILE_ORIGIN}`,
		// React applies inline style attributes; no inline <style> or script is served.
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob:",
		"font-src 'self'",
		`connect-src ${[...new Set(connectSources)].join(" ")}`,
		`frame-src ${TURNSTILE_ORIGIN}`,
		"form-action 'self'",
	];
	// Only omitted for loopback HTTP development, where upgrading would break every request.
	if (upgradeInsecureRequests) directives.push("upgrade-insecure-requests");
	return directives.join("; ");
}

/**
 * Ordered security headers. Values are identical for every target except the
 * CSP connect-src list and, on loopback HTTP only, upgrade-insecure-requests.
 *
 * @param {{ connectSources?: readonly string[], upgradeInsecureRequests?: boolean }} [options]
 * @returns {Array<[string, string]>}
 */
export function securityHeaders({ connectSources = STATIC_CONNECT_SOURCES, upgradeInsecureRequests = true } = {}) {
	return [
		["Strict-Transport-Security", STRICT_TRANSPORT_SECURITY],
		["Content-Security-Policy", contentSecurityPolicy({ connectSources, upgradeInsecureRequests })],
		["X-Content-Type-Options", "nosniff"],
		["X-Frame-Options", "DENY"],
		["Referrer-Policy", "no-referrer"],
		["Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"],
	];
}

/** Long-lived caching for content-hashed build assets on static hosting. */
const IMMUTABLE_ASSET_CACHE = "public, max-age=31536000, immutable";

/** Cloudflare `_headers` file content. */
export function renderCloudflareHeaders() {
	const lines = ["/*", ...securityHeaders().map(([name, value]) => `  ${name}: ${value}`), "", "/assets/*", `  Cache-Control: ${IMMUTABLE_ASSET_CACHE}`];
	return `${lines.join("\n")}\n`;
}

/** The `headers` array of `vercel.json`. */
export function renderVercelHeaders() {
	return [
		{ source: "/(.*)", headers: securityHeaders().map(([key, value]) => ({ key, value })) },
		{ source: "/assets/(.*)", headers: [{ key: "Cache-Control", value: IMMUTABLE_ASSET_CACHE }] },
	];
}
