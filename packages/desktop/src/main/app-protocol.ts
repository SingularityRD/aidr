import { extname, isAbsolute, join, normalize, relative } from "node:path";

/**
 * The app's pages are served from its own `app://aidr/` scheme (not
 * `file://`), so the Content Security Policy's `'self'` means exactly the
 * packaged renderer files. No remote origin is ever allowed.
 */

export const APP_SCHEME = "app";
export const APP_HOST = "aidr";
export const APP_ENTRY = `${APP_SCHEME}://${APP_HOST}/index.html`;

export const CONTENT_SECURITY_POLICY = [
	"default-src 'none'",
	"script-src 'self'",
	"style-src 'self'",
	"img-src 'self' data:",
	"font-src 'self'",
	"connect-src 'none'",
	"object-src 'none'",
	"base-uri 'none'",
	"form-action 'none'",
	"frame-ancestors 'none'",
].join("; ");

const TYPES: Record<string, string> = {
	".html": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".ico": "image/x-icon",
	".json": "application/json; charset=utf-8",
};

/** Map an `app://aidr/<path>` URL to a file under `root`, or null (wrong host, traversal, unknown type). */
export function resolveAppAsset(root: string, url: string): { file: string; type: string } | null {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return null;
	}
	if (parsed.protocol !== `${APP_SCHEME}:` || parsed.host !== APP_HOST) return null;
	let pathname: string;
	try {
		pathname = decodeURIComponent(parsed.pathname);
	} catch {
		return null;
	}
	if (pathname.includes("\0") || pathname.includes("\\")) return null;
	const relativePath = normalize(pathname === "/" ? "index.html" : pathname.replace(/^\/+/, ""));
	const file = join(root, relativePath);
	const inside = relative(root, file);
	if (inside === "" || inside.startsWith("..") || isAbsolute(inside)) return null;
	const type = TYPES[extname(file).toLowerCase()];
	return type ? { file, type } : null;
}
