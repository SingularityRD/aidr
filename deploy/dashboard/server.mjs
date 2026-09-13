import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { createReadinessMonitor, loadReadinessConfig } from "./monitoring.mjs";

const root = resolve(process.env.AIDR_STATIC_DIR || "/app/public");
const url = new URL(process.env.VITE_SUPABASE_URL);
if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("Invalid public Supabase URL");
const publicKey = process.env.VITE_SUPABASE_ANON_KEY;
if (!publicKey) throw new Error("VITE_SUPABASE_ANON_KEY is required");
try {
	const payload = JSON.parse(Buffer.from(publicKey.split(".")[1], "base64url").toString());
	if (payload.role !== "anon") throw new Error("Not an anonymous key");
} catch { if (!publicKey.startsWith("sb_publishable_")) throw new Error("Only an anonymous or publishable key may be exposed"); }
const authMethods = (process.env.AIDR_AUTH_METHODS || "password").split(",").map((method) => method.trim());
if (authMethods.some((method) => !["password", "magic-link", "google", "github", "azure"].includes(method))) throw new Error("Invalid AIDR_AUTH_METHODS");
const config = { supabaseUrl: url.href.replace(/\/$/, ""), supabaseAnonKey: publicKey, authMethods: [...new Set(authMethods)] };
await stat(resolve(root, "index.html"));
const types = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2" };
const port = Number(process.env.PORT || 8080);
const socketOrigin = url.origin.replace(/^http/, "ws");
const readiness = createReadinessMonitor(loadReadinessConfig());
const server = createServer(async (req, res) => {
	res.setHeader("X-Content-Type-Options", "nosniff");
	res.setHeader("Referrer-Policy", "no-referrer");
	res.setHeader("X-Frame-Options", "DENY");
	res.setHeader("Content-Security-Policy", `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' ${url.origin} ${socketOrigin}; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`);
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
			res.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
			res.end(req.method === "HEAD" ? undefined : await readiness.metrics());
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
