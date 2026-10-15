import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { AssistantOps, SetupEvent, SetupSummary } from "./types.js";

/**
 * The Setup Assistant's local web server.
 *
 * ## Threat model
 *
 * The wizard can register AIDR with the person's AI tools and connect the
 * computer to a company, so the server must only ever answer the person's own
 * browser tab, never another web page, another computer or an AI agent:
 *
 * - **Loopback only.** Bound to 127.0.0.1 on a random port; nothing else.
 * - **One-time token.** A random 256-bit token travels in the URL *fragment*
 *   (never sent in a request line, never logged by a proxy). The page posts it
 *   once to `/api/session`; it is consumed whether or not a session follows, and
 *   only one session ever exists. A second exchange (a copied link, a racing
 *   process) is refused, so the person sees "already used" instead of a silent
 *   takeover.
 * - **Session cookie.** HttpOnly, SameSite=Strict, path `/`; every API call
 *   needs it. The page's script never sees it.
 * - **DNS-rebinding defence.** The Host header must be exactly
 *   `127.0.0.1:<port>`; a name that resolves to 127.0.0.1 is refused. An Origin
 *   header, when present, must be this origin, and is required on every POST.
 * - **No CORS.** No Access-Control-* header is ever sent and OPTIONS is refused,
 *   so a cross-origin page cannot read a response or send a JSON body.
 * - **CSP `default-src 'self'`.** No inline script or style; the UI is three
 *   static files from the signed bundle.
 * - **Closes itself** after the wizard finishes or after 30 minutes without an
 *   authenticated request (a running setup counts as activity).
 * - **Fixed operations.** The routes call {@link AssistantOps} only: detect,
 *   setup (plain `aidr setup` semantics), verify, status and device-code
 *   enrollment. Nothing removes, approves or edits configuration.
 */

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const SESSION_COOKIE = "aidr_assistant_session";
const MAX_BODY_BYTES = 16 * 1024;

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
	"Content-Security-Policy":
		"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options": "DENY",
	"Referrer-Policy": "no-referrer",
	"Cache-Control": "no-store",
	"Cross-Origin-Opener-Policy": "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

export interface AssistantAssets {
	html: string;
	css: string;
	js: string;
	icon: string;
}

export type CloseReason = "done" | "idle" | "signal" | "error";

export interface AssistantServerOptions {
	ops: AssistantOps;
	assets: AssistantAssets;
	/** Idle shutdown (tests); default 30 minutes. */
	idleMs?: number;
	/** Fixed token (tests only); default 32 random bytes. */
	token?: string;
}

export interface AssistantServer {
	/** The address to open, with the one-time token in the fragment. */
	url: string;
	origin: string;
	port: number;
	/** Bound address, always 127.0.0.1. */
	address: string;
	close(reason?: CloseReason): Promise<void>;
	/** Resolves once the server has stopped, with the reason. */
	closed: Promise<CloseReason>;
}

class HttpError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
	) {
		super(code);
	}
}

function digest(value: string): Buffer {
	return createHash("sha256").update(value, "utf8").digest();
}

/** Constant-time comparison of two secrets of any length. */
export function sameSecret(a: string | undefined, b: string): boolean {
	if (typeof a !== "string" || a.length === 0) return false;
	return timingSafeEqual(digest(a), digest(b));
}

export function readCookie(header: string | undefined, name: string): string | undefined {
	if (!header) return undefined;
	for (const part of header.split(";")) {
		const index = part.indexOf("=");
		if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
	}
	return undefined;
}

/**
 * Host, Origin and fetch-metadata checks shared by every route. Returns null
 * when the request may proceed, else the refusal.
 */
function checkRequestOrigin(
	request: Pick<IncomingMessage, "headers" | "method">,
	port: number,
): HttpError | null {
	const expectedHost = `127.0.0.1:${port}`;
	if (request.headers.host !== expectedHost) return new HttpError(421, "bad_host");
	const origin = request.headers.origin;
	if (origin !== undefined && origin !== `http://${expectedHost}`) {
		return new HttpError(403, "bad_origin");
	}
	if (request.method === "POST" && origin === undefined)
		return new HttpError(403, "origin_required");
	const site = request.headers["sec-fetch-site"];
	if (site !== undefined && site !== "same-origin" && site !== "none") {
		return new HttpError(403, "cross_site");
	}
	return null;
}

function send(
	response: ServerResponse,
	status: number,
	body: string,
	type: string,
	extra: Record<string, string> = {},
): void {
	response.writeHead(status, {
		...SECURITY_HEADERS,
		"Content-Type": type,
		"Content-Length": String(Buffer.byteLength(body)),
		...extra,
	});
	response.end(body);
}

function sendJson(
	response: ServerResponse,
	status: number,
	value: unknown,
	extra?: Record<string, string>,
): void {
	send(response, status, JSON.stringify(value), "application/json; charset=utf-8", extra);
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
	const type = request.headers["content-type"] ?? "";
	if (!/^application\/json(?:;|$)/iu.test(type)) throw new HttpError(415, "json_required");
	const chunks: Buffer[] = [];
	let size = 0;
	for await (const chunk of request) {
		size += (chunk as Buffer).length;
		if (size > MAX_BODY_BYTES) throw new HttpError(413, "body_too_large");
		chunks.push(chunk as Buffer);
	}
	const text = Buffer.concat(chunks).toString("utf8");
	if (text.trim() === "") return {};
	try {
		const parsed: unknown = JSON.parse(text);
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as Record<string, unknown>;
		}
	} catch {
		// Fall through to the refusal.
	}
	throw new HttpError(400, "bad_json");
}

interface SetupJob {
	id: string;
	events: SetupEvent[];
	done: boolean;
	result?: SetupSummary;
	error?: string;
}

export async function startAssistantServer(
	options: AssistantServerOptions,
): Promise<AssistantServer> {
	const { ops, assets } = options;
	const idleMs = options.idleMs ?? IDLE_TIMEOUT_MS;
	const token = options.token ?? randomBytes(32).toString("hex");
	let tokenUsed = false;
	let session: string | null = null;
	let job: SetupJob | null = null;
	let closing: Promise<void> | null = null;
	let resolveClosed: (reason: CloseReason) => void = () => {};
	const closed = new Promise<CloseReason>((resolve) => {
		resolveClosed = resolve;
	});
	let idleTimer: NodeJS.Timeout | undefined;

	const server: Server = createServer((request, response) => {
		handle(request, response).catch((error: unknown) => {
			const failure = error instanceof HttpError ? error : new HttpError(500, "internal_error");
			if (!response.headersSent) sendJson(response, failure.status, { error: failure.code });
			else response.destroy();
		});
	});
	server.headersTimeout = 30_000;
	server.requestTimeout = 120_000;

	function touch(): void {
		if (idleTimer) clearTimeout(idleTimer);
		idleTimer = setTimeout(() => {
			if (job && !job.done) {
				touch();
				return;
			}
			void close("idle");
		}, idleMs);
		idleTimer.unref?.();
	}

	function close(reason: CloseReason = "done"): Promise<void> {
		if (closing) return closing;
		if (idleTimer) clearTimeout(idleTimer);
		closing = new Promise<void>((resolve) => {
			server.close(() => resolve());
			server.closeAllConnections?.();
		}).then(() => resolveClosed(reason));
		return closing;
	}

	const port = await new Promise<number>((resolve, reject) => {
		server.once("error", reject);
		server.listen({ port: 0, host: "127.0.0.1", exclusive: true }, () => {
			server.off("error", reject);
			resolve((server.address() as AddressInfo).port);
		});
	});
	const origin = `http://127.0.0.1:${port}`;
	touch();

	function requireSession(request: IncomingMessage): void {
		const presented = readCookie(request.headers.cookie, SESSION_COOKIE);
		if (session === null || !sameSecret(presented, session)) {
			throw new HttpError(401, "no_session");
		}
		touch();
	}

	async function exchangeToken(request: IncomingMessage, response: ServerResponse): Promise<void> {
		const body = await readJson(request);
		const presented = typeof body.token === "string" ? body.token : undefined;
		// One token, one exchange, one session: a second attempt is refused even
		// with the right token, so a copied or raced link cannot take over.
		if (tokenUsed || session !== null) throw new HttpError(403, "token_used");
		if (!sameSecret(presented, token)) throw new HttpError(403, "bad_token");
		tokenUsed = true;
		session = randomBytes(32).toString("hex");
		touch();
		sendJson(
			response,
			200,
			{ ok: true },
			{ "Set-Cookie": `${SESSION_COOKIE}=${session}; HttpOnly; SameSite=Strict; Path=/` },
		);
	}

	function startSetup(hosts: unknown): { job: string } {
		if (job && !job.done) throw new HttpError(409, "setup_running");
		if (!Array.isArray(hosts) || hosts.some((host) => typeof host !== "string")) {
			throw new HttpError(400, "bad_hosts");
		}
		const current: SetupJob = { id: randomBytes(8).toString("hex"), events: [], done: false };
		job = current;
		ops
			.setup(hosts as string[], (event) => {
				current.events.push(event);
				touch();
			})
			.then(
				(result) => {
					current.result = result;
				},
				(error: unknown) => {
					current.error = error instanceof Error ? error.message : String(error);
				},
			)
			.finally(() => {
				current.done = true;
				touch();
			});
		return { job: current.id };
	}

	async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
		const refused = checkRequestOrigin(request, port);
		if (refused) throw refused;
		const path = (request.url ?? "/").split("?")[0];
		const method = request.method ?? "";

		if (method === "GET") {
			switch (path) {
				case "/":
					return send(response, 200, assets.html, "text/html; charset=utf-8");
				case "/app.js":
					return send(response, 200, assets.js, "text/javascript; charset=utf-8");
				case "/app.css":
					return send(response, 200, assets.css, "text/css; charset=utf-8");
				case "/icon.svg":
					return send(response, 200, assets.icon, "image/svg+xml");
			}
			if (!path.startsWith("/api/")) throw new HttpError(404, "not_found");
			requireSession(request);
			if (path === "/api/state") return sendJson(response, 200, await ops.state());
			if (path === "/api/status") return sendJson(response, 200, await ops.status());
			if (path === "/api/setup") {
				if (!job) throw new HttpError(404, "no_setup");
				return sendJson(response, 200, {
					job: job.id,
					events: job.events,
					done: job.done,
					result: job.result ?? null,
					error: job.error ?? null,
				});
			}
			throw new HttpError(404, "not_found");
		}

		if (method !== "POST") throw new HttpError(405, "method_not_allowed");
		if (path === "/api/session") return exchangeToken(request, response);
		if (!path.startsWith("/api/")) throw new HttpError(404, "not_found");
		requireSession(request);
		const body = await readJson(request);
		switch (path) {
			case "/api/detect":
				return sendJson(response, 200, await ops.detect());
			case "/api/setup":
				return sendJson(response, 202, startSetup(body.hosts));
			case "/api/verify":
				return sendJson(response, 200, await ops.verify());
			case "/api/enroll/start":
				return sendJson(
					response,
					200,
					await ops.enrollStart({
						endpoint: typeof body.endpoint === "string" ? body.endpoint : "",
						useInstallerToken: body.useInstallerToken === true,
					}),
				);
			case "/api/enroll/poll":
				return sendJson(response, 200, await ops.enrollPoll());
			case "/api/enroll/cancel":
				return sendJson(response, 200, await ops.enrollCancel());
			case "/api/finish":
				sendJson(response, 200, { ok: true });
				setImmediate(() => void close("done"));
				return;
		}
		throw new HttpError(404, "not_found");
	}

	return {
		url: `${origin}/#t=${token}`,
		origin,
		port,
		address: (server.address() as AddressInfo).address,
		close,
		closed,
	};
}
