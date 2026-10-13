/**
 * Setup Assistant server security: localhost-only bind, the one-time token in
 * the URL fragment exchanged for an HttpOnly SameSite=Strict cookie, Host and
 * Origin checks (DNS rebinding), methods, no CORS, CSP, body limits, the fixed
 * operation list and the idle / finish shutdown.
 */
import { request } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type AssistantServer,
	readCookie,
	sameSecret,
	startAssistantServer,
} from "../assistant/server.js";
import type { AssistantOps, SetupEvent, SetupSummary } from "../assistant/types.js";

const ASSETS = {
	html: "<!doctype html><p>wizard</p>",
	css: "body{}",
	js: "void 0;",
	icon: "<svg/>",
};

interface Reply {
	status: number;
	headers: Record<string, string | string[] | undefined>;
	body: string;
	json: () => Record<string, unknown>;
}

function call(
	server: AssistantServer,
	method: string,
	path: string,
	options: { headers?: Record<string, string>; body?: string; host?: string | null } = {},
): Promise<Reply> {
	return new Promise((resolve, reject) => {
		const headers: Record<string, string> = { ...options.headers };
		if (options.host !== null) headers.Host = options.host ?? `127.0.0.1:${server.port}`;
		const req = request(
			{ host: "127.0.0.1", port: server.port, method, path, headers, setHost: false },
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (chunk) => chunks.push(chunk));
				res.on("end", () => {
					const body = Buffer.concat(chunks).toString("utf8");
					resolve({
						status: res.statusCode ?? 0,
						headers: res.headers,
						body,
						json: () => JSON.parse(body),
					});
				});
			},
		);
		req.on("error", reject);
		if (options.body !== undefined) req.write(options.body);
		req.end();
	});
}

function tokenOf(server: AssistantServer): string {
	return server.url.split("#t=")[1];
}

/** POST as the page does: same Origin, JSON body, session cookie. */
function post(server: AssistantServer, path: string, body: unknown, cookie?: string) {
	return call(server, "POST", path, {
		headers: {
			Origin: server.origin,
			"Content-Type": "application/json",
			...(cookie ? { Cookie: cookie } : {}),
		},
		body: JSON.stringify(body),
	});
}

async function login(server: AssistantServer): Promise<string> {
	const reply = await post(server, "/api/session", { token: tokenOf(server) });
	expect(reply.status).toBe(200);
	const setCookie = String(reply.headers["set-cookie"]);
	return setCookie.split(";")[0];
}

function fakeOps(overrides: Partial<AssistantOps> = {}): AssistantOps & {
	calls: string[];
} {
	const calls: string[] = [];
	const record =
		<T>(name: string, value: T) =>
		async (...args: unknown[]) => {
			calls.push(
				`${name}${args.length && typeof args[0] !== "function" ? ` ${JSON.stringify(args[0])}` : ""}`,
			);
			return value;
		};
	const summary: SetupSummary = { ok: true, rules: 519, hosts: [] };
	return {
		calls,
		state: record("state", { version: "0.6.0" }) as never,
		detect: record("detect", [{ id: "codex" }]) as never,
		setup: async (hosts, progress) => {
			calls.push(`setup ${JSON.stringify(hosts)}`);
			progress({ type: "rules", rules: 519 });
			return summary;
		},
		verify: record("verify", { hosts: [] }) as never,
		status: record("status", { protected: [] }) as never,
		enrollStart: record("enrollStart", { phase: "waiting" }) as never,
		enrollPoll: record("enrollPoll", { phase: "waiting" }) as never,
		enrollCancel: record("enrollCancel", { phase: "idle" }) as never,
		...overrides,
	};
}

const servers: AssistantServer[] = [];
async function start(options: { ops?: AssistantOps; idleMs?: number } = {}) {
	const server = await startAssistantServer({
		ops: options.ops ?? fakeOps(),
		assets: ASSETS,
		idleMs: options.idleMs,
	});
	servers.push(server);
	return server;
}

afterEach(async () => {
	vi.useRealTimers();
	await Promise.all(servers.splice(0).map((server) => server.close("signal")));
});

describe("binding and address", () => {
	it("listens on 127.0.0.1 only, on a random port, with a 256-bit token in the fragment", async () => {
		const first = await start();
		const second = await start();
		expect(first.address).toBe("127.0.0.1");
		expect(first.port).not.toBe(second.port);
		expect(first.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/#t=[0-9a-f]{64}$/u);
		expect(tokenOf(first)).not.toBe(tokenOf(second));
		// The token never appears in a request line: only in the fragment.
		expect(first.url.split("#")[0]).toBe(`${first.origin}/`);
	});
});

describe("token and session", () => {
	it("serves the page without a session but refuses every API call without the cookie", async () => {
		const server = await start();
		expect((await call(server, "GET", "/")).status).toBe(200);
		expect((await call(server, "GET", "/app.js")).status).toBe(200);
		expect((await call(server, "GET", "/api/state")).status).toBe(401);
		expect((await post(server, "/api/detect", {})).status).toBe(401);
		expect((await post(server, "/api/detect", {}, "aidr_assistant_session=forged")).status).toBe(
			401,
		);
	});

	it("exchanges the token once for an HttpOnly SameSite=Strict cookie", async () => {
		const server = await start();
		expect((await post(server, "/api/session", { token: "0".repeat(64) })).status).toBe(403);
		expect((await post(server, "/api/session", {})).status).toBe(403);
		const reply = await post(server, "/api/session", { token: tokenOf(server) });
		expect(reply.status).toBe(200);
		const setCookie = String(reply.headers["set-cookie"]);
		expect(setCookie).toMatch(
			/^aidr_assistant_session=[0-9a-f]{64}; HttpOnly; SameSite=Strict; Path=\/$/u,
		);
		const cookie = setCookie.split(";")[0];
		expect((await call(server, "GET", "/api/state", { headers: { Cookie: cookie } })).status).toBe(
			200,
		);
		// Single use: the same token, again, is refused and mints no second session.
		const again = await post(server, "/api/session", { token: tokenOf(server) });
		expect(again.status).toBe(403);
		expect(again.json().error).toBe("token_used");
		expect(again.headers["set-cookie"]).toBeUndefined();
	});

	it("compares secrets in constant time and parses cookies strictly", () => {
		expect(sameSecret("abc", "abc")).toBe(true);
		expect(sameSecret("abd", "abc")).toBe(false);
		expect(sameSecret(undefined, "abc")).toBe(false);
		expect(sameSecret("", "abc")).toBe(false);
		expect(readCookie("a=1; aidr_assistant_session=xyz", "aidr_assistant_session")).toBe("xyz");
		expect(readCookie("xaidr_assistant_session=xyz", "aidr_assistant_session")).toBeUndefined();
	});
});

describe("Host and Origin checks (DNS rebinding)", () => {
	it("refuses any Host but 127.0.0.1:<port>", async () => {
		const server = await start();
		for (const host of [
			"localhost",
			`localhost:${server.port}`,
			"evil.example",
			`evil.example:${server.port}`,
			"127.0.0.1",
			`127.0.0.1:${server.port + 1}`,
		]) {
			const reply = await call(server, "GET", "/", { host });
			expect(reply.status, host).toBe(421);
		}
		// HTTP/1.1 without Host: Node itself answers 400 before the handler runs.
		expect([400, 421]).toContain((await call(server, "GET", "/", { host: null })).status);
	});

	it("refuses a foreign Origin, a POST without Origin and cross-site fetches", async () => {
		const server = await start();
		const cookie = await login(server);
		const foreign = await call(server, "POST", "/api/detect", {
			headers: {
				Origin: "http://evil.example",
				"Content-Type": "application/json",
				Cookie: cookie,
			},
			body: "{}",
		});
		expect(foreign.status).toBe(403);
		const noOrigin = await call(server, "POST", "/api/detect", {
			headers: { "Content-Type": "application/json", Cookie: cookie },
			body: "{}",
		});
		expect(noOrigin.status).toBe(403);
		const otherPort = await call(server, "GET", "/api/state", {
			headers: { Origin: `http://127.0.0.1:${server.port + 1}`, Cookie: cookie },
		});
		expect(otherPort.status).toBe(403);
		const crossSite = await call(server, "GET", "/api/state", {
			headers: { "Sec-Fetch-Site": "cross-site", Cookie: cookie },
		});
		expect(crossSite.status).toBe(403);
		const sameOrigin = await call(server, "GET", "/api/state", {
			headers: { Origin: server.origin, "Sec-Fetch-Site": "same-origin", Cookie: cookie },
		});
		expect(sameOrigin.status).toBe(200);
	});
});

describe("methods, CORS, CSP and bodies", () => {
	it("allows GET and POST only and never sends CORS headers", async () => {
		const server = await start();
		const cookie = await login(server);
		for (const method of ["PUT", "DELETE", "PATCH", "OPTIONS"]) {
			const reply = await call(server, method, "/api/detect", {
				headers: { Origin: server.origin, Cookie: cookie, "Access-Control-Request-Method": "POST" },
			});
			expect(reply.status, method).toBe(405);
			expect(Object.keys(reply.headers).some((name) => name.startsWith("access-control-"))).toBe(
				false,
			);
		}
		const page = await call(server, "GET", "/");
		expect(Object.keys(page.headers).some((name) => name.startsWith("access-control-"))).toBe(
			false,
		);
	});

	it("sends a self-only CSP and hardening headers on every response", async () => {
		const server = await start();
		for (const path of ["/", "/app.js", "/app.css", "/icon.svg", "/api/state", "/nope"]) {
			const reply = await call(server, "GET", path);
			const csp = String(reply.headers["content-security-policy"]);
			expect(csp, path).toContain("default-src 'self'");
			expect(csp).toContain("frame-ancestors 'none'");
			expect(csp).not.toContain("unsafe-inline");
			expect(reply.headers["x-content-type-options"]).toBe("nosniff");
			expect(reply.headers["cache-control"]).toBe("no-store");
			expect(reply.headers["referrer-policy"]).toBe("no-referrer");
		}
	});

	it("requires a JSON body under 16 KiB", async () => {
		const server = await start();
		const cookie = await login(server);
		const text = await call(server, "POST", "/api/detect", {
			headers: { Origin: server.origin, "Content-Type": "text/plain", Cookie: cookie },
			body: "{}",
		});
		expect(text.status).toBe(415);
		const form = await call(server, "POST", "/api/detect", {
			headers: {
				Origin: server.origin,
				"Content-Type": "application/x-www-form-urlencoded",
				Cookie: cookie,
			},
			body: "a=b",
		});
		expect(form.status).toBe(415);
		const big = await post(server, "/api/enroll/start", { endpoint: "x".repeat(20_000) }, cookie);
		expect(big.status).toBe(413);
		const broken = await call(server, "POST", "/api/detect", {
			headers: { Origin: server.origin, "Content-Type": "application/json", Cookie: cookie },
			body: "{",
		});
		expect(broken.status).toBe(400);
	});
});

describe("operations", () => {
	it("routes each allowed operation to the ops and nothing else", async () => {
		const ops = fakeOps();
		const server = await start({ ops });
		const cookie = await login(server);
		const get = (path: string) => call(server, "GET", path, { headers: { Cookie: cookie } });
		expect((await get("/api/state")).json()).toEqual({ version: "0.6.0" });
		expect((await get("/api/status")).json()).toEqual({ protected: [] });
		expect((await post(server, "/api/detect", {}, cookie)).json()).toEqual([{ id: "codex" }]);
		expect((await post(server, "/api/verify", {}, cookie)).json()).toEqual({ hosts: [] });
		expect(
			(
				await post(
					server,
					"/api/enroll/start",
					{ endpoint: "https://aidr.example", useInstallerToken: true },
					cookie,
				)
			).json(),
		).toEqual({ phase: "waiting" });
		expect((await post(server, "/api/enroll/poll", {}, cookie)).json()).toEqual({
			phase: "waiting",
		});
		expect((await post(server, "/api/enroll/cancel", {}, cookie)).json()).toEqual({
			phase: "idle",
		});
		expect(ops.calls).toEqual([
			"state",
			"status",
			"detect",
			"verify",
			'enrollStart {"endpoint":"https://aidr.example","useInstallerToken":true}',
			"enrollPoll",
			"enrollCancel",
		]);
		// No destructive or approval route exists.
		for (const path of [
			"/api/uninstall",
			"/api/approve",
			"/api/config",
			"/api/setup/force",
			"/api/open",
		]) {
			expect((await post(server, path, {}, cookie)).status, path).toBe(404);
		}
	});

	it("runs setup as one job with progress and refuses a second concurrent run", async () => {
		let release: () => void = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const ops = fakeOps({
			setup: async (hosts: string[], progress: (event: SetupEvent) => void) => {
				progress({ type: "rules", rules: 519 });
				progress({ type: "host-start", id: "codex", label: "Codex" });
				await gate;
				return { ok: true, rules: 519, hosts: [] };
			},
		});
		const server = await start({ ops });
		const cookie = await login(server);
		expect((await call(server, "GET", "/api/setup", { headers: { Cookie: cookie } })).status).toBe(
			404,
		);
		const started = await post(server, "/api/setup", { hosts: ["codex"] }, cookie);
		expect(started.status).toBe(202);
		expect((await post(server, "/api/setup", { hosts: ["codex"] }, cookie)).status).toBe(409);
		const running = (
			await call(server, "GET", "/api/setup", { headers: { Cookie: cookie } })
		).json();
		expect(running.done).toBe(false);
		expect(running.events).toHaveLength(2);
		release();
		await new Promise((resolve) => setTimeout(resolve, 20));
		const done = (await call(server, "GET", "/api/setup", { headers: { Cookie: cookie } })).json();
		expect(done.done).toBe(true);
		expect(done.result).toEqual({ ok: true, rules: 519, hosts: [] });
		expect((await post(server, "/api/setup", { hosts: "codex" }, cookie)).status).toBe(400);
	});

	it("reports a failed setup job instead of crashing", async () => {
		const ops = fakeOps({
			setup: async () => {
				throw new Error("vault unavailable");
			},
		});
		const server = await start({ ops });
		const cookie = await login(server);
		await post(server, "/api/setup", { hosts: ["codex"] }, cookie);
		await new Promise((resolve) => setTimeout(resolve, 20));
		const job = (await call(server, "GET", "/api/setup", { headers: { Cookie: cookie } })).json();
		expect(job).toMatchObject({ done: true, error: "vault unavailable", result: null });
	});

	it("hides internal errors behind a generic code", async () => {
		const ops = fakeOps({
			detect: async () => {
				throw new Error("/home/secret/path exploded");
			},
		});
		const server = await start({ ops });
		const cookie = await login(server);
		const reply = await post(server, "/api/detect", {}, cookie);
		expect(reply.status).toBe(500);
		expect(reply.body).not.toContain("secret");
	});
});

describe("shutdown", () => {
	it("stops after the wizard finishes", async () => {
		const server = await start();
		const cookie = await login(server);
		expect((await post(server, "/api/finish", {}, cookie)).status).toBe(200);
		await expect(server.closed).resolves.toBe("done");
		await expect(call(server, "GET", "/")).rejects.toThrow();
	});

	it("stops after the idle timeout, and an authenticated request resets it", async () => {
		const server = await start({ idleMs: 150 });
		const cookie = await login(server);
		for (let i = 0; i < 3; i++) {
			await new Promise((resolve) => setTimeout(resolve, 80));
			expect(
				(await call(server, "GET", "/api/state", { headers: { Cookie: cookie } })).status,
			).toBe(200);
		}
		await expect(server.closed).resolves.toBe("idle");
	});

	it("unauthenticated requests do not keep it alive", async () => {
		const server = await start({ idleMs: 120 });
		const timer = setInterval(() => void call(server, "GET", "/").catch(() => {}), 30);
		try {
			await expect(server.closed).resolves.toBe("idle");
		} finally {
			clearInterval(timer);
		}
	});

	it("a running setup is not cut off by the idle timeout", async () => {
		let release: () => void = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const ops = fakeOps({
			setup: async () => {
				await gate;
				return { ok: true, rules: 1, hosts: [] };
			},
		});
		const server = await start({ ops, idleMs: 60 });
		const cookie = await login(server);
		await post(server, "/api/setup", { hosts: ["codex"] }, cookie);
		let closed = false;
		void server.closed.then(() => {
			closed = true;
		});
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(closed).toBe(false);
		release();
		await expect(server.closed).resolves.toBe("idle");
	});
});
