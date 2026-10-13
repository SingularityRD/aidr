/**
 * A real run of the built CLI: `aidr assistant --no-open` in a scratch HOME,
 * driven over HTTP the way the page drives it — token exchange, detection,
 * device-code enrollment against a fake control plane on loopback, setup with
 * progress, verify, status and finish — plus the server's refusals on the
 * real process. Nothing outside the scratch HOME is touched.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CLI = resolve(__dirname, "..", "..", "dist", "index.js");
const built = existsSync(CLI);

interface Reply {
	status: number;
	headers: Record<string, string | string[] | undefined>;
	body: string;
}

function http(
	port: number,
	method: string,
	path: string,
	headers: Record<string, string>,
	body?: unknown,
): Promise<Reply> {
	return new Promise((done, fail) => {
		const req = request(
			{ host: "127.0.0.1", port, method, path, headers, setHost: false },
			(res) => {
				const chunks: Buffer[] = [];
				res.on("data", (chunk) => chunks.push(chunk));
				res.on("end", () =>
					done({
						status: res.statusCode ?? 0,
						headers: res.headers,
						body: Buffer.concat(chunks).toString("utf8"),
					}),
				);
			},
		);
		req.on("error", fail);
		if (body !== undefined) req.write(JSON.stringify(body));
		req.end();
	});
}

/** Fake control plane: device-start, device-poll (pending once, then approved), enroll. */
function controlPlane(): Promise<{ server: Server; url: string; calls: string[] }> {
	const calls: string[] = [];
	let polls = 0;
	const server = createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (chunk) => chunks.push(chunk));
		req.on("end", () => {
			calls.push(`${req.method} ${req.url}`);
			const send = (status: number, body: unknown) => {
				res.writeHead(status, { "Content-Type": "application/json" });
				res.end(JSON.stringify(body));
			};
			const port = (server.address() as AddressInfo).port;
			if (req.url === "/v1/device-start") {
				return send(200, {
					ok: true,
					device_code: "device-secret-code",
					user_code: "WXYZ-1234",
					verification_url: `http://127.0.0.1:${port}/verify?code=WXYZ-1234`,
					expires_at: new Date(Date.now() + 600_000).toISOString(),
					interval_seconds: 1,
				});
			}
			if (req.url === "/v1/device-poll") {
				expect(req.headers.authorization).toBe("Bearer device-secret-code");
				polls += 1;
				return polls < 2
					? send(200, {
							ok: true,
							status: "pending",
							error: "authorization_pending",
							interval_seconds: 1,
						})
					: send(200, { ok: true, status: "approved", enrollment_token: "enroll-token-from-poll" });
			}
			if (req.url === "/v1/enroll") {
				expect(req.headers.authorization).toBe("Bearer enroll-token-from-poll");
				return send(200, { api_key: "aidr_live_assistant-e2e-key" });
			}
			send(404, { error: "not_found" });
		});
	});
	return new Promise((done) => {
		server.listen(0, "127.0.0.1", () => {
			done({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, calls });
		});
	});
}

// AIDR-SKIP: AIDR-063 qa-owner - needs the built CLI (dist/); `pnpm test` builds it in globalSetup, a bare vitest run in an unbuilt tree does not
describe.skipIf(!built)("aidr assistant (built CLI, scratch HOME)", () => {
	let home: string;
	let child: ChildProcess;
	let stdout = "";
	let exited: Promise<number | null>;
	let plane: Awaited<ReturnType<typeof controlPlane>>;
	let port = 0;
	let origin = "";
	let token = "";
	let cookie = "";

	const get = (path: string) =>
		http(port, "GET", path, { Host: `127.0.0.1:${port}`, Cookie: cookie });
	const post = (path: string, body: unknown = {}) =>
		http(
			port,
			"POST",
			path,
			{
				Host: `127.0.0.1:${port}`,
				Origin: origin,
				"Content-Type": "application/json",
				Cookie: cookie,
			},
			body,
		);
	const json = async (reply: Promise<Reply>) => {
		const answer = await reply;
		expect(answer.status, answer.body).toBeLessThan(300);
		return JSON.parse(answer.body);
	};

	beforeAll(async () => {
		home = mkdtempSync(join(tmpdir(), "aidr-assistant-e2e-"));
		mkdirSync(join(home, ".config", "opencode"), { recursive: true });
		writeFileSync(join(home, ".config", "opencode", "opencode.json"), "{}\n");
		// The fake control plane is plain HTTP on loopback: the existing opt-in for that.
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true, mode: 0o700 });
		writeFileSync(
			join(home, ".singularity-aidr", "config.json"),
			JSON.stringify({ control_plane: { allow_insecure_loopback: true } }),
			{ mode: 0o600 },
		);
		plane = await controlPlane();
		child = spawn(process.execPath, [CLI, "assistant", "--no-open"], {
			env: {
				PATH: process.env.PATH ?? "",
				HOME: home,
				USERPROFILE: home,
				AIDR_LOCALE: "en",
				XDG_CONFIG_HOME: join(home, ".config"),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		exited = new Promise((done) => child.once("exit", (code) => done(code)));
		child.stdout?.on("data", (chunk) => {
			stdout += String(chunk);
		});
		child.stderr?.on("data", (chunk) => {
			stdout += String(chunk);
		});
		for (let i = 0; i < 300 && !/#t=[0-9a-f]{64}/u.test(stdout); i++) {
			await new Promise((done) => setTimeout(done, 50));
		}
		const match = /(http:\/\/127\.0\.0\.1:(\d+))\/#t=([0-9a-f]{64})/u.exec(stdout);
		if (!match) throw new Error(`no address printed: ${stdout}`);
		[, origin, , token] = match;
		port = Number(match[2]);
	}, 60_000);

	afterAll(async () => {
		if (child && child.exitCode === null) child.kill("SIGTERM");
		await new Promise<void>((done) => plane?.server.close(() => done()));
		rmSync(home, { recursive: true, force: true });
	});

	it("prints the one-time address and refuses requests before the session", async () => {
		expect(stdout).toContain("Open this address in a browser on this computer:");
		expect(stdout).toContain("The address works once");
		expect((await get("/api/state")).status).toBe(401);
		expect((await http(port, "GET", "/", { Host: `localhost:${port}` })).status).toBe(421);
		const page = await http(port, "GET", "/", { Host: `127.0.0.1:${port}` });
		expect(page.status).toBe(200);
		expect(page.headers["content-security-policy"]).toContain("default-src 'self'");
		expect(page.body).toContain('<script src="/app.js" defer></script>');
		const script = await http(port, "GET", "/app.js", { Host: `127.0.0.1:${port}` });
		expect(script.body).toContain("Setup Assistant");
	});

	it("exchanges the token once", async () => {
		const reply = await post("/api/session", { token });
		expect(reply.status).toBe(200);
		cookie = String(reply.headers["set-cookie"]).split(";")[0];
		expect(String(reply.headers["set-cookie"])).toContain("HttpOnly; SameSite=Strict");
		expect((await post("/api/session", { token })).status).toBe(403);
	});

	it("reports the state and the AI tools of the scratch HOME", async () => {
		const state = await json(get("/api/state"));
		expect(state).toMatchObject({ locale: "en", company: null, pending: null });
		const tools = await json(post("/api/detect"));
		expect(tools.find((tool: { id: string }) => tool.id === "opencode").state).toBe(
			"runtime_present_not_installed",
		);
	});

	it("connects to the company with the device code and records managed mode", async () => {
		const waiting = await json(post("/api/enroll/start", { endpoint: `${plane.url}/` }));
		expect(waiting).toMatchObject({ phase: "waiting", userCode: "WXYZ-1234", endpoint: plane.url });
		let view = waiting;
		for (let i = 0; i < 20 && view.phase === "waiting"; i++) {
			await new Promise((done) => setTimeout(done, 600));
			view = await json(post("/api/enroll/poll"));
		}
		expect(view).toEqual({ phase: "enrolled", endpoint: plane.url });
		expect(plane.calls).toEqual([
			"POST /v1/device-start",
			"POST /v1/device-poll",
			"POST /v1/device-poll",
			"POST /v1/enroll",
		]);
		const config = JSON.parse(readFileSync(join(home, ".singularity-aidr", "config.json"), "utf8"));
		expect(config.mode).toBe("managed");
		expect(config.control_plane).toMatchObject({
			endpoint: plane.url,
			enabled: true,
			allow_insecure_loopback: true,
		});
		expect(existsSync(join(home, ".singularity-aidr", "managed.json"))).toBe(true);
		expect(existsSync(join(home, ".singularity-aidr", "managed.json.enrollment-pending"))).toBe(
			false,
		);
		const state = await json(get("/api/state"));
		expect(state.company).toEqual({ endpoint: plane.url, enrolled: true });
	}, 30_000);

	it("protects the selected tool with progress, then verifies and reports status", async () => {
		expect((await post("/api/setup", { hosts: ["opencode"] })).status).toBe(202);
		let job = await json(get("/api/setup"));
		for (let i = 0; i < 100 && !job.done; i++) {
			await new Promise((done) => setTimeout(done, 100));
			job = await json(get("/api/setup"));
		}
		expect(job.error).toBeNull();
		expect(job.events.map((event: { type: string }) => event.type)).toEqual([
			"rules",
			"host-start",
			"host-done",
		]);
		expect(job.result.hosts).toEqual([
			expect.objectContaining({ id: "opencode", label: "OpenCode", outcome: "restart" }),
		]);
		const opencode = JSON.parse(
			readFileSync(join(home, ".config", "opencode", "opencode.json"), "utf8"),
		);
		expect(opencode.plugin).toContain("@singularityrd/aidr-opencode");

		const verify = await json(post("/api/verify"));
		expect(verify.hosts.find((host: { id: string }) => host.id === "opencode").outcome).toBe(
			"skip",
		);
		const status = await json(get("/api/status"));
		expect(status.detection.ok).toBe(true);
		expect(status.restart).toEqual(["OpenCode"]);
	}, 60_000);

	it("offers no destructive route and stops when the wizard finishes", async () => {
		for (const path of ["/api/uninstall", "/api/approve", "/api/config"]) {
			expect((await post(path)).status, path).toBe(404);
		}
		expect((await post("/api/finish")).status).toBe(200);
		expect(await exited).toBe(0);
		expect(stdout).toContain("Setup Assistant finished. Run it again anytime: aidr assistant");
	}, 30_000);
});
