import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import ts from "typescript";
import { readDeviceCode } from "../_shared/auth.ts";
import { evaluateDevicePollState } from "../_shared/device-auth.ts";

type Session = {
	id: string;
	user_id: string;
	tenant_id: string;
	authorized_at: string;
	exchanged_at: string | null;
	expires_at: string;
	user_code: string;
};
type Token = {
	token_hash: string;
	user_id: string;
	tenant_id: string;
	expires_at: string;
	consumed_at: string | null;
	previous_hash: string | null;
};

const sourcePath = join(dirname(fileURLToPath(import.meta.url)), "..", "device-poll", "index.ts");
const source = readFileSync(sourcePath, "utf8").replace(/^import .*;\r?\n/gm, "");
const compiled = ts.transpileModule(source, {
	compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

function harness(options: {
	lostFirstRpcResponse?: boolean;
	lookupError?: boolean;
	approvalError?: boolean;
	concurrentReadBarrier?: boolean;
} = {}) {
	const session: Session = {
		id: "session-1", user_id: "user-1", tenant_id: "tenant-1",
		authorized_at: new Date(Date.now() - 60_000).toISOString(), exchanged_at: null,
		expires_at: new Date(Date.now() + 600_000).toISOString(), user_code: "USERCODE",
	};
	const tokens: Token[] = [];
	let rpcCalls = 0;
	let sessionReads = 0;
	let clientCreations = 0;
	let releaseReads: (() => void) | undefined;
	const bothReads = new Promise<void>((resolve) => { releaseReads = resolve; });
	let handler: ((request: Request) => Promise<Response>) | undefined;
	const client = {
		from(table: string) {
			const filters = new Map<string, unknown>();
			const query = {
				select(_columns: string) { return query; },
				eq(column: string, value: unknown) { filters.set(column, value); return query; },
				limit(_count: number) { return query; },
				async maybeSingle() {
					if (table === "device_sessions") {
						if (options.lookupError) return { data: null, error: { message: "database unavailable" } };
						const snapshot = { ...session };
						if (options.concurrentReadBarrier) {
							sessionReads++;
							if (sessionReads === 2) releaseReads?.();
							await bothReads;
						}
						return { data: snapshot, error: null };
					}
					if (table === "tenant_members") return { data: { role: "owner", expires_at: null }, error: null };
					if (table === "tenants") return { data: { status: "active" }, error: null };
					if (table === "enrollment_tokens") {
						return { data: tokens.find((token) => [...filters].every(([key, value]) => token[key as keyof Token] === value)) ?? null, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return query;
		},
		async rpc(name: string, args: Record<string, string>) {
			if (name === "tenant_admission_capacity") return options.approvalError
				? { data: null, error: { message: "database unavailable" } }
				: { data: 1, error: null };
			expect(name).toBe("issue_device_enrollment_token");
			rpcCalls++;
			if (session.exchanged_at) return { data: { status: "already_exchanged_or_invalid" }, error: null };
			tokens.push({ token_hash: args.p_token_hash!, user_id: session.user_id,
				tenant_id: session.tenant_id, expires_at: args.p_expires_at!, consumed_at: null,
				previous_hash: null });
			session.exchanged_at = new Date().toISOString();
			if (options.lostFirstRpcResponse && rpcCalls === 1) {
				return { data: null, error: { message: "response lost after commit" } };
			}
			return { data: { status: "issued" }, error: null };
		},
	};
	new Function("Deno", "createClient", "readDeviceCode", "configFailure", "loadConfig",
		"runtimeEnv", "corsJson", "handleCors", "evaluateDevicePollState", compiled)(
		{ env: { get: () => undefined }, serve: (fn: typeof handler) => { handler = fn; } },
		() => { clientCreations++; return client; },
		readDeviceCode,
		() => { throw new Error("unexpected config failure"); },
		() => ({ ok: true, values: { SUPABASE_URL: "https://test.invalid", SUPABASE_SERVICE_ROLE_KEY: "test" } }),
		{},
		(_request: Request, status: number, body: unknown) => Response.json(body, { status }),
		() => null,
		evaluateDevicePollState,
	);
	if (!handler) throw new Error("device-poll handler was not registered");
	const poll = async (request = new Request("https://test.invalid/device-poll", {
		method: "POST", headers: { Authorization: "Bearer aidr_device_test-secret" },
	})) => {
		const response = await handler!(request);
		return { status: response.status, body: await response.json() as Record<string, unknown> };
	};
	return { poll, session, tokens, get rpcCalls() { return rpcCalls; }, get clientCreations() { return clientCreations; } };
}

describe("device poll retry after an atomic issue", () => {
	it("rejects an oversized bearer before creating a database client", async () => {
		const app = harness();
		const response = await app.poll(new Request("https://test.invalid/device-poll", {
			method: "POST", headers: { Authorization: `Bearer ${"x".repeat(1025)}` }, body: "{}",
		}));
		expect(response).toMatchObject({ status: 401, body: { error: "missing_device_code" } });
		expect(app.clientCreations).toBe(0);
	});

	it("recovers the same hash-only token after the RPC commits but its response is lost", async () => {
		const app = harness({ lostFirstRpcResponse: true });
		expect(await app.poll()).toMatchObject({ status: 503, body: { enrollment_outcome: "unknown" } });
		const retry = await app.poll();
		expect(retry).toMatchObject({ status: 200, body: { ok: true, status: "approved" } });
		expect(retry.body.enrollment_token).toMatch(/^aidr_enroll_[A-Za-z0-9_-]+$/);
		expect(app.tokens).toHaveLength(1);
		expect(app.tokens[0]!.token_hash).toMatch(/^[a-f0-9]{64}$/);
		expect(app.tokens[0]!.token_hash).not.toBe(retry.body.enrollment_token);
		expect(app.rpcCalls).toBe(1);
	});

	it("returns one reusable token to concurrent polls and does not issue a second row", async () => {
		const app = harness({ concurrentReadBarrier: true });
		const [first, second] = await Promise.all([app.poll(), app.poll()]);
		expect(first.status).toBe(200);
		expect(second.status).toBe(200);
		expect(first.body.enrollment_token).toBe(second.body.enrollment_token);
		expect(app.tokens).toHaveLength(1);
		expect(app.rpcCalls).toBe(2);
	});

	it("recovers only while the issued token is valid and unused", async () => {
		const app = harness();
		const issued = await app.poll();
		app.session.expires_at = new Date(Date.now() - 1_000).toISOString();
		expect((await app.poll()).body.enrollment_token).toBe(issued.body.enrollment_token);
		app.tokens[0]!.consumed_at = new Date().toISOString();
		expect(await app.poll()).toMatchObject({ status: 409, body: { error: "already_exchanged" } });
	});

	it("rejects a device code presented after the enrollment key was rotated", async () => {
		const app = harness();
		const issued = await app.poll();
		expect(issued).toMatchObject({ status: 200, body: { ok: true, status: "approved" } });

		// Renewal replaces the stored hash and records the retired one for a
		// bounded overlap. The device code can only present the retired hash, so
		// it must not recover it: otherwise a rotation could be undone by the
		// device that minted the token.
		const retired = app.tokens[0]!.token_hash;
		app.tokens[0]!.previous_hash = retired;
		app.tokens[0]!.token_hash = "f".repeat(64);

		expect(app.tokens).toHaveLength(1);
		expect(await app.poll()).toMatchObject({ status: 409, body: { error: "already_exchanged" } });
		// The recovery path resolves the active hash only, so the device code
		// never sees the overlap window that the exchange path honors.
		expect(source).not.toContain("previous_hash");
	});

	it("keeps transient lookup failures distinct from an invalid device code", async () => {
		expect(await harness({ lookupError: true }).poll()).toMatchObject({
			status: 503, body: { error: "device_session_lookup_failed", enrollment_outcome: "unknown" },
		});
		expect(await harness({ approvalError: true }).poll()).toMatchObject({
			status: 503, body: { error: "tenant_admission_unavailable", enrollment_outcome: "unknown" },
		});
	});
});
