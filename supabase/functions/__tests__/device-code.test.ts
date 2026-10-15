import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import ts from "typescript";
import { readDeviceCode } from "../_shared/auth.ts";
import * as deviceAuth from "../_shared/device-auth.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";

const functionsDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const verifySource = readFileSync(join(functionsDir, "device-verify", "index.ts"), "utf8");
const onboardingSource = readFileSync(join(functionsDir, "..", "..", "scripts", "verify-customer-onboarding.mjs"), "utf8");

type VerifyHandler = (request: Request) => Promise<Response>;
const DEVICE_ID = "d0000000-0000-4000-8000-000000000001";

function deviceVerifyHarness(
	approvalError: boolean,
	approved: boolean,
	sessionTenantId: string | null = "tenant-1",
	options: { env?: Record<string, string>; aal?: "aal1" | "aal2" } = {},
) {
	const compiled = ts.transpileModule(verifySource.replace(/^import .*;\r?\n/gm, ""), {
		compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
	}).outputText;
	let handler: VerifyHandler | undefined;
	let admissionTenantId: string | undefined;
	let rateLimitCount = 0;
	const rpcCalls: string[] = [];
	const client = {
		auth: {
			getUser: async () => ({ data: { user: { id: "user-1" } }, error: null }),
			mfa: {
				getAuthenticatorAssuranceLevel: async () => ({ data: { currentLevel: options.aal ?? "aal1" }, error: null }),
			},
		},
		async rpc(name: string, args: Record<string, unknown>) {
			rpcCalls.push(name);
			if (name === "increment_rate_limit") {
				rateLimitCount += Number(args.p_delta ?? 0);
				return { data: null, error: null };
			}
			if (name === "tenant_admission_capacity") {
				admissionTenantId = String(args.p_tenant_id);
				return { data: approved && admissionTenantId === "tenant-1" ? 1 : 0,
					error: approvalError ? { message: "database unavailable" } : null };
			}
			if (name === "authorize_device_session") return { data: [{ id: "device-1" }], error: null };
			throw new Error(`unexpected RPC ${name}`);
		},
		from(table: string) {
			const query = {
				select(_columns: string) { return query; },
				eq(_column: string, _value: unknown) { return query; },
				limit(_count: number) { return query; },
				async maybeSingle() {
					if (table === "rate_limits") return { data: { count: rateLimitCount }, error: null };
					if (table === "device_sessions") {
						return {
							data: {
								id: DEVICE_ID,
								user_code: "ABCDEFGH",
								created_at: new Date(Date.now() - 30_000).toISOString(),
								authorized_at: null,
								expires_at: new Date(Date.now() + 60_000).toISOString(),
								user_id: null,
								tenant_id: sessionTenantId,
								requested_ip: "203.0.113.9",
								requested_runtime: "claude-code",
								requested_runtime_version: "2.1.0",
								requested_os: "darwin",
								requested_hostname: "build-mac",
								requested_scope: "tenant",
							},
							error: null,
						};
					}
					if (table === "tenants") return { data: { status: "active" }, error: null };
					if (table === "tenant_members") return { data: { role: "owner", expires_at: null }, error: null };
					throw new Error(`unexpected table ${table}`);
				},
			};
			return query;
		},
	};

	new Function(
		"Deno",
		"createClient",
		"checkIdentityBarrier",
		"getBearerToken",
		"configFailure",
		"loadConfig",
		"runtimeEnv",
		"corsJson",
		"handleCors",
		"booleanSetting",
		"deviceSessionDetails",
		"evaluateDeviceVerifyState",
		"parseDeviceVerifyCommand",
		"readBoundedJson",
		"jwtIssuedAtMs",
		compiled,
	)(
		{ env: { get: (name: string) => options.env?.[name] }, serve: (fn: VerifyHandler) => { handler = fn; } },
		() => client,
		async () => ({ ok: true }),
		(header: string | null) => header?.replace(/^Bearer\s+/i, "") ?? null,
		() => { throw new Error("unexpected config failure"); },
		() => ({ ok: true, values: { SUPABASE_URL: "https://test.invalid", SUPABASE_SERVICE_ROLE_KEY: "test" } }),
		{},
		(_request: Request, status: number, body: unknown) => Response.json(body, { status }),
		() => null,
		deviceAuth.booleanSetting,
		deviceAuth.deviceSessionDetails,
		deviceAuth.evaluateDeviceVerifyState,
		deviceAuth.parseDeviceVerifyCommand,
		readBoundedJson,
		() => Date.now(),
	);
	if (!handler) throw new Error("device-verify handler was not registered");
	const send = async (body: Record<string, unknown>, tenantHeader?: string) => {
		const response = await handler!(new Request("https://test.invalid/device-verify", {
			method: "POST",
			headers: {
				Authorization: "Bearer test-session",
				...(tenantHeader ? { "X-AIDR-Tenant-ID": tenantHeader } : {}),
			},
			body: JSON.stringify(body),
		}));
		return { status: response.status, body: await response.json() as Record<string, unknown> };
	};
	const run = (tenantHeader?: string) =>
		send({ action: "authorize", user_code: "ABCD-EFGH", device_session_id: DEVICE_ID, confirmed: true }, tenantHeader);
	return { run, send, rpcCalls, get admissionTenantId() { return admissionTenantId; } };
}

describe("device verification against remote phishing (CP-1)", () => {
	it("refuses to bind a code in one request: lookup and an explicit confirmation come first", async () => {
		const harness = deviceVerifyHarness(false, true);
		await expect(harness.send({ user_code: "ABCD-EFGH" })).resolves.toEqual({
			status: 400,
			body: { error: "device_confirmation_required" },
		});
		await expect(
			harness.send({ action: "authorize", user_code: "ABCD-EFGH", device_session_id: DEVICE_ID }),
		).resolves.toMatchObject({ status: 400, body: { error: "device_confirmation_required" } });
		expect(harness.rpcCalls).not.toContain("authorize_device_session");
	});

	it("shows the requester context on lookup without binding the session", async () => {
		const harness = deviceVerifyHarness(false, true);
		const looked = await harness.send({ action: "lookup", user_code: "abcd-efgh" });
		expect(looked.status).toBe(200);
		expect(looked.body.device).toMatchObject({
			device_session_id: DEVICE_ID,
			user_code: "ABCDEFGH",
			requester_ip: "203.0.113.9",
			runtime: "claude-code",
			runtime_version: "2.1.0",
			os: "darwin",
			hostname: "build-mac",
			requested_scope: "tenant",
		});
		expect(typeof (looked.body.device as Record<string, unknown>).requested_at).toBe("string");
		expect(harness.rpcCalls).not.toContain("authorize_device_session");
	});

	it("binds only the session the user was shown, after confirmation", async () => {
		const harness = deviceVerifyHarness(false, true);
		await expect(
			harness.send({
				action: "authorize", user_code: "ABCD-EFGH", confirmed: true,
				device_session_id: "d0000000-0000-4000-8000-000000000002",
			}),
		).resolves.toEqual({ status: 409, body: { error: "device_confirmation_mismatch" } });
		expect(harness.rpcCalls).not.toContain("authorize_device_session");
		await expect(harness.run()).resolves.toMatchObject({ status: 200, body: { ok: true } });
		expect(harness.rpcCalls).toContain("authorize_device_session");
	});

	it("can require an AAL2 session for enrollment and fails closed on a malformed switch", async () => {
		const aal1 = deviceVerifyHarness(false, true, "tenant-1", { env: { AIDR_DEVICE_VERIFY_REQUIRE_AAL2: "true" } });
		await expect(aal1.run()).resolves.toEqual({ status: 403, body: { error: "mfa_required" } });
		expect(aal1.rpcCalls).not.toContain("authorize_device_session");
		const aal2 = deviceVerifyHarness(false, true, "tenant-1", { env: { AIDR_DEVICE_VERIFY_REQUIRE_AAL2: "true" }, aal: "aal2" });
		await expect(aal2.run()).resolves.toMatchObject({ status: 200 });
		const broken = deviceVerifyHarness(false, true, "tenant-1", { env: { AIDR_DEVICE_VERIFY_REQUIRE_AAL2: "yes" } });
		await expect(broken.run()).resolves.toEqual({
			status: 500,
			body: { error: "server_misconfigured", invalid: ["AIDR_DEVICE_VERIFY_REQUIRE_AAL2"] },
		});
	});

	it("parses device-reported context strictly and bounds the code lifetime", () => {
		expect(deviceAuth.parseDeviceStartContext({
			agent_runtime: "codex", agent_runtime_version: "0.141.0", os: "linux", hostname: "ci-runner-7",
		})).toEqual({ runtime: "codex", runtime_version: "0.141.0", os: "linux", hostname: "ci-runner-7" });
		expect(deviceAuth.parseDeviceStartContext({
			agent_runtime: "Codex\u202e", agent_runtime_version: "x".repeat(65), os: "linux\nINFO", hostname: "evil host",
		})).toEqual({ runtime: null, runtime_version: null, os: null, hostname: null });
		expect(deviceAuth.parseDeviceStartContext(null)).toEqual({ runtime: null, runtime_version: null, os: null, hostname: null });
		expect(deviceAuth.deviceTtlMinutes(undefined)).toBe(10);
		expect(deviceAuth.deviceTtlMinutes("15")).toBe(15);
		for (const bad of ["0", "16", "60", "ten", ""]) expect(deviceAuth.deviceTtlMinutes(bad)).toBeNull();
		expect(deviceAuth.normalizeUserCode("abcd-efgh")).toBe("ABCDEFGH");
		expect(deviceAuth.normalizeUserCode("ABCD-EFG")).toBeNull();
	});

	it("records the requester context at device-start and in the binding audit", () => {
		const start = readFileSync(join(functionsDir, "device-start", "index.ts"), "utf8");
		for (const field of ["requested_ip: ip", "requested_runtime: reported.runtime", "requested_os: reported.os",
			"requested_hostname: reported.hostname", "requested_scope: DEVICE_REQUESTED_SCOPE"]) {
			expect(start).toContain(field);
		}
		expect(start).toContain('invalid.push("AIDR_DEVICE_TTL_MINUTES")');
		const migration = readFileSync(
			join(functionsDir, "..", "migrations", "20261013000530_device_session_requester_context.sql"), "utf8",
		);
		expect(migration).toContain("add column if not exists requested_ip text");
		expect(migration).toMatch(/'requester_ip', v_session\.requested_ip/);
		expect(migration).toMatch(/d\.authorized_at is null\s+and d\.expires_at > clock_timestamp\(\)/);
	});
});

describe("device poll credential selection", () => {
	it("uses the device code when the browser SDK sends a session JWT", async () => {
		const request = new Request("https://aidr.test/device-poll", {
			method: "POST", headers: { Authorization: "Bearer browser-jwt" },
			body: JSON.stringify({ device_code: "device-secret" }),
		});
		expect(await readDeviceCode(request)).toBe("device-secret");
	});
	it("supports native bearer device codes", async () => {
		expect(await readDeviceCode(new Request("https://aidr.test", {
			method: "POST", headers: { Authorization: "Bearer native-device" }, body: "{}",
		}))).toBe("native-device");
	});
	it("rejects an oversized bearer device code before database lookup", async () => {
		expect(await readDeviceCode(new Request("https://aidr.test", {
			method: "POST", headers: { Authorization: `Bearer ${"x".repeat(1025)}` }, body: "{}",
		}))).toBeNull();
	});
	it.each(["", 123, null, "x".repeat(1025)])("rejects an invalid explicit code without falling back to a JWT", async (code) => {
		expect(await readDeviceCode(new Request("https://aidr.test", {
			method: "POST", headers: { Authorization: "Bearer jwt" }, body: JSON.stringify({ device_code: code }),
		}))).toBeNull();
	});
	it("rejects an understated oversized body without falling back to bearer auth", async () => {
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode(`{"device_code":"${"x".repeat(2048)}"}`));
				controller.close();
			},
		});
		const request = new Request("https://aidr.test", {
			method: "POST",
			headers: { Authorization: "Bearer jwt", "content-length": "2" },
			body,
			duplex: "half",
		} as RequestInit);
		expect(await readDeviceCode(request)).toBeNull();
	});
});

describe("device authorization revocation binding", () => {
	it("checks admission against the resolved device tenant, never another tenant", () => {
		expect(verifySource).toContain("const tenantId = session.tenant_id ?? requested ?? userId");
		expect(verifySource).toContain('supabase.rpc("tenant_admission_capacity", { p_tenant_id: tenantId })');
	});

	it("uses the user-scoped fallback for tenantless device sessions without a tenant header", async () => {
		const harness = deviceVerifyHarness(false, true, null);
		await expect(harness.run()).resolves.toMatchObject({
			status: 403,
			body: { error: "tenant_not_admitted" },
		});
		expect(harness.admissionTenantId).toBe("user-1");
	});

	it("customer onboarding carries its provisioned tenant into device verification", () => {
		expect(onboardingSource).toContain(
			`request("/functions/v1/device-verify", token, { action: "lookup", user_code: device.user_code }, { "X-AIDR-Tenant-ID": receipt.tenant_id })`,
		);
		expect(onboardingSource).toContain(
			`{ action: "authorize", user_code: device.user_code, device_session_id: lookup.data.device.device_session_id, confirmed: true }, { "X-AIDR-Tenant-ID": receipt.tenant_id }`,
		);
	});

	it("passes Auth-verified JWT issuance time into the atomic authorization RPC", () => {
		const source = readFileSync(join(functionsDir, "device-verify", "index.ts"), "utf8");
		const verifiedAt = source.indexOf("await supabase.auth.getUser(accessToken)");
		const issuedAt = source.indexOf("jwtIssuedAtMs(accessToken)");
		const barrierAt = source.indexOf("await checkIdentityBarrier(");
		const authorizeAt = source.indexOf('"authorize_device_session"');
		expect(verifiedAt).toBeGreaterThan(0);
		expect(issuedAt).toBeGreaterThan(verifiedAt);
		expect(barrierAt).toBeGreaterThan(issuedAt);
		expect(authorizeAt).toBeGreaterThan(barrierAt);
		expect(source).toContain(
			"p_access_token_issued_at: new Date(accessTokenIssuedAtMs).toISOString()",
		);
		expect(source).not.toContain('from("admin_audit_logs")');
	});

	it("distinguishes unavailable admission from an unadmitted tenant", async () => {
		await expect(deviceVerifyHarness(true, false).run()).resolves.toMatchObject({
			status: 503,
			body: { error: "tenant_admission_unavailable" },
		});
		await expect(deviceVerifyHarness(false, false).run()).resolves.toMatchObject({
			status: 403,
			body: { error: "tenant_not_admitted" },
		});
	});
});
