import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import ts from "typescript";
import { readDeviceCode } from "../_shared/auth.ts";
import { evaluateDeviceVerifyState } from "../_shared/device-auth.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";

const functionsDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const verifySource = readFileSync(join(functionsDir, "device-verify", "index.ts"), "utf8");
const onboardingSource = readFileSync(join(functionsDir, "..", "..", "scripts", "verify-customer-onboarding.mjs"), "utf8");

type VerifyHandler = (request: Request) => Promise<Response>;

function deviceVerifyHarness(approvalError: boolean, approved: boolean, sessionTenantId: string | null = "tenant-1") {
	const compiled = ts.transpileModule(verifySource.replace(/^import .*;\r?\n/gm, ""), {
		compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
	}).outputText;
	let handler: VerifyHandler | undefined;
	let admissionTenantId: string | undefined;
	let rateLimitCount = 0;
	const client = {
		auth: { getUser: async () => ({ data: { user: { id: "user-1" } }, error: null }) },
		async rpc(name: string, args: Record<string, unknown>) {
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
								id: "device-1",
								authorized_at: null,
								expires_at: new Date(Date.now() + 60_000).toISOString(),
								user_id: null,
								tenant_id: sessionTenantId,
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
		"evaluateDeviceVerifyState",
		"readBoundedJson",
		"jwtIssuedAtMs",
		compiled,
	)(
		{ env: { get: () => undefined }, serve: (fn: VerifyHandler) => { handler = fn; } },
		() => client,
		async () => ({ ok: true }),
		(header: string | null) => header?.replace(/^Bearer\s+/i, "") ?? null,
		() => { throw new Error("unexpected config failure"); },
		() => ({ ok: true, values: { SUPABASE_URL: "https://test.invalid", SUPABASE_SERVICE_ROLE_KEY: "test" } }),
		{},
		(_request: Request, status: number, body: unknown) => Response.json(body, { status }),
		() => null,
		evaluateDeviceVerifyState,
		readBoundedJson,
		() => Date.now(),
	);
	if (!handler) throw new Error("device-verify handler was not registered");
	const run = async (tenantHeader?: string) => {
		const response = await handler!(new Request("https://test.invalid/device-verify", {
			method: "POST",
			headers: {
				Authorization: "Bearer test-session",
				...(tenantHeader ? { "X-AIDR-Tenant-ID": tenantHeader } : {}),
			},
			body: JSON.stringify({ user_code: "ABCD-EFGH" }),
		}));
		return { status: response.status, body: await response.json() as Record<string, unknown> };
	};
	return { run, get admissionTenantId() { return admissionTenantId; } };
}

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
			`request("/functions/v1/device-verify", token, { user_code: device.user_code }, { "X-AIDR-Tenant-ID": receipt.tenant_id })`,
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
