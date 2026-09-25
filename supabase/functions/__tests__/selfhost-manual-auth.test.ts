import { afterEach, describe, expect, it, vi } from "vitest";

type Handler = (request: Request) => Promise<Response>;
type Route =
	| "api-keys"
	| "enrollment-tokens"
	| "azure-ad-groups"
	| "device-verify"
	| "pilot-admin"
	| "operator-admin"
	| "response-playbooks"
	| "audit-export"
	| "tenant-settings"
	| "compliance-report";

const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "33333333-3333-4333-8333-333333333333";
const INCIDENT = "44444444-4444-4444-8444-444444444444";

function database() {
	const privilegedCalls: string[] = [];
	const getUser = vi.fn(async (_token: string) => ({
		data: { user: null },
		error: new Error("invalid_access_token"),
	}));
	const db = {
		auth: {
			getUser,
			mfa: { getAuthenticatorAssuranceLevel: vi.fn() },
		},
		from: vi.fn((table: string) => {
			privilegedCalls.push(`from:${table}`);
			throw new Error(`unexpected privileged table access: ${table}`);
		}),
		rpc: vi.fn((name: string) => {
			privilegedCalls.push(`rpc:${name}`);
			throw new Error(`unexpected privileged RPC: ${name}`);
		}),
		storage: {
			from: vi.fn((bucket: string) => {
				privilegedCalls.push(`storage:${bucket}`);
				throw new Error(`unexpected privileged storage access: ${bucket}`);
			}),
		},
	};
	return { db, getUser, privilegedCalls };
}

async function loadHandler(route: Route) {
	vi.resetModules();
	const served: Handler[] = [];
	const { db, getUser, privilegedCalls } = database();
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "synthetic-service-role-key");
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (handler: Handler) => served.push(handler),
	});
	vi.doMock("npm:@supabase/supabase-js@2.116.0", () => ({
		createClient: () => db,
	}));

	switch (route) {
		case "api-keys": await import("../api-keys/index.ts"); break;
		case "enrollment-tokens": await import("../enrollment-tokens/index.ts"); break;
		case "azure-ad-groups": await import("../azure-ad-groups/index.ts"); break;
		case "device-verify": await import("../device-verify/index.ts"); break;
		case "pilot-admin": await import("../pilot-admin/index.ts"); break;
		case "operator-admin": await import("../operator-admin/index.ts"); break;
		case "response-playbooks": await import("../response-playbooks/index.ts"); break;
		case "audit-export": await import("../audit-export/index.ts"); break;
		case "tenant-settings": await import("../tenant-settings/index.ts"); break;
		case "compliance-report": await import("../compliance-report/index.ts"); break;
	}
	const handler = served[0];
	if (!handler) throw new Error(`${route} did not register its Edge handler`);
	return { handler, getUser, privilegedCalls };
}

function request(route: Route, token?: string): Request {
	const auth = token === undefined ? {} : { Authorization: `Bearer ${token}` };
	const headers = { "Content-Type": "application/json", ...auth };
	const bodies: Record<Route, unknown> = {
		"api-keys": { action: "create", label: "auth-regression" },
		"enrollment-tokens": { action: "create", label: "auth-regression" },
		"azure-ad-groups": undefined,
		"device-verify": { user_code: "ABCD-EFGH" },
		"pilot-admin": { action: "approve", user_id: USER },
		"operator-admin": { action: "list_tenants" },
		"response-playbooks": {
			action: "start",
			tenant_id: TENANT,
			agent_id: AGENT,
			incident_reference: INCIDENT,
			playbook_id: "agent_containment_v1",
			reason: "Auth regression fixture",
			idempotency_key: "auth-regression-0001",
			ttl_seconds: 300,
		},
		"audit-export": { team_id: TENANT, format: "json" },
		"tenant-settings": { tenant_id: TENANT, action: "close", confirm_name: "Acme" },
		"compliance-report": { tenant_id: TENANT, from: "2026-09-01T00:00:00.000Z", to: "2026-09-02T00:00:00.000Z" },
	};
	const method = route === "azure-ad-groups" ? "GET" : route === "tenant-settings" ? "PATCH" : "POST";
	return new Request(`https://project.supabase.co/functions/v1/${route}`, {
		method,
		headers,
		...(method !== "GET" ? { body: JSON.stringify(bodies[route]) } : {}),
	});
}

afterEach(() => {
	vi.doUnmock("npm:@supabase/supabase-js@2.116.0");
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("manual session guards when the self-host gateway JWT check is disabled", () => {
	it.each([
		"api-keys",
		"enrollment-tokens",
		"azure-ad-groups",
		"device-verify",
		"pilot-admin",
		"operator-admin",
		"response-playbooks",
		"audit-export",
		"tenant-settings",
		"compliance-report",
	] satisfies Route[])("%s rejects a missing bearer before privileged access", async (route) => {
		const { handler, getUser, privilegedCalls } = await loadHandler(route);
		const response = await handler(request(route));

		expect(response.status).toBe(401);
		expect(await response.json()).toMatchObject({ error: "missing_access_token" });
		expect(getUser).not.toHaveBeenCalled();
		expect(privilegedCalls).toEqual([]);
	});

	it.each([
		"api-keys",
		"enrollment-tokens",
		"azure-ad-groups",
		"device-verify",
		"pilot-admin",
		"operator-admin",
		"response-playbooks",
		"audit-export",
		"tenant-settings",
		"compliance-report",
	] satisfies Route[])("%s rejects an Auth-rejected bearer before privileged access", async (route) => {
		const { handler, getUser, privilegedCalls } = await loadHandler(route);
		const response = await handler(request(route, "not-a-valid-supabase-jwt"));

		expect(response.status).toBe(401);
		expect(await response.json()).toMatchObject({ error: "invalid_access_token" });
		expect(getUser).toHaveBeenCalledExactlyOnceWith("not-a-valid-supabase-jwt");
		expect(privilegedCalls).toEqual([]);
	});
});
