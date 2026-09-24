import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through ResponsePlaybooksDeps.client");
	},
}));

const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "33333333-3333-4333-8333-333333333333";
const INCIDENT = "44444444-4444-4444-8444-444444444444";
const RUN = "55555555-5555-4555-8555-555555555555";
const COMMAND = "66666666-6666-4666-8666-666666666666";

const RUN_RESPONSE = {
	id: RUN,
	tenant_id: TENANT,
	actor_user_id: USER,
	agent_id: AGENT,
	incident_reference: INCIDENT,
	playbook_id: "agent_containment_v1",
	state: "running",
	current_step: 1,
	expires_at: "2026-09-23T10:05:00.000Z",
	steps: [{
		step_id: "pause_agent",
		ordinal: 1,
		command_type: "agent_pause",
		command_id: COMMAND,
		state: "pending",
		result_code: null,
		expires_at: "2026-09-23T10:05:00.000Z",
	}],
};

interface DatabaseOptions {
	role?: string;
	assurance?: string;
	user?: { id: string } | null;
	startError?: { code: string } | null;
	statusRun?: Record<string, unknown> | null;
}

function database(options: DatabaseOptions = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const queriedTables: string[] = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => token === "valid-token"
				? { data: { user: options.user === undefined ? { id: USER } : options.user }, error: null }
				: { data: { user: null }, error: new Error("invalid") }),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({
					data: { currentLevel: options.assurance ?? "aal2" }, error: null,
				})),
			},
		},
		from(table: string) {
			queriedTables.push(table);
			const filters: Record<string, unknown> = {};
			const chain = {
				select: () => chain,
				eq: (column: string, value: unknown) => {
					filters[column] = value;
					return chain;
				},
				maybeSingle: async () => {
					if (table === "identity_user_session_state") {
						return { data: { revoked_before: null, global_revoke_pending_session_id: null }, error: null };
					}
					if (table === "tenant_identity_policies") return { data: null, error: null };
					if (table === "tenant_members") {
						return { data: { role: options.role ?? "owner", expires_at: null }, error: null };
					}
					if (table === "tenants") return { data: { status: "active" }, error: null };
					return { data: null, error: null };
				},
			};
			return chain;
		},
		async rpc(name: string, args: Record<string, unknown>) {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") {
				return { data: { allowed: true, remaining: 29 }, error: null };
			}
			if (name === "start_fleet_response_playbook") {
				return options.startError
					? { data: null, error: options.startError }
					: { data: RUN_RESPONSE, error: null };
			}
			if (name === "get_fleet_response_playbook") {
				return { data: options.statusRun === undefined ? RUN_RESPONSE : options.statusRun, error: null };
			}
			return { data: null, error: null };
		},
	};
	return { db, rpcCalls, queriedTables };
}

function post(body: unknown): Request {
	return new Request("https://project.supabase.co/functions/v1/response-playbooks", {
		method: "POST",
		headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

const START = {
	action: "start",
	tenant_id: TENANT,
	agent_id: AGENT,
	incident_reference: INCIDENT,
	playbook_id: "agent_containment_v1",
	reason: "Contain agent after confirmed incident",
	idempotency_key: "incident-run-0001",
	ttl_seconds: 300,
};

describe("response playbook API contract", () => {
	beforeEach(() => {
		vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.resetModules();
	});

	async function handlerWith(options: DatabaseOptions = {}) {
		const { db, rpcCalls, queriedTables } = database(options);
		const mod = await import("../response-playbooks/index.ts");
		const handler = mod.createResponsePlaybooksHandler({
			env: (name) => ({
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
			} as Record<string, string>)[name],
			client: () => db as never,
			now: () => Date.parse("2026-09-23T10:00:00.000Z"),
		});
		return { handler, rpcCalls, queriedTables };
	}

	it("starts only the built-in typed run through the durable start RPC", async () => {
		const { handler, rpcCalls } = await handlerWith();
		const response = await handler(post(START));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, run: RUN_RESPONSE });
		expect(rpcCalls.find((call) => call.name === "start_fleet_response_playbook")?.args).toEqual({
			p_tenant_id: TENANT,
			p_actor_user_id: USER,
			p_agent_id: AGENT,
			p_incident_id: INCIDENT,
			p_playbook_id: "agent_containment_v1",
			p_reason: START.reason,
			p_idempotency_key: START.idempotency_key,
			p_ttl_seconds: 300,
		});
		expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({
			p_tenant_id: TENANT,
			p_subject: USER,
			p_endpoint: "response-playbooks",
		});
	});

	it("treats incident_reference as an operator-supplied value, without incident-record lookup", async () => {
		const suppliedReference = "77777777-7777-4777-8777-777777777777";
		const { handler, rpcCalls, queriedTables } = await handlerWith();
		const response = await handler(post({ ...START, incident_reference: suppliedReference }));

		expect(response.status).toBe(200);
		expect(rpcCalls.find((call) => call.name === "start_fleet_response_playbook")?.args.p_incident_id)
			.toBe(suppliedReference);
		expect(queriedTables.some((table) => table.toLowerCase().includes("incident"))).toBe(false);
	});

	it("rejects arbitrary steps and unknown playbook identifiers before authorization or SQL", async () => {
		const { handler, rpcCalls } = await handlerWith();
		const response = await handler(post({ ...START, steps: [{ command: "shell_exec" }] }));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_request" });
		expect(rpcCalls).toEqual([]);

		const unsupported = await handler(post({ ...START, playbook_id: "custom_script" }));
		expect(unsupported.status).toBe(400);
		expect(await unsupported.json()).toEqual({ error: "unsupported_playbook" });
	});

	it("requires an active owner or admin and AAL2 before creating a run", async () => {
		const member = await handlerWith({ role: "member" });
		const deniedRole = await member.handler(post(START));
		expect(deniedRole.status).toBe(403);
		expect(member.rpcCalls.some((call) => call.name === "start_fleet_response_playbook")).toBe(false);

		const aal1 = await handlerWith({ assurance: "aal1" });
		const deniedAssurance = await aal1.handler(post(START));
		expect(deniedAssurance.status).toBe(403);
		expect(aal1.rpcCalls.some((call) => call.name === "start_fleet_response_playbook")).toBe(false);
	});

	it("returns persisted terminal state as recorded, including partial runs", async () => {
		const partial = { ...RUN_RESPONSE, state: "partial", result_code: "unsupported_action" };
		const { handler, rpcCalls } = await handlerWith({ statusRun: partial });
		const response = await handler(post({ action: "status", tenant_id: TENANT, run_id: RUN }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, run: partial });
		expect(rpcCalls.find((call) => call.name === "get_fleet_response_playbook")?.args).toEqual({
			p_tenant_id: TENANT,
			p_run_id: RUN,
		});
	});

	it("does not convert idempotency conflicts into a successful run", async () => {
		const { handler } = await handlerWith({ startError: { code: "PT409" } });
		const response = await handler(post(START));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "response_playbook_conflict" });
	});
});
