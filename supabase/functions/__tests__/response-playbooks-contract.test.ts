import { createHash } from "node:crypto";
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
const GRANT = "77777777-7777-4777-8777-777777777777";
const NOW = Date.parse("2026-09-23T10:00:00.000Z");
function jwtWith(claims: Record<string, unknown>) {
	return `header.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.verified-signature`;
}
const HUMAN_JWT = jwtWith({ iat: NOW / 1000, exp: NOW / 1000 + 3600, sub: USER, aal: "aal2" });
const AUTOMATION_SECRET = `aidr_rsp_${"a".repeat(64)}`;
const GRANT_RESPONSE = {
	grant_id: GRANT, tenant_id: TENANT, agent_id: AGENT, playbook_id: "agent_containment_v1",
	trigger_source: "alarm", created_by: USER, max_ttl_seconds: 300,
	created_at: new Date(NOW).toISOString(), expires_at: new Date(NOW + 86400_000).toISOString(), revoked_at: null,
};

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
	expiresAt?: string | null;
	tenantStatus?: string;
	requiredSamlProvider?: string;
	revokedBefore?: string;
	failTable?: string;
	rateAllowed?: boolean;
	rateError?: boolean;
	rpcThrows?: boolean;
	authenticatedToken?: string;
	automationError?: { code: string; message?: string };
	grantResponse?: Record<string, unknown> | null;
	automationRun?: Record<string, unknown> | null;
}

function database(options: DatabaseOptions = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const queriedTables: string[] = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => token === "valid-token" || token === options.authenticatedToken
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
					if (table === options.failTable) return { data: null, error: new Error("private database failure") };
					if (table === "identity_user_session_state") {
						return { data: { revoked_before: options.revokedBefore ?? null, global_revoke_pending_session_id: null }, error: null };
					}
					if (table === "tenant_identity_policies") return { data: options.requiredSamlProvider ? { required_saml_provider_id: options.requiredSamlProvider } : null, error: null };
					if (table === "tenant_members") {
						return { data: { role: options.role ?? "owner", expires_at: options.expiresAt ?? null }, error: null };
					}
					if (table === "tenants") return { data: { status: options.tenantStatus ?? "active" }, error: null };
					return { data: null, error: null };
				},
			};
			return chain;
		},
		async rpc(name: string, args: Record<string, unknown>) {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") {
				return { data: { allowed: options.rateAllowed !== false, remaining: 29 }, error: options.rateError ? new Error("private rate error") : null };
			}
			if (name === "start_fleet_response_playbook" || name === "trigger_fleet_response_playbook") {
				if (options.rpcThrows) throw new Error("private service credential");
				return options.startError
					? { data: null, error: options.startError }
					: { data: RUN_RESPONSE, error: null };
			}
			if (name === "get_fleet_response_playbook") {
				return { data: options.statusRun === undefined ? RUN_RESPONSE : options.statusRun, error: null };
			}
			if (["create_response_automation_grant", "revoke_response_automation_grant", "trigger_response_automation_playbook"].includes(name)) {
				if (options.rpcThrows) throw new Error("private automation credential");
				if (options.automationError) return { data: null, error: options.automationError };
				if (name === "trigger_response_automation_playbook") return {
					data: options.automationRun === undefined ? RUN_RESPONSE : options.automationRun, error: null,
				};
				return { data: options.grantResponse === undefined ? {
					...GRANT_RESPONSE, ...(name === "revoke_response_automation_grant" ? { revoked_at: new Date(NOW).toISOString() } : {}),
				} : options.grantResponse, error: null };
			}
			return { data: null, error: null };
		},
	};
	return { db, rpcCalls, queriedTables };
}

function post(body: unknown, extraHeaders: Record<string, string> = {}): Request {
	return new Request("https://project.supabase.co/functions/v1/response-playbooks", {
		method: "POST",
		headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json", ...extraHeaders },
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
const GRANT_BODY = { action: "grant_automation", tenant_id: TENANT, agent_id: AGENT,
	playbook_id: "agent_containment_v1", trigger_source: "alarm", reason: "Allow confirmed alarm containment" };
const REVOKE_BODY = { action: "revoke_automation", tenant_id: TENANT, grant_id: GRANT, reason: "Automation authorization withdrawn" };
const AUTOMATION_BODY = { action: "trigger_automation", tenant_id: TENANT, grant_id: GRANT,
	incident_reference: INCIDENT, reason: "Confirmed unattended alarm event" };

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
			now: () => NOW,
		});
		return { handler, rpcCalls, queriedTables, db };
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

	it.each(["alarm", "soar"] as const)("triggers the built-in playbook from a verified operator's %s reference", async (triggerSource) => {
		const { handler, rpcCalls, queriedTables } = await handlerWith({ role: "admin" });
		const body = { ...START, action: "trigger", trigger_source: triggerSource, ttl_seconds: undefined };
		const response = await handler(post(body, { "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, run: RUN_RESPONSE });
		expect(rpcCalls.find((call) => call.name === "trigger_fleet_response_playbook")?.args).toEqual({
			p_tenant_id: TENANT, p_actor_user_id: USER, p_agent_id: AGENT, p_incident_id: INCIDENT,
			p_playbook_id: "agent_containment_v1", p_reason: START.reason,
			p_idempotency_key: START.idempotency_key, p_ttl_seconds: 300, p_trigger_source: triggerSource,
		});
		expect(rpcCalls.some((call) => call.name === "start_fleet_response_playbook")).toBe(false);
		expect(queriedTables.some((table) => table.toLowerCase().includes("incident"))).toBe(false);
	});

	it.each([
		{ trigger_source: undefined }, { trigger_source: "webhook" }, { trigger_source: { type: "alarm" } },
		{ actor_user_id: USER }, { user_id: USER }, { service_role_key: "private" },
		{ incident_id: INCIDENT }, { steps: [{ command: "shell_exec" }] },
		{ agent_id: "bad" }, { incident_reference: "bad" }, { ttl_seconds: 1 },
	])("rejects invalid trigger fields and caller-selected actors before SQL %#", async (overrides) => {
		const { handler, rpcCalls, queriedTables } = await handlerWith();
		const response = await handler(post({ ...START, action: "trigger", trigger_source: "alarm", ...overrides }));
		expect(response.status).toBe(400);
		expect(rpcCalls).toEqual([]);
		expect(queriedTables).toEqual([]);
	});

	it.each(["start", "trigger", "status"])("rejects malformed/conflicting tenant headers for %s", async (action) => {
		const { handler, rpcCalls, queriedTables } = await handlerWith();
		const body = action === "status" ? { action, tenant_id: TENANT, run_id: RUN }
			: { ...START, action, ...(action === "trigger" ? { trigger_source: "alarm" } : {}) };
		for (const header of ["bad", USER]) {
			const response = await handler(post(body, { "X-AIDR-Tenant-ID": header }));
			expect(response.status).toBe(header === "bad" ? 400 : 403);
		}
		expect(rpcCalls).toEqual([]);
		expect(queriedTables).toEqual([]);
	});

	it.each(["service-role-key", "aidr_live_machine_key", "invalid-access-token"])("rejects %s as a trigger operator credential", async (token) => {
		const { handler, rpcCalls, queriedTables } = await handlerWith();
		const response = await handler(post({ ...START, action: "trigger", trigger_source: "soar" }, { Authorization: `Bearer ${token}` }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_access_token" });
		expect(rpcCalls).toEqual([]);
		expect(queriedTables).toEqual([]);
	});

	it.each([
		[{ role: "member" }, 403], [{ assurance: "aal1" }, 403], [{ expiresAt: "2026-09-23T10:00:00.000Z" }, 403],
		[{ tenantStatus: "suspended" }, 403], [{ requiredSamlProvider: USER }, 403],
		[{ revokedBefore: "2026-09-23T10:00:00.000Z" }, 401], [{ failTable: "identity_user_session_state" }, 503],
	] as const)("preserves operator, tenant, MFA and identity barriers for triggers %#", async (options, status) => {
		const { handler, rpcCalls } = await handlerWith(options);
		const response = await handler(post({ ...START, action: "trigger", trigger_source: "alarm" }));
		expect(response.status).toBe(status);
		expect(rpcCalls.some((call) => call.name === "trigger_fleet_response_playbook")).toBe(false);
	});

	it.each([[{ rateAllowed: false }, 429], [{ rateError: true }, 503]] as const)("fails closed before a trigger when quota enforcement rejects %#", async (options, status) => {
		const { handler, rpcCalls } = await handlerWith(options);
		const response = await handler(post({ ...START, action: "trigger", trigger_source: "soar" }));
		expect(response.status).toBe(status);
		expect(rpcCalls.map((call) => call.name)).toEqual(["consume_tenant_rate_limit"]);
	});

	it.each([
		[{ startError: { code: "PT409" } }, 409, "response_playbook_conflict"],
		[{ startError: { code: "42501" } }, 403, "response_playbook_operator_forbidden"],
		[{ startError: { code: "22023" } }, 400, "invalid_response_playbook"],
		[{ startError: { code: "private credentials" } }, 503, "response_playbook_unavailable"],
		[{ rpcThrows: true }, 503, "response_playbook_unavailable"],
	] as const)("reports trigger conflicts and unavailable results without exposing service details %#", async (options, status, error) => {
		const { handler } = await handlerWith(options);
		const response = await handler(post({ ...START, action: "trigger", trigger_source: "alarm" }));
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error });
	});

	it("creates a random scoped automation secret once, while storing only its hash and trusted issuance", async () => {
		const { handler, rpcCalls } = await handlerWith({ authenticatedToken: HUMAN_JWT,
			grantResponse: { ...GRANT_RESPONSE, secret_hash: "private-hash", validated_session_issued_at: "private-proof", target_identity: { iid: "private-device" } } });
		const response = await handler(post(GRANT_BODY, { Authorization: `Bearer ${HUMAN_JWT}` }));
		expect(response.status).toBe(200);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		const body = await response.json();
		expect(Object.keys(body).sort()).toEqual(["automation_secret", "grant", "ok"]);
		expect(body.grant).toEqual(GRANT_RESPONSE);
		expect(body.automation_secret).toMatch(/^aidr_rsp_[a-f0-9]{64}$/);
		expect(rpcCalls.find(call => call.name === "create_response_automation_grant")?.args).toEqual({
			p_tenant_id: TENANT, p_actor_user_id: USER, p_agent_id: AGENT, p_source: "alarm", p_reason: GRANT_BODY.reason,
			p_max_ttl_seconds: 300, p_grant_expires_in_seconds: 86400,
			p_secret_hash: createHash("sha256").update(body.automation_secret).digest("hex"),
			p_validated_session_issued_at: new Date(NOW).toISOString(),
		});
		expect(JSON.stringify(rpcCalls)).not.toContain(body.automation_secret);
		const another = await handler(post(GRANT_BODY, { Authorization: `Bearer ${HUMAN_JWT}` }));
		expect((await another.json()).automation_secret).not.toBe(body.automation_secret);
	});

	it("revokes a grant through a current human AAL2 session with trusted issuance and no returned secret", async () => {
		const { handler, rpcCalls } = await handlerWith({ authenticatedToken: HUMAN_JWT, role: "admin" });
		const response = await handler(post(REVOKE_BODY, { Authorization: `Bearer ${HUMAN_JWT}` }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, grant: { ...GRANT_RESPONSE, revoked_at: new Date(NOW).toISOString() } });
		expect(rpcCalls.find(call => call.name === "revoke_response_automation_grant")?.args).toEqual({
			p_tenant_id: TENANT, p_actor_user_id: USER, p_grant_id: GRANT, p_reason: REVOKE_BODY.reason,
			p_validated_session_issued_at: new Date(NOW).toISOString(),
		});
	});

	it.each([GRANT_BODY, REVOKE_BODY])("rejects forged human JWT claims and automation secrets as grant-manager credentials %#", async (body) => {
		const { handler, rpcCalls, queriedTables } = await handlerWith();
		for (const token of [HUMAN_JWT, AUTOMATION_SECRET, "service-role-key"]) {
			const response = await handler(post(body, { Authorization: `Bearer ${token}` }));
			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ error: "invalid_access_token" });
		}
		expect(rpcCalls).toEqual([]);
		expect(queriedTables).toEqual([]);
	});

	it("normalizes UUID casing before validating returned automation scope", async () => {
		const tenant = "abcdefab-abcd-4bcd-8bcd-abcdefabcdef";
		const agent = "bcdefabc-bcde-4cde-8cde-bcdefabcdefa";
		const grantId = "cdefabcd-cdef-4def-8def-cdefabcdefab";
		const incident = "defabcde-defa-4efa-8efa-defabcdefabc";
		const create = await handlerWith({ authenticatedToken: HUMAN_JWT,
			grantResponse: { ...GRANT_RESPONSE, tenant_id: tenant, agent_id: agent, grant_id: grantId } });
		const response = await create.handler(post({ ...GRANT_BODY, tenant_id: tenant.toUpperCase(), agent_id: agent.toUpperCase() },
			{ Authorization: `Bearer ${HUMAN_JWT}`, "X-AIDR-Tenant-ID": tenant.toUpperCase() }));
		expect(response.status).toBe(200);
		expect(create.rpcCalls.find(call => call.name === "create_response_automation_grant")?.args).toMatchObject({ p_tenant_id: tenant, p_agent_id: agent });
		const trigger = await handlerWith({ automationRun: { ...RUN_RESPONSE, tenant_id: tenant, agent_id: agent, incident_reference: incident } });
		expect((await trigger.handler(post({ ...AUTOMATION_BODY, tenant_id: tenant.toUpperCase(), grant_id: grantId.toUpperCase(),
			incident_reference: incident.toUpperCase() }, { Authorization: `Bearer ${AUTOMATION_SECRET}` }))).status).toBe(200);
		expect(trigger.rpcCalls.find(call => call.name === "trigger_response_automation_playbook")?.args).toMatchObject({
			p_tenant_id: tenant, p_grant_id: grantId, p_incident_id: incident,
		});
	});

	it.each(["grant_automation", "revoke_automation"])("preserves all human authorization barriers for %s", async (action) => {
		for (const [options, status] of [
			[{ role: "member" }, 403], [{ assurance: "aal1" }, 403], [{ expiresAt: new Date(NOW).toISOString() }, 403],
			[{ tenantStatus: "closed" }, 403], [{ requiredSamlProvider: USER }, 403],
			[{ revokedBefore: new Date(NOW + 1).toISOString() }, 401], [{ failTable: "identity_user_session_state" }, 503],
		] as const) {
			const { handler, rpcCalls } = await handlerWith({ ...options, authenticatedToken: HUMAN_JWT });
			const response = await handler(post(action === "grant_automation" ? GRANT_BODY : REVOKE_BODY,
				{ Authorization: `Bearer ${HUMAN_JWT}` }));
			expect(response.status).toBe(status);
			expect(rpcCalls.some(call => call.name === "create_response_automation_grant" || call.name === "revoke_response_automation_grant")).toBe(false);
		}
	});

	it.each([undefined, null, "1690000000", 0, -1, NOW / 1000 + 0.5, NOW / 1000 + 120, 9e15])("rejects invalid trusted JWT issuance before granting or revoking %#", async (iat) => {
		const token = jwtWith({ iat });
		const { handler, rpcCalls } = await handlerWith({ authenticatedToken: token });
		for (const body of [GRANT_BODY, REVOKE_BODY]) {
			const response = await handler(post(body, { Authorization: `Bearer ${token}` }));
			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ error: "invalid_access_token" });
		}
		expect(rpcCalls.some(call => call.name === "create_response_automation_grant" || call.name === "revoke_response_automation_grant")).toBe(false);
	});

	it.each([
		{ actor_user_id: USER }, { validated_session_issued_at: new Date(NOW).toISOString() }, { secret_hash: "a".repeat(64) },
		{ automation_secret: AUTOMATION_SECRET }, { steps: [] }, { trigger_source: "other" }, { playbook_id: "shell_exec" },
		{ max_ttl_seconds: null }, { max_ttl_seconds: 29 }, { max_ttl_seconds: 901 }, { max_ttl_seconds: 30.5 },
		{ grant_expires_in_seconds: null }, { grant_expires_in_seconds: 59 }, { grant_expires_in_seconds: 7776001 },
		{ reason: "too short" }, { reason: "Control character\u0000 in reason" },
	])("rejects grant fields that could expand the delegation or spoof proof %#", async (patch) => {
		const { handler, rpcCalls, db } = await handlerWith({ authenticatedToken: HUMAN_JWT });
		const response = await handler(post({ ...GRANT_BODY, ...patch }, { Authorization: `Bearer ${HUMAN_JWT}` }));
		expect(response.status).toBe(400);
		expect(rpcCalls).toEqual([]);
		expect(db.auth.getUser).not.toHaveBeenCalled();
	});

	it.each(["grant_automation", "revoke_automation", "trigger_automation"])("rejects tenant header conflicts for %s before SQL", async (action) => {
		const { handler, rpcCalls } = await handlerWith({ authenticatedToken: HUMAN_JWT });
		const body = action === "grant_automation" ? GRANT_BODY : action === "revoke_automation" ? REVOKE_BODY : AUTOMATION_BODY;
		const response = await handler(post(body, { "X-AIDR-Tenant-ID": USER }));
		expect(response.status).toBe(403);
		expect(rpcCalls).toEqual([]);
	});

	it("triggers unattended through the dedicated secret without human or machine fallback, and strips DB-only fields", async () => {
		const { handler, rpcCalls, queriedTables, db } = await handlerWith({ automationRun: {
			...RUN_RESPONSE, secret_hash: "private-hash", target_identity: { user_id: USER, iid: "private-iid" },
			steps: [{ ...RUN_RESPONSE.steps[0], token: "private-token" }],
		} });
		const response = await handler(post(AUTOMATION_BODY, { Authorization: `Bearer ${AUTOMATION_SECRET}` }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, run: RUN_RESPONSE });
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(rpcCalls.find(call => call.name === "trigger_response_automation_playbook")?.args).toEqual({
			p_tenant_id: TENANT, p_grant_id: GRANT,
			p_secret_hash: createHash("sha256").update(AUTOMATION_SECRET).digest("hex"),
			p_incident_id: INCIDENT, p_reason: AUTOMATION_BODY.reason, p_ttl_seconds: 300,
		});
		expect(rpcCalls[0]).toMatchObject({ name: "consume_tenant_rate_limit", args: {
			p_tenant_id: TENANT, p_subject: GRANT, p_endpoint: "response-playbooks", p_subject_limit: 30, p_tenant_limit: 600,
		} });
		expect(JSON.stringify(rpcCalls)).not.toContain(AUTOMATION_SECRET);
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.auth.mfa.getAuthenticatorAssuranceLevel).not.toHaveBeenCalled();
		expect(queriedTables).toEqual([]);
	});

	it.each(["", "valid-token", HUMAN_JWT, "service-role-key", "aidr_live_machine_key", `aidr_rsp_${"A".repeat(64)}`, `aidr_rsp_${"a".repeat(63)}`])("rejects non-automation credentials after consuming the bounded anonymous quota %#", async (token) => {
		const { handler, rpcCalls, db } = await handlerWith();
		const response = await handler(post(AUTOMATION_BODY, { Authorization: token ? `Bearer ${token}` : "" }));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "automation_forbidden" });
		expect(rpcCalls.map(call => call.name)).toEqual(["consume_tenant_rate_limit"]);
		expect(db.auth.getUser).not.toHaveBeenCalled();
	});

	it.each([
		{ agent_id: AGENT }, { actor_user_id: USER }, { user_id: USER }, { trigger_source: "soar" },
		{ playbook_id: "agent_containment_v1" }, { idempotency_key: "caller-selects-replay" }, { steps: [] },
		{ secret_hash: "a".repeat(64) }, { grant_id: "bad" }, { incident_reference: "bad" },
		{ ttl_seconds: null }, { ttl_seconds: 29 }, { ttl_seconds: 901 }, { ttl_seconds: 30.5 },
	])("rejects caller-selected automation target, source, template, idempotency and invalid bounds %#", async (patch) => {
		const { handler, rpcCalls } = await handlerWith();
		const response = await handler(post({ ...AUTOMATION_BODY, ...patch }, { Authorization: `Bearer ${AUTOMATION_SECRET}` }));
		expect(response.status).toBe(400);
		expect(rpcCalls).toEqual([]);
	});

	it.each([[{ rateAllowed: false }, 429], [{ rateError: true }, 503]] as const)("fails closed before automation lookup when quota rejects %#", async (options, status) => {
		const { handler, rpcCalls } = await handlerWith(options);
		const response = await handler(post(AUTOMATION_BODY, { Authorization: `Bearer ${AUTOMATION_SECRET}` }));
		expect(response.status).toBe(status);
		expect(rpcCalls.map(call => call.name)).toEqual(["consume_tenant_rate_limit"]);
	});

	it.each([
		[{ automationError: { code: "42501", message: "expired or target reassigned private detail" } }, 403, "automation_forbidden"],
		[{ automationError: { code: "PT409", message: "private event fingerprint" } }, 409, "automation_conflict"],
		[{ automationError: { code: "23505", message: "private unique grant event" } }, 409, "automation_conflict"],
		[{ automationError: { code: "XX000", message: "private database service error" } }, 503, "response_playbook_unavailable"],
		[{ rpcThrows: true }, 503, "response_playbook_unavailable"],
		[{ automationRun: null }, 503, "response_playbook_unavailable"],
		[{ automationRun: { ...RUN_RESPONSE, tenant_id: USER } }, 503, "response_playbook_unavailable"],
	] as const)("returns generic errors without scope details or secret on rejected automation %#", async (options, status, error) => {
		const { handler } = await handlerWith(options);
		const response = await handler(post(AUTOMATION_BODY, { Authorization: `Bearer ${AUTOMATION_SECRET}` }));
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error });
	});

	it.each([
		{ automationError: { code: "42501" } }, { automationError: { code: "XX000", message: "private hash" } },
		{ rpcThrows: true }, { grantResponse: null }, { grantResponse: { ...GRANT_RESPONSE, agent_id: USER } },
	])("never returns a secret when grant persistence fails or the returned scope mismatches %#", async (options) => {
		const { handler } = await handlerWith({ ...options, authenticatedToken: HUMAN_JWT });
		const response = await handler(post(GRANT_BODY, { Authorization: `Bearer ${HUMAN_JWT}` }));
		expect(response.status).toBeGreaterThanOrEqual(400);
		const body = await response.json();
		expect(Object.keys(body)).toEqual(["error"]);
	});
});
