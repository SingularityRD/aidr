// Contract suite for central SIEM forwarding (E3): the `siem-destinations`
// handler (authorization, AAL2, plan gate, write-only configuration, private
// network gate, test send, dead-letter requeue), the `siem-forwarder`
// handler (scheduler token, keyring), and the SQL contract of the migration.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeIdentityBarrier } from "../../../scripts/lib/tenant-identity-barrier.mjs";
import { parseKeyring } from "../_shared/notification-targets.ts";
import { decryptSiemConfig } from "../_shared/siem-config.ts";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through the handler deps");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const migration = readFileSync(join(ROOT, "supabase", "migrations", "20261014000100_siem_forwarding.sql"), "utf8");
const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");

const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const DESTINATION = "55555555-5555-4555-8555-555555555555";
const KEYS = `k1:${Buffer.alloc(32, 9).toString("base64")}`;
const DISPATCH_TOKEN = "dispatch-token-0123456789abcdef0123456789";
const HEC_TOKEN = "hec-token-never-returned-0123";
const FILTERS = { incidents: true, decisions: ["deny", "ask"], browser: false, min_severity: "info" };

interface Options {
	role?: string | null;
	assurance?: string;
	features?: string[];
	planError?: boolean;
	tenantStatus?: string;
	existingProvider?: string | null;
	leak?: boolean;
}

function view(overrides: Record<string, unknown> = {}) {
	return {
		id: DESTINATION,
		provider: "splunk_hec",
		format: "json",
		name: "SOC Splunk",
		target_hint: "splunk.corp.example:8088",
		enabled: true,
		filters: FILTERS,
		created_by: USER,
		created_at: "2026-10-14T08:00:00.000Z",
		updated_at: "2026-10-14T08:00:00.000Z",
		last_delivery_at: null,
		last_delivery_status: null,
		last_error: null,
		consecutive_failures: 0,
		dropped_events: 0,
		pending: 0,
		dead: 0,
		...overrides,
	};
}

function database(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const state = { ciphertext: "" };
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) =>
				token === "valid-token" ? { data: { user: { id: USER } }, error: null } : { data: { user: null }, error: new Error("invalid") }),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: options.assurance ?? "aal2" }, error: null })),
			},
		},
		from(table: string) {
			const builder = {
				select: () => builder,
				eq: () => builder,
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: null, error: null };
					if (table === "tenant_identity_policies") return { data: { require_mfa: false, required_saml_provider_id: null }, error: null };
					if (table === "tenant_members") {
						return options.role === null ? { data: null, error: null } : { data: { role: options.role ?? "owner", expires_at: null }, error: null };
					}
					if (table === "tenants") return { data: { id: TENANT, status: options.tenantStatus ?? "active" }, error: null };
					if (table === "siem_destinations") {
						return options.existingProvider === null
							? { data: null, error: null }
							: { data: { id: DESTINATION, provider: options.existingProvider ?? "splunk_hec" }, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			switch (name) {
				case "tenant_plan_entitlements":
					if (options.planError) return { data: null, error: { message: "down" } };
					return {
						data: {
							tenant_id: TENANT,
							plan_id: options.features ? "team" : "business",
							plan_source: "team_record",
							trial_active: false,
							features: options.features ?? ["siem_export"],
							retention_days_max: 365,
						},
						error: null,
					};
				case "consume_tenant_rate_limit":
					return { data: { allowed: true, remaining: 3 }, error: null };
				case "list_siem_destinations":
					return { data: { destinations: [options.leak ? { ...view(), config_ciphertext: "must-not-leak" } : view()], dead_letters: [] }, error: null };
				case "create_siem_destination":
					state.ciphertext = String(args.p_config_ciphertext);
					return { data: view({ id: args.p_destination_id, target_hint: args.p_target_hint }), error: null };
				case "update_siem_destination":
					return { data: { ...view(), changed: ["format"] }, error: null };
				case "delete_siem_destination":
					return { data: { id: DESTINATION, deleted: true }, error: null };
				case "requeue_siem_dead_letters":
					return { data: { requeued: 7 }, error: null };
				case "enqueue_siem_test":
					return { data: { delivery_id: "77", destination_id: DESTINATION }, error: null };
				case "claim_siem_deliveries":
					return { data: [], error: null };
				default:
					throw new Error(`unexpected rpc ${name}`);
			}
		}),
	};
	return { db, rpcCalls, state };
}

async function destinationsHandler(options: Options = {}, env: Record<string, string> = {}) {
	const fake = database(options);
	const mod = await import("../siem-destinations/index.ts");
	const handle = mod.createSiemDestinationsHandler({
		env: (name) =>
			(
			({
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
				AIDR_NOTIFICATION_ENCRYPTION_KEYS: KEYS,
				...env,
			}) as Record<string, string>)[name],
		client: () => fake.db as never,
		now: () => Date.parse("2026-10-14T08:00:00.000Z"),
		newId: () => DESTINATION,
	});
	return { ...fake, handle };
}

function get(token = "valid-token") {
	return new Request("https://project.supabase.co/functions/v1/siem-destinations", {
		method: "GET",
		headers: { Authorization: `Bearer ${token}`, "X-AIDR-Tenant-ID": TENANT },
	});
}

function post(body: unknown, token = "valid-token") {
	return new Request("https://project.supabase.co/functions/v1/siem-destinations", {
		method: "POST",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

const createHec = {
	tenant_id: TENANT,
	action: "create",
	provider: "splunk_hec",
	format: "json",
	name: "SOC Splunk",
	config: { url: "https://splunk.corp.example:8088", token: HEC_TOKEN },
	filters: FILTERS,
};

const mutations = (calls: Array<{ name: string }>) =>
	calls.map((call) => call.name).filter((name) => !["consume_tenant_rate_limit", "tenant_plan_entitlements"].includes(name));

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("siem-destinations", () => {
	it("lists destinations for owners/admins without ciphertext", async () => {
		const { handle } = await destinationsHandler({ assurance: "aal1" });
		const response = await handle(get());
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body).toMatchObject({ ok: true, configured: true, private_networks_allowed: false, limits: { max_destinations: 10 } });
		// A view that carries the ciphertext is a contract breach: fail closed, never forward it.
		const leaking = await (await destinationsHandler({ leak: true })).handle(get());
		expect(leaking.status).toBe(503);
		expect(await leaking.text()).not.toContain("must-not-leak");
	});

	it("refuses members, missing sessions, other plans and plan outages", async () => {
		expect((await (await destinationsHandler({ role: "member" })).handle(get())).status).toBe(403);
		expect((await (await destinationsHandler({ role: null })).handle(get())).status).toBe(403);
		expect((await (await destinationsHandler()).handle(get("bad-token"))).status).toBe(401);
		const downgraded = await (await destinationsHandler({ features: ["sso"] })).handle(get());
		expect(downgraded.status).toBe(402);
		expect(await downgraded.json()).toMatchObject({ error: "plan_feature_required", feature: "siem_export" });
		expect((await (await destinationsHandler({ planError: true })).handle(get())).status).toBe(503);
	});

	it("requires AAL2 for every change", async () => {
		const { handle, rpcCalls } = await destinationsHandler({ assurance: "aal1" });
		const response = await handle(post(createHec));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(mutations(rpcCalls)).toEqual([]);
	});

	it("seals the configuration, never echoes it and stores only a host hint", async () => {
		const { handle, rpcCalls, state } = await destinationsHandler();
		const response = await handle(post(createHec));
		expect(response.status).toBe(200);
		const text = await response.text();
		expect(text).not.toContain(HEC_TOKEN);
		expect(text).not.toContain("config_ciphertext");
		const create = rpcCalls.find((call) => call.name === "create_siem_destination");
		expect(create?.args).toMatchObject({ p_provider: "splunk_hec", p_format: "json", p_target_hint: "splunk.corp.example:8088" });
		expect(JSON.stringify(create?.args)).not.toContain(HEC_TOKEN);
		const keyring = await parseKeyring(KEYS);
		expect(await decryptSiemConfig(keyring as NonNullable<typeof keyring>, { tenantId: TENANT, destinationId: DESTINATION, provider: "splunk_hec" }, state.ciphertext))
			.toMatchObject({ token: HEC_TOKEN });
	});

	it("validates commands before any database work", async () => {
		const { handle, rpcCalls } = await destinationsHandler();
		for (const [body, error] of [
			[{ ...createHec, provider: "kafka" }, "invalid_provider"],
			[{ ...createHec, format: "cef" }, "invalid_format"],
			[{ ...createHec, filters: { ...FILTERS, decisions: ["deny", "deny"] } }, "invalid_filters"],
			[{ ...createHec, filters: { incidents: false, decisions: [], browser: false, min_severity: "info" } }, "invalid_filters"],
			[{ ...createHec, name: "bad\nname" }, "invalid_destination_name"],
			[{ ...createHec, extra: true }, "invalid_request"],
			[{ tenant_id: TENANT, action: "update", destination_id: DESTINATION }, "no_changes"],
		] as const) {
			const response = await handle(post(body));
			expect(response.status, error).toBe(400);
			expect(await response.json()).toEqual({ error });
		}
		expect(mutations(rpcCalls)).toEqual([]);
		const invalidConfig = await handle(post({ ...createHec, config: { url: "http://splunk.example", token: HEC_TOKEN } }));
		expect(await invalidConfig.json()).toEqual({ error: "url_not_https" });
	});

	it("refuses a private collector unless the operator allowed private networks", async () => {
		const privateHec = { ...createHec, config: { ...createHec.config, allow_private_network: true } };
		const denied = await (await destinationsHandler()).handle(post(privateHec));
		expect(denied.status).toBe(400);
		expect(await denied.json()).toEqual({ error: "private_network_not_allowed" });
		const allowed = await (await destinationsHandler({}, { AIDR_SIEM_ALLOW_PRIVATE_NETWORKS: "true" })).handle(post(privateHec));
		expect(allowed.status).toBe(200);
	});

	it("keeps CEF/LEEF to syslog destinations on update", async () => {
		const { handle } = await destinationsHandler({ existingProvider: "splunk_hec" });
		const response = await handle(post({ tenant_id: TENANT, action: "update", destination_id: DESTINATION, format: "leef" }));
		expect(response.status).toBe(400);
		const syslog = await destinationsHandler({ existingProvider: "syslog" });
		expect((await syslog.handle(post({ tenant_id: TENANT, action: "update", destination_id: DESTINATION, format: "leef" }))).status).toBe(200);
	});

	it("requeues dead letters, deletes and runs a test send through the forwarder path", async () => {
		const { handle, rpcCalls } = await destinationsHandler();
		const requeue = await handle(post({ tenant_id: TENANT, action: "requeue", destination_id: DESTINATION }));
		expect(await requeue.json()).toEqual({ ok: true, requeued: 7 });
		const removed = await handle(post({ tenant_id: TENANT, action: "delete", destination_id: DESTINATION }));
		expect(await removed.json()).toEqual({ ok: true, deleted: DESTINATION });
		const test = await handle(post({ tenant_id: TENANT, action: "test", destination_id: DESTINATION }));
		expect(await test.json()).toMatchObject({ ok: true, delivery: { id: "77" } });
		expect(rpcCalls.find((call) => call.name === "claim_siem_deliveries")?.args).toMatchObject({ p_delivery_id: "77" });
	});
});

describe("siem-forwarder", () => {
	async function forwarder(env: Record<string, string> = {}) {
		const fake = database();
		const mod = await import("../siem-forwarder/index.ts");
		const handle = mod.createSiemForwarderHandler({
			env: (name) =>
				(
				({
					SUPABASE_URL: "https://project.supabase.co",
					SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
					AIDR_NOTIFICATION_ENCRYPTION_KEYS: KEYS,
					AIDR_NOTIFICATION_DISPATCH_TOKEN: DISPATCH_TOKEN,
					...env,
				}) as Record<string, string>)[name],
			client: () => ({ ...fake.db, rpc: async (name: string, args: Record<string, unknown>) =>
				name === "prune_siem_deliveries" ? { data: { deleted: 3 }, error: null } : fake.db.rpc(name, args) }) as never,
		});
		return { handle, rpcCalls: fake.rpcCalls };
	}
	const run = (token: string) =>
		new Request("https://project.supabase.co/functions/v1/siem-forwarder", { method: "POST", headers: { Authorization: `Bearer ${token}` } });

	it("runs only with the scheduler token and reports a summary", async () => {
		const { handle, rpcCalls } = await forwarder();
		expect((await handle(run("wrong-token-0123456789abcdef0123456789"))).status).toBe(401);
		expect(rpcCalls).toHaveLength(0);
		const response = await handle(run(DISPATCH_TOKEN));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, claimed: 0, delivered: 0, retrying: 0, dead: 0, lease_lost: 0, pruned: 3 });
		// The service-role key is never accepted as the scheduler credential.
		expect((await handle(run("service-role-key"))).status).toBe(401);
	});

	it("fails closed when the token is short or the keyring is malformed", async () => {
		expect((await (await forwarder({ AIDR_NOTIFICATION_DISPATCH_TOKEN: "short" })).handle(run("short"))).status).toBe(500);
		expect((await (await forwarder({ AIDR_NOTIFICATION_ENCRYPTION_KEYS: "nonsense" })).handle(run(DISPATCH_TOKEN))).status).toBe(500);
	});
});

describe("SIEM forwarding SQL contract", () => {
	it("never grants the configuration ciphertext or writes to clients", () => {
		const grant = /grant select \(([^)]*)\) on public\.siem_destinations to authenticated/.exec(migration)?.[1] ?? "";
		expect(grant).toContain("target_hint");
		expect(grant).not.toContain("config_ciphertext");
		expect(grant).not.toContain("config_key_id");
		expect(migration).toMatch(/siem_destinations_no_client_writes[\s\S]*with check \(false\)/);
		for (const fn of [
			"claim_siem_deliveries(integer, integer, integer, bigint)",
			"complete_siem_deliveries(jsonb)",
			"create_siem_destination(uuid, uuid, uuid, text, text, text, text, text, text, jsonb, boolean)",
			"requeue_siem_dead_letters(uuid, uuid, uuid, integer)",
		]) {
			const name = fn.replace(/[()]/g, "\\$&");
			expect(migration).toMatch(new RegExp(`revoke all on function public\\.${name}\\s+from public, anon, authenticated;`));
			expect(migration).toMatch(new RegExp(`grant execute on function public\\.${name}\\s+to service_role;`));
		}
	});

	it("enqueues transactionally without ever losing telemetry and purges on offboarding", () => {
		expect(migration).toMatch(/after insert on public\.events[\s\S]*execute function app\.enqueue_event_siem_trigger\(\)/);
		expect(migration).toMatch(/exception when others then[\s\S]*raise warning 'siem_enqueue_failed'/);
		expect(migration).toMatch(/dropped_events = dropped_events \+ 1/);
		expect(migration).toMatch(/tenants_purge_siem_destinations[\s\S]*new\.status in \('closing', 'closed'\)/);
		expect(migration).toContain("siem_offboarding_residue");
	});

	it("applies the restrictive tenant identity barrier to both tables", () => {
		const report = analyzeIdentityBarrier([{ name: "20261014000100_siem_forwarding.sql", sql: migration }]);
		expect(report.missing).toEqual([]);
		expect(migration.match(/create policy tenant_identity_access_restrict/g)).toHaveLength(2);
	});

	it("registers both functions with the right JWT posture", () => {
		expect(config).toMatch(/\[functions\.siem-destinations\][\s\S]*?verify_jwt = true/);
		expect(config).toMatch(/\[functions\.siem-forwarder\][\s\S]*?verify_jwt = false/);
	});
});
