// Contract suite for tenant alert integrations: the `notification-channels`
// handler (CRUD authorization, AAL2, rate limits, write-only destinations,
// test send) and the `notification-dispatch` handler (dispatcher token), plus
// the SQL contract of the migrations (RLS, column grants, identity barrier,
// service-only RPCs, transactional enqueue, offboarding purge).

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeIdentityBarrier } from "../../../scripts/lib/tenant-identity-barrier.mjs";
import type { Mailer } from "../_shared/mailer.ts";
import { decryptTarget, parseKeyring } from "../_shared/notification-targets.ts";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through the handler deps");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const channelsSql = readFileSync(join(ROOT, "supabase", "migrations", "20260926000020_notification_channels.sql"), "utf8");
const outboxSql = readFileSync(join(ROOT, "supabase", "migrations", "20260926000021_notification_outbox.sql"), "utf8");
const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
const manifest = JSON.parse(
	readFileSync(join(ROOT, "docs", "production-readiness", "edge-function-contract-manifest.json"), "utf8"),
) as { functions: Record<string, { tests: string[] }> };

const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const CHANNEL = "44444444-4444-4444-8444-444444444444";
const DELIVERY = "77777777-7777-4777-8777-777777777777";
const KEYS = `k1:${Buffer.alloc(32, 3).toString("base64")}`;
const DISPATCH_TOKEN = "dispatch-token-0123456789abcdef0123456789";
const SLACK_URL = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnopqrstuvwx";
const WEBHOOK_URL = "https://alerts.example.com/aidr?token=supersecret";
// Generated per run so no fixed signing secret is committed.
const WEBHOOK_SECRET = `whsec_${randomBytes(16).toString("hex")}`;
const FILTERS = {
	incident_created: true,
	incident_min_severity: "high",
	runtime_deny_critical: true,
	approval_requested: false,
	privacy_blocked_spike: true,
	privacy_spike_threshold: 10,
	privacy_spike_window_minutes: 15,
};

interface Options {
	role?: string | null;
	tenantStatus?: string;
	assurance?: string;
	rateAllowed?: boolean;
	rateError?: boolean;
	memberError?: boolean;
	rpcError?: Record<string, { code: string }>;
	existingType?: string | null;
	storedCiphertext?: string;
}

function channelView(overrides: Record<string, unknown> = {}) {
	return {
		id: CHANNEL,
		type: "webhook",
		name: "SOC webhook",
		target_hint: "alerts.example.com · #abc123",
		enabled: true,
		filters: FILTERS,
		created_by: USER,
		created_at: "2026-09-25T10:00:00.000Z",
		updated_at: "2026-09-25T10:00:00.000Z",
		last_delivery_at: null,
		last_delivery_status: null,
		last_error: null,
		consecutive_failures: 0,
		...overrides,
	};
}

function database(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const state = { ciphertext: options.storedCiphertext ?? "", completed: [] as Record<string, unknown>[] };
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => token === "valid-token"
				? { data: { user: { id: USER } }, error: null }
				: { data: { user: null }, error: new Error("invalid") }),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({
					data: { currentLevel: options.assurance ?? "aal2" },
					error: null,
				})),
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
						if (options.memberError) return { data: null, error: new Error("down") };
						return options.role === null ? { data: null, error: null } : { data: { role: options.role ?? "owner", expires_at: null }, error: null };
					}
					if (table === "tenants") return { data: { id: TENANT, status: options.tenantStatus ?? "active" }, error: null };
					if (table === "notification_channels") {
						return options.existingType === null
							? { data: null, error: null }
							: { data: { id: CHANNEL, type: options.existingType ?? "webhook" }, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			const forced = options.rpcError?.[name];
			if (forced) return { data: null, error: forced };
			switch (name) {
				case "consume_tenant_rate_limit":
					if (options.rateError) return { data: null, error: { message: "down" } };
					return { data: { allowed: options.rateAllowed ?? true, remaining: 3 }, error: null };
				case "list_notification_channels":
					return { data: { channels: [channelView()], recent_deliveries: [] }, error: null };
				case "create_notification_channel":
					state.ciphertext = String(args.p_target_ciphertext);
					return {
						data: channelView({ id: args.p_channel_id, type: args.p_type, name: args.p_name, target_hint: args.p_target_hint }),
						error: null,
					};
				case "update_notification_channel":
					if (args.p_target_ciphertext) state.ciphertext = String(args.p_target_ciphertext);
					return { data: { ...channelView(), changed: ["target"] }, error: null };
				case "delete_notification_channel":
					return { data: { id: CHANNEL, deleted: true }, error: null };
				case "enqueue_notification_test":
					return { data: { delivery_id: DELIVERY, channel_id: CHANNEL }, error: null };
				case "claim_notification_deliveries":
					return {
						data: [{
							delivery_id: DELIVERY,
							lease_token: "88888888-8888-4888-8888-888888888888",
							tenant_id: TENANT,
							channel_id: CHANNEL,
							channel_type: options.existingType ?? "webhook",
							target_ciphertext: state.ciphertext,
							event_type: "notification.test",
							payload: { occurred_at: "2026-09-25T10:00:00.000Z" },
							attempts: 1,
							max_attempts: 1,
							created_at: "2026-09-25T10:00:00.000Z",
						}],
						error: null,
					};
				case "complete_notification_delivery":
					state.completed.push(args);
					return { data: { status: args.p_outcome === "delivered" ? "delivered" : "dead" }, error: null };
				case "prune_notification_deliveries":
					return { data: { deleted: 0 }, error: null };
				default:
					throw new Error(`unexpected rpc ${name}`);
			}
		}),
	};
	return { db, rpcCalls, state };
}

const quietMailer: Mailer = { provider: "none", send: async () => ({ ok: false, reason: "not_configured" }) };

async function channelsHandler(options: Options = {}, env: Record<string, string> = {}, fetchImpl?: typeof fetch) {
	const fake = database(options);
	const mod = await import("../notification-channels/index.ts");
	const fetch = vi.fn(fetchImpl ?? (async () => new Response(null, { status: 204 })));
	const handle = mod.createNotificationChannelsHandler({
		env: (name) => ({
			SUPABASE_URL: "https://project.supabase.co",
			SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
			AIDR_NOTIFICATION_ENCRYPTION_KEYS: KEYS,
			AIDR_DASHBOARD_URL: "https://aidr.example.com",
			...env,
		} as Record<string, string>)[name],
		client: () => fake.db as never,
		now: () => Date.parse("2026-09-25T10:00:00.000Z"),
		random: () => 0.5,
		fetch: fetch as unknown as typeof globalThis.fetch,
		resolveDns: async () => ["93.184.216.34"],
		mailer: quietMailer,
		newId: () => CHANNEL,
	});
	return { ...fake, handle, fetch };
}

function get(token = "valid-token", tenant = TENANT) {
	return new Request("https://project.supabase.co/functions/v1/notification-channels", {
		method: "GET",
		headers: { Authorization: `Bearer ${token}`, "X-AIDR-Tenant-ID": tenant },
	});
}

function post(body: unknown, token = "valid-token") {
	return new Request("https://project.supabase.co/functions/v1/notification-channels", {
		method: "POST",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

const createWebhook = {
	tenant_id: TENANT,
	action: "create",
	type: "webhook",
	name: "SOC webhook",
	target: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET },
	filters: FILTERS,
};

function mutations(calls: Array<{ name: string }>) {
	return calls.map((call) => call.name).filter((name) => name !== "consume_tenant_rate_limit");
}

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("notification-channels authorization", () => {
	it("lists channels for owners and admins without any destination secret", async () => {
		for (const role of ["owner", "admin"]) {
			const { handle } = await channelsHandler({ role, assurance: "aal1" });
			const response = await handle(get());
			expect(response.status, role).toBe(200);
			const body = await response.json();
			expect(body).toMatchObject({
				ok: true,
				configured: true,
				mail_configured: false,
				permissions: { can_manage: true, requires_aal2: true },
				limits: { max_channels: 20 },
			});
			expect(body.channels).toHaveLength(1);
			expect(JSON.stringify(body)).not.toMatch(/ciphertext|secret|hooks\.slack\.com\/services/);
		}
	});

	it("refuses members, viewers, strangers, bad sessions and unreadable membership", async () => {
		for (const role of ["member", "viewer", null]) {
			const { handle, rpcCalls } = await channelsHandler({ role });
			const response = await handle(post(createWebhook));
			expect(response.status, String(role)).toBe(403);
			expect(await response.json()).toEqual({ error: "notification_channels_forbidden" });
			expect(mutations(rpcCalls)).toEqual([]);
		}
		expect((await (await channelsHandler()).handle(post(createWebhook, "bad-token"))).status).toBe(401);
		expect((await (await channelsHandler()).handle(new Request("https://x/y", { method: "POST", body: "{}" }))).status).toBe(401);
		expect((await (await channelsHandler({ memberError: true })).handle(get())).status).toBe(503);
		expect((await (await channelsHandler({ tenantStatus: "closing" })).handle(get())).status).toBe(403);
	});

	it("requires AAL2 and a rate-limit slot for every mutation", async () => {
		const aal1 = await channelsHandler({ assurance: "aal1" });
		const mfa = await aal1.handle(post(createWebhook));
		expect(mfa.status).toBe(403);
		expect(await mfa.json()).toEqual({ error: "mfa_required" });
		expect(mutations(aal1.rpcCalls)).toEqual([]);

		const limited = await channelsHandler({ rateAllowed: false });
		const response = await limited.handle(post({ tenant_id: TENANT, action: "test", channel_id: CHANNEL }));
		expect(response.status).toBe(429);
		expect(response.headers.get("Retry-After")).toBeTruthy();
		expect(limited.rpcCalls[0].args).toMatchObject({ p_endpoint: "notification-channels:test", p_subject_limit: 5, p_tenant_limit: 20 });
		expect(mutations(limited.rpcCalls)).toEqual([]);

		const down = await channelsHandler({ rateError: true });
		expect((await down.handle(post(createWebhook))).status).toBe(503);
		expect(mutations(down.rpcCalls)).toEqual([]);
	});
});

describe("notification-channels destinations are write-only", () => {
	it("encrypts the destination bound to the channel and never echoes it", async () => {
		const { handle, rpcCalls, state } = await channelsHandler();
		const response = await handle(post(createWebhook));
		expect(response.status).toBe(200);
		const text = await response.text();
		expect(text).not.toContain("supersecret");
		expect(text).not.toContain(WEBHOOK_SECRET);
		expect(text).not.toContain("ciphertext");
		const body = JSON.parse(text);
		expect(body.channel).toMatchObject({ id: CHANNEL, type: "webhook", name: "SOC webhook" });
		const create = rpcCalls.find((call) => call.name === "create_notification_channel")!;
		expect(create.args).toMatchObject({
			p_tenant_id: TENANT,
			p_actor_user_id: USER,
			p_channel_id: CHANNEL,
			p_type: "webhook",
			p_target_key_id: "k1",
			p_filters: FILTERS,
			p_enabled: true,
		});
		expect(String(create.args.p_target_hint)).toMatch(/^alerts\.example\.com · #[0-9a-f]{6}$/);
		expect(JSON.stringify(create.args)).not.toContain("supersecret");
		const keyring = await parseKeyring(KEYS);
		expect(await decryptTarget(keyring!, { tenantId: TENANT, channelId: CHANNEL, type: "webhook" }, state.ciphertext))
			.toEqual({ type: "webhook", url: WEBHOOK_URL, secret: WEBHOOK_SECRET });
	});

	it("refuses SSRF-prone and off-allow-list destinations before storing anything", async () => {
		const cases: Array<[string, unknown, string]> = [
			["webhook", { url: "http://alerts.example.com/hook", secret: WEBHOOK_SECRET }, "url_not_https"],
			["webhook", { url: "https://169.254.169.254/latest/meta-data/", secret: WEBHOOK_SECRET }, "url_host_forbidden"],
			["webhook", { url: "https://10.0.0.8/hook", secret: WEBHOOK_SECRET }, "url_host_forbidden"],
			["webhook", { url: "https://kubernetes.default.svc.cluster.local/api", secret: WEBHOOK_SECRET }, "url_host_forbidden"],
			["webhook", { url: WEBHOOK_URL, secret: "too-short" }, "invalid_webhook_secret"],
			["slack", { url: "https://slack.evil.example/services/x" }, "url_host_not_allowed"],
			["teams", { url: "https://alerts.example.com/hook" }, "url_host_not_allowed"],
			["email", { recipients: ["not-an-address"] }, "invalid_recipients"],
		];
		for (const [type, target, error] of cases) {
			const { handle, rpcCalls } = await channelsHandler();
			const response = await handle(post({ ...createWebhook, type, target }));
			expect(response.status, `${type} ${JSON.stringify(target)}`).toBe(400);
			expect(await response.json()).toEqual({ error });
			expect(mutations(rpcCalls)).toEqual([]);
		}
	});

	it("fails closed when the encryption keyring is absent or malformed", async () => {
		for (const keys of ["", "k1:short"]) {
			const { handle, rpcCalls } = await channelsHandler({}, { AIDR_NOTIFICATION_ENCRYPTION_KEYS: keys });
			const response = await handle(post(createWebhook));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "notifications_not_configured" });
			expect(mutations(rpcCalls)).toEqual([]);
			const list = await (await handle(get())).json();
			expect(list.configured).toBe(false);
		}
	});

	it("validates request shape, names and filters", async () => {
		const bad: Array<[unknown, string]> = [
			[{ ...createWebhook, type: "sms" }, "invalid_channel_type"],
			[{ ...createWebhook, name: " " }, "invalid_channel_name"],
			[{ ...createWebhook, name: "a\u0007b" }, "invalid_channel_name"],
			[{ ...createWebhook, filters: { ...FILTERS, incident_created: false, runtime_deny_critical: false, privacy_blocked_spike: false } }, "invalid_filters"],
			[{ ...createWebhook, filters: { ...FILTERS, privacy_spike_threshold: 0 } }, "invalid_filters"],
			[{ ...createWebhook, filters: { ...FILTERS, extra: true } }, "invalid_filters"],
			[{ ...createWebhook, owner: USER }, "invalid_request"],
			[{ tenant_id: TENANT, action: "update", channel_id: CHANNEL }, "no_changes"],
			[{ tenant_id: TENANT, action: "approve", channel_id: CHANNEL }, "invalid_action"],
			[{ tenant_id: "nope", action: "delete", channel_id: CHANNEL }, "invalid_request"],
		];
		for (const [body, error] of bad) {
			const { handle } = await channelsHandler();
			const response = await handle(post(body));
			expect(response.status, JSON.stringify(body)).toBe(400);
			expect(await response.json()).toEqual({ error });
		}
	});

	it("re-encrypts a replacement destination with the stored channel type", async () => {
		const { handle, rpcCalls, state } = await channelsHandler({ existingType: "slack" });
		const response = await handle(post({ tenant_id: TENANT, action: "update", channel_id: CHANNEL, target: { url: SLACK_URL }, enabled: false }));
		expect(response.status).toBe(200);
		expect(await response.text()).not.toContain("abcdefghijklmnop");
		const update = rpcCalls.find((call) => call.name === "update_notification_channel")!;
		expect(update.args).toMatchObject({ p_expected_type: "slack", p_enabled: false, p_name: null, p_filters: null });
		const keyring = await parseKeyring(KEYS);
		expect(await decryptTarget(keyring!, { tenantId: TENANT, channelId: CHANNEL, type: "slack" }, state.ciphertext))
			.toEqual({ type: "slack", url: SLACK_URL });
		// A webhook-shaped target for a Slack channel is refused.
		const wrong = await channelsHandler({ existingType: "slack" });
		expect((await wrong.handle(post({ tenant_id: TENANT, action: "update", channel_id: CHANNEL, target: { url: WEBHOOK_URL, secret: WEBHOOK_SECRET } }))).status).toBe(400);
		const missing = await channelsHandler({ existingType: null });
		expect((await missing.handle(post({ tenant_id: TENANT, action: "update", channel_id: CHANNEL, enabled: true }))).status).toBe(404);
	});

	it("maps RPC refusals without leaking database detail", async () => {
		const cases: Array<[string, string, number, string]> = [
			["create_notification_channel", "42501", 403, "notification_channels_forbidden"],
			["create_notification_channel", "23505", 409, "notification_channel_name_conflict"],
			["create_notification_channel", "54000", 409, "notification_channel_limit"],
			["create_notification_channel", "XX000", 503, "notification_channels_unavailable"],
		];
		for (const [rpc, code, status, error] of cases) {
			const { handle } = await channelsHandler({ rpcError: { [rpc]: { code } } });
			const response = await handle(post(createWebhook));
			expect(response.status, code).toBe(status);
			expect(await response.json()).toEqual({ error });
		}
		const { handle } = await channelsHandler({ rpcError: { delete_notification_channel: { code: "P0002" } } });
		const response = await handle(post({ tenant_id: TENANT, action: "delete", channel_id: CHANNEL }));
		expect(response.status).toBe(404);
	});
});

describe("notification-channels test send", () => {
	it("enqueues an audited test row and delivers it immediately through the dispatcher", async () => {
		const created = await channelsHandler();
		await created.handle(post(createWebhook));
		const { handle, rpcCalls, fetch } = await channelsHandler({ storedCiphertext: created.state.ciphertext });
		const response = await handle(post({ tenant_id: TENANT, action: "test", channel_id: CHANNEL }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			ok: true,
			delivery: { id: DELIVERY, status: "delivered", error: null, status_code: 204 },
		});
		expect(mutations(rpcCalls)).toEqual([
			"enqueue_notification_test",
			"claim_notification_deliveries",
			"complete_notification_delivery",
		]);
		expect(rpcCalls.find((call) => call.name === "claim_notification_deliveries")!.args.p_delivery_id).toBe(DELIVERY);
		const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe(WEBHOOK_URL);
		const sent = JSON.parse(String(init.body));
		expect(sent).toMatchObject({ event: "notification.test", test: true, links: { dashboard: "https://aidr.example.com/settings" } });
	});

	it("reports the receiver's refusal as the test result", async () => {
		const created = await channelsHandler();
		await created.handle(post(createWebhook));
		const { handle } = await channelsHandler(
			{ storedCiphertext: created.state.ciphertext },
			{},
			async () => new Response("no", { status: 401 }),
		);
		const response = await handle(post({ tenant_id: TENANT, action: "test", channel_id: CHANNEL }));
		expect(await response.json()).toEqual({
			ok: true,
			delivery: { id: DELIVERY, status: "dead", error: "receiver_rejected", status_code: 401 },
		});
	});
});

describe("notification-dispatch", () => {
	async function dispatchHandler(env: Record<string, string> = {}) {
		const fake = database();
		const mod = await import("../notification-dispatch/index.ts");
		const handle = mod.createNotificationDispatchHandler({
			env: (name) => ({
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
				AIDR_NOTIFICATION_DISPATCH_TOKEN: DISPATCH_TOKEN,
				AIDR_NOTIFICATION_ENCRYPTION_KEYS: KEYS,
				...env,
			} as Record<string, string>)[name],
			client: () => fake.db as never,
			now: () => Date.parse("2026-09-25T10:00:00.000Z"),
			random: () => 0.5,
			fetch: vi.fn(async () => new Response(null, { status: 204 })) as unknown as typeof fetch,
			resolveDns: async () => ["93.184.216.34"],
			mailer: quietMailer,
		});
		return { ...fake, handle };
	}
	const call = (token?: string) => new Request("https://project.supabase.co/functions/v1/notification-dispatch", {
		method: "POST",
		headers: token ? { Authorization: `Bearer ${token}` } : {},
	});

	it("requires the dedicated dispatch token and never touches the database without it", async () => {
		for (const token of [undefined, "wrong-token-0123456789abcdef0123456789", "service-role-key"]) {
			const { handle, rpcCalls } = await dispatchHandler();
			const response = await handle(call(token));
			expect(response.status, String(token)).toBe(401);
			expect(rpcCalls).toEqual([]);
		}
		const { handle } = await dispatchHandler();
		expect((await handle(new Request("https://x/notification-dispatch", { method: "GET" }))).status).toBe(405);
	});

	it("refuses to run with a missing, weak or malformed configuration", async () => {
		for (const env of [
			{ AIDR_NOTIFICATION_DISPATCH_TOKEN: "" },
			{ AIDR_NOTIFICATION_DISPATCH_TOKEN: "short" },
			{ AIDR_NOTIFICATION_ENCRYPTION_KEYS: "k1:nope" },
		]) {
			const { handle, rpcCalls } = await dispatchHandler(env);
			const response = await handle(call(DISPATCH_TOKEN));
			expect(response.status, JSON.stringify(env)).toBe(500);
			expect((await response.json()).error).toBe("server_misconfigured");
			expect(rpcCalls).toEqual([]);
		}
	});

	it("drains the outbox and prunes terminal rows", async () => {
		const { handle, rpcCalls, state } = await dispatchHandler();
		state.ciphertext = "v1.k1.invalid-ciphertext-for-this-binding-000000000000";
		const response = await handle(call(DISPATCH_TOKEN));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			ok: true, claimed: 1, delivered: 0, retrying: 0, dead: 1, lease_lost: 0, pruned: 0,
		});
		expect(rpcCalls.map((entry) => entry.name)).toEqual([
			"claim_notification_deliveries",
			"complete_notification_delivery",
			"prune_notification_deliveries",
		]);
		expect(state.completed[0]).toMatchObject({ p_outcome: "failed", p_error: "decrypt_failed" });
	});
});

describe("deployment and SQL contract", () => {
	it("registers both functions and the browser contract", () => {
		expect(config).toMatch(/\[functions\.notification-channels\]\n(?:#.*\n)*verify_jwt = true/);
		expect(config).toMatch(/\[functions\.notification-dispatch\]\n(?:#.*\n)*verify_jwt = false/);
		expect(manifest.functions["notification-channels"].tests).toContain(
			"supabase/functions/__tests__/notification-channels-contract.test.ts",
		);
	});

	it("keeps both tables client-read-only for admins, barrier-protected and ciphertext-free", () => {
		for (const table of ["notification_channels", "notification_deliveries"]) {
			expect(channelsSql).toContain(`alter table public.${table} enable row level security;`);
			expect(channelsSql).toContain(`revoke all on public.${table} from public, anon, authenticated;`);
			expect(channelsSql).toMatch(new RegExp(`create policy ${table}_select_admin on public\\.${table}\\s+for select to authenticated\\s+using \\(app\\.is_tenant_member_with_role\\(tenant_id, 'admin'\\)\\)`));
			expect(channelsSql).toMatch(new RegExp(`create policy ${table}_no_client_writes on public\\.${table}\\s+as restrictive for all to authenticated[\\s\\S]*?with check \\(false\\)`));
		}
		const grant = /grant select \(([\s\S]*?)\) on public\.notification_channels to authenticated/.exec(channelsSql)?.[1] ?? "";
		expect(grant).toContain("target_hint");
		expect(grant).not.toContain("target_ciphertext");
		expect(grant).not.toContain("target_key_id");
		expect(channelsSql).not.toMatch(/grant (insert|update|delete)[^;]*to (anon|authenticated)/i);
		expect(outboxSql).not.toMatch(/grant (insert|update|delete)[^;]*to (anon|authenticated)/i);

		const files = ["20260926000020_notification_channels.sql", "20260926000021_notification_outbox.sql"];
		const analysis = analyzeIdentityBarrier(files.map((name, index) => ({ name, sql: [channelsSql, outboxSql][index] })));
		expect(analysis.missing).toEqual([]);
	});

	it("exposes every RPC to the service role only", () => {
		const rpcs = [
			[channelsSql, "list_notification_channels\\(uuid\\)"],
			[channelsSql, "create_notification_channel\\(uuid, uuid, uuid, text, text, text, text, text, jsonb, boolean\\)"],
			[channelsSql, "update_notification_channel\\(uuid, uuid, uuid, text, text, boolean, jsonb, text, text, text\\)"],
			[channelsSql, "delete_notification_channel\\(uuid, uuid, uuid\\)"],
			[channelsSql, "enqueue_notification_test\\(uuid, uuid, uuid\\)"],
			[outboxSql, "claim_notification_deliveries\\(integer, integer, uuid\\)"],
			[outboxSql, "complete_notification_delivery\\(uuid, uuid, text, text, integer, integer\\)"],
			[outboxSql, "prune_notification_deliveries\\(integer\\)"],
		] as const;
		for (const [sql, signature] of rpcs) {
			expect(sql).toMatch(new RegExp(`revoke all on function public\\.${signature}\\s+from public, anon, authenticated;`));
			expect(sql).toMatch(new RegExp(`grant execute on function public\\.${signature}\\s+to service_role;`));
		}
		for (const helper of ["lock_notification_admin", "audit_notification_channel", "enqueue_event_notifications"]) {
			expect(`${channelsSql}\n${outboxSql}`).toMatch(new RegExp(`revoke all on function app\\.${helper}\\([^)]*\\) from public, anon, authenticated;`));
		}
	});

	it("enqueues transactionally from telemetry without copying content", () => {
		expect(outboxSql).toMatch(/create trigger events_enqueue_notifications\s+after insert on public\.events/);
		expect(outboxSql).toMatch(/exception when others then[\s\S]*raise warning 'notification_enqueue_failed'/);
		expect(outboxSql).toContain("on conflict (channel_id, dedupe_key) do nothing");
		const payload = /v_payload := jsonb_strip_nulls\(jsonb_build_object\(([\s\S]*?)\)\);/.exec(outboxSql)?.[1] ?? "";
		const keys = [...payload.matchAll(/'([a-z_]+)',/g)].map((match) => match[1]);
		expect(keys).toEqual([
			"event_row_id", "agent_id", "occurred_at", "severity", "category", "incident_id",
			"findings_count", "blocked_count", "window_minutes",
		]);
		expect(payload).not.toMatch(/tool_input|reasons|artifacts|prompt|command|payload->'/);
		expect(outboxSql).toMatch(/for update of d skip locked/);
	});

	it("purges destinations when offboarding starts and audits every mutation", () => {
		expect(channelsSql).toMatch(/after update of status on public\.tenants[\s\S]*when \(new\.status in \('closing', 'closed'\)/);
		expect(channelsSql).toMatch(/raise exception 'notification_offboarding_residue'/);
		for (const action of ["created", "updated", "deleted", "test_sent"]) {
			expect(channelsSql).toContain(`'notification_channel.${action}'`);
		}
		expect(channelsSql).toMatch(/insert into public\.admin_audit_logs[\s\S]*insert into public\.audit_logs/);
		expect(channelsSql).toMatch(/if \(select count\(\*\) from public\.notification_channels where tenant_id = p_tenant_id\) >= 20/);
	});
});
