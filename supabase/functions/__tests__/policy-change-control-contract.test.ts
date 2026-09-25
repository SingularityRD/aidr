// Four-eyes policy change control in `policy-management` (docs/ai-governance.md).
//
// With `policy_four_eyes` enabled, every publication path (publish, compiled
// YAML publish, restore/rollback, targeted stage, ordered rollout, DLP save)
// files a change request for a second owner/admin instead of publishing, and
// the database guard's refusal is reported as such. With it disabled the
// existing publication path is unchanged. The SQL guard and the approval that
// applies a request run against PostgreSQL in scripts/ai-governance-postgres.test.mjs.

import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("client must be injected");
	},
}));
vi.mock("npm:zod@3.25.76", () => {
	const requireCore = createRequire(new URL("../../../packages/core/package.json", import.meta.url));
	return requireCore("zod");
});
vi.mock("npm:yaml@2.8.3", () => {
	const requireCore = createRequire(new URL("../../../packages/core/package.json", import.meta.url));
	return requireCore("yaml");
});

const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "44444444-4444-4444-8444-444444444444";
const AGENT_TWO = "55555555-5555-4555-8555-555555555555";
const DOCUMENT_ID = "66666666-6666-4666-8666-666666666666";
const REQUEST_ID = "77777777-7777-4777-8777-777777777777";
const NOW = "2026-09-27T12:00:00.000Z";
const POLICY = { command_default: "ask", mcp_default: "ask" };
const DOCUMENT = ['version: "1.0"', "default_action: ask", "unknown_action: deny", "rules: []"].join("\n");
const DOCUMENT_SHA = createHash("sha256").update(DOCUMENT, "utf8").digest("hex");

type Row = Record<string, unknown>;

interface Options {
	fourEyes?: boolean | "unreadable";
	role?: string;
	submitError?: { code: string; message?: string };
	publishError?: { code: string; message: string };
}

function fixture(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Row }> = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => ({
				data: { user: token === "valid-token" ? { id: USER } : null },
				error: token === "valid-token" ? null : new Error("invalid"),
			})),
			mfa: { getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: "aal2" }, error: null })) },
		},
		from(table: string) {
			const filters: Row = {};
			const single = () => {
				switch (table) {
					case "identity_user_session_state": return { data: { revoked_before: null }, error: null };
					case "tenant_identity_policies": return { data: { require_mfa: false }, error: null };
					case "tenant_members": return { data: { role: options.role ?? "owner", expires_at: null }, error: null };
					case "tenants": return { data: { status: "active" }, error: null };
					case "tenant_ai_governance_settings":
						return options.fourEyes === "unreadable"
							? { data: null, error: new Error("db_down") }
							: { data: options.fourEyes === undefined ? null : { policy_four_eyes: options.fourEyes }, error: null };
					case "runtime_policy_revisions":
						return { data: filters.version === 2 ? { policy: { command_default: "deny" } } : null, error: null };
					default: throw new Error(`unexpected table ${table}`);
				}
			};
			const list = () => table === "team_policies"
				? { data: [{ id: DOCUMENT_ID, content: DOCUMENT, version: 4, source_sha256: DOCUMENT_SHA, updated_at: NOW }], error: null }
				: { data: [], error: null };
			const query = {
				select: () => query,
				eq: (column: string, value: unknown) => { filters[column] = value; return query; },
				order: () => query,
				limit: () => query,
				maybeSingle: async () => single(),
				then: (resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) =>
					Promise.resolve(list()).then(resolve, reject),
			};
			return query;
		},
		rpc: vi.fn(async (name: string, args: Row) => {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 9 }, error: null };
			if (name === "submit_policy_change_request") {
				if (options.submitError) return { data: null, error: options.submitError };
				return { data: { request_id: REQUEST_ID, status: "pending", change_kind: args.p_change_kind,
					payload_sha256: "a".repeat(64), expires_at: "2026-10-04T12:00:00.000Z" }, error: null };
			}
			if (["publish_runtime_policy", "publish_runtime_policy_document", "stage_runtime_policy", "create_policy_rollout", "publish_dlp_policy"].includes(name)) {
				if (options.publishError) return { data: null, error: options.publishError };
				if (name === "publish_dlp_policy") {
					return { data: { version: 1, policy: args.p_policy, updated_at: NOW }, error: null };
				}
				if (name === "create_policy_rollout") return { data: { rollout_id: REQUEST_ID, version: 4 }, error: null };
				return { data: { version: 4, policy: args.p_policy, updated_at: NOW, target_count: 2 }, error: null };
			}
			throw new Error(`unexpected rpc ${name}`);
		}),
	};
	return { db, rpcCalls };
}

async function call(options: Options, body: Row) {
	const { createPolicyManagementHandler } = await import("../policy-management/index.ts");
	const fake = fixture(options);
	const response = await createPolicyManagementHandler({ db: fake.db as never })(
		new Request("https://project.supabase.co/functions/v1/policy-management", {
			method: "POST",
			headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json" },
			body: JSON.stringify({ tenant_id: TENANT, ...body }),
		}),
	);
	return { status: response.status, body: (await response.json()) as Row, rpcCalls: fake.rpcCalls };
}

const published = (calls: Array<{ name: string }>) =>
	calls.filter((c) => ["publish_runtime_policy", "publish_runtime_policy_document", "stage_runtime_policy",
		"create_policy_rollout", "publish_dlp_policy"].includes(c.name));

function dlpPolicy(): Row {
	return {
		version: 1, tenantId: TENANT,
		labels: [{ id: "secret", tenantId: TENANT, name: "Secret", sensitivity: "restricted" }],
		rules: [{ id: "rule", tenantId: TENANT, labelId: "secret", name: "Rule", action: "block",
			matchers: [{ type: "keyword", values: ["secret-value"] }] }],
	};
}

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: (key: string) => process.env[key] }, serve: () => undefined });
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "server-only-key");
	vi.spyOn(Date, "now").mockReturnValue(Date.parse(NOW));
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
	vi.unstubAllEnvs();
});

describe("policy-management with four-eyes change control", () => {
	it("files a runtime publish for a second approver and publishes nothing", async () => {
		const result = await call({ fourEyes: true }, { action: "publish", expected_version: 3, policy: POLICY });
		expect(result.status).toBe(202);
		expect(result.body).toMatchObject({ ok: true, pending_approval: true, change_request_id: REQUEST_ID,
			change_kind: "runtime_publish", status: "pending", published: false });
		expect(published(result.rpcCalls)).toEqual([]);
		expect(result.rpcCalls.find((c) => c.name === "submit_policy_change_request")?.args).toEqual({
			p_tenant_id: TENANT, p_actor_user_id: USER, p_change_kind: "runtime_publish", p_base_version: 3,
			p_expected_revision_version: null, p_target_version: null, p_payload: { policy: POLICY },
		});
	});

	it("files a rollback (restore) with the exact revision content it would republish", async () => {
		const result = await call({ fourEyes: true }, { action: "restore", expected_version: 3, target_version: 2 });
		expect(result.status).toBe(202);
		expect(result.rpcCalls.find((c) => c.name === "submit_policy_change_request")?.args).toMatchObject({
			p_change_kind: "runtime_restore", p_base_version: 3, p_target_version: 2,
			p_payload: { policy: { command_default: "deny" } },
		});
	});

	it("files a targeted stage and an ordered rollout with their targets", async () => {
		const stage = await call({ fourEyes: true }, { action: "stage", expected_version: 3, expected_revision_version: 3,
			policy: POLICY, agent_ids: [AGENT, AGENT_TWO.toUpperCase()] });
		expect(stage.status).toBe(202);
		expect(stage.rpcCalls.find((c) => c.name === "submit_policy_change_request")?.args).toMatchObject({
			p_change_kind: "runtime_stage", p_expected_revision_version: 3,
			p_payload: { policy: POLICY, agent_ids: [AGENT, AGENT_TWO] },
		});
		const rings = [{ ring_order: 1, batches: [{ batch_order: 1, agent_ids: [AGENT] }] }];
		const rollout = await call({ fourEyes: true }, { action: "rollout", expected_version: 3, expected_revision_version: 3,
			policy: POLICY, rings });
		expect(rollout.status).toBe(202);
		expect(rollout.rpcCalls.find((c) => c.name === "submit_policy_change_request")?.args).toMatchObject({
			p_change_kind: "runtime_rollout", p_payload: { policy: POLICY, rings },
		});
		expect(published([...stage.rpcCalls, ...rollout.rpcCalls])).toEqual([]);
	});

	it("files a compiled YAML publish bound to the reviewed document revision", async () => {
		const expected = { id: DOCUMENT_ID, version: 4, source_sha256: DOCUMENT_SHA };
		const result = await call({ fourEyes: true }, { action: "publish_document", expected_version: 3, expected_document: expected });
		expect(result.status).toBe(202);
		const args = result.rpcCalls.find((c) => c.name === "submit_policy_change_request")?.args as Row;
		expect(args.p_change_kind).toBe("runtime_publish_document");
		expect((args.p_payload as Row).expected_document).toEqual(expected);
		expect((args.p_payload as Row).policy).toMatchObject({ mcp_unknown: "deny" });
	});

	it("files a DLP save with the server-owned next version", async () => {
		const result = await call({ fourEyes: true }, { action: "publish_dlp_policy", expected_version: 0, policy: dlpPolicy() });
		expect(result.status).toBe(202);
		const args = result.rpcCalls.find((c) => c.name === "submit_policy_change_request")?.args as Row;
		expect(args).toMatchObject({ p_change_kind: "dlp_publish", p_base_version: 0 });
		expect((args.p_payload as { policy: Row }).policy).toMatchObject({ tenantId: TENANT, version: 1 });
		expect(published(result.rpcCalls)).toEqual([]);
	});

	it("publishes directly when four-eyes is off", async () => {
		for (const fourEyes of [undefined, false] as const) {
			const result = await call({ fourEyes }, { action: "publish", expected_version: 3, policy: POLICY });
			expect(result.status).toBe(200);
			expect(published(result.rpcCalls).map((c) => c.name)).toEqual(["publish_runtime_policy"]);
			expect(result.rpcCalls.some((c) => c.name === "submit_policy_change_request")).toBe(false);
		}
	});

	it("fails closed when the setting cannot be read, and reports the database guard", async () => {
		const unreadable = await call({ fourEyes: "unreadable" }, { action: "publish", expected_version: 3, policy: POLICY });
		expect(unreadable.status).toBe(503);
		expect(published(unreadable.rpcCalls)).toEqual([]);
		const dlpUnreadable = await call({ fourEyes: "unreadable" }, { action: "publish_dlp_policy", expected_version: 0, policy: dlpPolicy() });
		expect(dlpUnreadable.status).toBe(503);
		const guard = { code: "42501", message: "policy_four_eyes_required" };
		for (const body of [
			{ action: "publish", expected_version: 3, policy: POLICY },
			{ action: "publish_dlp_policy", expected_version: 0, policy: dlpPolicy() },
			{ action: "rollout", expected_version: 3, expected_revision_version: 3, policy: POLICY,
				rings: [{ ring_order: 1, batches: [{ batch_order: 1, agent_ids: [AGENT] }] }] },
		]) {
			const refused = await call({ fourEyes: false, publishError: guard }, body);
			expect(refused).toMatchObject({ status: 409, body: { error: "policy_four_eyes_required" } });
		}
	});

	it("keeps publication owner/admin-only and maps submission failures", async () => {
		const member = await call({ fourEyes: true, role: "member" }, { action: "publish", expected_version: 3, policy: POLICY });
		expect(member.status).toBe(403);
		expect(member.rpcCalls.some((c) => c.name === "submit_policy_change_request")).toBe(false);
		expect((await call({ fourEyes: true, submitError: { code: "54000" } }, { action: "publish", expected_version: 3, policy: POLICY })).body)
			.toEqual({ error: "policy_change_request_quota" });
		expect((await call({ fourEyes: true, submitError: { code: "XX000" } }, { action: "publish", expected_version: 3, policy: POLICY })).status)
			.toBe(503);
	});
});
