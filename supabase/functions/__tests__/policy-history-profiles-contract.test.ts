// Contract suite for the policy-management actions added for
//   * DLP revision history, per-revision read (diff) and rollback, and
//   * agent permission profile validation, staging, history and rollback,
// plus the SQL contract of 20260928000002_agent_profile_staging.sql.
//
// The fake database is tenant-filtered; transactional behaviour (CAS,
// four-eyes guard, immutability) is proven against real PostgreSQL in
// scripts/control-plane-gaps-postgres.test.mjs.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { agentProfileTemplateDocument, canonicalDetectorPolicyPayload } from "../../../packages/core/src/index.ts";
import { analyzeIdentityBarrier } from "../../../scripts/lib/tenant-identity-barrier.mjs";
import {
	agentProfileEdgeSchemaPath,
	agentProfileEdgeSchemaSource,
} from "../../../scripts/sync-agent-profile-edge-schema.mjs";

vi.mock("npm:zod@3.25.76", () => {
	const requireCore = createRequire(new URL("../../../packages/core/package.json", import.meta.url));
	return requireCore("zod");
});
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("client must be injected");
	},
}));
vi.mock("npm:yaml@2.8.3", () => {
	const requireCore = createRequire(new URL("../../../packages/core/package.json", import.meta.url));
	return requireCore("yaml");
});

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const stagingSql = readFileSync(join(ROOT, "supabase", "migrations", "20260928000002_agent_profile_staging.sql"), "utf8");
const TENANT = "22222222-2222-4222-8222-222222222222";
const FOREIGN = "33333333-3333-4333-8333-333333333333";
const USER = "11111111-1111-4111-8111-111111111111";
type Row = Record<string, any>;

function dlp(version: number, rules = 1, exceptions: Row[] = []): Row {
	return {
		version,
		tenantId: TENANT,
		labels: [{ id: "secret", tenantId: TENANT, name: "Secret", sensitivity: "restricted" }],
		rules: Array.from({ length: rules }, (_, index) => ({
			id: `rule-${index}`, tenantId: TENANT, labelId: "secret", name: `Rule ${index}`, action: "block",
			matchers: [{ type: "keyword", values: [`marker-${index}`] }],
		})),
		exceptions,
	};
}

function sha(document: unknown) {
	return createHash("sha256").update(canonicalDetectorPolicyPayload(document)).digest("hex");
}

interface Options {
	role?: string;
	aal?: string;
	fourEyes?: boolean;
	dlpRevisions?: Row[];
	profileRevisions?: Row[];
	currentProfile?: Row | null;
	rpcError?: Record<string, { code: string; message?: string }>;
}

function fixture(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Row }> = [];
	const reads: Array<{ table: string; filters: Row }> = [];
	const dlpRevisions = options.dlpRevisions ?? [];
	const profileRevisions = options.profileRevisions ?? [];
	const db = {
		auth: {
			getUser: vi.fn(async () => ({ data: { user: { id: USER } }, error: null })),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: options.aal ?? "aal2" }, error: null })),
			},
		},
		from(table: string) {
			const filters: Row = {};
			const bounds: Row = {};
			reads.push({ table, filters });
			const rows = () => {
				const source = table === "dlp_policy_revisions" ? dlpRevisions
					: table === "agent_profile_revisions" ? profileRevisions : [];
				// The service answers only for the tenant the query names.
				return source
					.filter((row) => filters.tenant_id === TENANT && (filters.version === undefined || row.version === filters.version))
					.filter((row) => bounds.lt === undefined || row.version < bounds.lt)
					.sort((a, b) => b.version - a.version)
					.slice(0, bounds.limit ?? 1000);
			};
			const query: Row = {
				select: () => query,
				eq: (key: string, value: unknown) => { filters[key] = value; return query; },
				lt: (_key: string, value: number) => { bounds.lt = value; return query; },
				order: () => query,
				limit: (value: number) => { bounds.limit = value; return query; },
				then: (resolve: (value: unknown) => unknown) => resolve({ data: rows(), error: null }),
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: null, error: null };
					if (table === "tenant_identity_policies") return { data: { require_mfa: false }, error: null };
					if (table === "tenant_members") return { data: { role: options.role ?? "owner", expires_at: null }, error: null };
					if (table === "tenants") return { data: { status: "active" }, error: null };
					if (table === "tenant_ai_governance_settings") {
						return { data: options.fourEyes ? { policy_four_eyes: true } : null, error: null };
					}
					if (table === "tenant_agent_profiles") {
						return { data: filters.tenant_id === TENANT ? (options.currentProfile ?? null) : null, error: null };
					}
					if (table === "dlp_policy_revisions" || table === "agent_profile_revisions") {
						return { data: rows()[0] ?? null, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return query;
		},
		rpc: vi.fn(async (name: string, args: Row) => {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 10 }, error: null };
			const forced = options.rpcError?.[name];
			if (forced) return { data: null, error: forced };
			if (name === "publish_dlp_policy") {
				return {
					data: { version: args.p_expected_version + 1, policy: args.p_policy, updated_at: "2026-09-28T10:00:00.000Z" },
					error: null,
				};
			}
			if (name === "stage_agent_profiles") {
				return {
					data: {
						tenant_id: TENANT, version: args.p_expected_version + 1, policy: args.p_policy,
						policy_sha256: sha(args.p_policy), profile_count: args.p_policy.profiles.length,
						updated_at: "2026-09-28T10:00:00.000Z",
					},
					error: null,
				};
			}
			if (name === "submit_policy_change_request") {
				return {
					data: {
						request_id: "99999999-9999-4999-8999-999999999999", status: "pending",
						expires_at: "2026-10-05T10:00:00.000Z", payload_sha256: "a".repeat(64),
					},
					error: null,
				};
			}
			throw new Error(`unexpected rpc ${name}`);
		}),
	};
	return { db, rpcCalls, reads };
}

async function call(options: Options, body: Row) {
	const fake = fixture(options);
	const { createPolicyManagementHandler } = await import("../policy-management/index.ts");
	const handle = createPolicyManagementHandler({ db: fake.db as never });
	const response = await handle(new Request("https://example.test/policy-management", {
		method: "POST",
		headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json" },
		body: JSON.stringify({ tenant_id: TENANT, ...body }),
	}));
	return { response, json: await response.json(), ...fake };
}

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: (key: string) => process.env[key] }, serve: () => undefined });
	vi.stubEnv("SUPABASE_URL", "https://example.test");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "server-only-key");
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
	vi.unstubAllEnvs();
});

const dlpHistory = [1, 2, 3].map((version) => ({
	version, policy: dlp(version, version), updated_by: USER, created_at: `2026-09-2${version}T10:00:00.000Z`,
}));

describe("DLP revision history", () => {
	it("lists revisions newest first with counts only, never the document", async () => {
		const { response, json } = await call({ dlpRevisions: dlpHistory }, { action: "dlp_policy_history" });
		expect(response.status).toBe(200);
		expect(json.revisions.map((row: Row) => row.version)).toEqual([3, 2, 1]);
		expect(json.revisions[0]).toEqual({
			version: 3, created_at: "2026-09-23T10:00:00.000Z", updated_by: USER,
			counts: { labels: 1, rules: 3, exceptions: 0 },
		});
		expect(JSON.stringify(json)).not.toContain("marker-");
		expect(json.next_before_version).toBeNull();
	});

	it("pages with before_version and refuses a malformed cursor", async () => {
		const many = Array.from({ length: 55 }, (_, index) => ({
			version: index + 1, policy: dlp(index + 1), updated_by: USER, created_at: "2026-09-20T10:00:00.000Z",
		}));
		const first = await call({ dlpRevisions: many }, { action: "dlp_policy_history" });
		expect(first.json.revisions).toHaveLength(50);
		expect(first.json.next_before_version).toBe(6);
		const second = await call({ dlpRevisions: many }, { action: "dlp_policy_history", before_version: 6 });
		expect(second.json.revisions.map((row: Row) => row.version)).toEqual([5, 4, 3, 2, 1]);
		const bad = await call({ dlpRevisions: many }, { action: "dlp_policy_history", before_version: "6" });
		expect(bad.response.status).toBe(400);
	});

	it("serves one revision for a diff and fails closed on a foreign or mismatched row", async () => {
		const ok = await call({ dlpRevisions: dlpHistory }, { action: "read_dlp_policy_revision", version: 2 });
		expect(ok.json.revision.policy).toEqual(dlp(2, 2));
		const missing = await call({ dlpRevisions: dlpHistory }, { action: "read_dlp_policy_revision", version: 9 });
		expect(missing.response.status).toBe(404);
		const foreign = await call({
			dlpRevisions: [{ version: 1, policy: { ...dlp(1), tenantId: FOREIGN }, created_at: "2026-09-20T10:00:00.000Z" }],
		}, { action: "read_dlp_policy_revision", version: 1 });
		expect(foreign.response.status).toBe(503);
	});

	it("requires AAL2 for history reads", async () => {
		const { response, json, rpcCalls } = await call({ aal: "aal1", dlpRevisions: dlpHistory }, { action: "dlp_policy_history" });
		expect(response.status).toBe(403);
		expect(json.error).toBe("mfa_required");
		expect(rpcCalls.map((entry) => entry.name)).not.toContain("publish_dlp_policy");
	});

	it("rolls back by publishing the earlier content as the next revision", async () => {
		const { response, json, rpcCalls } = await call({ dlpRevisions: dlpHistory }, {
			action: "restore_dlp_policy", version: 1, expected_version: 3,
		});
		expect(response.status).toBe(200);
		expect(json).toMatchObject({ ok: true, version: 4, restored_from: 1, saved: true, delivered: false });
		const publish = rpcCalls.find((entry) => entry.name === "publish_dlp_policy");
		expect(publish?.args).toMatchObject({ p_expected_version: 3, p_user_id: USER, p_tenant_id: TENANT });
		expect(publish?.args.p_policy).toMatchObject({ version: 4, tenantId: TENANT, rules: [{ id: "rule-0" }] });
	});

	it("files a rollback for four-eyes approval instead of publishing", async () => {
		const { response, json, rpcCalls } = await call({ dlpRevisions: dlpHistory, fourEyes: true }, {
			action: "restore_dlp_policy", version: 2, expected_version: 3,
		});
		expect(response.status).toBe(202);
		expect(json.pending_approval).toBe(true);
		const submitted = rpcCalls.find((entry) => entry.name === "submit_policy_change_request");
		expect(submitted?.args).toMatchObject({ p_change_kind: "dlp_publish", p_base_version: 3 });
		expect(rpcCalls.map((entry) => entry.name)).not.toContain("publish_dlp_policy");
	});

	it("refuses a rollback by a member, to the current or a newer revision, or of a revision that no longer validates", async () => {
		const member = await call({ role: "member", dlpRevisions: dlpHistory }, {
			action: "restore_dlp_policy", version: 1, expected_version: 3,
		});
		expect(member.response.status).toBe(403);
		for (const version of [3, 4]) {
			const same = await call({ dlpRevisions: dlpHistory }, { action: "restore_dlp_policy", version, expected_version: 3 });
			expect(same.json.error).toBe("restore_target_not_older");
		}
		const expired = [{
			version: 1,
			// Most of its exceptions have expired since: today's schema refuses it.
			policy: dlp(1, 1, ["old-1", "old-2", "live"].map((id) => ({
				id, tenantId: TENANT, ruleId: "rule-0", ownerId: USER, justification: "Known false positive",
				scope: "rule", createdAt: "2025-01-01T00:00:00Z",
				expiresAt: id === "live" ? "2099-01-01T00:00:00Z" : "2025-02-01T00:00:00Z",
			}))),
			created_at: "2025-01-01T00:00:00.000Z",
		}, ...dlpHistory.slice(1)];
		const refused = await call({ dlpRevisions: expired }, { action: "restore_dlp_policy", version: 1, expected_version: 3 });
		expect(refused.response.status).toBe(400);
		expect(refused.json.error).toBe("invalid_dlp_policy");
		expect(refused.rpcCalls.map((entry) => entry.name)).not.toContain("publish_dlp_policy");
	});
});

describe("agent permission profiles: validation and staging", () => {
	const document = agentProfileTemplateDocument("standard-developer");
	const source = JSON.stringify(document);

	it("uses a byte-identical copy of the engine schema", () => {
		expect(readFileSync(agentProfileEdgeSchemaPath, "utf8").replaceAll("\r\n", "\n")).toBe(agentProfileEdgeSchemaSource());
	});

	it("validates JSON and YAML with the engine schema without storing anything", async () => {
		const valid = await call({ aal: "aal1", role: "member" }, { action: "validate_agent_profiles", source });
		expect(valid.json).toMatchObject({ ok: true, valid: true, profiles: ["standard-developer"] });
		const yaml = await call({}, {
			action: "validate_agent_profiles",
			source: "version: 1\nprofiles:\n  - name: reviewer\n    default: deny\n    tools: { file_read: allow }\n",
		});
		expect(yaml.json).toMatchObject({ valid: true, profiles: ["reviewer"] });
		const invalid = await call({}, {
			action: "validate_agent_profiles",
			source: JSON.stringify({ version: 1, profiles: [{ name: "Bad Name", default: "maybe" }] }),
		});
		expect(invalid.json.valid).toBe(false);
		expect(invalid.json.errors.join(" ")).toMatch(/profiles\.0\.name/);
		const alias = await call({}, { action: "validate_agent_profiles", source: "a: &x 1\nb: *x\n" });
		expect(alias.json.valid).toBe(false);
		for (const result of [valid, yaml, invalid, alias]) {
			expect(result.rpcCalls.map((entry) => entry.name)).toEqual(["consume_tenant_rate_limit"]);
		}
	});

	it("stages a validated document for owners/admins at AAL2", async () => {
		const { response, json, rpcCalls } = await call({}, {
			action: "stage_agent_profiles", source, expected_version: 0,
		});
		expect(response.status).toBe(200);
		expect(json).toMatchObject({
			ok: true, staged: true, version: 1, profiles: ["standard-developer"], delivered: false,
			delivery_status: "staged_not_signed",
		});
		expect(json.policy_sha256).toBe(sha(document));
		const stage = rpcCalls.find((entry) => entry.name === "stage_agent_profiles");
		expect(stage?.args).toMatchObject({ p_tenant_id: TENANT, p_user_id: USER, p_expected_version: 0, p_restored_from: null });
		expect(stage?.args.p_policy).toEqual(document);
	});

	it("refuses staging by a member, without AAL2, or of an invalid document, and maps a version conflict", async () => {
		const member = await call({ role: "member" }, { action: "stage_agent_profiles", source, expected_version: 0 });
		expect(member.response.status).toBe(403);
		const aal1 = await call({ aal: "aal1" }, { action: "stage_agent_profiles", source, expected_version: 0 });
		expect(aal1.json.error).toBe("mfa_required");
		const invalid = await call({}, { action: "stage_agent_profiles", source: "{\"version\":2}", expected_version: 0 });
		expect(invalid.response.status).toBe(400);
		expect(invalid.json.error).toBe("invalid_agent_profiles");
		const badVersion = await call({}, { action: "stage_agent_profiles", source, expected_version: -1 });
		expect(badVersion.json.error).toBe("invalid_version");
		for (const result of [member, aal1, invalid, badVersion]) {
			expect(result.rpcCalls.map((entry) => entry.name)).not.toContain("stage_agent_profiles");
		}
		const conflict = await call({ rpcError: { stage_agent_profiles: { code: "PT409" } } }, {
			action: "stage_agent_profiles", source, expected_version: 0,
		});
		expect(conflict.response.status).toBe(409);
		expect(conflict.json.error).toBe("policy_version_conflict");
		const guard = await call({
			rpcError: { stage_agent_profiles: { code: "42501", message: "policy_four_eyes_required" } },
		}, { action: "stage_agent_profiles", source, expected_version: 0 });
		expect(guard.json.error).toBe("policy_four_eyes_required");
	});

	it("files staging as an agent_profiles_stage change request when four-eyes is on", async () => {
		const { response, rpcCalls } = await call({ fourEyes: true }, { action: "stage_agent_profiles", source, expected_version: 2 });
		expect(response.status).toBe(202);
		const submitted = rpcCalls.find((entry) => entry.name === "submit_policy_change_request");
		expect(submitted?.args).toMatchObject({ p_change_kind: "agent_profiles_stage", p_base_version: 2 });
		expect(submitted?.args.p_payload).toEqual({ policy: document });
		expect(rpcCalls.map((entry) => entry.name)).not.toContain("stage_agent_profiles");
	});
});

describe("agent permission profiles: history, operator pull and rollback", () => {
	const v1 = agentProfileTemplateDocument("read-only-reviewer");
	const v2 = agentProfileTemplateDocument("ci-agent");
	const revisions = [
		{ version: 1, policy: v1, policy_sha256: sha(v1), profile_count: 1, restored_from: null, updated_by: USER, created_at: "2026-09-27T10:00:00.000Z" },
		{ version: 2, policy: v2, policy_sha256: sha(v2), profile_count: 1, restored_from: null, updated_by: USER, created_at: "2026-09-28T10:00:00.000Z" },
	];
	const current = { version: 2, policy: v2, policy_sha256: sha(v2), profile_count: 1, updated_by: USER, updated_at: "2026-09-28T10:00:00.000Z" };

	it("reads the current staged document with its not-delivered status", async () => {
		const { json } = await call({ currentProfile: current, profileRevisions: revisions }, { action: "read_agent_profiles" });
		expect(json).toMatchObject({ staged: true, version: 2, policy: v2, delivered: false, delivery_status: "staged_not_signed" });
		const empty = await call({}, { action: "read_agent_profiles" });
		expect(empty.json).toMatchObject({ staged: false, version: 0, policy: null });
	});

	it("lists history without documents", async () => {
		const { json } = await call({ currentProfile: current, profileRevisions: revisions }, { action: "agent_profile_history" });
		expect(json.revisions.map((row: Row) => row.version)).toEqual([2, 1]);
		expect(json.revisions[0]).not.toHaveProperty("policy");
		expect(json.revisions[0].policy_sha256).toBe(sha(v2));
	});

	it("tells the operator pull whether a revision is the current one", async () => {
		const latest = await call({ currentProfile: current, profileRevisions: revisions }, { action: "read_agent_profile_revision", version: 2 });
		expect(latest.json).toMatchObject({ tenant_id: TENANT, current: true, current_version: 2 });
		expect(latest.json.revision.policy).toEqual(v2);
		const old = await call({ currentProfile: current, profileRevisions: revisions }, { action: "read_agent_profile_revision", version: 1 });
		expect(old.json).toMatchObject({ current: false, current_version: 2 });
		const aal1 = await call({ aal: "aal1", currentProfile: current, profileRevisions: revisions }, {
			action: "read_agent_profile_revision", version: 2,
		});
		expect(aal1.response.status).toBe(403);
	});

	it("rolls back by staging the stored document verbatim with restored_from", async () => {
		const { response, json, rpcCalls } = await call({ currentProfile: current, profileRevisions: revisions }, {
			action: "restore_agent_profiles", version: 1, expected_version: 2,
		});
		expect(response.status).toBe(200);
		expect(json).toMatchObject({ staged: true, version: 3, restored_from: 1 });
		const stage = rpcCalls.find((entry) => entry.name === "stage_agent_profiles");
		expect(stage?.args).toMatchObject({ p_expected_version: 2, p_restored_from: 1 });
		expect(stage?.args.p_policy).toEqual(v1);
		const newer = await call({ currentProfile: current, profileRevisions: revisions }, {
			action: "restore_agent_profiles", version: 2, expected_version: 2,
		});
		expect(newer.json.error).toBe("restore_target_not_older");
		const fourEyes = await call({ fourEyes: true, currentProfile: current, profileRevisions: revisions }, {
			action: "restore_agent_profiles", version: 1, expected_version: 2,
		});
		expect(fourEyes.response.status).toBe(202);
		expect(fourEyes.rpcCalls.find((entry) => entry.name === "submit_policy_change_request")?.args.p_payload)
			.toEqual({ policy: v1, restored_from: 1 });
	});
});

describe("agent profile staging SQL contract", () => {
	it("keeps staged profiles service-role only, barrier-protected and immutable", () => {
		for (const table of ["tenant_agent_profiles", "agent_profile_revisions"]) {
			expect(stagingSql).toContain(`alter table public.${table} enable row level security;`);
			expect(stagingSql).toMatch(new RegExp(`create policy ${table}_no_client_access on public\\.${table}\\s+as restrictive for all to authenticated\\s+using \\(false\\)`));
		}
		expect(stagingSql).toContain(
			"revoke all on public.tenant_agent_profiles, public.agent_profile_revisions from public, anon, authenticated, service_role;",
		);
		expect(stagingSql).not.toMatch(/grant (select|insert|update|delete)[^;]*to (anon|authenticated)/i);
		const analysis = analyzeIdentityBarrier([{ name: "20260928000002_agent_profile_staging.sql", sql: stagingSql }]);
		expect(analysis.missing).toEqual([]);
		expect(stagingSql).toMatch(/before update or delete on public\.agent_profile_revisions/);
		expect(stagingSql).toMatch(/before insert on public\.agent_profile_revisions\s+for each row execute function app\.enforce_policy_four_eyes\(\)/);
		expect(stagingSql).toContain("when 'agent_profiles_stage' then");
		for (const signature of [
			"stage_agent_profiles\\(uuid, uuid, bigint, jsonb, bigint\\)",
			"submit_policy_change_request\\(uuid, uuid, text, bigint, bigint, bigint, jsonb\\)",
			"decide_policy_change_request\\(uuid, uuid, uuid, text, text\\)",
		]) {
			expect(stagingSql).toMatch(new RegExp(`revoke all on function public\\.${signature}\\s+from public, anon, authenticated;`));
			expect(stagingSql).toMatch(new RegExp(`grant execute on function public\\.${signature}\\s+to service_role;`));
		}
		// The audit row carries metadata, never commands, paths or hosts.
		const audit = /'agent_profiles\.staged', jsonb_build_object\(([\s\S]*?)\)\);/.exec(stagingSql)?.[1] ?? "";
		expect(audit).not.toMatch(/p_policy[^_]/);
	});
});
