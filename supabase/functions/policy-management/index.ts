import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { parseDocument } from "npm:yaml@2.8.3";
import { getBearerToken } from "../_shared/auth.ts";
import { handleDlpPolicyAction } from "../_shared/dlp-policy-store.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { compileRuntimePolicyDocument, compileRuntimePolicyDraft, simulateCompiledRuntimePolicy, type RuntimePolicyDocumentCompilation } from "../_shared/policy-document.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive, validateRuntimePolicy } from "../_shared/runtime-policy.ts";
import {
	dispatchPolicyRollout,
	isPolicyRolloutAction,
	MAX_POLICY_MANAGEMENT_BODY_BYTES,
	rolloutAdoptionEvidence,
} from "../_shared/policy-rollout.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
type PolicyDocumentPrecondition = { id: string; version: number; source_sha256: string };
type ReadTable<Row extends Record<string, unknown>> = { Row: Row; Insert: never; Update: never; Relationships: [] };
type RuntimePolicyRow = { tenant_id: string; version: number; policy: Record<string, unknown>; updated_at: string };
type PublishedPolicy = RuntimePolicyRow & { target_count?: number };
type SavedDraft = { id: string; version: number; source_sha256: string; updated_at: string };
type PolicyManagementDatabase = {
	public: {
		Tables: {
			tenant_members: ReadTable<{ tenant_id: string; user_id: string; role: string; expires_at: string | null }>;
			tenants: ReadTable<{ id: string; status: string }>;
			tenant_runtime_policies: ReadTable<RuntimePolicyRow>;
			runtime_policy_revisions: ReadTable<{ tenant_id: string; version: number; policy: Record<string, unknown>; created_at: string }>;
			agents: ReadTable<{ id: string; tenant_id: string; iid: string; display_name: string | null; last_seen: string | null }>;
			agent_policy_receipts: ReadTable<{ tenant_id: string; agent_id: string; version: number; received_at: string }>;
			agent_policy_assignments: ReadTable<{ tenant_id: string; agent_id: string; version: number }>;
			team_policies: ReadTable<{ id: string; team_id: string; content: string; version: number; source_sha256: string; updated_at: string }>;
		};
		Views: Record<string, never>;
		Functions: {
			save_policy_document_draft: { Args: { p_tenant_id: string; p_user_id: string; p_content: string; p_source_sha256: string; p_expected_id: string | null; p_expected_version: number | null; p_expected_source_sha256: string | null }; Returns: SavedDraft };
			stage_runtime_policy: { Args: { p_tenant_id: string; p_user_id: string; p_expected_version: number; p_expected_revision_version: number; p_policy: Record<string, unknown>; p_agent_ids: string[] }; Returns: PublishedPolicy };
			publish_runtime_policy_document: { Args: { p_tenant_id: string; p_user_id: string; p_expected_version: number; p_policy: Record<string, unknown>; p_expected_document_id: string; p_expected_document_version: number; p_expected_source_sha256: string }; Returns: PublishedPolicy };
			publish_runtime_policy: { Args: { p_tenant_id: string; p_user_id: string; p_expected_version: number; p_policy: Record<string, unknown> }; Returns: PublishedPolicy };
		};
		Enums: Record<string, never>;
		CompositeTypes: Record<string, never>;
	};
};

function isPolicyDocumentPrecondition(value: unknown): value is PolicyDocumentPrecondition {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const source = value as Record<string, unknown>;
	return typeof source.id === "string" && UUID_PATTERN.test(source.id) &&
		Number.isSafeInteger(source.version) && Number(source.version) >= 1 &&
		typeof source.source_sha256 === "string" && /^[0-9a-f]{64}$/.test(source.source_sha256);
}

function parseStoredDocument(source: string): unknown {
	if (!source || source.length > 65_536) throw new Error(source ? "policy_document_too_large" : "policy_document_empty");
	const document = parseDocument(source, { schema: "core", uniqueKeys: true, prettyErrors: false });
	if (document.errors.length > 0) throw new Error(`invalid_policy_yaml:${document.errors[0]?.message ?? "parse_error"}`);
	try {
		return document.toJS({ maxAliasCount: 0 });
	} catch (error) {
		throw new Error(`invalid_policy_yaml:${error instanceof Error ? error.message : "alias_not_allowed"}`);
	}
}

export interface PolicyManagementDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: SupabaseClient<PolicyManagementDatabase>;
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createPolicyManagementHandler(deps: PolicyManagementDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("policy-management", config.error, (status, body) => corsJson(req, status, body));
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		try {
			const db = deps.db ?? createClient<PolicyManagementDatabase>(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user) return corsJson(req, 401, { error: "invalid_access_token" });
			const parsed = await readBoundedJson(req, MAX_POLICY_MANAGEMENT_BODY_BYTES);
			if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
			const body = parsed.value as Record<string, unknown>;
			if (!body || typeof body !== "object" || Array.isArray(body)) return corsJson(req, 400, { error: "invalid_request" });
			const tenant = body.tenant_id ?? auth.user.id;
			if (typeof tenant !== "string" || !/^[0-9a-f-]{36}$/i.test(tenant)) return corsJson(req, 400, { error: "invalid_tenant" });
			const identity = await checkIdentityBarrier(db, token, auth.user.id, tenant);
			if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
			const { data: member, error: memberError } = await db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenant).eq("user_id", auth.user.id).maybeSingle();
			if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (!member || !membershipActive(member)) return corsJson(req, 403, { error: "tenant_access_denied" });
			const state = await db.from("tenants").select("status").eq("id", tenant).maybeSingle();
			if (state.error) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (state.data?.status !== "active") return corsJson(req, 403, { error: "tenant_access_denied" });
			const action = typeof body.action === "string" ? body.action : "";
			const expectedDocument = isPolicyDocumentPrecondition(body.expected_document) ? body.expected_document : null;
			if (action === "publish_document" && !expectedDocument) return corsJson(req, 400, { error: "invalid_document_precondition" });
			const workCost = ["adoption", "rollout_progress", "rollout", "create_rollout"].includes(action) ? 5 : action === "history" ? 2 : 1;
			const rate = await consumeTenantRateLimit(db, {
				tenantId: tenant,
				subject: auth.user.id,
				endpoint: "policy-management",
				perSubject: 600,
				perTenant: 30_000,
				cost: workCost,
			});
			if (!rate.ok) {
				return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			}
			if (action === "read_dlp_policy" || action === "publish_dlp_policy") {
				return await handleDlpPolicyAction(req, db, body, { tenant, userId: auth.user.id, role: member.role, token });
			}
			if (body.action === "read") {
				const { data, error } = await db.from("tenant_runtime_policies").select("version,policy,updated_at").eq("tenant_id", tenant).maybeSingle();
				return error ? corsJson(req, 503, { error: "policy_unavailable" }) : corsJson(req, 200, { ok: true, version: data?.version ?? 0, policy: data?.policy ?? null, updated_at: data?.updated_at ?? null });
			}
			if (body.action === "history") {
				const result = await db.from("runtime_policy_revisions").select("version,policy,created_at").eq("tenant_id", tenant).order("version", { ascending: false }).limit(101);
				return result.error ? corsJson(req, 503, { error: "history_unavailable" }) : corsJson(req, 200, { ok: true, revisions: result.data.slice(0, 100), truncated: result.data.length > 100 });
			}
			if (body.action === "adoption") {
				if (body.after_agent !== undefined && (typeof body.after_agent !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(body.after_agent))) return corsJson(req, 400, { error: "invalid_agent_cursor" });
				if (body.rollout_id !== undefined && (typeof body.rollout_id !== "string" || !UUID_PATTERN.test(body.rollout_id))) return corsJson(req, 400, { error: "invalid_rollout_id" });
				let agentQuery = db.from("agents").select("id,iid,display_name,last_seen").eq("tenant_id", tenant).order("id").limit(501);
				if (body.after_agent) agentQuery = agentQuery.gt("id", body.after_agent);
				const [agents, current] = await Promise.all([
					agentQuery,
					db.from("tenant_runtime_policies").select("version").eq("tenant_id", tenant).maybeSingle(),
				]);
				if (agents.error || current.error) return corsJson(req, 503, { error: "adoption_unavailable" });
				const page = agents.data.slice(0, 500);
				const ids = page.map((agent) => agent.id);
				// Fetch only this page's agents so a larger fleet cannot silently lose a
				// targeted assignment or receipt to PostgREST's row limit.
				const chunks = Array.from({ length: Math.ceil(ids.length / 100) }, (_, i) => ids.slice(i * 100, (i + 1) * 100));
				const [receiptPages, assignmentPages] = await Promise.all([
					Promise.all(chunks.map((chunk) => db.from("agent_policy_receipts").select("agent_id,version,received_at").eq("tenant_id", tenant).in("agent_id", chunk))),
					Promise.all(chunks.map((chunk) => db.from("agent_policy_assignments").select("agent_id,version").eq("tenant_id", tenant).in("agent_id", chunk))),
				]);
				if ([...receiptPages, ...assignmentPages].some((page) => page.error)) return corsJson(req, 503, { error: "adoption_unavailable" });
				const receiptByAgent = new Map(receiptPages.flatMap((page) => page.data ?? []).map((row) => [row.agent_id, row]));
				const assignmentByAgent = new Map(assignmentPages.flatMap((page) => page.data ?? []).map((row) => [row.agent_id, row.version]));
				const rolloutEvidence = await rolloutAdoptionEvidence(db, tenant, body.rollout_id);
				return corsJson(req, 200, { ok: true, truncated: agents.data.length > 500, next_agent: agents.data.length > 500 ? page[page.length - 1].id : null, receipt_type: "agent_reported_policy_loaded", ...rolloutEvidence, agents: page.map((agent) => {
					const receipt = receiptByAgent.get(agent.id); const target = assignmentByAgent.get(agent.id) ?? current.data?.version ?? 0;
					return { ...agent, target_version: target, loaded_version: receipt?.version ?? null, received_at: receipt?.received_at ?? null, state: !receipt ? "unknown" : Date.parse(receipt.received_at) < Date.now() - 300000 ? "stale" : receipt.version === target ? "current" : "outdated" };
				}) });
			}
			if (body.action === "compile_document_draft" || body.action === "save_document_draft") {
				const save = body.action === "save_document_draft";
				// Draft authors retain member access; publishing remains owner/admin-only.
				if (save && (!member || !["owner", "admin", "member"].includes(member.role))) return corsJson(req, 403, { error: "policy_forbidden" });
				const expected = body.expected_document as { id?: unknown; version?: unknown; source_sha256?: unknown } | null;
				if (save && expected !== null && (
					!expected || typeof expected !== "object" || Array.isArray(expected) ||
					typeof expected.id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(expected.id) ||
					!Number.isSafeInteger(expected.version) || Number(expected.version) < 1 ||
					typeof expected.source_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(expected.source_sha256)
				)) return corsJson(req, 400, { error: "invalid_document_precondition" });
				let compiled: Awaited<ReturnType<typeof compileRuntimePolicyDraft>>;
				let simulation: ReturnType<typeof simulateCompiledRuntimePolicy> | null = null;
				try {
					compiled = await compileRuntimePolicyDraft(body.content, parseStoredDocument);
					validateRuntimePolicy(compiled.runtime_policy);
					if (body.simulation !== undefined) simulation = simulateCompiledRuntimePolicy(compiled.runtime_policy, body.simulation);
				} catch (error) {
					return corsJson(req, 400, { error: error instanceof Error ? error.message : "invalid_policy_document" });
				}
				const { source_sha256, ...compilation } = compiled;
				if (!save) return corsJson(req, 200, { ok: true, dry_run: true, source: { source_sha256 }, ...compilation, ...(simulation ? { simulation } : {}) });
				// No write (or browser compensation) precedes compilation. The RPC
				// compares the originally loaded revision under one transaction lock.
				const { data, error } = await db.rpc("save_policy_document_draft", {
					p_tenant_id: tenant,
					p_user_id: auth.user.id,
					p_content: body.content as string,
					p_source_sha256: source_sha256,
					p_expected_id: expectedDocument?.id ?? null,
					p_expected_version: expectedDocument?.version ?? null,
					p_expected_source_sha256: expectedDocument?.source_sha256 ?? null,
				});
				if (error) return corsJson(req, error.code === "PT409" ? 409 : error.code === "42501" ? 403 : error.code === "22023" ? 400 : 503, { error: error.code === "PT409" ? "policy_document_conflict" : "policy_document_save_failed" });
				if (!data || typeof data.id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(data.id) ||
					typeof data.updated_at !== "string" || !Number.isFinite(Date.parse(data.updated_at)) ||
					data.version !== (expected ? Number(expected.version) + 1 : 1) || !Number.isSafeInteger(data.version) ||
					(expected && data.id !== expected.id) || data.source_sha256 !== source_sha256) {
					return corsJson(req, 503, { error: "policy_document_save_failed" });
				}
				return corsJson(req, 200, { ok: true, source: { id: data.id, version: data.version, source_sha256, updated_at: data.updated_at }, ...compilation, ...(simulation ? { simulation } : {}) });
			}
			if (isPolicyRolloutAction(action)) return await dispatchPolicyRollout(req, db, body, tenant, auth.user.id, member.role);
			let documentCompilation: RuntimePolicyDocumentCompilation | null = null;
			let documentSource: { id: string; version: number; source_sha256: string; updated_at: string } | null = null;
			if (["compile_document", "publish_document"].includes(String(body.action))) {
				const stored = await db.from("team_policies").select("id,content,version,source_sha256,updated_at").eq("team_id", tenant).order("updated_at", { ascending: false }).order("id", { ascending: false }).limit(1);
				if (stored.error) return corsJson(req, 503, { error: "policy_document_unavailable" });
				const row = stored.data?.[0];
				if (!row || typeof row.content !== "string") return corsJson(req, 404, { error: "policy_document_not_found" });
				if (typeof row.id !== "string" || !UUID_PATTERN.test(row.id) || !Number.isSafeInteger(row.version) || Number(row.version) < 1 || typeof row.source_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(row.source_sha256) || typeof row.updated_at !== "string") return corsJson(req, 503, { error: "policy_document_unavailable" });
				documentSource = { id: row.id, version: Number(row.version), source_sha256: row.source_sha256, updated_at: row.updated_at };
				if (body.action === "publish_document" && (
					documentSource.id !== expectedDocument?.id ||
					documentSource.version !== expectedDocument.version ||
					documentSource.source_sha256 !== expectedDocument.source_sha256
				)) return corsJson(req, 409, { error: "policy_document_conflict" });
				try {
					documentCompilation = compileRuntimePolicyDocument(parseStoredDocument(row.content));
				} catch (error) {
					return corsJson(req, 400, { error: error instanceof Error ? error.message : "invalid_policy_document" });
				}
				if (body.action === "compile_document") {
					let simulation: ReturnType<typeof simulateCompiledRuntimePolicy> | null = null;
					if (body.simulation !== undefined) {
						try { simulation = simulateCompiledRuntimePolicy(documentCompilation.runtime_policy, body.simulation); }
						catch (error) { return corsJson(req, 400, { error: error instanceof Error ? error.message : "invalid_simulation" }); }
					}
					return corsJson(req, 200, { ok: true, dry_run: true, source: documentSource, ...documentCompilation, ...(simulation ? { simulation } : {}) });
				}
			}
			if (!["publish", "stage", "restore", "publish_document"].includes(String(body.action))) return corsJson(req, 400, { error: "invalid_action" });
			if (!member || !["owner", "admin"].includes(member.role)) return corsJson(req, 403, { error: "policy_forbidden" });
			if (!Number.isSafeInteger(body.expected_version) || Number(body.expected_version) < 0) return corsJson(req, 400, { error: "invalid_version" });
			let policy: Record<string, unknown>;
			if (body.action === "restore") {
				if (!Number.isSafeInteger(body.target_version) || Number(body.target_version) < 1) return corsJson(req, 400, { error: "invalid_target_version" });
				const revision = await db.from("runtime_policy_revisions").select("policy").eq("tenant_id", tenant).eq("version", Number(body.target_version)).maybeSingle();
				if (revision.error) return corsJson(req, 503, { error: "history_unavailable" });
				if (!revision.data) return corsJson(req, 404, { error: "revision_not_found" });
				body.policy = revision.data.policy;
			}
			try { policy = validateRuntimePolicy(documentCompilation?.runtime_policy ?? body.policy); } catch (error) { return corsJson(req, 400, { error: error instanceof Error ? error.message : "invalid_policy" }); }
			if (body.action === "stage") {
				if (!Array.isArray(body.agent_ids) || body.agent_ids.length < 1 || body.agent_ids.length > 200 || body.agent_ids.some((id) => typeof id !== "string" || !/^[0-9a-f-]{36}$/i.test(id))) return corsJson(req, 400, { error: "invalid_stage_agents" });
				if (!Number.isSafeInteger(body.expected_revision_version) || Number(body.expected_revision_version) < Number(body.expected_version)) return corsJson(req, 400, { error: "invalid_revision_version" });
			}
			const { data, error } = body.action === "stage"
				? await db.rpc("stage_runtime_policy", { p_tenant_id: tenant, p_user_id: auth.user.id, p_expected_version: Number(body.expected_version), p_expected_revision_version: Number(body.expected_revision_version), p_policy: policy, p_agent_ids: body.agent_ids as string[] })
				: body.action === "publish_document"
					? await db.rpc("publish_runtime_policy_document", {
							p_tenant_id: tenant, p_user_id: auth.user.id, p_expected_version: Number(body.expected_version), p_policy: policy,
							p_expected_document_id: expectedDocument!.id, p_expected_document_version: expectedDocument!.version,
							p_expected_source_sha256: expectedDocument!.source_sha256,
						})
					: await db.rpc("publish_runtime_policy", { p_tenant_id: tenant, p_user_id: auth.user.id, p_expected_version: Number(body.expected_version), p_policy: policy });
			if (error) {
				const documentConflict = body.action === "publish_document" && error.code === "PT409" && String(error.message).includes("policy_document_conflict");
				return corsJson(req, error.code === "PT409" ? 409 : error.code === "42501" ? 403 : error.code === "22023" ? 400 : 503, {
					error: documentConflict ? "policy_document_conflict" : error.code === "PT409" ? "policy_version_conflict" : "policy_publish_failed",
				});
			}
			// The RPC always returns the row it wrote. A payload without a stored
			// version is a contract breach, never a publication to acknowledge.
			if (!data || !Number.isSafeInteger(data.version)) return corsJson(req, 503, { error: "policy_publish_failed" });
			return corsJson(req, 200, { ok: true, version: data.version, policy: data.policy, updated_at: data.updated_at, ...(body.action === "stage" ? { target_count: data.target_count, staged: true } : {}), ...(documentCompilation && documentSource ? { compiled_from: documentSource, compiler: { diagnostics: documentCompilation.diagnostics, semantics: documentCompilation.semantics } } : {}) });
		} catch {
			return corsJson(req, 503, { error: "policy_unavailable" });
		}
	};
}

Deno.serve(createPolicyManagementHandler());
