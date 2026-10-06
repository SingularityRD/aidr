import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import {
	collectorCredentialHash,
	createCollectorCredential,
	hasCollectorCredentialPrefix,
	validCollectorCredential,
} from "./credential.ts";
import {
	canonicalDiscoveryOrigin,
	discoveryAlertState,
	discoveryCollectorState,
	discoveryFreshness,
	parseDiscoveryIngest,
	parseProviderScope,
	validCollectorId,
	validUuid,
} from "./logic.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function unavailable(req: Request): Response {
	return corsJson(req, 503, { error: "discovery_unavailable" });
}

function credentialError(req: Request, code?: string): Response {
	if (code === "42501") return corsJson(req, 401, { error: "invalid_collector_credential" });
	if (code === "PT409") return corsJson(req, 409, { error: "discovery_sequence_exhausted" });
	if (code === "22023") return corsJson(req, 400, { error: "invalid_request" });
	return unavailable(req);
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("discovery", config.error, (status, body) => corsJson(req, status, body));
	const token = getBearerToken(req.headers.get("Authorization"));
	if (!token) return corsJson(req, 401, { error: "missing_access_token" });
	try {
		const parsed = await readBoundedJson(req, 524_288);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const body = parsed.value;
		if (!body || typeof body !== "object" || Array.isArray(body)) return corsJson(req, 400, { error: "invalid_request" });
		const input = body as Record<string, unknown>;
		if (!Object.hasOwn(input, "provider_resources") && parsed.bytes > 65_536) return corsJson(req, 413, { error: "request_too_large" });
		if (!validUuid(input.tenant_id)) return corsJson(req, 400, { error: "invalid_tenant" });
		const tenant = input.tenant_id;
		const action = input.action;
		const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
			auth: { persistSession: false, autoRefreshToken: false },
		});
		if (hasCollectorCredentialPrefix(token)) {
			if (!validCollectorCredential(token)) return corsJson(req, 401, { error: "invalid_collector_credential" });
			if (action !== "ingest" && action !== "cursor") return corsJson(req, 403, { error: "collector_scope_forbidden" });
			if (!validCollectorId(input.collector_id)) return corsJson(req, 400, { error: "invalid_collector" });
			if (action === "cursor" && !exactKeys(input, ["action", "tenant_id", "collector_id"])) return corsJson(req, 400, { error: "invalid_request" });
			const cycle = action === "ingest" ? parseDiscoveryIngest(input) : null;
			if (action === "ingest" && !cycle) return corsJson(req, 400, { error: "invalid_discovery_cycle" });
			const tokenHash = await collectorCredentialHash(token);
			const cursor = await db.rpc("read_tenant_discovery_collector_cursor", {
				p_tenant_id: tenant,
				p_collector_id: input.collector_id,
				p_token_hash: tokenHash,
			});
			if (cursor.error) return credentialError(req, cursor.error.code);
			if (!cursor.data || typeof cursor.data !== "object" || Array.isArray(cursor.data)
				|| !validUuid(cursor.data.credential_id) || cursor.data.collector_id !== input.collector_id
				|| !Number.isSafeInteger(cursor.data.last_sequence) || cursor.data.last_sequence < 0
				|| !Number.isSafeInteger(cursor.data.next_sequence) || cursor.data.next_sequence !== cursor.data.last_sequence + 1) return unavailable(req);
			const rate = await consumeTenantRateLimit(db, {
				tenantId: tenant,
				subject: `collector:${cursor.data.credential_id}`,
				endpoint: "discovery-machine",
				perSubject: 600,
				perTenant: 30_000,
				cost: action === "ingest" ? 5 : 1,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			if (action === "cursor") return corsJson(req, 200, {
				ok: true,
				collector_id: cursor.data.collector_id,
				last_sequence: cursor.data.last_sequence,
				next_sequence: cursor.data.next_sequence,
			}, { ...rateLimitHeaders(rate), "Cache-Control": "no-store" });
			if (!cycle) return corsJson(req, 400, { error: "invalid_discovery_cycle" });
			if (cycle.sequence !== cursor.data.next_sequence) return corsJson(req, 409, { error: "discovery_sequence_conflict" });
			const result = await db.rpc("ingest_tenant_discovery_cycle_machine", {
				p_tenant_id: tenant,
				p_collector_id: cycle.collector_id,
				p_token_hash: tokenHash,
				p_cycle_id: cycle.cycle_id,
				p_sequence: cycle.sequence,
				p_stale_after_ms: cycle.stale_after_ms,
				p_complete: cycle.complete,
				p_expected_targets: cycle.expected_targets,
				p_items: cycle.items,
				...(cycle.provider_resources ? { p_provider_resources: cycle.provider_resources } : {}),
			});
			if (result.error) {
				if (result.error.code === "PT409") return corsJson(req, 409, { error: "discovery_cycle_replayed" });
				if (result.error.code === "42501") return corsJson(req, 401, { error: "invalid_collector_credential" });
				if (result.error.code === "22023" || result.error.code === "23514") return corsJson(req, 400, { error: "invalid_discovery_cycle" });
				return unavailable(req);
			}
			return corsJson(req, 201, { ok: true, cycle: result.data }, rateLimitHeaders(rate));
		}
		const { data: auth, error: authError } = await db.auth.getUser(token);
		if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
		const [membership, state] = await Promise.all([
			db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenant).eq("user_id", auth.user.id).maybeSingle(),
			db.from("tenants").select("status").eq("id", tenant).maybeSingle(),
		]);
		if (membership.error || state.error) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (!membershipActive(membership.data) || state.data?.status !== "active") return corsJson(req, 403, { error: "tenant_access_denied" });
		const barrier = await checkIdentityBarrier(db, token, auth.user.id, tenant);
		if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });
		if (action !== "ingest" && action !== "read" && action !== "resources" && action !== "list" && action !== "summary"
			&& action !== "issue_credential" && action !== "revoke_credential") return corsJson(req, 400, { error: "invalid_action" });
		if ((action === "ingest" || action === "issue_credential" || action === "revoke_credential")
			&& !["owner", "admin"].includes(String(membership.data?.role))) return corsJson(req, 403, { error: "discovery_write_forbidden" });
		const rate = await consumeTenantRateLimit(db, {
			tenantId: tenant,
			subject: auth.user.id,
			endpoint: "discovery",
			perSubject: 600,
			perTenant: 30_000,
			cost: action === "ingest" ? 5 : action === "summary" || action === "list" ? 2 : action === "issue_credential" || action === "revoke_credential" ? 10 : 1,
		});
		if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));

		if (action === "issue_credential" || action === "revoke_credential") {
			if (!exactKeys(input, ["action", "tenant_id", "collector_id"], action === "issue_credential" ? ["expires_in_days", "allowed_provider_scope"] : [])
				|| !validCollectorId(input.collector_id)) return corsJson(req, 400, { error: "invalid_request" });
			const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
			if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
			if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });
			if (action === "revoke_credential") {
				const result = await db.rpc("revoke_tenant_discovery_credential", {
					p_tenant_id: tenant, p_actor_user_id: auth.user.id, p_collector_id: input.collector_id,
				});
				if (result.error) return result.error.code === "42501"
					? corsJson(req, 403, { error: "discovery_write_forbidden" }) : unavailable(req);
				return corsJson(req, 200, { ok: true, ...result.data }, { ...rateLimitHeaders(rate), "Cache-Control": "no-store" });
			}
			const expiresInDays = input.expires_in_days === undefined ? 30 : input.expires_in_days;
			if (typeof expiresInDays !== "number" || !Number.isSafeInteger(expiresInDays)
				|| expiresInDays < 1 || expiresInDays > 90) return corsJson(req, 400, { error: "invalid_expiry" });
			const credential = createCollectorCredential();
			const providerScope = input.allowed_provider_scope === undefined ? null : parseProviderScope(input.allowed_provider_scope);
			if (input.allowed_provider_scope !== undefined && !providerScope) return corsJson(req, 400, { error: "invalid_provider_scope" });
			const result = await db.rpc("issue_tenant_discovery_credential", {
				p_tenant_id: tenant,
				p_actor_user_id: auth.user.id,
				p_collector_id: input.collector_id,
				p_token_hash: await collectorCredentialHash(credential),
				p_expires_in_days: expiresInDays,
				p_allowed_provider_scope: providerScope,
			});
			if (result.error) {
				if (result.error.code === "42501") return corsJson(req, 403, { error: "discovery_write_forbidden" });
				if (result.error.code === "PT409") return corsJson(req, 409, { error: "discovery_sequence_exhausted" });
				return unavailable(req);
			}
			return corsJson(req, 201, { ok: true, credential, ...result.data }, {
				...rateLimitHeaders(rate), "Cache-Control": "no-store", "Pragma": "no-cache",
			});
		}

		if (action === "ingest") {
			const cycle = parseDiscoveryIngest(input);
			if (!cycle) return corsJson(req, 400, { error: "invalid_discovery_cycle" });
			const result = await db.rpc("ingest_tenant_discovery_cycle", {
				p_tenant_id: tenant,
				p_actor_user_id: auth.user.id,
				p_collector_id: cycle.collector_id,
				p_cycle_id: cycle.cycle_id,
				p_sequence: cycle.sequence,
				p_stale_after_ms: cycle.stale_after_ms,
				p_complete: cycle.complete,
				p_expected_targets: cycle.expected_targets,
				p_items: cycle.items,
				...(cycle.provider_resources ? { p_provider_resources: cycle.provider_resources } : {}),
			});
			if (result.error) {
				if (result.error.code === "PT409") return corsJson(req, 409, { error: "discovery_cycle_replayed" });
				if (result.error.code === "42501") return corsJson(req, 403, { error: "discovery_write_forbidden" });
				if (result.error.code === "22023" || result.error.code === "23514") return corsJson(req, 400, { error: "invalid_discovery_cycle" });
				return unavailable(req);
			}
			return corsJson(req, 201, { ok: true, cycle: result.data }, rateLimitHeaders(rate));
		}

		if (action === "summary") {
			if (!exactKeys(input, ["action", "tenant_id"])) return corsJson(req, 400, { error: "invalid_request" });
			const result = await db.rpc("read_tenant_discovery_summary", { p_tenant_id: tenant, p_actor_user_id: auth.user.id });
			if (result.error) return unavailable(req);
			return corsJson(req, 200, { ok: true, summary: result.data }, rateLimitHeaders(rate));
		}

		if (action === "list") {
			if (!exactKeys(input, ["action", "tenant_id"], ["after_collector", "limit"])) return corsJson(req, 400, { error: "invalid_request" });
			if (input.after_collector !== undefined && !validCollectorId(input.after_collector)) return corsJson(req, 400, { error: "invalid_cursor" });
			if (input.limit !== undefined && (typeof input.limit !== "number" || !Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 100)) return corsJson(req, 400, { error: "invalid_limit" });
			const limit = (input.limit as number | undefined) ?? 50;
			let query = db.from("tenant_discovery_collectors")
				.select("collector_id,cycle_id,sequence,stale_after_ms,complete,expected_targets,observed_targets,reported_at,provider_evidence")
				.eq("tenant_id", tenant)
				.order("collector_id", { ascending: true })
				.limit(limit + 1);
			if (typeof input.after_collector === "string") query = query.gt("collector_id", input.after_collector);
			const result = await query;
			if (result.error || !Array.isArray(result.data)) return unavailable(req);
			const page = result.data.slice(0, limit);
			const now = Date.now();
			return corsJson(req, 200, {
				ok: true,
				coverage_scope: "reported_collectors_only",
				collectors: page.map((collector) => ({
					...collector,
					state: discoveryCollectorState(collector.reported_at, collector.complete, collector.stale_after_ms, now),
				})),
				truncated: result.data.length > limit,
				next_collector: result.data.length > limit ? page[page.length - 1]?.collector_id ?? null : null,
			}, rateLimitHeaders(rate));
		}

		const resourceRead = action === "resources";
		if (!exactKeys(input, ["action", "tenant_id", "collector_id"], resourceRead ? ["after_resource", "expected_sequence", "limit"] : ["after_target", "limit"]) || !validCollectorId(input.collector_id)) return corsJson(req, 400, { error: "invalid_request" });
		if (input.limit !== undefined && (typeof input.limit !== "number" || !Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 100)) return corsJson(req, 400, { error: "invalid_limit" });
		const after = input.after_target === undefined ? null : canonicalDiscoveryOrigin(input.after_target);
		if (input.after_target !== undefined && !after) return corsJson(req, 400, { error: "invalid_cursor" });
		if (input.after_resource !== undefined && (typeof input.after_resource !== "string" || !input.after_resource.length || input.after_resource.length > 1024 || /[\u0000-\u001f\u007f]/.test(input.after_resource))) return corsJson(req, 400, { error: "invalid_cursor" });
		if (input.expected_sequence !== undefined && (typeof input.expected_sequence !== "number" || !Number.isSafeInteger(input.expected_sequence) || input.expected_sequence < 1)
			|| input.after_resource !== undefined && input.expected_sequence === undefined) return corsJson(req, 400, { error: "invalid_cursor" });
		const limit = (input.limit as number | undefined) ?? 100;
		const collector = await db.from("tenant_discovery_collectors")
			.select("collector_id,cycle_id,sequence,stale_after_ms,complete,expected_targets,observed_targets,reported_at,provider_evidence")
			.eq("tenant_id", tenant).eq("collector_id", input.collector_id).maybeSingle();
		if (collector.error) return unavailable(req);
		const collectorRow = collector.data;
		if (!collectorRow) return corsJson(req, 404, { error: "collector_not_found" });
		if (resourceRead && input.expected_sequence !== undefined && input.expected_sequence !== collectorRow.sequence) return corsJson(req, 409, { error: "discovery_inventory_changed" });
		let query = db.from(resourceRead ? "tenant_discovery_provider_resources" : "tenant_discovery_items")
			.select(resourceRead ? "provider,scope_hash,resource_id,resource_type,scope_id,region,observed_at,last_cycle_id" : "target,first_reported_at,last_reported_at,last_reachable_at,last_cycle_id,reachable,attempts,error_code")
			.eq("tenant_id", tenant).eq("collector_id", input.collector_id)
			.order(resourceRead ? "resource_id" : "target").limit(limit + 1);
		if (resourceRead && typeof input.after_resource === "string") query = query.gt("resource_id", input.after_resource);
		if (!resourceRead && after) query = query.gt("target", after);
		const rows = await query;
		if (rows.error || !Array.isArray(rows.data)) return unavailable(req);
		const latestCollector = await db.from("tenant_discovery_collectors")
			.select("cycle_id,sequence")
			.eq("tenant_id", tenant).eq("collector_id", input.collector_id).maybeSingle();
		if (latestCollector.error) return unavailable(req);
		if (!latestCollector.data || latestCollector.data.cycle_id !== collectorRow.cycle_id
			|| latestCollector.data.sequence !== collectorRow.sequence) {
			return corsJson(req, 409, { error: "discovery_inventory_changed" });
		}
		const page = rows.data.slice(0, limit) as Record<string, unknown>[];
		const now = Date.now();
		const collectorState = discoveryCollectorState(collectorRow.reported_at, collectorRow.complete, collectorRow.stale_after_ms, now);
		if (resourceRead) return corsJson(req, 200, {
			ok: true,
			collector: { ...collectorRow, state: collectorState },
			provider_resources: page.map((item) => ({ ...item,
				freshness: discoveryFreshness(typeof item.observed_at === "string" ? item.observed_at : null, collectorRow.stale_after_ms, now),
				alert_state: !collectorRow.complete ? "collection_partial"
					: item.last_cycle_id !== collectorRow.cycle_id ? "not_reported"
					: discoveryFreshness(typeof item.observed_at === "string" ? item.observed_at : null, collectorRow.stale_after_ms, now) === "fresh" ? "healthy" : "stale",
			})),
			truncated: rows.data.length > limit,
			next_resource: rows.data.length > limit ? page[page.length - 1]?.resource_id ?? null : null,
		}, rateLimitHeaders(rate));
		return corsJson(req, 200, {
			ok: true,
			collector: { ...collectorRow, state: collectorState },
			items: page.map((item) => ({
				...item,
				freshness: discoveryFreshness(typeof item.last_reachable_at === "string" ? item.last_reachable_at : null, collectorRow.stale_after_ms, now),
				alert_state: discoveryAlertState({
					lastReachableAt: typeof item.last_reachable_at === "string" ? item.last_reachable_at : null,
					lastCycleId: typeof item.last_cycle_id === "string" ? item.last_cycle_id : "",
					cycleId: collectorRow.cycle_id,
					reachable: item.reachable === true,
					complete: collectorRow.complete,
					staleAfterMs: collectorRow.stale_after_ms,
				}, now),
			})),
			truncated: rows.data.length > limit,
			next_target: rows.data.length > limit ? page[page.length - 1]?.target ?? null : null,
		}, rateLimitHeaders(rate));
	} catch {
		return unavailable(req);
	}
});
