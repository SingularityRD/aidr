import type { SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { corsJson } from "./cors.ts";
import { validateRuntimePolicy } from "./runtime-policy.ts";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const MAX_POLICY_MANAGEMENT_BODY_BYTES = 65_536;
// A minimum policy and safe-integer versions leave room for at most 1,667 UUIDs.
export const MAX_POLICY_ROLLOUT_TARGETS = 1_667;
type RolloutBatch = { batch_order: number; agent_ids: string[] };
type RolloutRing = { ring_order: number; batches: RolloutBatch[] };
function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

/** Explicit ordered cohorts; an agent may occur only once across the whole plan. */
export function normalizeRolloutRings(value: unknown): RolloutRing[] {
	if (!Array.isArray(value) || value.length < 1 || value.length > 100) throw new Error("invalid_rollout_rings");
	const seenAgents = new Set<string>();
	let totalBatches = 0;
	let totalAgents = 0;
	return value.map((item, ringIndex) => {
		if (!isRecord(item) || item.ring_order !== ringIndex + 1 || !Array.isArray(item.batches) || item.batches.length < 1 || item.batches.length > 1000) throw new Error("invalid_rollout_order");
		const batches = item.batches.map((batch, batchIndex) => {
			if (!isRecord(batch) || batch.batch_order !== batchIndex + 1 || !Array.isArray(batch.agent_ids) || batch.agent_ids.length < 1 || batch.agent_ids.length > 200) throw new Error("invalid_rollout_batch");
			const agentIds = batch.agent_ids.map((agent) => {
				if (typeof agent !== "string" || !UUID_PATTERN.test(agent) || seenAgents.has(agent.toLowerCase())) throw new Error("invalid_rollout_agents");
				seenAgents.add(agent.toLowerCase());
				return agent.toLowerCase();
			});
			totalBatches += 1;
			totalAgents += agentIds.length;
			if (totalBatches > 1000 || totalAgents > MAX_POLICY_ROLLOUT_TARGETS) throw new Error("rollout_too_large");
			return { batch_order: batchIndex + 1, agent_ids: agentIds };
		});
		return { ring_order: ringIndex + 1, batches };
	});
}

export const isPolicyRolloutAction = (action: string) => ["rollout", "create_rollout", "rollout_progress"].includes(action);

/** Call only after the common session/MFA, active membership/tenant and quota guards. */
export async function dispatchPolicyRollout(req: Request, db: SupabaseClient, body: Record<string, unknown>, tenant: string, userId: string, role: string): Promise<Response> {
	if (body.action === "rollout_progress") {
		if (body.rollout_id !== undefined && (typeof body.rollout_id !== "string" || !UUID_PATTERN.test(body.rollout_id))) return corsJson(req, 400, { error: "invalid_rollout_id" });
		const progress = await db.rpc("read_policy_rollout_progress", { p_tenant_id: tenant, p_rollout_id: body.rollout_id ?? null });
		if (progress.error || !isRecord(progress.data)) return corsJson(req, 503, { error: "rollout_progress_unavailable" });
		return corsJson(req, 200, { ok: true, ...progress.data });
	}
	if (!["owner", "admin"].includes(role)) return corsJson(req, 403, { error: "policy_forbidden" });
	if (!Number.isSafeInteger(body.expected_version) || Number(body.expected_version) < 0) return corsJson(req, 400, { error: "invalid_version" });
	if (!Number.isSafeInteger(body.expected_revision_version) || Number(body.expected_revision_version) < Number(body.expected_version)) return corsJson(req, 400, { error: "invalid_revision_version" });
	let policy: Record<string, unknown>;
	let rings: RolloutRing[];
	try {
		policy = validateRuntimePolicy(body.policy);
		rings = normalizeRolloutRings(body.rings);
	} catch (error) {
		const message = error instanceof Error ? error.message : "invalid_rollout";
		return corsJson(req, message === "rollout_too_large" ? 413 : 400, { error: message });
	}
	const result = await db.rpc("create_policy_rollout", {
		p_tenant_id: tenant, p_user_id: userId, p_expected_version: body.expected_version,
		p_expected_revision_version: body.expected_revision_version, p_policy: policy, p_rings: rings,
	});
	if (result.error) {
		const code = result.error.code;
		return corsJson(req, code === "PT409" ? 409 : code === "42501" ? 403 : code === "22023" ? 400 : 503, {
			error: code === "PT409" ? "rollout_conflict" : code === "42501" ? "policy_forbidden" : "rollout_failed",
		});
	}
	if (!isRecord(result.data) || typeof result.data.rollout_id !== "string" || !UUID_PATTERN.test(result.data.rollout_id) || !Number.isSafeInteger(result.data.version)) return corsJson(req, 503, { error: "rollout_failed" });
	return corsJson(req, 200, { ok: true, ...result.data });
}

/** Optional additive evidence: unavailable storage is explicitly unknown, never convergence. */
export async function rolloutAdoptionEvidence(db: SupabaseClient, tenant: string, rolloutId: unknown): Promise<Record<string, unknown>> {
	if (rolloutId !== undefined && (typeof rolloutId !== "string" || !UUID_PATTERN.test(rolloutId))) return { rollout_evidence: "invalid_rollout_id" };
	try {
		const result = await db.rpc("read_policy_rollout_progress", { p_tenant_id: tenant, p_rollout_id: rolloutId ?? null });
		if (!result.error && isRecord(result.data) && isRecord(result.data.rollout_progress)) return { rollout_progress: result.data.rollout_progress, rollout_rings: result.data.rings ?? [], rollout_evidence: "agent_reported_policy_loaded" };
	} catch { /* Preserve the legacy fleet view without inventing evidence. */ }
	return { rollout_evidence: "unavailable" };
}
