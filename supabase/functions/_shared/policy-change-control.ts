// Four-eyes policy change control (docs/ai-governance.md).
//
// When a tenant has enabled `policy_four_eyes`, policy-management files a
// change request instead of publishing. A second owner/admin approves it from
// the dashboard (ai-governance `decide_policy_change`), which runs the same
// publication RPC with the author as publisher. The database refuses any new
// runtime or DLP revision while four-eyes is on unless it is being applied by
// such an approval, so this module is the friendly path, not the control.

import type { SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { corsJson } from "./cors.ts";

type PolicyChangeKind =
	| "runtime_publish"
	| "runtime_publish_document"
	| "runtime_restore"
	| "runtime_stage"
	| "runtime_rollout"
	| "dlp_publish";

export type FourEyesState = { ok: true; enabled: boolean } | { ok: false };

/** Unreadable settings are an availability failure, never "four-eyes off". */
export async function readPolicyFourEyes(db: SupabaseClient, tenantId: string): Promise<FourEyesState> {
	try {
		const { data, error } = await db
			.from("tenant_ai_governance_settings")
			.select("policy_four_eyes")
			.eq("tenant_id", tenantId)
			.maybeSingle();
		if (error) return { ok: false };
		if (data === null || data === undefined) return { ok: true, enabled: false };
		const enabled = (data as { policy_four_eyes?: unknown }).policy_four_eyes;
		return typeof enabled === "boolean" ? { ok: true, enabled } : { ok: false };
	} catch {
		return { ok: false };
	}
}

export interface PolicyChangeSubmission {
	tenantId: string;
	userId: string;
	kind: PolicyChangeKind;
	baseVersion: number;
	expectedRevisionVersion?: number | null;
	targetVersion?: number | null;
	payload: Record<string, unknown>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * File the change for a second approver. 202 means nothing was published:
 * the response names the pending request the dashboard shows for review.
 */
export async function submitPolicyChange(
	req: Request,
	db: SupabaseClient,
	change: PolicyChangeSubmission,
): Promise<Response> {
	const { data, error } = await db.rpc("submit_policy_change_request", {
		p_tenant_id: change.tenantId,
		p_actor_user_id: change.userId,
		p_change_kind: change.kind,
		p_base_version: change.baseVersion,
		p_expected_revision_version: change.expectedRevisionVersion ?? null,
		p_target_version: change.targetVersion ?? null,
		p_payload: change.payload,
	});
	if (error) {
		const code = (error as { code?: string }).code;
		return corsJson(req, code === "42501" ? 403 : code === "22023" ? 400 : code === "54000" ? 429 : 503, {
			error: code === "42501" ? "policy_forbidden" : code === "22023" ? "invalid_policy_change"
				: code === "54000" ? "policy_change_request_quota" : "policy_change_request_failed",
		});
	}
	const row = data as { request_id?: unknown; status?: unknown; expires_at?: unknown; payload_sha256?: unknown } | null;
	if (!row || typeof row.request_id !== "string" || !UUID.test(row.request_id) || row.status !== "pending" ||
		typeof row.expires_at !== "string" || typeof row.payload_sha256 !== "string") {
		return corsJson(req, 503, { error: "policy_change_request_failed" });
	}
	return corsJson(req, 202, {
		ok: true,
		pending_approval: true,
		change_request_id: row.request_id,
		change_kind: change.kind,
		status: "pending",
		expires_at: row.expires_at,
		payload_sha256: row.payload_sha256,
		published: false,
	});
}

/** Postgres raised the four-eyes guard: publication needs an approved change request. */
export function isFourEyesRefusal(error: unknown): boolean {
	const message = (error as { message?: unknown } | null)?.message;
	return typeof message === "string" && message.includes("policy_four_eyes_required");
}
