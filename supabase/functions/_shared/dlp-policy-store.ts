import type { SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
// Generated, byte-parity-checked artifact of the engine schema, packaged with
// functions/ for self-hosted deployments; never the dashboard validation mirror.
import { DlpPolicySchema } from "./dlp-policy-schema.ts";
import { corsJson } from "./cors.ts";
import { isFourEyesRefusal, readPolicyFourEyes, submitPolicyChange } from "./policy-change-control.ts";

const DELIVERY = {
	delivered: false,
	delivery_status: "not_delivered",
	delivery_detail: "Saved policy is not signed runtime distribution; the signed provisioning path must consume it separately.",
} as const;

/** policy-management actions served by this module. */
const DLP_POLICY_ACTIONS = [
	"read_dlp_policy",
	"publish_dlp_policy",
	"dlp_policy_history",
	"read_dlp_policy_revision",
	"restore_dlp_policy",
] as const;
export type DlpPolicyAction = (typeof DLP_POLICY_ACTIONS)[number];

export function isDlpPolicyAction(action: string): action is DlpPolicyAction {
	return (DLP_POLICY_ACTIONS as readonly string[]).includes(action);
}

/** Revisions per history page; the dashboard pages with `before_version`. */
const DLP_HISTORY_PAGE = 50;

type Context = { tenant: string; userId: string; role: string; token: string };
type Row = Record<string, unknown>;

function isRecord(value: unknown): value is Row {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function positiveVersion(value: unknown): value is number {
	return Number.isSafeInteger(value) && Number(value) >= 1 && Number(value) < Number.MAX_SAFE_INTEGER;
}

function validVersionPrecondition(value: unknown): value is number {
	return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) < Number.MAX_SAFE_INTEGER;
}

function count(value: unknown): number {
	return Array.isArray(value) ? value.length : 0;
}

/** A stored revision row as the history view needs it; null when malformed. */
function revisionRow(value: unknown, tenant: string) {
	if (!isRecord(value) || !positiveVersion(value.version) || !isRecord(value.policy) ||
		value.policy.tenantId !== tenant || value.policy.version !== value.version ||
		typeof value.created_at !== "string" || !Number.isFinite(Date.parse(value.created_at))) {
		return null;
	}
	return {
		version: value.version,
		created_at: value.created_at,
		updated_by: typeof value.updated_by === "string" ? value.updated_by : null,
		policy: value.policy,
	};
}

/** One stored revision of this tenant, or the error response to return instead. */
async function readRevision(
	req: Request,
	db: SupabaseClient,
	tenant: string,
	version: number,
): Promise<{ revision: NonNullable<ReturnType<typeof revisionRow>> } | { response: Response }> {
	const { data, error } = await db.from("dlp_policy_revisions").select("version,policy,updated_by,created_at")
		.eq("tenant_id", tenant).eq("version", version).maybeSingle();
	if (error || data === undefined) return { response: corsJson(req, 503, { error: "dlp_history_unavailable" }) };
	if (data === null) return { response: corsJson(req, 404, { error: "revision_not_found" }) };
	const revision = revisionRow(data, tenant);
	if (!revision) return { response: corsJson(req, 503, { error: "dlp_history_unavailable" }) };
	return { revision };
}

/**
 * Validate and save one DLP document at `expected + 1`, through four-eyes when
 * the tenant has it on. Shared by publish and restore.
 */
async function commitDlpPolicy(
	req: Request,
	db: SupabaseClient,
	context: Context,
	expected: number,
	document: unknown,
	extra: Row = {},
): Promise<Response> {
	const { tenant, userId } = context;
	const validated = DlpPolicySchema.safeParse(document);
	if (!validated.success) {
		return corsJson(req, 400, {
			error: "invalid_dlp_policy",
			issues: validated.error.issues.map(({ path, message }) => ({ path, message })),
		});
	}
	if (validated.data.tenantId !== tenant) return corsJson(req, 400, { error: "dlp_tenant_mismatch" });
	// The editor keeps its document version independent of its CAS precondition.
	// Storage owns the revision counter; never allow client-chosen version jumps.
	const policy = { ...validated.data, version: expected + 1 };
	// Four-eyes change control: the saved revision waits for a second owner/admin.
	const fourEyes = await readPolicyFourEyes(db, tenant);
	if (!fourEyes.ok) return corsJson(req, 503, { error: "dlp_policy_publish_failed" });
	if (fourEyes.enabled) {
		return await submitPolicyChange(req, db, {
			tenantId: tenant, userId, kind: "dlp_publish", baseVersion: expected, payload: { policy },
		});
	}
	const { data, error } = await db.rpc("publish_dlp_policy", {
		p_tenant_id: tenant, p_user_id: userId, p_expected_version: expected, p_policy: policy,
	});
	if (error) {
		if (isFourEyesRefusal(error)) return corsJson(req, 409, { error: "policy_four_eyes_required" });
		return corsJson(req, error.code === "PT409" ? 409 : error.code === "42501" ? 403 : error.code === "22023" ? 400 : 503, {
			error: error.code === "PT409" ? "policy_version_conflict" : "dlp_policy_publish_failed",
		});
	}
	// A successful RPC must confirm the committed row, not just a truthy payload.
	if (!data || data.version !== policy.version || data.policy?.version !== policy.version ||
		data.policy?.tenantId !== tenant || typeof data.updated_at !== "string" ||
		!Number.isFinite(Date.parse(data.updated_at))) {
		return corsJson(req, 503, { error: "dlp_policy_publish_failed" });
	}
	return corsJson(req, 200, {
		ok: true, version: data.version, policy: data.policy, updated_at: data.updated_at,
		saved: true, ...extra, ...DELIVERY,
	});
}

/** Called only after verified identity, live tenant membership/status and quota checks. */
export async function handleDlpPolicyAction(
	req: Request,
	db: SupabaseClient,
	body: Record<string, unknown>,
	context: Context,
): Promise<Response> {
	const { tenant, role, token } = context;
	const action = String(body.action);
	const writing = action === "publish_dlp_policy" || action === "restore_dlp_policy";
	if (writing && !["owner", "admin"].includes(role)) {
		return corsJson(req, 403, { error: "policy_forbidden" });
	}
	// DLP documents contain sensitive matchers and exceptions. Require step-up
	// for both reads and writes, even when the tenant's general MFA is optional.
	const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
	if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
	if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

	if (action === "read_dlp_policy") {
		const { data, error } = await db.from("tenant_dlp_policies")
			.select("version,policy,updated_at").eq("tenant_id", tenant).maybeSingle();
		if (error) return corsJson(req, 503, { error: "dlp_policy_unavailable" });
		// PostgREST's maybeSingle contract is `row | null`. Do not turn a malformed
		// response with missing `data` into `saved: true` (`undefined !== null`).
		if (data === undefined) return corsJson(req, 503, { error: "dlp_policy_unavailable" });
		// Do not revalidate time-sensitive exception expiry on reload: a saved
		// document can age, and must remain readable so an operator can repair it.
		if (data && (!Number.isSafeInteger(data.version) || data.version < 1 ||
			data.policy?.tenantId !== tenant || data.policy?.version !== data.version ||
			typeof data.updated_at !== "string" || !Number.isFinite(Date.parse(data.updated_at)))) {
			return corsJson(req, 503, { error: "dlp_policy_unavailable" });
		}
		return corsJson(req, 200, {
			ok: true, version: data?.version ?? 0, policy: data?.policy ?? null,
			updated_at: data?.updated_at ?? null, saved: data !== null, ...DELIVERY,
		});
	}

	if (action === "dlp_policy_history") {
		// Newest first, one page at a time. The list carries counts only; the
		// full document of a revision is read (and diffed) on demand.
		if (body.before_version !== undefined && !positiveVersion(body.before_version)) {
			return corsJson(req, 400, { error: "invalid_version" });
		}
		let query = db.from("dlp_policy_revisions").select("version,policy,updated_by,created_at")
			.eq("tenant_id", tenant);
		if (body.before_version !== undefined) query = query.lt("version", Number(body.before_version));
		const { data, error } = await query.order("version", { ascending: false }).limit(DLP_HISTORY_PAGE + 1);
		if (error || !Array.isArray(data)) return corsJson(req, 503, { error: "dlp_history_unavailable" });
		const rows = data.slice(0, DLP_HISTORY_PAGE).map((row) => revisionRow(row, tenant));
		if (rows.some((row) => row === null)) return corsJson(req, 503, { error: "dlp_history_unavailable" });
		const revisions = (rows as NonNullable<ReturnType<typeof revisionRow>>[]).map(({ policy, ...meta }) => ({
			...meta,
			counts: { labels: count(policy.labels), rules: count(policy.rules), exceptions: count(policy.exceptions) },
		}));
		return corsJson(req, 200, {
			ok: true,
			revisions,
			next_before_version: data.length > DLP_HISTORY_PAGE ? revisions[revisions.length - 1].version : null,
		});
	}

	if (action === "read_dlp_policy_revision") {
		if (!positiveVersion(body.version)) return corsJson(req, 400, { error: "invalid_version" });
		const read = await readRevision(req, db, tenant, Number(body.version));
		if ("response" in read) return read.response;
		return corsJson(req, 200, { ok: true, revision: read.revision });
	}

	const expected = body.expected_version;
	if (!validVersionPrecondition(expected)) return corsJson(req, 400, { error: "invalid_version" });

	if (action === "restore_dlp_policy") {
		// Rollback = publish an earlier revision's content as a NEW revision, so
		// history stays append-only and the change goes through four-eyes too.
		if (!positiveVersion(body.version)) return corsJson(req, 400, { error: "invalid_version" });
		if (Number(body.version) >= Number(expected)) {
			return corsJson(req, 400, { error: "restore_target_not_older" });
		}
		const read = await readRevision(req, db, tenant, Number(body.version));
		if ("response" in read) return read.response;
		// Re-validated with today's schema and clock: an exception that has
		// expired since that revision refuses the rollback with its path.
		return await commitDlpPolicy(req, db, context, Number(expected), read.revision.policy, {
			restored_from: read.revision.version,
		});
	}

	return await commitDlpPolicy(req, db, context, Number(expected), body.policy);
}
