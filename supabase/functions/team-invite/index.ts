import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { createMailer, type Mailer } from "../_shared/mailer.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";
import {
	createPendingInvitation,
	invitationSecret,
	invitationUrl,
	parseInvitationCommand,
	resendPendingInvitation,
	revokePendingInvitation,
} from "./lifecycle.ts";
import { invitationEmail } from "./email.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_DASHBOARD_URL"] as const;
const MAX_BODY_BYTES = 16 * 1024;

// ponytail: keep this route-local until reset-DB generated types include Edge tables/RPCs.
type ReadTable<Row extends Record<string, unknown>> = {
	Row: Row;
	Insert: never;
	Update: never;
	Relationships: [];
};

type InvitationResult = { id: string; expires_at?: string; email?: string; role?: string };
type TeamInviteDatabase = {
	public: {
		Tables: {
			tenant_members: ReadTable<{ tenant_id: string; user_id: string; role: string; expires_at: string | null }>;
			tenants: ReadTable<{ id: string; status: string; name: string }>;
			team_invitations: ReadTable<{ id: string; tenant_id: string; email: string; role: string; expires_at: string; accepted_at: string | null; created_at: string; created_by: string }>;
			rate_limits: ReadTable<{ key: string; window_start: number; count: number }>;
		};
		Views: Record<string, never>;
		Functions: {
			increment_rate_limit: { Args: { p_key: string; p_window_start: number; p_delta: number }; Returns: undefined };
			mutate_team_invitation: { Args: { p_action: string; p_tenant_id: string; p_actor_user_id: string; p_email: string | null; p_role: string | null; p_invitation_id: string | null; p_token_hash: string | null }; Returns: InvitationResult | null };
		};
		Enums: Record<string, never>;
		CompositeTypes: Record<string, never>;
	};
};

export interface TeamInviteDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: SupabaseClient<TeamInviteDatabase>;
	/**
	 * Overrides the deployment mailer (`createMailer(runtimeEnv)`). The contract
	 * suite injects a recording mailer or a Resend transport over a mocked fetch.
	 */
	mailer?: Mailer;
}

type DeliveryOutcome = "email" | "manual" | "email_failed";

/**
 * Try to deliver a freshly minted link by email. Runs only after the atomic
 * RPC confirmed a live invitation, so a revoked, consumed or expired
 * invitation never produces mail. Never throws and never logs the link.
 */
async function deliverInvitation(
	mailer: Mailer,
	input: Parameters<typeof invitationEmail>[0],
): Promise<DeliveryOutcome> {
	if (mailer.provider === "none") return "manual";
	try {
		const result = await mailer.send(invitationEmail(input));
		if (result.ok) return "email";
		if (result.reason === "not_configured") return "manual";
		console.error("[team-invite] invitation email not delivered", JSON.stringify({ reason: result.reason }));
		return "email_failed";
	} catch {
		console.error("[team-invite] invitation email not delivered", JSON.stringify({ reason: "exception" }));
		return "email_failed";
	}
}

/**
 * Delivery projection. `delivery: "email"` is reported only after the provider
 * accepted the message, and then the link is NOT returned: the recipient's
 * mailbox is the only place it exists. Otherwise the operator gets the link to
 * share manually, and a failed attempt is reported as such.
 */
function deliveryFields(outcome: DeliveryOutcome, inviteUrl: string): Record<string, unknown> {
	if (outcome === "email") return { delivery: "email" };
	return outcome === "email_failed"
		? { delivery: "manual", invite_url: inviteUrl, email_delivery: "failed" }
		: { delivery: "manual", invite_url: inviteUrl };
}

// The runtime entry point is declared above the factory on purpose: the
// repository's `config-contract` gate anchors a function's request path at the
// first `Deno.serve(` occurrence in the file and requires the configuration
// guard, the CORS preflight and every database call to appear after it.
Deno.serve(createTeamInviteHandler());

/** Build the request handler. Exported so the contract suite can drive it. */
export function createTeamInviteHandler(deps: TeamInviteDeps = {}) {
	return async (req: Request) => handleTeamInvite(req, deps);
}

async function handleTeamInvite(req: Request, deps: TeamInviteDeps): Promise<Response> {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("team-invite", config.error, (status, body) => corsJson(req, status, body));
	try {
		const db = deps.db ?? createClient<TeamInviteDatabase>(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const { data: auth, error } = await db.auth.getUser(token);
		if (error || !auth.user) return corsJson(req, 401, { error: "invalid_access_token" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const command = parseInvitationCommand(parsed.value);
		if (!command) return corsJson(req, 400, { error: "invalid_invitation" });
		const identity = await checkIdentityBarrier(db, token, auth.user.id, command.teamId);
		if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
		const { data: member, error: memberError } = await db.from("tenant_members").select("role,expires_at").eq("tenant_id", command.teamId).eq("user_id", auth.user.id).maybeSingle();
		if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (!membershipActive(member) || !["owner", "admin"].includes(member?.role ?? "")) return corsJson(req, 403, { error: "team_forbidden" });
		const { data: tenant, error: tenantError } = await db.from("tenants").select("status,name").eq("id", command.teamId).maybeSingle();
		if (tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (tenant?.status !== "active") return corsJson(req, 403, { error: "tenant_inactive" });
		if (command.action === "list") {
			const { data, error: listError } = await db.from("team_invitations")
				.select("id,email,role,expires_at,created_at,created_by")
				.eq("tenant_id", command.teamId).is("accepted_at", null)
				.gt("expires_at", new Date().toISOString())
				.order("created_at", { ascending: false }).limit(100);
			if (listError) return corsJson(req, 503, { error: "invitation_list_failed" });
			return corsJson(req, 200, { ok: true, invitations: data ?? [] }, { "Cache-Control": "no-store" });
		}
		if (command.action === "revoke") {
			const { data, error: revokeError } = await revokePendingInvitation(db, command.teamId, command.invitationId, auth.user.id);
			if (revokeError?.code === "42501") return corsJson(req, 403, { error: "team_forbidden" });
			if (revokeError) return corsJson(req, 503, { error: "invitation_revoke_failed" });
			if (!data) return corsJson(req, 404, { error: "invitation_not_pending" });
			if (typeof data.id !== "string" || data.id !== command.invitationId) return corsJson(req, 503, { error: "invitation_revoke_failed" });
			return corsJson(req, 200, { ok: true, invitation_id: data.id });
		}

		const minute = Math.floor(Date.now() / 60000);
		const limitKey = `team-invite:${auth.user.id}`;
		const { error: limitError } = await db.rpc("increment_rate_limit", { p_key: limitKey, p_window_start: minute, p_delta: 1 });
		const { data: count, error: countError } = await db.from("rate_limits").select("count").eq("key", limitKey).eq("window_start", minute).maybeSingle();
		if (limitError || countError || !count) return corsJson(req, 503, { error: "rate_limit_unavailable" });
		if (count.count > 10) return corsJson(req, 429, { error: "rate_limited" });
		const secret = invitationSecret();
		const inviteUrl = invitationUrl(config.values.AIDR_DASHBOARD_URL, secret);
		const tokenHash = await sha256(secret);
		if (command.action === "resend") {
			const { data, error: resendError } = await resendPendingInvitation(db, command.teamId, command.invitationId, tokenHash, auth.user.id);
			// `token_hash` is unique: a rotation that collides with a stored
			// invitation is a caller-visible conflict, not a server outage.
			if (resendError?.code === "23505") return corsJson(req, 409, { error: "invitation_conflict" });
			if (resendError?.code === "42501") return corsJson(req, 403, { error: "team_forbidden" });
			if (resendError) return corsJson(req, 503, { error: "invitation_resend_failed" });
			if (!data) return corsJson(req, 404, { error: "invitation_not_pending" });
			if (data.id !== command.invitationId || typeof data.email !== "string" || typeof data.role !== "string" || typeof data.expires_at !== "string") return corsJson(req, 503, { error: "invitation_resend_failed" });
			const outcome = await deliverInvitation(deps.mailer ?? createMailer(runtimeEnv), {
				to: data.email, workspaceName: tenant.name, role: data.role, inviteUrl,
				expiresAt: data.expires_at, invitationId: data.id, tokenHash,
			});
			return corsJson(req, 200, { ok: true, ...deliveryFields(outcome, inviteUrl), invitation_id: data.id, email: data.email, role: data.role, expires_at: data.expires_at }, { "Cache-Control": "no-store" });
		}
		if (command.action !== "create") return corsJson(req, 400, { error: "invalid_invitation" });
		// A repeated create must not rotate a previously returned link. The
		// operator must explicitly choose resend to invalidate the old link.
		//
		// The read is deliberately scoped to the recipient and NOT to the role.
		// Scoping it by role would treat "same recipient, different role" as a
		// brand-new invitation and leave the recipient holding two live links
		// with two different grants. The newest live row decides whether the
		// conflict is a role change.
		const { data: pending, error: pendingError } = await db.from("team_invitations")
			.select("id,role")
			.eq("tenant_id", command.teamId)
			.eq("email", command.email)
			.is("accepted_at", null)
			.gt("expires_at", new Date().toISOString())
			.order("created_at", { ascending: false })
			.limit(1)
			.maybeSingle();
		if (pendingError) return corsJson(req, 503, { error: "invitation_create_failed" });
		if (pending) {
			// A pending invitation already grants this recipient a role. Minting
			// a second one for a different role would silently widen or narrow
			// that grant, and rewriting the existing row's role would decide the
			// operator's intent for them. Refuse instead: changing a pending
			// invitation's role requires revoking it first, which is an explicit
			// operator action.
			if (pending.role !== command.role) return corsJson(req, 409, { error: "invitation_role_conflict" });
			return corsJson(req, 409, { error: "invitation_conflict" });
		}
		const { data, error: insertError } = await createPendingInvitation(db, command.teamId, command.email, command.role, tokenHash, auth.user.id);
		if (insertError?.code === "23505") {
			// A concurrent request can win the recipient slot after the read above.
			// Never rotate its token: the winning response already gave out that link.
			const { data: raced, error: racedError } = await db.from("team_invitations")
				.select("id,role")
				.eq("tenant_id", command.teamId)
				.eq("email", command.email)
				.is("accepted_at", null)
				.gt("expires_at", new Date().toISOString())
				.order("created_at", { ascending: false })
				.limit(1)
				.maybeSingle();
			if (racedError) return corsJson(req, 503, { error: "invitation_create_failed" });
			if (!raced) return corsJson(req, 409, { error: "invitation_conflict" });
			if (raced.role !== command.role) return corsJson(req, 409, { error: "invitation_role_conflict" });
			return corsJson(req, 409, { error: "invitation_conflict" });
		}
		if (insertError?.code === "42501") return corsJson(req, 403, { error: "team_forbidden" });
		if (insertError || typeof data?.id !== "string" || typeof data.expires_at !== "string") return corsJson(req, 503, { error: "invitation_create_failed" });
		const outcome = await deliverInvitation(deps.mailer ?? createMailer(runtimeEnv), {
			to: command.email, workspaceName: tenant.name, role: command.role, inviteUrl,
			expiresAt: data.expires_at, invitationId: data.id, tokenHash,
		});
		return corsJson(req, 200, { ok: true, ...deliveryFields(outcome, inviteUrl), invitation_id: data.id, expires_at: data.expires_at }, { "Cache-Control": "no-store" });
	} catch { return corsJson(req, 503, { error: "invitation_unavailable" }); }
}
