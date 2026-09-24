import type { SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export type InvitationCommand =
	| { action: "create"; teamId: string; email: string; role: "admin" | "member" | "viewer" }
	| { action: "list"; teamId: string }
	| { action: "revoke" | "resend"; teamId: string; invitationId: string };

export function parseInvitationCommand(value: unknown): InvitationCommand | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const body = value as Record<string, unknown>;
	if (typeof body.team_id !== "string" || !UUID.test(body.team_id)) return null;
	const action = body.action ?? "create";
	if (action === "list") return { action, teamId: body.team_id };
	if (action === "revoke" || action === "resend") {
		return typeof body.invitation_id === "string" && UUID.test(body.invitation_id)
			? { action, teamId: body.team_id, invitationId: body.invitation_id }
			: null;
	}
	if (action !== "create" || typeof body.email !== "string" || body.email.length > 254 || !EMAIL.test(body.email)) return null;
	if (body.role !== "admin" && body.role !== "member" && body.role !== "viewer") return null;
	return { action, teamId: body.team_id, email: body.email.toLowerCase(), role: body.role };
}

export function invitationSecret(): string {
	return Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function invitationUrl(dashboardUrl: string, secret: string): string {
	const url = new URL("/enterprise", dashboardUrl);
	url.searchParams.set("invite", secret);
	return url.toString();
}

/** Each RPC writes the invitation and privileged audit row in one DB transaction. */
export function createPendingInvitation(db: Pick<SupabaseClient, "rpc">, teamId: string, email: string, role: "admin" | "member" | "viewer", tokenHash: string, actorId: string) {
	return db.rpc("mutate_team_invitation", {
		p_action: "create", p_tenant_id: teamId, p_actor_user_id: actorId,
		p_email: email, p_role: role, p_invitation_id: null, p_token_hash: tokenHash,
	});
}

export function revokePendingInvitation(db: Pick<SupabaseClient, "rpc">, teamId: string, invitationId: string, actorId: string) {
	return db.rpc("mutate_team_invitation", {
		p_action: "revoke", p_tenant_id: teamId, p_actor_user_id: actorId,
		p_email: null, p_role: null, p_invitation_id: invitationId, p_token_hash: null,
	});
}

export function resendPendingInvitation(db: Pick<SupabaseClient, "rpc">, teamId: string, invitationId: string, tokenHash: string, actorId: string) {
	return db.rpc("mutate_team_invitation", {
		p_action: "resend", p_tenant_id: teamId, p_actor_user_id: actorId,
		p_email: null, p_role: null, p_invitation_id: invitationId, p_token_hash: tokenHash,
	});
}
