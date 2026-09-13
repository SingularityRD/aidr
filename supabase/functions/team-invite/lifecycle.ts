import type { SupabaseClient } from "npm:@supabase/supabase-js@2";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const INVITATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;

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

export function invitationExpiry(now = new Date()): string {
	return new Date(now.getTime() + INVITATION_LIFETIME_MS).toISOString();
}

export function invitationUrl(dashboardUrl: string, secret: string): string {
	const url = new URL("/enterprise", dashboardUrl);
	url.searchParams.set("invite", secret);
	return url.toString();
}

/** Conditions stay on the database write so acceptance, revocation and resend races fail closed. */
export async function revokePendingInvitation(db: Pick<SupabaseClient, "from">, teamId: string, invitationId: string, now: string) {
	return db.from("team_invitations")
		.update({ expires_at: now })
		.eq("tenant_id", teamId)
		.eq("id", invitationId)
		.is("accepted_at", null)
		.gt("expires_at", now)
		.select("id")
		.maybeSingle();
}

export async function resendPendingInvitation(db: Pick<SupabaseClient, "from">, teamId: string, invitationId: string, tokenHash: string, actorId: string, now: Date) {
	return db.from("team_invitations")
		.update({ token_hash: tokenHash, expires_at: invitationExpiry(now), created_by: actorId })
		.eq("tenant_id", teamId)
		.eq("id", invitationId)
		.is("accepted_at", null)
		.select("id,email,role,expires_at")
		.maybeSingle();
}
