import { describe, expect, it, vi } from "vitest";
import {
	createPendingInvitation,
	invitationSecret,
	invitationUrl,
	parseInvitationCommand,
	resendPendingInvitation,
	revokePendingInvitation,
} from "../lifecycle.ts";

const TEAM = "11111111-1111-4111-8111-111111111111";
const INVITE = "33333333-3333-4333-8333-333333333333";
const ACTOR = "44444444-4444-4444-8444-444444444444";

function invitationDatabase(data: Record<string, unknown> | null = { id: INVITE }) {
	const rpc = vi.fn(async () => ({ data, error: null }));
	const db = { rpc } as unknown as Parameters<typeof createPendingInvitation>[0];
	return { db, rpc };
}

describe("team invitation lifecycle", () => {
	it("accepts only a valid team, recipient and role for creation", () => {
		expect(parseInvitationCommand({ team_id: TEAM, email: "Mixed@Example.COM", role: "viewer" }))
			.toEqual({ action: "create", teamId: TEAM, email: "mixed@example.com", role: "viewer" });
		// The read-only auditor role is invitable; owner and unknown roles are not.
		expect(parseInvitationCommand({ team_id: TEAM, email: "audit@example.com", role: "auditor" }))
			.toEqual({ action: "create", teamId: TEAM, email: "audit@example.com", role: "auditor" });
		expect(parseInvitationCommand({ team_id: TEAM, email: "audit@example.com", role: "superuser" })).toBeNull();
		for (const body of [
			{ team_id: "1".repeat(36), email: "member@example.com", role: "member" },
			{ team_id: TEAM, email: "member@example.com", role: "owner" },
			{ team_id: TEAM, email: "member@example.com", role: "member", action: "delete" },
			{ team_id: TEAM, action: "revoke", invitation_id: "bad" },
		]) expect(parseInvitationCommand(body)).toBeNull();
		expect(parseInvitationCommand({ team_id: TEAM, action: "resend", invitation_id: INVITE }))
			.toEqual({ action: "resend", teamId: TEAM, invitationId: INVITE });
	});

	it("creates fresh opaque links", () => {
		const first = invitationSecret();
		const second = invitationSecret();
		expect(first).toMatch(/^[a-f0-9]{64}$/);
		expect(second).not.toBe(first);
		expect(invitationUrl("https://dashboard.example/path", first))
			.toBe(`https://dashboard.example/enterprise?invite=${first}`);
	});

	it("sends create, resend, and revoke through the atomic mutation RPC", async () => {
		const fake = invitationDatabase();
		await createPendingInvitation(fake.db, TEAM, "member@example.com", "member", "new-hash", ACTOR);
		await resendPendingInvitation(fake.db, TEAM, INVITE, "replacement-hash", ACTOR);
		await revokePendingInvitation(fake.db, TEAM, INVITE, ACTOR);
		expect(fake.rpc.mock.calls).toEqual([
			["mutate_team_invitation", {
				p_action: "create", p_tenant_id: TEAM, p_actor_user_id: ACTOR,
				p_email: "member@example.com", p_role: "member", p_invitation_id: null,
				p_token_hash: "new-hash",
			}],
			["mutate_team_invitation", {
				p_action: "resend", p_tenant_id: TEAM, p_actor_user_id: ACTOR,
				p_email: null, p_role: null, p_invitation_id: INVITE,
				p_token_hash: "replacement-hash",
			}],
			["mutate_team_invitation", {
				p_action: "revoke", p_tenant_id: TEAM, p_actor_user_id: ACTOR,
				p_email: null, p_role: null, p_invitation_id: INVITE,
				p_token_hash: null,
			}],
		]);
	});

	it("passes through a non-pending result without claiming a mutation", async () => {
		const fake = invitationDatabase(null);
		expect((await resendPendingInvitation(fake.db, TEAM, INVITE, "new-hash", ACTOR)).data).toBeNull();
		expect((await revokePendingInvitation(fake.db, TEAM, INVITE, ACTOR)).data).toBeNull();
	});
});
