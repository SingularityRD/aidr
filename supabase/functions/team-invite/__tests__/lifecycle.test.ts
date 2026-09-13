import { describe, expect, it } from "vitest";
import {
	invitationExpiry,
	invitationSecret,
	invitationUrl,
	parseInvitationCommand,
	resendPendingInvitation,
	revokePendingInvitation,
} from "../lifecycle.ts";

const TEAM = "11111111-1111-4111-8111-111111111111";
const OTHER_TEAM = "22222222-2222-4222-8222-222222222222";
const INVITE = "33333333-3333-4333-8333-333333333333";
const ACTOR = "44444444-4444-4444-8444-444444444444";
const NOW = new Date("2030-01-01T00:00:00.000Z");

type Invitation = {
	id: string;
	tenant_id: string;
	accepted_at: string | null;
	expires_at: string;
	token_hash: string;
	created_by: string;
	email: string;
	role: string;
};

function invitationDatabase(overrides: Partial<Invitation> = {}) {
	const row: Invitation = {
		id: INVITE, tenant_id: TEAM, accepted_at: null,
		expires_at: "2030-01-02T00:00:00.000Z", token_hash: "old-hash",
		created_by: "previous-admin", email: "member@example.com", role: "member",
		...overrides,
	};
	const filters: Array<(candidate: Invitation) => boolean> = [];
	let change: Partial<Invitation> = {};
	const query = {
		update(value: Partial<Invitation>) { change = value; return query; },
		eq(column: keyof Invitation, value: string) { filters.push((candidate) => candidate[column] === value); return query; },
		is(column: keyof Invitation, value: null) { filters.push((candidate) => candidate[column] === value); return query; },
		gt(column: keyof Invitation, value: string) { filters.push((candidate) => String(candidate[column]) > value); return query; },
		select(_columns: string) { return query; },
		async maybeSingle() {
			if (!filters.every((filter) => filter(row))) return { data: null, error: null };
			Object.assign(row, change);
			return { data: { ...row }, error: null };
		},
	};
	const db = { from(table: string) { expect(table).toBe("team_invitations"); return query; } };
	return { db: db as unknown as Parameters<typeof revokePendingInvitation>[0], row };
}

describe("team invitation lifecycle", () => {
	it("accepts only a valid team, recipient and role for creation", () => {
		expect(parseInvitationCommand({ team_id: TEAM, email: "Mixed@Example.COM", role: "viewer" }))
			.toEqual({ action: "create", teamId: TEAM, email: "mixed@example.com", role: "viewer" });
		for (const body of [
			{ team_id: "1".repeat(36), email: "member@example.com", role: "member" },
			{ team_id: TEAM, email: "member@example.com", role: "owner" },
			{ team_id: TEAM, email: "member@example.com", role: "member", action: "delete" },
			{ team_id: TEAM, action: "revoke", invitation_id: "bad" },
		]) expect(parseInvitationCommand(body)).toBeNull();
		expect(parseInvitationCommand({ team_id: TEAM, action: "resend", invitation_id: INVITE }))
			.toEqual({ action: "resend", teamId: TEAM, invitationId: INVITE });
	});

	it("creates fresh opaque links with seven-day expiry", () => {
		const first = invitationSecret();
		const second = invitationSecret();
		expect(first).toMatch(/^[a-f0-9]{64}$/);
		expect(second).not.toBe(first);
		expect(invitationExpiry(NOW)).toBe("2030-01-08T00:00:00.000Z");
		expect(invitationUrl("https://dashboard.example/path", first))
			.toBe(`https://dashboard.example/enterprise?invite=${first}`);
	});

	it("revokes only an unaccepted, unexpired invitation in the selected team", async () => {
		const valid = invitationDatabase();
		expect((await revokePendingInvitation(valid.db, TEAM, INVITE, NOW.toISOString())).data?.id).toBe(INVITE);
		expect(valid.row.expires_at).toBe(NOW.toISOString());
		for (const overrides of [
			{ tenant_id: OTHER_TEAM },
			{ accepted_at: "2029-12-31T00:00:00.000Z" },
			{ expires_at: "2029-12-31T00:00:00.000Z" },
		]) {
			const blocked = invitationDatabase(overrides);
			expect((await revokePendingInvitation(blocked.db, TEAM, INVITE, NOW.toISOString())).data).toBeNull();
			expect(blocked.row.expires_at).toBe(overrides.expires_at ?? "2030-01-02T00:00:00.000Z");
		}
	});

	it("resends by replacing the old token atomically, but never reopens accepted or other-team invitations", async () => {
		const valid = invitationDatabase({ expires_at: "2029-12-31T00:00:00.000Z" });
		expect((await resendPendingInvitation(valid.db, TEAM, INVITE, "new-hash", ACTOR, NOW)).data?.id).toBe(INVITE);
		expect(valid.row).toMatchObject({ token_hash: "new-hash", created_by: ACTOR, expires_at: "2030-01-08T00:00:00.000Z" });
		for (const overrides of [{ tenant_id: OTHER_TEAM }, { accepted_at: "2029-12-31T00:00:00.000Z" }]) {
			const blocked = invitationDatabase(overrides);
			expect((await resendPendingInvitation(blocked.db, TEAM, INVITE, "new-hash", ACTOR, NOW)).data).toBeNull();
			expect(blocked.row.token_hash).toBe("old-hash");
		}
	});
});
