/**
 * Regressions for the team dashboard's fail-closed behaviour.
 *
 * `TeamDashboard.getUsageStats` used to ignore its team argument and return
 * hardcoded zeros, and `TeamDashboard.inviteMember` used to ignore the team,
 * address and role, write nothing, and still hand back an invite URL on a domain
 * that serves nothing. Both are false clean results on a security surface, so
 * these tests assert that an unconfigured dashboard refuses the call instead of
 * inventing an answer, and that a misbehaving host cannot make it report
 * nonsense such as `NaN` or a non-HTTP invite URL.
 */
import { describe, expect, it, vi } from "vitest";
import {
	type SecurityEvent,
	type Team,
	type TeamDatabase,
	TeamCapabilityUnavailableError,
	TeamDashboard,
	type TeamUsageStats,
} from "../team-dashboard.js";

function team(overrides: Partial<Team> = {}): Team {
	return {
		id: "team-1",
		name: "Team One",
		ownerId: "user-1",
		plan: "pro",
		seats: { total: 10, used: 2 },
		billing: { subscriptionId: "sub-1", nextBillingDate: new Date("2026-10-01T00:00:00.000Z") },
		settings: { ssoEnabled: false, requireApproval: true },
		createdAt: new Date("2026-01-01T00:00:00.000Z"),
		...overrides,
	};
}

function event(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
	return {
		id: "event-1",
		teamId: "team-1",
		agentId: "agent-1",
		userId: "user-1",
		timestamp: new Date("2026-09-01T00:00:00.000Z"),
		eventType: "threat_blocked",
		severity: "high",
		details: { threatId: "AIDR-T-001", tool: "Bash" },
		...overrides,
	};
}

function database(overrides: Partial<TeamDatabase> = {}): TeamDatabase {
	return {
		getTeam: vi.fn(async () => team()),
		saveTeam: vi.fn(async () => {}),
		getMembers: vi.fn(async () => []),
		addMember: vi.fn(async () => {}),
		removeMember: vi.fn(async () => {}),
		getSecurityEvents: vi.fn(async () => [event()]),
		logSecurityEvent: vi.fn(async () => {}),
		...overrides,
	};
}

describe("TeamDashboard.getUsageStats", () => {
	it("refuses to report usage when no usage source is configured", async () => {
		// The defect: this call used to resolve with zeroed counters for any team.
		const dashboard = new TeamDashboard(database());
		await expect(dashboard.getUsageStats("team-1")).rejects.toBeInstanceOf(TeamCapabilityUnavailableError);
		await expect(dashboard.getUsageStats("team-1")).rejects.toMatchObject({ capability: "getUsageStats" });
	});

	it("never resolves with fabricated zeros when the source is absent", async () => {
		const dashboard = new TeamDashboard(database());
		const settled = await dashboard.getUsageStats("team-1").then(
			(value) => ({ ok: true as const, value }),
			(error: unknown) => ({ ok: false as const, error }),
		);
		expect(settled.ok).toBe(false);
	});

	it("passes the team and a bounded window to the configured source", async () => {
		const getUsageStats = vi.fn(
			async (_teamId: string, _window: { from: Date; to: Date }): Promise<TeamUsageStats> => ({
				checksToday: 4,
				checksThisMonth: 90,
				threatsBlocked: 2,
				activeAgents: 1,
				topThreats: [{ threatId: "AIDR-T-001", count: 2 }],
			}),
		);
		const dashboard = new TeamDashboard(database(), { getUsageStats });
		const to = new Date("2026-09-30T00:00:00.000Z");
		const from = new Date("2026-09-01T00:00:00.000Z");

		const stats = await dashboard.getUsageStats("team-9", { from, to });

		expect(getUsageStats).toHaveBeenCalledTimes(1);
		expect(getUsageStats.mock.calls[0]?.[0]).toBe("team-9");
		expect(getUsageStats.mock.calls[0]?.[1]).toEqual({ from, to });
		expect(stats).toEqual({
			checksToday: 4,
			checksThisMonth: 90,
			threatsBlocked: 2,
			activeAgents: 1,
			topThreats: [{ threatId: "AIDR-T-001", count: 2 }],
		});
	});

	it("keeps an explicitly unmeasured count as null instead of turning it into zero", async () => {
		// `null` means "the host cannot measure this"; 0 would mean "measured, and
		// nothing happened". Only the latter is a clean result.
		const dashboard = new TeamDashboard(database(), {
			getUsageStats: async () => ({ checksToday: null, checksThisMonth: null, threatsBlocked: 0, activeAgents: 0, topThreats: [] }),
		});

		await expect(dashboard.getUsageStats("team-1")).resolves.toEqual({
			checksToday: null,
			checksThisMonth: null,
			threatsBlocked: 0,
			activeAgents: 0,
			topThreats: [],
		});
	});

	it("rejects counts a dashboard could not render honestly", async () => {
		for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, "7" as unknown as number, undefined as unknown as number]) {
			const dashboard = new TeamDashboard(database(), {
				getUsageStats: async () => ({ checksToday: bad, checksThisMonth: 1, threatsBlocked: 0, activeAgents: 0, topThreats: [] }),
			});
			await expect(dashboard.getUsageStats("team-1")).rejects.toBeInstanceOf(TypeError);
		}
	});

	it("rejects a source that returns no figures at all", async () => {
		const dashboard = new TeamDashboard(database(), {
			getUsageStats: async () => null as unknown as TeamUsageStats,
		});
		await expect(dashboard.getUsageStats("team-1")).rejects.toBeInstanceOf(TypeError);
	});

	it("does not query the security-event log to invent a usage figure", async () => {
		// The event log records threats, not tool volume. Reading it here would
		// produce a number that looks measured but is not.
		const db = database();
		const dashboard = new TeamDashboard(db);
		await expect(dashboard.getUsageStats("team-1")).rejects.toBeInstanceOf(TeamCapabilityUnavailableError);
		expect(db.getSecurityEvents).not.toHaveBeenCalled();
	});
});

describe("TeamDashboard.inviteMember", () => {
	it("refuses to invent an invitation when no invite capability is configured", async () => {
		const dashboard = new TeamDashboard(database());
		await expect(dashboard.inviteMember("team-1", "person@example.com", "member")).rejects.toBeInstanceOf(
			TeamCapabilityUnavailableError,
		);
		await expect(dashboard.inviteMember("team-1", "person@example.com", "member")).rejects.toMatchObject({
			capability: "createInvite",
		});
	});

	it("never resolves with a URL on the undeployed default domain", async () => {
		const dashboard = new TeamDashboard(database());
		const settled = await dashboard.inviteMember("team-1", "person@example.com", "member").then(
			(value) => ({ ok: true as const, value }),
			() => ({ ok: false as const }),
		);
		expect(settled.ok).toBe(false);
	});

	it("forwards the team, address and role to the configured capability", async () => {
		const createInvite = vi.fn(async () => ({ inviteId: "invite-1", inviteUrl: "https://control.example.com/invite/invite-1" }));
		const dashboard = new TeamDashboard(database(), { createInvite });

		const invite = await dashboard.inviteMember("team-1", "person@example.com", "admin");

		expect(createInvite).toHaveBeenCalledWith({ teamId: "team-1", email: "person@example.com", role: "admin" });
		expect(invite).toEqual({ inviteId: "invite-1", inviteUrl: "https://control.example.com/invite/invite-1" });
	});

	it("rejects an invitation with no identifier", async () => {
		const dashboard = new TeamDashboard(database(), {
			createInvite: async () => ({ inviteId: "  ", inviteUrl: "https://control.example.com/invite/x" }),
		});
		await expect(dashboard.inviteMember("team-1", "person@example.com", "member")).rejects.toBeInstanceOf(TypeError);
	});

	it("rejects an invite URL that is not absolute HTTP", async () => {
		for (const inviteUrl of ["/invite/1", "not a url", "mailto:person@example.com", ""]) {
			const dashboard = new TeamDashboard(database(), { createInvite: async () => ({ inviteId: "invite-1", inviteUrl }) });
			await expect(dashboard.inviteMember("team-1", "person@example.com", "member")).rejects.toBeInstanceOf(TypeError);
		}
	});
});

describe("TeamDashboard unchanged calls", () => {
	it("still reads the team and its members from the database", async () => {
		const db = database();
		const dashboard = new TeamDashboard(db);
		await expect(dashboard.getTeam("team-1")).resolves.toMatchObject({ id: "team-1" });
		await expect(dashboard.getMembers("team-1")).resolves.toEqual([]);
		await expect(dashboard.getSecurityEvents("team-1", { severity: "high" })).resolves.toHaveLength(1);
	});

	it("still refuses to update settings for an unknown team", async () => {
		const dashboard = new TeamDashboard(database({ getTeam: vi.fn(async () => null) }));
		await expect(dashboard.updateSettings("missing", { ssoEnabled: true })).rejects.toThrow(/Team not found/);
	});
});
