export interface Team {
	id: string;
	name: string;
	ownerId: string;
	plan: "free" | "pro" | "enterprise";
	seats: {
		total: number;
		used: number;
	};
	billing: {
		subscriptionId: string;
		nextBillingDate: Date;
		paymentMethod?: string;
	};
	settings: {
		ssoEnabled: boolean;
		ssoProvider?: "okta" | "google" | "github";
		requireApproval: boolean;
	};
	createdAt: Date;
}

export interface TeamMember {
	id: string;
	userId: string;
	teamId: string;
	role: "owner" | "admin" | "member";
	seatNumber: number;
	joinedAt: Date;
	lastActiveAt?: Date;
}

export interface SecurityEvent {
	id: string;
	teamId: string;
	agentId: string;
	userId: string;
	timestamp: Date;
	eventType: "threat_blocked" | "suspicious_activity" | "policy_violation";
	severity: "low" | "medium" | "high" | "critical";
	details: {
		threatId?: string;
		tool?: string;
		input?: string;
		action?: string;
	};
}

/**
 * Usage figures for one team over one window.
 *
 * `checksToday` and `checksThisMonth` are nullable on purpose. A team's tool
 * volume is not derivable from its security-event log, and reporting an
 * unmeasured volume as `0` is indistinguishable from a genuinely quiet team -
 * which is exactly the false clean result an operations dashboard must never
 * show. A host that cannot measure check volume returns `null` and the UI is
 * expected to render "not measured" rather than a number.
 */
export interface TeamUsageStats {
	checksToday: number | null;
	checksThisMonth: number | null;
	threatsBlocked: number;
	activeAgents: number;
	topThreats: { threatId: string; count: number }[];
}

/**
 * Raised when a call needs host-supplied data that the embedder has not
 * configured.
 *
 * This is a deliberate, visible failure. `TeamDashboard` previously answered
 * both of these calls with invented values - zeroed usage counters for every
 * team, and an invite URL on a domain that serves nothing - while persisting no
 * invitation at all. An absent data source is now an error the caller can catch
 * and surface, instead of a plausible-looking number.
 */
export class TeamCapabilityUnavailableError extends Error {
	readonly capability: string;

	constructor(capability: string, message: string) {
		super(message);
		this.name = "TeamCapabilityUnavailableError";
		this.capability = capability;
	}
}

/**
 * Host-supplied data sources the embedder must provide for the calls that
 * cannot be answered from `TeamDatabase` alone.
 */
export interface TeamDashboardCapabilities {
	/**
	 * Resolves usage for a team over a window. Required by `getUsageStats`.
	 * Return `null` for a figure the host cannot measure; never `0`.
	 */
	getUsageStats?: (teamId: string, window: { from: Date; to: Date }) => Promise<TeamUsageStats>;
	/**
	 * Creates and persists an invitation, returning the identifier the host
	 * stored it under and the absolute URL the invitee should open. Required by
	 * `inviteMember`.
	 */
	createInvite?: (input: {
		teamId: string;
		email: string;
		role: "admin" | "member";
	}) => Promise<{ inviteId: string; inviteUrl: string }>;
}

/** Rejects a provider figure that would be rendered as `NaN`, `-1` or `undefined`. */
function reportableCount(value: number | null, field: string): number | null {
	if (value === null) return null;
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
		throw new TypeError(`getUsageStats: the usage source returned ${field}=${String(value)}; a count must be a finite non-negative number or null`);
	}
	return value;
}

export class TeamDashboard {
	constructor(
		private db: TeamDatabase,
		private capabilities: TeamDashboardCapabilities = {},
	) {}

	async getTeam(teamId: string): Promise<Team | null> {
		return this.db.getTeam(teamId);
	}

	async getMembers(teamId: string): Promise<TeamMember[]> {
		return this.db.getMembers(teamId);
	}

	async inviteMember(
		teamId: string,
		email: string,
		role: "admin" | "member",
	): Promise<{ inviteId: string; inviteUrl: string }> {
		const createInvite = this.capabilities.createInvite;
		if (!createInvite) {
			throw new TeamCapabilityUnavailableError(
				"createInvite",
				"inviteMember needs a host-supplied createInvite capability so the invitation is actually persisted and its URL comes from a deployed service; none is configured, so no invitation was created.",
			);
		}

		const invite = await createInvite({ teamId, email, role });
		if (typeof invite?.inviteId !== "string" || invite.inviteId.trim() === "") {
			throw new TypeError("inviteMember: the invite capability did not return an inviteId, so the invitation cannot be referenced");
		}
		let parsed: URL;
		try {
			parsed = new URL(String(invite.inviteUrl));
		} catch {
			throw new TypeError(`inviteMember: the invite capability returned an unusable inviteUrl (${String(invite.inviteUrl)})`);
		}
		if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
			throw new TypeError(`inviteMember: the invite capability returned a non-HTTP inviteUrl (${parsed.protocol})`);
		}
		return { inviteId: invite.inviteId, inviteUrl: parsed.toString() };
	}

	async removeMember(teamId: string, userId: string): Promise<void> {
		await this.db.removeMember(teamId, userId);
	}

	async getSecurityEvents(
		teamId: string,
		filters: {
			from?: Date;
			to?: Date;
			severity?: string;
			agentId?: string;
		},
	): Promise<SecurityEvent[]> {
		const events = await this.db.getSecurityEvents({ teamId, ...filters });
		return events;
	}

	async getUsageStats(teamId: string, window?: { from?: Date; to?: Date }): Promise<TeamUsageStats> {
		const getUsageStats = this.capabilities.getUsageStats;
		if (!getUsageStats) {
			throw new TeamCapabilityUnavailableError(
				"getUsageStats",
				"getUsageStats needs a host-supplied getUsageStats capability: the security-event log cannot answer tool volume, and reporting an unmeasured team as zero would look like a clean tenant; none is configured, so no usage was reported.",
			);
		}

		const to = window?.to ?? new Date();
		const from = window?.from ?? new Date(to.getTime() - 30 * 24 * 60 * 60 * 1000);
		const stats = await getUsageStats(teamId, { from, to });
		if (stats === null || typeof stats !== "object") {
			throw new TypeError("getUsageStats: the usage source returned no figures");
		}
		if (!Array.isArray(stats.topThreats)) {
			throw new TypeError("getUsageStats: the usage source returned topThreats that is not an array");
		}
		return {
			checksToday: reportableCount(stats.checksToday, "checksToday"),
			checksThisMonth: reportableCount(stats.checksThisMonth, "checksThisMonth"),
			threatsBlocked: reportableCount(stats.threatsBlocked, "threatsBlocked") ?? 0,
			activeAgents: reportableCount(stats.activeAgents, "activeAgents") ?? 0,
			topThreats: stats.topThreats,
		};
	}

	async updateSettings(teamId: string, settings: Partial<Team["settings"]>): Promise<void> {
		const team = await this.db.getTeam(teamId);
		if (!team) {
			throw new Error(`Team not found: ${teamId}`);
		}

		const updatedTeam: Team = {
			...team,
			settings: {
				...team.settings,
				...settings,
			},
		};

		await this.db.saveTeam(updatedTeam);
	}
}

export interface TeamDatabase {
	getTeam(id: string): Promise<Team | null>;
	saveTeam(team: Team): Promise<void>;
	getMembers(teamId: string): Promise<TeamMember[]>;
	addMember(member: TeamMember): Promise<void>;
	removeMember(teamId: string, userId: string): Promise<void>;
	getSecurityEvents(filters: {
		teamId: string;
		from?: Date;
		to?: Date;
		severity?: string;
		agentId?: string;
	}): Promise<SecurityEvent[]>;
	logSecurityEvent(event: SecurityEvent): Promise<void>;
}
