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

export class TeamDashboard {
	constructor(private db: TeamDatabase) {}

	async getTeam(teamId: string): Promise<Team | null> {
		return this.db.getTeam(teamId);
	}

	async getMembers(teamId: string): Promise<TeamMember[]> {
		return this.db.getMembers(teamId);
	}

	async inviteMember(
		_teamId: string,
		_email: string,
		_role: "admin" | "member",
	): Promise<{ inviteId: string; inviteUrl: string }> {
		// Generate unique invite ID
		const inviteId = crypto.randomUUID();
		// Create invite URL (base URL would typically come from config)
		const inviteUrl = `https://aidr.singularityrd.com/invite/${inviteId}`;

		// TODO: Send invite email via email service
		// This would integrate with an email provider like SendGrid, Resend, etc.

		return { inviteId, inviteUrl };
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

	async getUsageStats(_teamId: string): Promise<{
		checksToday: number;
		checksThisMonth: number;
		threatsBlocked: number;
		activeAgents: number;
		topThreats: { threatId: string; count: number }[];
	}> {
		// TODO: Implement actual aggregation from database
		// This would query usage metrics, aggregate by time periods, etc.
		return {
			checksToday: 0,
			checksThisMonth: 0,
			threatsBlocked: 0,
			activeAgents: 0,
			topThreats: [],
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
