import { createContext, type ReactNode, useContext, useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

export type TeamRole = "admin" | "member" | "viewer";

export interface TeamMember {
	id: string;
	user_id: string;
	role: TeamRole;
	email: string;
	avatar_url?: string;
	invited_by?: string;
	joined_at: string;
}

export interface Team {
	id: string;
	name: string;
	github_org?: string;
	gitlab_group?: string;
	plan: "free" | "pro" | "enterprise";
	created_at: string;
	updated_at: string;
}

export interface TeamAuditLog {
	id: string;
	team_id: string;
	user_id: string;
	user_email?: string;
	action: string;
	verdict?: {
		tool?: string;
		input?: unknown;
		decision?: "allow" | "deny" | "ask";
		confidence?: number;
		threats?: string[];
	};
	timestamp: number;
	created_at: string;
}

interface TeamContextType {
	currentTeam: Team | null;
	teams: Team[];
	members: TeamMember[];
	auditLogs: TeamAuditLog[];
	isLoading: boolean;
	error: string | null;
	createTeam: (name: string) => Promise<void>;
	inviteMember: (email: string, role: TeamRole) => Promise<void>;
	removeMember: (userId: string) => Promise<void>;
	updateMemberRole: (userId: string, role: TeamRole) => Promise<void>;
	switchTeam: (teamId: string) => void;
	refreshAuditLogs: () => Promise<void>;
	exportAuditLogs: (format: "csv" | "json") => Promise<string>;
	canManageTeam: boolean;
	canViewAudit: boolean;
	canEditPolicy: boolean;
}

const TeamContext = createContext<TeamContextType | null>(null);

export function TeamProvider({ children }: { children: ReactNode }) {
	const [currentTeam, setCurrentTeam] = useState<Team | null>(null);
	const [teams, setTeams] = useState<Team[]>([]);
	const [members, setMembers] = useState<TeamMember[]>([]);
	const [auditLogs, setAuditLogs] = useState<TeamAuditLog[]>([]);
	const [isLoading, setIsLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [currentRole, setCurrentRole] = useState<TeamRole | null>(null);

	// Load teams on mount
	useEffect(() => {
		async function loadTeams() {
			try {
				setIsLoading(true);
				setError(null);

				// Get user's teams with their role
				const { data: memberships, error: membershipError } = await supabase
					.from("team_members")
					.select(
						"team_id, role, teams:id(name, github_org, gitlab_group, plan, created_at, updated_at)",
					)
					.order("joined_at", { ascending: false });

				if (membershipError) {
					throw membershipError;
				}

				if (memberships && memberships.length > 0) {
					const mappedTeams: Team[] = memberships.map((m: Record<string, unknown>) => ({
						id: m.team_id as string,
						name: (m.teams as Record<string, unknown>)?.name as string,
						github_org: (m.teams as Record<string, unknown>)?.github_org as string | undefined,
						gitlab_group: (m.teams as Record<string, unknown>)?.gitlab_group as string | undefined,
						plan: ((m.teams as Record<string, unknown>)?.plan as string) || "free",
						created_at: (m.teams as Record<string, unknown>)?.created_at as string,
						updated_at: (m.teams as Record<string, unknown>)?.updated_at as string,
					}));

					setTeams(mappedTeams);
					setCurrentTeam(mappedTeams[0]);
					setCurrentRole(memberships[0].role as TeamRole);
				}
			} catch (err) {
				setError(err instanceof Error ? err.message : "Failed to load teams");
			} finally {
				setIsLoading(false);
			}
		}

		void loadTeams();
	}, []);

	// Load members when team changes
	useEffect(() => {
		async function loadMembers() {
			if (!currentTeam) return;

			try {
				const { data, error } = await supabase
					.from("team_members")
					.select(
						"id, user_id, role, invited_by, joined_at, users:user_id(email, raw_user_meta_data)",
					)
					.eq("team_id", currentTeam.id);

				if (error) throw error;

				if (data) {
					const mappedMembers: TeamMember[] = data.map((m: Record<string, unknown>) => {
						const userData = m.users as Record<string, unknown> | null;
						const metaData = userData?.raw_user_meta_data as Record<string, unknown> | null;
						return {
							id: m.id as string,
							user_id: m.user_id as string,
							role: m.role as TeamRole,
							email: (userData?.email as string) || "",
							avatar_url: metaData?.avatar_url as string | undefined,
							invited_by: m.invited_by as string | undefined,
							joined_at: m.joined_at as string,
						};
					});
					setMembers(mappedMembers);
				}
			} catch (err) {
				setError(err instanceof Error ? err.message : "Failed to load members");
			}
		}

		void loadMembers();
	}, [currentTeam?.id]);

	// Load audit logs when team changes
	useEffect(() => {
		void refreshAuditLogs();
	}, [currentTeam?.id]);

	async function refreshAuditLogs() {
		if (!currentTeam) return;

		try {
			const { data, error } = await supabase
				.from("audit_logs")
				.select("*")
				.eq("team_id", currentTeam.id)
				.order("created_at", { ascending: false })
				.limit(1000);

			if (error) throw error;
			setAuditLogs(data || []);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to load audit logs");
		}
	}

	async function createTeam(name: string) {
		try {
			const {
				data: { user },
			} = await supabase.auth.getUser();
			if (!user) throw new Error("Not authenticated");

			// Create team
			const { data: team, error: teamError } = await supabase
				.from("teams")
				.insert({ name, plan: "free" })
				.select()
				.single();

			if (teamError) throw teamError;

			// Add creator as admin
			const { error: memberError } = await supabase.from("team_members").insert({
				team_id: team.id,
				user_id: user.id,
				role: "admin",
			});

			if (memberError) throw memberError;

			setTeams((prev) => [team as Team, ...prev]);
			setCurrentTeam(team as Team);
			setCurrentRole("admin");
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to create team");
			throw err;
		}
	}

	async function inviteMember(email: string, role: TeamRole) {
		if (!currentTeam) throw new Error("No team selected");

		try {
			const { data, error } = await supabase.functions.invoke("team-invite", {
				body: { team_id: currentTeam.id, email, role },
			});

			if (error) throw error;
			if (data?.error) throw new Error(data.error);
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to invite member");
			throw err;
		}
	}

	async function removeMember(userId: string) {
		if (!currentTeam) throw new Error("No team selected");

		try {
			const { error } = await supabase
				.from("team_members")
				.delete()
				.eq("team_id", currentTeam.id)
				.eq("user_id", userId);

			if (error) throw error;
			setMembers((prev) => prev.filter((m) => m.user_id !== userId));
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to remove member");
			throw err;
		}
	}

	async function updateMemberRole(userId: string, role: TeamRole) {
		if (!currentTeam) throw new Error("No team selected");

		try {
			const { error } = await supabase
				.from("team_members")
				.update({ role })
				.eq("team_id", currentTeam.id)
				.eq("user_id", userId);

			if (error) throw error;
			setMembers((prev) => prev.map((m) => (m.user_id === userId ? { ...m, role } : m)));
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to update role");
			throw err;
		}
	}

	function switchTeam(teamId: string) {
		const team = teams.find((t) => t.id === teamId);
		if (team) {
			setCurrentTeam(team);
			// Update current role
			supabase
				.from("team_members")
				.select("role")
				.eq("team_id", teamId)
				.single()
				.then(({ data }) => {
					if (data) setCurrentRole(data.role as TeamRole);
				});
		}
	}

	async function exportAuditLogs(format: "csv" | "json"): Promise<string> {
		if (!currentTeam) throw new Error("No team selected");

		try {
			const { data, error } = await supabase.functions.invoke("audit-export", {
				body: { team_id: currentTeam.id, format },
			});

			if (error) throw error;
			if (data?.error) throw new Error(data.error);

			return data.url || "";
		} catch (err) {
			setError(err instanceof Error ? err.message : "Failed to export audit logs");
			throw err;
		}
	}

	const canManageTeam = currentRole === "admin";
	const canViewAudit =
		currentRole === "admin" || currentRole === "member" || currentRole === "viewer";
	const canEditPolicy = currentRole === "admin" || currentRole === "member";

	return (
		<TeamContext.Provider
			value={{
				currentTeam,
				teams,
				members,
				auditLogs,
				isLoading,
				error,
				createTeam,
				inviteMember,
				removeMember,
				updateMemberRole,
				switchTeam,
				refreshAuditLogs,
				exportAuditLogs,
				canManageTeam,
				canViewAudit,
				canEditPolicy,
			}}
		>
			{children}
		</TeamContext.Provider>
	);
}

export function useTeam() {
	const context = useContext(TeamContext);
	if (!context) {
		throw new Error("useTeam must be used within TeamProvider");
	}
	return context;
}
