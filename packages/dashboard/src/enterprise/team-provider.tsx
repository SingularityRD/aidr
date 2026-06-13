import { createContext, type ReactNode, useContext, useEffect, useState } from "react";
import type { Database } from "../lib/database.types";
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

interface MembershipWithTeam {
	team_id: string;
	role: string;
	teams: {
		id: string;
		name: string;
		github_org: string | null;
		gitlab_group: string | null;
		plan: string;
		created_at: string;
		updated_at: string;
	} | null;
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
						"team_id, role, teams!inner(id, name, github_org, gitlab_group, plan, created_at, updated_at)",
					)
					.order("joined_at", { ascending: false });

				if (membershipError) {
					throw membershipError;
				}

				const typedMemberships = memberships as MembershipWithTeam[] | null;

				if (typedMemberships && typedMemberships.length > 0) {
					const mappedTeams: Team[] = [];
					for (const m of typedMemberships) {
						if (!m.teams) continue;
						const planValue = m.teams.plan;
						const validPlan: Team["plan"] =
							planValue === "free" || planValue === "pro" || planValue === "enterprise"
								? planValue
								: "free";
						mappedTeams.push({
							id: m.teams.id,
							name: m.teams.name,
							github_org: m.teams.github_org ?? undefined,
							gitlab_group: m.teams.gitlab_group ?? undefined,
							plan: validPlan,
							created_at: m.teams.created_at,
							updated_at: m.teams.updated_at,
						});
					}

					if (mappedTeams.length > 0) {
						setTeams(mappedTeams);
						setCurrentTeam(mappedTeams[0] ?? null);
						setCurrentRole(typedMemberships[0]?.role as TeamRole);
					}
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
						"id, user_id, role, invited_by, joined_at, users!inner(email, raw_user_meta_data)",
					)
					.eq("team_id", currentTeam.id);

				if (error) throw error;

				if (data) {
					const mappedMembers: TeamMember[] = data.map((m) => {
						const mData = m as Record<string, unknown>;
						const userData = mData.users as Record<string, unknown> | null;
						const metaData = userData?.raw_user_meta_data as Record<string, unknown> | null;
						return {
							id: mData.id as string,
							user_id: mData.user_id as string,
							role: mData.role as TeamRole,
							email: (userData?.email as string) || "",
							avatar_url: metaData?.avatar_url as string | undefined,
							invited_by: mData.invited_by as string | undefined,
							joined_at: mData.joined_at as string,
						};
					});
					setMembers(mappedMembers);
				}
			} catch (err) {
				setError(err instanceof Error ? err.message : "Failed to load members");
			}
		}

		void loadMembers();
	}, [currentTeam?.id, currentTeam]);

	// Load audit logs when team changes
	useEffect(() => {
		void refreshAuditLogs();
	}, [refreshAuditLogs]);

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
			setAuditLogs((data as TeamAuditLog[]) || []);
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
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const { data: team, error: teamError } = await supabase
				.from("teams")
				.insert({ name, plan: "free" } as any)
				.select()
				.single();

			if (teamError) throw teamError;
			if (!team) throw new Error("Failed to create team");

			const typedTeam = team as Database["public"]["Tables"]["teams"]["Row"];

			// Add creator as admin
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const { error: memberError } = await supabase.from("team_members").insert({
				team_id: typedTeam.id,
				user_id: user.id,
				role: "admin",
			} as any);

			if (memberError) throw memberError;

			const newTeam: Team = {
				id: typedTeam.id,
				name: typedTeam.name,
				github_org: typedTeam.github_org ?? undefined,
				gitlab_group: typedTeam.gitlab_group ?? undefined,
				plan: typedTeam.plan,
				created_at: typedTeam.created_at,
				updated_at: typedTeam.updated_at,
			};

			setTeams((prev) => [newTeam, ...prev]);
			setCurrentTeam(newTeam);
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
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const query = supabase.from("team_members") as any;
			const { error } = await query
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
					if (data) {
						const roleData = data as { role: string };
						setCurrentRole(roleData.role as TeamRole);
					}
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
