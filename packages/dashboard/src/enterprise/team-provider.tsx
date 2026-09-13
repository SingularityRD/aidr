import { createContext, type ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { Database } from "../lib/database.types";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { collectAuditExport } from "./audit-export";

// Mirrors the database check constraint on public.team_members.role
// (`owner | admin | member | viewer`). "owner" is not cosmetic: the
// handle_new_user_team trigger makes every new user the owner of their
// personal team, so omitting it silently removed team management from the
// people who own the team.
export type TeamRole = "owner" | "admin" | "member" | "viewer";

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
	currentRole: TeamRole | null;
	teams: Team[];
	members: TeamMember[];
	auditLogs: TeamAuditLog[];
	isLoading: boolean;
	error: string | null;
	/**
	 * Member-list specific failure. Tracked separately from `error` so the team
	 * page can tell "this team has no members" apart from "the membership rows
	 * could not be read" instead of rendering a fabricated count of zero.
	 */
	membersError: string | null;
	/**
	 * False when the membership rows loaded through the fallback path because
	 * the database exposes no relation the dashboard can read member emails
	 * from. Roles and removal stay usable; the UI says emails are unavailable.
	 */
	memberEmailsAvailable: boolean;
	/** True once the caller's role has been resolved (or proven absent). */
	roleResolved: boolean;
	createTeam: (name: string) => Promise<void>;
	inviteMember: (email: string, role: TeamRole) => Promise<string>;
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

const MEMBER_COLUMNS = "id, user_id, role, invited_by, joined_at";
// The generated types declare a `public.users` projection for this embed, but
// no migration in this repository creates such a relation (public.team_members
// references auth.users, which PostgREST does not expose). The embed is tried
// first so a deployment that does provide the relation keeps showing emails.
const MEMBER_COLUMNS_WITH_EMAIL = `${MEMBER_COLUMNS}, users!team_members_user_id_fkey!inner(email, raw_user_meta_data)`;

function isMissingUsersProjection(error: { code?: string; message?: string }): boolean {
	const code = error.code ?? "";
	if (code === "PGRST200" || code === "PGRST205") return true;
	return /relationship|schema cache|does not exist/i.test(error.message ?? "");
}

function mapMemberRow(row: Record<string, unknown>): TeamMember {
	const userData = row.users as Record<string, unknown> | null | undefined;
	const metaData = userData?.raw_user_meta_data as Record<string, unknown> | null | undefined;
	return {
		id: row.id as string,
		user_id: row.user_id as string,
		role: row.role as TeamRole,
		email: (userData?.email as string) ?? "",
		avatar_url: metaData?.avatar_url as string | undefined,
		invited_by: row.invited_by as string | undefined,
		joined_at: row.joined_at as string,
	};
}

export function TeamProvider({ children }: { children: ReactNode }) {
	const [currentTeam, setCurrentTeam] = useState<Team | null>(null);
	const [teams, setTeams] = useState<Team[]>([]);
	const [members, setMembers] = useState<TeamMember[]>([]);
	const [auditLogs, setAuditLogs] = useState<TeamAuditLog[]>([]);
	const [isLoading, setIsLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [membersError, setMembersError] = useState<string | null>(null);
	const [memberEmailsAvailable, setMemberEmailsAvailable] = useState(false);
	const [roleResolved, setRoleResolved] = useState(false);
	const [currentRole, setCurrentRole] = useState<TeamRole | null>(null);
	const selectedTeam = useRef(currentTeam?.id);
	selectedTeam.current = currentTeam?.id;

	// Load teams on mount
	useEffect(() => {
		async function loadTeams() {
			try {
				setIsLoading(true);
				setError(null);

				// Get user's teams with their role
				const { data: identity, error: identityError } = await supabase.auth.getUser();
				if (identityError || !identity.user) throw new Error("Your session could not be verified.");
				const { data: memberships, error: membershipError } = await supabase
					.from("team_members")
					.select(
						"team_id, role, teams!inner(id, name, github_org, gitlab_group, plan, created_at, updated_at)",
					)
					.eq("user_id", identity.user.id)
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
						setCurrentRole(typedMemberships.find((m) => m.team_id === mappedTeams[0]?.id)?.role as TeamRole);
					}
				}
			} catch (err) {
				setError(readErrorMessage(err, "Failed to load teams"));
			} finally {
				setIsLoading(false);
				setRoleResolved(true);
			}
		}

		void loadTeams();
	}, []);

	// Load members when team changes
	useEffect(() => {
		async function loadMembers() {
			if (!currentTeam) {
				setMembers([]);
				setMembersError(null);
				setMemberEmailsAvailable(false);
				return;
			}

			try {
				setMembersError(null);

				const withEmail = await supabase
					.from("team_members")
					.select(MEMBER_COLUMNS_WITH_EMAIL)
					.eq("team_id", currentTeam.id);
				if (selectedTeam.current !== currentTeam.id) return;

				if (!withEmail.error) {
					const rows = (withEmail.data ?? []) as unknown as Record<string, unknown>[];
					setMembers(rows.map(mapMemberRow));
					setMemberEmailsAvailable(true);
					return;
				}

				// Only a genuinely absent users relation falls back. Network,
				// permission and data errors stay visible instead of degrading
				// into an empty member list that looks like a real answer.
				if (!isMissingUsersProjection(withEmail.error)) {
					setMembers([]);
					setMemberEmailsAvailable(false);
					setMembersError(withEmail.error.message);
					return;
				}

				const plain = await supabase
					.from("team_members")
					.select(MEMBER_COLUMNS)
					.eq("team_id", currentTeam.id);
				if (selectedTeam.current !== currentTeam.id) return;

				if (plain.error) {
					setMembers([]);
					setMemberEmailsAvailable(false);
					setMembersError(plain.error.message);
					return;
				}

				const rows = (plain.data ?? []) as unknown as Record<string, unknown>[];
				setMembers(rows.map(mapMemberRow));
				setMemberEmailsAvailable(false);
			} catch (err) {
				if (selectedTeam.current !== currentTeam.id) return;
				setMembers([]);
				setMemberEmailsAvailable(false);
				setMembersError(readErrorMessage(err, "Failed to load members"));
			}
		}

		void loadMembers();
	}, [currentTeam?.id, currentTeam]);

	// Load audit logs when team changes
	const refreshAuditLogs = useCallback(async () => {
		if (!currentTeam) return;

		try {
			const { data, error } = await supabase
				.from("audit_logs")
				.select("*")
				.eq("team_id", currentTeam.id)
				.order("created_at", { ascending: false })
				.limit(1000);

			if (selectedTeam.current !== currentTeam.id) return;
			if (error) throw error;
			setAuditLogs(((data ?? []) as unknown as TeamAuditLog[]).map((row) => ({ ...row, timestamp: Date.parse(row.created_at) })));
		} catch (err) {
			if (selectedTeam.current !== currentTeam.id) return;
			setError(readErrorMessage(err, "Failed to load audit logs"));
		}
	}, [currentTeam]);

	useEffect(() => {
		void refreshAuditLogs();
	}, [refreshAuditLogs]);

	async function createTeam(name: string) {
		try {
			const {
				data: { user },
			} = await supabase.auth.getUser();
			if (!user) throw new Error("Not authenticated");

			// Create the tenant, team, and first membership atomically.  The RPC
			// derives the creator from auth.uid() and keeps the tenant_id immutable.
			const { data: team, error: teamError } = await supabase.rpc("create_team_tenant", {
				p_name: name,
				p_plan: "free",
			});

			if (teamError) throw teamError;
			if (!team) throw new Error("Failed to create team");

			const typedTeam = team as Database["public"]["Tables"]["teams"]["Row"];

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
			// Mutation failures are surfaced once, by the caller that rendered the
			// action, so they are not mirrored into the load-error channel where a
			// stale message could outlive the action that caused it.
			throw new Error(readErrorMessage(err, "Failed to create team"));
		}
	}

	async function inviteMember(email: string, role: TeamRole) {
		if (!currentTeam) throw new Error("No team selected");

		try {
			const { data, error } = await supabase.functions.invoke("team-invite", {
				body: { team_id: currentTeam.id, email, role },
			});

			if (error) {
				throw new Error(
					`the "team-invite" Edge Function is unavailable (${error.message}). No invitation was sent and no member was added.`,
				);
			}

			const response = (data ?? null) as { ok?: unknown; error?: unknown; invite_url?: unknown } | null;
			if (response?.error) throw new Error(String(response.error));

			// Fail closed on an unconfirmed response. An empty 200 (or any body
			// without the service's explicit acknowledgement) must never be
			// reported as "Invitation sent".
			if (response?.ok !== true) {
				throw new Error(
					'the "team-invite" Edge Function did not confirm the invitation (expected {"ok":true}). No invitation was sent.',
				);
			}
			if (typeof response.invite_url !== "string") throw new Error("The invitation service returned no shareable link.");
			const inviteUrl = new URL(response.invite_url);
			if (inviteUrl.origin !== window.location.origin || inviteUrl.pathname !== "/enterprise") throw new Error("The invitation service returned an invalid link.");
			return inviteUrl.toString();
		} catch (err) {
			const message = readErrorMessage(err, "Failed to invite member");
			throw new Error(message);
		}
	}

	async function removeMember(userId: string) {
		if (!currentTeam) throw new Error("No team selected");

		try {
			// `.select()` returns the deleted rows: a delete that matched nothing
			// (or that row-level security filtered out) is an error the admin must
			// see, not a silent "member removed".
			const { data, error } = await supabase
				.from("team_members")
				.delete()
				.eq("team_id", currentTeam.id)
				.eq("user_id", userId)
				.select("user_id");

			if (error) throw error;
			if (!data || data.length === 0) {
				throw new Error(
					"No membership row was removed. The team database rejected the change (row not found, or your role does not permit it).",
				);
			}
			setMembers((prev) => prev.filter((m) => m.user_id !== userId));
		} catch (err) {
			const message = readErrorMessage(err, "Failed to remove member");
			throw new Error(message);
		}
	}

	async function updateMemberRole(userId: string, role: TeamRole) {
		if (!currentTeam) throw new Error("No team selected");

		try {
			const { data, error } = await supabase
				.from("team_members")
				.update({ role })
				.eq("team_id", currentTeam.id)
				.eq("user_id", userId)
				.select("user_id");

			if (error) throw error;
			if (!data || data.length === 0) {
				throw new Error(
					"No membership row was updated. The team database rejected the change (row not found, or your role does not permit it).",
				);
			}
			setMembers((prev) => prev.map((m) => (m.user_id === userId ? { ...m, role } : m)));
		} catch (err) {
			const message = readErrorMessage(err, "Failed to update role");
			throw new Error(message);
		}
	}

	function switchTeam(teamId: string) {
		const team = teams.find((t) => t.id === teamId);
		if (team) {
			selectedTeam.current = teamId;
			setCurrentTeam(team);
			setCurrentRole(null);
			setMembers([]);
			setAuditLogs([]);
			setRoleResolved(false);
			void (async () => {
				try {
					const { data: identity, error: identityError } = await supabase.auth.getUser();
					if (identityError || !identity.user) throw new Error("Your session could not be verified.");
					const { data, error } = await supabase.from("team_members").select("role").eq("team_id", teamId).eq("user_id", identity.user.id).single();
					if (selectedTeam.current !== teamId) return;
					if (error || !data) throw new Error("Team permissions could not be loaded.");
					setCurrentRole(data.role as TeamRole);
				} catch { if (selectedTeam.current === teamId) setError("Team permissions could not be loaded."); }
				finally { if (selectedTeam.current === teamId) setRoleResolved(true); }
			})();
		}
	}

	async function exportAuditLogs(format: "csv" | "json"): Promise<string> {
		if (!currentTeam) throw new Error("No team selected");

		try {
			const teamId = currentTeam.id;
			const file = await collectAuditExport(format, async (cursor) => {
				const { data, error } = await supabase.functions.invoke("audit-export", {
					body: { team_id: teamId, format, ...(cursor ? { cursor } : {}) },
				});
				if (error || data?.error) throw new Error("Audit export failed. No partial file was produced.");
				return data;
			});
			return URL.createObjectURL(file);
		} catch (err) {
			setError(readErrorMessage(err, "Failed to export audit logs"));
			throw err;
		}
	}

	// Owner and admin both manage the team. The database check constraint allows
	// `owner`, and the signup trigger assigns it, so treating only "admin" as
	// manageable locked owners out of their own team.
	const canManageTeam = currentRole === "owner" || currentRole === "admin";
	const canViewAudit = currentRole !== null;
	const canEditPolicy =
		currentRole === "owner" || currentRole === "admin" || currentRole === "member";

	return (
		<TeamContext.Provider
			value={{
				currentTeam,
				currentRole,
				teams,
				members,
				auditLogs,
				isLoading,
				error,
				membersError,
				memberEmailsAvailable,
				roleResolved,
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
