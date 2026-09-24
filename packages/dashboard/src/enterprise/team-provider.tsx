import {
	createContext,
	type ReactNode,
	useCallback,
	useContext,
	useEffect,
	useRef,
	useState,
} from "react";
import type { Database } from "../lib/database.types";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { collectAuditExport } from "./audit-export";
import { IdentityBootstrap } from "./identity-bootstrap";

// Mirrors the database check constraint on public.team_members.role
// (`owner | admin | member | viewer`). "owner" is not cosmetic: the
// handle_new_user_team trigger makes every new user the owner of their
// personal team, so omitting it silently removed team management from the
// people who own the team.
export type TeamRole = "owner" | "admin" | "member" | "viewer";

/**
 * How the service delivered a confirmed invitation. `email` is reported only
 * when the mail provider accepted the message, and then no link is returned.
 * Otherwise the operator receives the link to share, and `emailFailed` says a
 * configured mail attempt did not go through.
 */
export type InvitationDelivery =
	| { delivery: "email" }
	| { delivery: "manual"; inviteUrl: string; emailFailed: boolean };

/** Accept only a link this deployment issued for its invitation route. */
export function readInvitationLink(value: unknown): string {
	if (typeof value !== "string")
		throw new Error("The invitation service returned no shareable link.");
	const inviteUrl = new URL(value);
	if (
		inviteUrl.origin !== window.location.origin ||
		inviteUrl.pathname !== "/enterprise" ||
		!inviteUrl.searchParams.get("invite")
	)
		throw new Error("The invitation service returned an invalid link.");
	return inviteUrl.toString();
}

/** Project a confirmed `team-invite` response onto its delivery outcome. */
export function readInvitationDelivery(response: {
	delivery?: unknown;
	invite_url?: unknown;
	email_delivery?: unknown;
}): InvitationDelivery {
	if (response.delivery === "email") return { delivery: "email" };
	return {
		delivery: "manual",
		inviteUrl: readInvitationLink(response.invite_url),
		emailFailed: response.email_delivery === "failed",
	};
}

export interface TeamMember {
	id: string;
	user_id: string;
	role: TeamRole;
	email: string;
	avatar_url?: string;
	invited_by?: string;
	joined_at: string;
}

interface Team {
	id: string;
	tenant_id: string;
	name: string;
	github_org?: string;
	gitlab_group?: string;
	plan: "free" | "pro" | "team" | "business" | "enterprise";
	created_at: string;
	updated_at: string;
}

interface TeamAuditLog {
	id: string;
	team_id: string;
	user_id: string | null;
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
		tenant_id: string;
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
	currentUserId: string;
	currentRole: TeamRole | null;
	teams: Team[];
	members: TeamMember[];
	auditLogs: TeamAuditLog[];
	auditLoaded: boolean;
	auditError: string | null;
	isLoading: boolean;
	error: string | null;
	/**
	 * Member-list specific failure. Tracked separately from `error` so the team
	 * page can tell "this team has no members" apart from "the membership rows
	 * could not be read" instead of rendering a fabricated count of zero.
	 */
	membersError: string | null;
	/**
	 * False when this role cannot read emails or an older deployment lacks the
	 * dedicated, tenant-scoped member directory RPC.
	 */
	memberEmailsAvailable: boolean;
	/** True once the caller's role has been resolved (or proven absent). */
	roleResolved: boolean;
	createTeam: (name: string, requestId: string) => Promise<void>;
	inviteMember: (email: string, role: TeamRole) => Promise<InvitationDelivery>;
	removeMember: (userId: string) => Promise<void>;
	updateMemberRole: (userId: string, role: TeamRole) => Promise<void>;
	switchTeam: (teamId: string) => void;
	refreshAuditLogs: () => Promise<void>;
	/** Reflect a server-confirmed workspace rename in the loaded team list. */
	applyWorkspaceName: (teamId: string, name: string) => void;
	exportAuditLogs: (format: "csv" | "json") => Promise<string>;
	canManageTeam: boolean;
	canViewAudit: boolean;
	canEditPolicy: boolean;
}

const TeamContext = createContext<TeamContextType | null>(null);

const MEMBER_COLUMNS = "id, user_id, role, invited_by, joined_at";
function isMissingMemberDirectory(error: { code?: string }): boolean {
	return error.code === "PGRST202" || error.code === "42883";
}

function mapMemberRow(row: Record<string, unknown>): TeamMember {
	return {
		id: row.id as string,
		user_id: row.user_id as string,
		role: row.role as TeamRole,
		email: typeof row.email === "string" ? row.email : "",
		avatar_url: typeof row.avatar_url === "string" ? row.avatar_url : undefined,
		invited_by: row.invited_by as string | undefined,
		joined_at: row.joined_at as string,
	};
}

export function TeamProvider({ children }: { children: ReactNode }) {
	return (
		<IdentityBootstrap>
			{(teamId, switchTeam, refreshMemberships, isCurrent, userId) => (
				<ProtectedTeamProvider
					key={teamId}
					selectedTeamId={teamId}
					currentUserId={userId}
					onSwitchTeam={switchTeam}
					refreshMemberships={refreshMemberships}
					isIdentityCurrent={isCurrent}
				>
					{children}
				</ProtectedTeamProvider>
			)}
		</IdentityBootstrap>
	);
}

/** Never mounted until the selected tenant and current token pass assurance. */
function ProtectedTeamProvider({
	children,
	selectedTeamId,
	currentUserId,
	onSwitchTeam,
	refreshMemberships,
	isIdentityCurrent,
}: {
	children: ReactNode;
	isIdentityCurrent: () => boolean;
	selectedTeamId: string | null;
	currentUserId: string;
	onSwitchTeam: (teamId: string) => void;
	refreshMemberships: (tenantId: string) => Promise<void>;
}) {
	const [currentTeam, setCurrentTeam] = useState<Team | null>(null);
	const [teams, setTeams] = useState<Team[]>([]);
	const [members, setMembers] = useState<TeamMember[]>([]);
	const [auditLogs, setAuditLogs] = useState<TeamAuditLog[]>([]);
	const [auditLoaded, setAuditLoaded] = useState(false);
	const [auditError, setAuditError] = useState<string | null>(null);
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
		let cancelled = false;
		async function loadTeams() {
			try {
				setIsLoading(true);
				setError(null);
				if (!selectedTeamId) return;

				// Get user's teams with their role only after the identity gate.
				const { data: identity, error: identityError } = await supabase.auth.getUser();
				if (cancelled || !isIdentityCurrent()) return;
				if (identityError || !identity.user) throw new Error("Your session could not be verified.");
				const { data: memberships, error: membershipError } = await supabase
					.from("team_members")
					.select(
						"team_id, role, teams!inner(id, tenant_id, name, github_org, gitlab_group, plan, created_at, updated_at)",
					)
					.eq("user_id", identity.user.id)
					.order("joined_at", { ascending: false });

				if (cancelled || !isIdentityCurrent()) return;
				if (membershipError) {
					throw membershipError;
				}

				const typedMemberships = memberships as MembershipWithTeam[] | null;
				if (
					!typedMemberships?.some(
						(membership) => membership.team_id === selectedTeamId && membership.teams,
					)
				) {
					throw new Error("The selected team is no longer accessible.");
				}

				if (typedMemberships && typedMemberships.length > 0) {
					const mappedTeams: Team[] = [];
					for (const m of typedMemberships) {
						if (!m.teams) continue;
						const planValue = m.teams.plan;
						const validPlan: Team["plan"] =
							planValue === "free" ||
							planValue === "pro" ||
							planValue === "team" ||
							planValue === "business" ||
							planValue === "enterprise"
								? planValue
								: "free";
						mappedTeams.push({
							id: m.teams.id,
							tenant_id: m.teams.tenant_id,
							name: m.teams.name,
							github_org: m.teams.github_org ?? undefined,
							gitlab_group: m.teams.gitlab_group ?? undefined,
							plan: validPlan,
							created_at: m.teams.created_at,
							updated_at: m.teams.updated_at,
						});
					}

					if (mappedTeams.length > 0) {
						const selected = mappedTeams.find((team) => team.id === selectedTeamId);
						if (!selected) throw new Error("The selected team is no longer accessible.");
						setTeams(mappedTeams);
						setCurrentTeam(selected);
						setCurrentRole(
							typedMemberships.find((m) => m.team_id === selected.id)?.role as TeamRole,
						);
					}
				}
			} catch (err) {
				if (!cancelled) setError(readErrorMessage(err, "Failed to load teams"));
			} finally {
				if (!cancelled) {
					setIsLoading(false);
					setRoleResolved(true);
				}
			}
		}

		void loadTeams();
		return () => {
			cancelled = true;
			selectedTeam.current = undefined;
		};
	}, [selectedTeamId, isIdentityCurrent]);

	// Load members when team changes
	useEffect(() => {
		async function loadMembers() {
			if (!isIdentityCurrent()) return;
			if (!currentTeam) {
				setMembers([]);
				setMembersError(null);
				setMemberEmailsAvailable(false);
				return;
			}

			try {
				setMembersError(null);

				if (currentRole === "owner" || currentRole === "admin") {
					const directory = await supabase.rpc("list_team_members_with_email", {
						p_team_id: currentTeam.id,
					});
					if (!isIdentityCurrent() || selectedTeam.current !== currentTeam.id) return;
					if (!directory.error) {
						const rows = (directory.data ?? []) as Record<string, unknown>[];
						setMembers(rows.map(mapMemberRow));
						setMemberEmailsAvailable(true);
						return;
					}
					// Only a genuinely absent RPC falls back. Denied or failed reads
					// must not become a plausible, partially populated member list.
					if (!isMissingMemberDirectory(directory.error)) {
						setMembers([]);
						setMemberEmailsAvailable(false);
						setMembersError(readErrorMessage(directory.error, "Failed to load members"));
						return;
					}
				}

				const plain = await supabase
					.from("team_members")
					.select(MEMBER_COLUMNS)
					.eq("team_id", currentTeam.id);
				if (!isIdentityCurrent() || selectedTeam.current !== currentTeam.id) return;

				if (plain.error) {
					setMembers([]);
					setMemberEmailsAvailable(false);
					setMembersError(readErrorMessage(plain.error, "Failed to load members"));
					return;
				}

				const rows = (plain.data ?? []) as unknown as Record<string, unknown>[];
				setMembers(rows.map(mapMemberRow));
				setMemberEmailsAvailable(false);
			} catch (err) {
				if (!isIdentityCurrent() || selectedTeam.current !== currentTeam.id) return;
				setMembers([]);
				setMemberEmailsAvailable(false);
				setMembersError(readErrorMessage(err, "Failed to load members"));
			}
		}

		void loadMembers();
	}, [currentTeam?.id, currentTeam, currentRole, isIdentityCurrent]);

	// Load audit logs when team changes
	const refreshAuditLogs = useCallback(async () => {
		if (!currentTeam || !isIdentityCurrent()) return;
		const teamId = currentTeam.id;
		setAuditLogs([]);
		setAuditLoaded(false);
		setAuditError(null);

		try {
			const { data, error } = await supabase
				.from("audit_logs")
				.select("id,team_id,user_id,action,created_at")
				.eq("tenant_id", teamId)
				.order("created_at", { ascending: false })
				.limit(1000);

			if (!isIdentityCurrent() || selectedTeam.current !== teamId) return;
			if (error) throw error;
			setAuditLogs(
				((data ?? []) as unknown as TeamAuditLog[]).map((row) => ({
					...row,
					timestamp: Date.parse(row.created_at),
				})),
			);
			setAuditLoaded(true);
		} catch (err) {
			if (!isIdentityCurrent() || selectedTeam.current !== teamId) return;
			setAuditError(readErrorMessage(err, "Failed to load audit logs"));
			setAuditLoaded(true);
		}
	}, [currentTeam, isIdentityCurrent]);

	useEffect(() => {
		void refreshAuditLogs();
	}, [refreshAuditLogs]);

	async function createTeam(name: string, requestId: string) {
		try {
			const {
				data: { user },
			} = await supabase.auth.getUser();
			if (!user || user.id !== currentUserId || !isIdentityCurrent())
				throw new Error("The authenticated identity changed before team creation.");

			// Create the tenant, team, and first membership atomically.  The RPC
			// derives the creator from auth.uid() and keeps the tenant_id immutable.
			const { data: team, error: teamError } = await supabase.rpc("create_team_tenant", {
				p_name: name,
				p_request_id: requestId,
				p_plan: "free",
			});

			if (!isIdentityCurrent())
				throw new Error("The session changed before team creation completed.");
			if (teamError) throw teamError;
			if (!team) throw new Error("Failed to create team");

			const typedTeam = team as Database["public"]["Tables"]["teams"]["Row"];

			// A newly created tenant needs its own membership/assurance binding too.
			await refreshMemberships(typedTeam.tenant_id);
		} catch (err) {
			// Mutation failures are surfaced once, by the caller that rendered the
			// action, so they are not mirrored into the load-error channel where a
			// stale message could outlive the action that caused it.
			throw new Error(readErrorMessage(err, "Failed to create team"));
		}
	}

	function applyWorkspaceName(teamId: string, name: string) {
		setTeams((prev) => prev.map((team) => (team.id === teamId ? { ...team, name } : team)));
		setCurrentTeam((prev) => (prev && prev.id === teamId ? { ...prev, name } : prev));
	}

	async function inviteMember(email: string, role: TeamRole) {
		if (!currentTeam) throw new Error("No team selected");

		try {
			const { data, error } = await supabase.functions.invoke("team-invite", {
				body: { team_id: currentTeam.id, email, role },
			});

			if (error) {
				throw new Error(readErrorMessage(error, "The invitation service is unavailable."));
			}

			const response = (data ?? null) as {
				ok?: unknown;
				error?: unknown;
				delivery?: unknown;
				invite_url?: unknown;
				email_delivery?: unknown;
			} | null;
			if (response?.error) throw new Error(String(response.error));

			// Fail closed on an unconfirmed response. An empty 200 (or any body
			// without the service's explicit acknowledgement) must never be
			// reported as "Invitation sent".
			if (response?.ok !== true) {
				throw new Error(
					'the "team-invite" Edge Function did not confirm the invitation (expected {"ok":true}). No invitation was sent.',
				);
			}
			return readInvitationDelivery(response);
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
		// Selection invalidates the entire protected provider. Do not fetch B's
		// role/members/audit until B's own assurance report has allowed access.
		onSwitchTeam(teamId);
	}

	async function exportAuditLogs(format: "csv" | "json"): Promise<string> {
		if (!currentTeam || !currentRole || !isIdentityCurrent())
			throw new Error("No accessible team selected");

		try {
			const teamId = currentTeam.id;
			const file = await collectAuditExport(format, async (cursor) => {
				const { data, error } = await supabase.functions.invoke("audit-export", {
					body: { team_id: teamId, format, ...(cursor ? { cursor } : {}) },
				});
				if (error || data?.error)
					throw new Error("Audit export failed. No partial file was produced.");
				return data;
			});
			if (!isIdentityCurrent() || selectedTeam.current !== teamId) {
				throw new Error(
					"The selected team changed during audit export. Retry for the current team.",
				);
			}
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
				currentUserId,
				currentRole,
				teams,
				members,
				auditLogs,
				auditLoaded,
				auditError,
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
				applyWorkspaceName,
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
