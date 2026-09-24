import { useCallback, useEffect, useRef, useState } from "react";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { type TeamMember, type TeamRole, useTeam } from "./team-provider";

const ROLE_LABELS: Record<TeamRole, string> = {
	owner: "Owner",
	admin: "Administrator",
	member: "Member",
	viewer: "Viewer",
};

const ROLE_DESCRIPTIONS: Record<TeamRole, string> = {
	owner: "Team owner: full access, including ownership of the team tenant",
	admin: "Full access: manage team, members, policies, and billing",
	member: "Standard access: edit policies, view audit logs",
	viewer: "Read-only: view audit logs and team activity",
};

// Administrators cannot grant ownership. Owner changes require AAL2 and are
// appended to the audit log atomically by the database owner-role guard.
const ASSIGNABLE_ROLES: TeamRole[] = ["admin", "member", "viewer"];
const CHANGEABLE_ROLES: TeamRole[] = ["owner", "admin", "member", "viewer"];

/**
 * Outcome of the last action, kept as a typed value. The previous
 * implementation decided between success and error styling with
 * `status.includes("Failed")`, so any error text that did not happen to
 * contain that word rendered as a neutral, success-looking notice.
 */
interface ActionStatus {
	tone: "success" | "error";
	message: string;
}

interface PendingInvitation {
	id: string;
	email: string;
	role: "admin" | "member" | "viewer";
	expires_at: string;
}

function isPendingInvitation(value: unknown): value is PendingInvitation {
	if (!value || typeof value !== "object") return false;
	const row = value as Record<string, unknown>;
	return (
		typeof row.id === "string" &&
		typeof row.email === "string" &&
		(row.role === "admin" || row.role === "member" || row.role === "viewer") &&
		typeof row.expires_at === "string" &&
		Number.isFinite(Date.parse(row.expires_at))
	);
}

function memberLabel(member: TeamMember): string {
	return member.email || `user ${member.user_id}`;
}

export function AdminPanel() {
	const {
		currentTeam,
		currentRole,
		members,
		isLoading,
		error,
		membersError,
		memberEmailsAvailable,
		canManageTeam,
		inviteMember,
		removeMember,
		updateMemberRole,
		createTeam,
	} = useTeam();

	const [inviteEmail, setInviteEmail] = useState("");
	const [inviteRole, setInviteRole] = useState<TeamRole>("member");
	const [newTeamName, setNewTeamName] = useState("");
	const [showCreateTeam, setShowCreateTeam] = useState(false);
	const [busy, setBusy] = useState(false);
	const [status, setStatus] = useState<ActionStatus | null>(null);
	const [inviteLink, setInviteLink] = useState("");
	const [invitations, setInvitations] = useState<PendingInvitation[]>([]);
	const [invitationsError, setInvitationsError] = useState<string | null>(null);
	const [loadingInvitations, setLoadingInvitations] = useState(false);
	const [teamCreateAttempt, setTeamCreateAttempt] = useState<{
		name: string;
		requestId: string;
	} | null>(null);
	const teamCreateBusy = useRef(false);
	const invitationRequest = useRef(0);
	const teamId = currentTeam?.id;

	function cancelTeamCreate() {
		setShowCreateTeam(false);
		setTeamCreateAttempt(null);
		setNewTeamName("");
	}

	function startTeamCreate() {
		setTeamCreateAttempt(null);
		setNewTeamName("");
		setShowCreateTeam(true);
	}

	function toggleTeamCreate() {
		if (showCreateTeam) cancelTeamCreate();
		else startTeamCreate();
	}

	const loadInvitations = useCallback(async () => {
		if (!teamId || !canManageTeam) {
			setInvitations([]);
			setInvitationsError(null);
			return;
		}
		const requestId = ++invitationRequest.current;
		setLoadingInvitations(true);
		setInvitationsError(null);
		try {
			const { data, error } = await supabase.functions.invoke("team-invite", {
				body: { team_id: teamId, action: "list" },
			});
			if (
				error ||
				data?.ok !== true ||
				!Array.isArray(data.invitations) ||
				!data.invitations.every(isPendingInvitation)
			) {
				throw new Error("Pending invitations could not be loaded.");
			}
			if (requestId === invitationRequest.current) {
				setInvitations(
					data.invitations.filter(
						(row: PendingInvitation) => Date.parse(row.expires_at) > Date.now(),
					),
				);
			}
		} catch {
			if (requestId === invitationRequest.current) {
				setInvitations([]);
				setInvitationsError(
					"Pending invitations could not be loaded. Try again before creating or replacing a link.",
				);
			}
		} finally {
			if (requestId === invitationRequest.current) setLoadingInvitations(false);
		}
	}, [teamId, canManageTeam]);

	useEffect(() => {
		void loadInvitations();
		return () => {
			invitationRequest.current++;
		};
	}, [loadInvitations]);

	async function handleInvite(e: React.FormEvent) {
		e.preventDefault();
		if (!inviteEmail.trim() || !currentTeam) return;

		setBusy(true);
		setStatus(null);
		setInviteLink("");

		try {
			const link = await inviteMember(inviteEmail.trim(), inviteRole);
			setInviteLink(link);
			setStatus({
				tone: "success",
				message: `Invitation created for ${inviteEmail}. Share the link below; no email was sent.`,
			});
			setInviteEmail("");
			void loadInvitations();
		} catch (err) {
			setStatus({
				tone: "error",
				message: readErrorMessage(err, "Failed to send invitation"),
			});
		} finally {
			setBusy(false);
		}
	}

	async function handleInvitationAction(
		invitation: PendingInvitation,
		action: "resend" | "revoke",
	) {
		if (!teamId) return;
		if (
			!window.confirm(
				action === "resend"
					? `Replace the link for ${invitation.email}? The previous link will stop working.`
					: `Revoke the invitation for ${invitation.email}?`,
			)
		)
			return;
		setBusy(true);
		setStatus(null);
		setInviteLink("");
		try {
			const { data, error } = await supabase.functions.invoke("team-invite", {
				body: { team_id: teamId, action, invitation_id: invitation.id },
			});
			if (error || data?.ok !== true || data.invitation_id !== invitation.id)
				throw new Error("Invitation change was not confirmed.");
			if (action === "resend") {
				if (typeof data.invite_url !== "string")
					throw new Error("The invitation service returned no shareable link.");
				const link = new URL(data.invite_url);
				if (
					link.origin !== window.location.origin ||
					link.pathname !== "/enterprise" ||
					!link.searchParams.get("invite")
				) {
					throw new Error("The invitation service returned an invalid link.");
				}
				setInviteLink(link.toString());
				setStatus({
					tone: "success",
					message: `Link replaced for ${invitation.email}. Share the new link below; no email was sent.`,
				});
			} else {
				setStatus({ tone: "success", message: `Invitation revoked for ${invitation.email}.` });
			}
			void loadInvitations();
		} catch (err) {
			setStatus({ tone: "error", message: readErrorMessage(err, "Failed to change invitation") });
		} finally {
			setBusy(false);
		}
	}

	async function handleCreateTeam(e: React.FormEvent) {
		e.preventDefault();
		if (!newTeamName.trim() || teamCreateBusy.current) return;
		teamCreateBusy.current = true;

		setBusy(true);
		setStatus(null);

		const attempt = teamCreateAttempt ?? {
			name: newTeamName.trim(),
			requestId: crypto.randomUUID(),
		};
		setTeamCreateAttempt(attempt);
		try {
			await createTeam(attempt.name, attempt.requestId);
			setStatus({ tone: "success", message: `Team "${attempt.name}" created successfully` });
			setNewTeamName("");
			setTeamCreateAttempt(null);
			setShowCreateTeam(false);
		} catch (err) {
			setStatus({
				tone: "error",
				message: readErrorMessage(err, "Failed to create team"),
			});
		} finally {
			teamCreateBusy.current = false;
			setBusy(false);
		}
	}

	async function handleRemoveMember(member: TeamMember) {
		if (!window.confirm(`Remove ${memberLabel(member)} from the team?`)) return;

		setBusy(true);
		setStatus(null);
		try {
			await removeMember(member.user_id);
			setStatus({ tone: "success", message: `${memberLabel(member)} removed from team` });
		} catch (err) {
			setStatus({
				tone: "error",
				message: readErrorMessage(err, "Failed to remove member"),
			});
		} finally {
			setBusy(false);
		}
	}

	async function handleRoleChange(userId: string, newRole: TeamRole) {
		setBusy(true);
		setStatus(null);
		try {
			await updateMemberRole(userId, newRole);
			setStatus({ tone: "success", message: `Role updated to ${ROLE_LABELS[newRole]}` });
		} catch (err) {
			setStatus({
				tone: "error",
				message: readErrorMessage(err, "Failed to update role"),
			});
		} finally {
			setBusy(false);
		}
	}

	if (isLoading) {
		return (
			<div className="card">
				<p className="muted">Loading team...</p>
			</div>
		);
	}

	if (!currentTeam) {
		return (
			<div className="card">
				<h2>Team Management</h2>
				{error ? (
					<>
						<div className="notice notice-danger" role="alert" aria-live="assertive">
							<b>Your team membership could not be loaded.</b>
							<div className="muted small" style={{ marginTop: 6 }}>
								{error}
							</div>
							<div className="muted small" style={{ marginTop: 6 }}>
								This is not a confirmed &quot;no team&quot; state, so no team creation is offered
								until the membership query succeeds.
							</div>
						</div>
					</>
				) : (
					<>
						<p className="muted">You are not part of any team yet.</p>

						{showCreateTeam ? (
							<form onSubmit={handleCreateTeam}>
								<label className="label">
									Team Name
									<input
										className="input"
										type="text"
										readOnly={Boolean(teamCreateAttempt)}
										value={newTeamName}
										onChange={(e) => setNewTeamName(e.target.value)}
										placeholder="e.g., Acme Security"
										required
									/>
								</label>
								<div className="row">
									<button className="button" type="submit" disabled={busy}>
										{teamCreateAttempt ? "Retry Team Creation" : "Create Team"}
									</button>
									<button
										className="button button-secondary"
										type="button"
										onClick={cancelTeamCreate}
									>
										Cancel
									</button>
								</div>
							</form>
						) : (
							<button className="button" onClick={startTeamCreate}>
								Create Your First Team
							</button>
						)}
					</>
				)}

				{status ? (
					<div
						className={`notice ${status.tone === "error" ? "notice-danger" : ""}`}
						role={status.tone === "error" ? "alert" : "status"}
					>
						{status.message}
					</div>
				) : null}
			</div>
		);
	}

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between">
					<div>
						<h2 style={{ margin: 0 }}>{currentTeam.name}</h2>
						<p className="muted" style={{ margin: "6px 0 0" }}>
							Plan: <span className="pill">{currentTeam.plan}</span>
							{currentTeam.github_org && (
								<span className="pill" style={{ marginLeft: "8px" }}>
									GitHub: {currentTeam.github_org}
								</span>
							)}
							{currentTeam.gitlab_group && (
								<span className="pill" style={{ marginLeft: "8px" }}>
									GitLab: {currentTeam.gitlab_group}
								</span>
							)}
						</p>
					</div>
					{canManageTeam && (
						<button className="button button-secondary" onClick={toggleTeamCreate}>
							+ New Team
						</button>
					)}
				</div>

				{canManageTeam ? null : (
					<div className="notice" style={{ marginTop: 14 }}>
						You have read-only access to this team. Only an owner or an administrator can invite,
						remove, or re-role members.
					</div>
				)}

				{showCreateTeam && (
					<form
						onSubmit={handleCreateTeam}
						style={{ marginTop: "16px", paddingTop: "16px", borderTop: "1px solid var(--border)" }}
					>
						<label className="label">
							New Team Name
							<input
								className="input"
								type="text"
								readOnly={Boolean(teamCreateAttempt)}
								value={newTeamName}
								onChange={(e) => setNewTeamName(e.target.value)}
								placeholder="e.g., Security Team"
								required
							/>
						</label>
						<div className="row">
							<button className="button" type="submit" disabled={busy}>
								{teamCreateAttempt ? "Retry Team Creation" : "Create Team"}
							</button>
							<button className="button button-secondary" type="button" onClick={cancelTeamCreate}>
								Cancel
							</button>
						</div>
					</form>
				)}
			</div>

			{/* Members List */}
			<div className="card">
				<h3>{membersError ? "Team Members" : `Team Members (${members.length})`}</h3>

				{membersError ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						<b>Member list unavailable.</b>
						<div className="muted small" style={{ marginTop: 6 }}>
							{membersError}
						</div>
						<div className="muted small" style={{ marginTop: 6 }}>
							No member count is shown because the membership rows could not be read.
						</div>
					</div>
				) : null}

				{!membersError && !memberEmailsAvailable ? (
					<div className="notice notice-warning" style={{ marginBottom: 14 }}>
						<b>
							{canManageTeam
								? "Member email addresses are unavailable in this deployment."
								: "Member email addresses are restricted to team owners and administrators."}
						</b>
						<div className="muted small" style={{ marginTop: 6 }}>
							{canManageTeam
								? "The secure member directory is not available. Members are identified by user id; role changes and removal still apply to the real rows."
								: "Members are identified by user id on this read-only view."}
						</div>
					</div>
				) : null}

				{canManageTeam && (
					<form
						onSubmit={handleInvite}
						style={{
							marginBottom: "20px",
							paddingBottom: "20px",
							borderBottom: "1px solid var(--border)",
						}}
					>
						<div className="row" style={{ alignItems: "flex-end", gap: "12px" }}>
							<label className="label" style={{ flex: 1, margin: 0 }}>
								Email
								<input
									className="input"
									type="email"
									value={inviteEmail}
									onChange={(e) => setInviteEmail(e.target.value)}
									placeholder="colleague@company.com"
									required
								/>
							</label>
							<label className="label" style={{ margin: 0 }}>
								Role
								<select
									className="input"
									value={inviteRole}
									onChange={(e) => setInviteRole(e.target.value as TeamRole)}
									style={{ padding: "10px 13px" }}
								>
									{ASSIGNABLE_ROLES.map((role) => (
										<option key={role} value={role}>
											{ROLE_LABELS[role]}
										</option>
									))}
								</select>
							</label>
							<button className="button" type="submit" disabled={busy}>
								Invite
							</button>
						</div>
						<p className="muted small">{ROLE_DESCRIPTIONS[inviteRole]}</p>
						{inviteLink && (
							<label>
								Invitation link
								<input
									className="input"
									readOnly
									value={inviteLink}
									onFocus={(event) => event.target.select()}
								/>
							</label>
						)}
					</form>
				)}

				{canManageTeam && (
					<div style={{ marginBottom: 20 }}>
						<div className="row space-between">
							<h4>Pending invitations</h4>
							<button
								className="button button-secondary"
								type="button"
								disabled={busy || loadingInvitations}
								onClick={() => void loadInvitations()}
							>
								Refresh invitations
							</button>
						</div>
						{invitationsError ? (
							<div className="notice notice-danger" role="alert">
								{invitationsError}
							</div>
						) : null}
						{loadingInvitations ? <p className="muted">Loading invitations...</p> : null}
						{!loadingInvitations && !invitationsError && invitations.length === 0 ? (
							<p className="muted">No pending invitations.</p>
						) : null}
						{!loadingInvitations && !invitationsError && invitations.length > 0 ? (
							<table className="table">
								<thead>
									<tr>
										<th>Recipient</th>
										<th>Role</th>
										<th>Expires</th>
										<th className="right">Actions</th>
									</tr>
								</thead>
								<tbody>
									{invitations.map((invitation) => (
										<tr key={invitation.id}>
											<td>{invitation.email}</td>
											<td>{ROLE_LABELS[invitation.role]}</td>
											<td>{new Date(invitation.expires_at).toLocaleString()}</td>
											<td className="right">
												<button
													className="button button-secondary"
													type="button"
													disabled={busy}
													onClick={() => void handleInvitationAction(invitation, "resend")}
												>
													Replace link
												</button>{" "}
												<button
													className="button button-secondary"
													type="button"
													disabled={busy}
													onClick={() => void handleInvitationAction(invitation, "revoke")}
												>
													Revoke invitation
												</button>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						) : null}
					</div>
				)}

				{members.length > 0 ? (
					<table className="table">
						<thead>
							<tr>
								<th>Member</th>
								<th>Role</th>
								{canManageTeam && <th className="right">Actions</th>}
							</tr>
						</thead>
						<tbody>
							{members.map((member) => (
								<tr key={member.id}>
									<td>
										<div className="row">
											<div>
												<div>{memberLabel(member)}</div>
												{member.invited_by && (
													<div className="small muted">Invited by team member</div>
												)}
											</div>
										</div>
									</td>
									<td>
										{canManageTeam && (currentRole === "owner" || member.role !== "owner") ? (
											<select
												className="input"
												value={member.role}
												onChange={(e) =>
													void handleRoleChange(member.user_id, e.target.value as TeamRole)
												}
												style={{ padding: "6px 10px", minWidth: "120px" }}
												disabled={busy}
											>
												{(currentRole === "owner" ? CHANGEABLE_ROLES : ASSIGNABLE_ROLES).map(
													(role) => (
														<option key={role} value={role}>
															{ROLE_LABELS[role]}
														</option>
													),
												)}
											</select>
										) : (
											<span className="pill">{ROLE_LABELS[member.role]}</span>
										)}
									</td>
									{canManageTeam && (
										<td className="right">
											{(currentRole === "owner" || member.role !== "owner") && (
												<button
													className="button button-secondary"
													style={{ padding: "6px 10px", fontSize: "12px" }}
													onClick={() => void handleRemoveMember(member)}
													disabled={busy}
												>
													Remove
												</button>
											)}
										</td>
									)}
								</tr>
							))}
						</tbody>
					</table>
				) : null}
			</div>

			{error && (
				<div className="notice notice-danger" role="alert">
					<b>Error:</b> {error}
				</div>
			)}

			{status && (
				<div
					className={`notice ${status.tone === "error" ? "notice-danger" : ""}`}
					role={status.tone === "error" ? "alert" : "status"}
					aria-live="assertive"
				>
					{status.message}
				</div>
			)}
		</div>
	);
}
