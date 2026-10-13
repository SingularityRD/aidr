import { useCallback, useEffect, useRef, useState } from "react";
import type { DashboardMessageKey } from "../i18n/en";
import { type Translate, useT } from "../i18n/I18nProvider";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import {
	type InvitationDelivery,
	readInvitationDelivery,
	type TeamMember,
	type TeamRole,
	useTeam,
} from "./team-provider";

const ROLE_LABELS: Record<TeamRole, DashboardMessageKey> = {
	owner: "common.role.owner",
	admin: "common.role.admin",
	member: "common.role.member",
	viewer: "common.role.viewer",
};

const ROLE_DESCRIPTIONS: Record<TeamRole, DashboardMessageKey> = {
	owner: "team.role.ownerDesc",
	admin: "team.role.adminDesc",
	member: "team.role.memberDesc",
	viewer: "team.role.viewerDesc",
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

/**
 * Operator copy for a confirmed invitation. Email delivery is claimed only when
 * the service reported that the mail provider accepted the message.
 */
function invitationStatus(
	action: "create" | "resend",
	email: string,
	result: InvitationDelivery,
	t: Translate,
): string {
	const lead =
		action === "create"
			? t("team.invite.created", { email })
			: t("team.invite.replaced", { email });
	if (result.delivery === "email") {
		return action === "create"
			? `${lead} ${t("team.invite.emailSent")}`
			: `${lead} ${t("team.invite.emailResent")}`;
	}
	const share = action === "create" ? t("team.invite.share") : t("team.invite.shareNew");
	return result.emailFailed
		? `${lead} ${t("team.invite.emailFailed", { share })}`
		: `${lead} ${t("team.invite.noEmail", { share })}`;
}

function memberLabel(member: TeamMember, t: Translate): string {
	return member.email || t("team.memberUser", { id: member.user_id });
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
	const t = useT();

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
				throw new Error(t("team.invites.loadFailed"));
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
				setInvitationsError(t("team.invites.loadFailedRetry"));
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
			const result = await inviteMember(inviteEmail.trim(), inviteRole);
			if (result.delivery === "manual") setInviteLink(result.inviteUrl);
			setStatus({
				tone: "success",
				message: invitationStatus("create", inviteEmail, result, t),
			});
			setInviteEmail("");
			void loadInvitations();
		} catch (err) {
			setStatus({
				tone: "error",
				message: readErrorMessage(err, t("team.invite.failed")),
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
					? t("team.invite.confirmReplace", { email: invitation.email })
					: t("team.invite.confirmRevoke", { email: invitation.email }),
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
				throw new Error(t("team.invite.changeUnconfirmed"));
			if (action === "resend") {
				const result = readInvitationDelivery(data);
				if (result.delivery === "manual") setInviteLink(result.inviteUrl);
				setStatus({
					tone: "success",
					message: invitationStatus("resend", invitation.email, result, t),
				});
			} else {
				setStatus({
					tone: "success",
					message: t("team.invite.revoked", { email: invitation.email }),
				});
			}
			void loadInvitations();
		} catch (err) {
			setStatus({ tone: "error", message: readErrorMessage(err, t("team.invite.changeFailed")) });
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
			setStatus({ tone: "success", message: t("team.created", { name: attempt.name }) });
			setNewTeamName("");
			setTeamCreateAttempt(null);
			setShowCreateTeam(false);
		} catch (err) {
			setStatus({
				tone: "error",
				message: readErrorMessage(err, t("team.createFailed")),
			});
		} finally {
			teamCreateBusy.current = false;
			setBusy(false);
		}
	}

	async function handleRemoveMember(member: TeamMember) {
		if (!window.confirm(t("team.confirmRemove", { member: memberLabel(member, t) }))) return;

		setBusy(true);
		setStatus(null);
		try {
			await removeMember(member.user_id);
			setStatus({
				tone: "success",
				message: t("team.removed", { member: memberLabel(member, t) }),
			});
		} catch (err) {
			setStatus({
				tone: "error",
				message: readErrorMessage(err, t("team.removeFailed")),
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
			setStatus({
				tone: "success",
				message: t("team.roleUpdated", { role: t(ROLE_LABELS[newRole]) }),
			});
		} catch (err) {
			setStatus({
				tone: "error",
				message: readErrorMessage(err, t("team.roleFailed")),
			});
		} finally {
			setBusy(false);
		}
	}

	if (isLoading) {
		return (
			<div className="card">
				<p className="muted">{t("team.loading")}</p>
			</div>
		);
	}

	if (!currentTeam) {
		return (
			<div className="card">
				<h2>{t("team.management")}</h2>
				{error ? (
					<>
						<div className="notice notice-danger" role="alert" aria-live="assertive">
							<b>{t("team.membershipFailed")}</b>
							<div className="muted small" style={{ marginTop: 6 }}>
								{error}
							</div>
							<div className="muted small" style={{ marginTop: 6 }}>
								{t("team.membershipFailedBody")}
							</div>
						</div>
					</>
				) : (
					<>
						<p className="muted">{t("team.noTeam")}</p>

						{showCreateTeam ? (
							<form onSubmit={handleCreateTeam}>
								<label className="label">
									{t("team.name")}
									<input
										className="input"
										type="text"
										readOnly={Boolean(teamCreateAttempt)}
										value={newTeamName}
										onChange={(e) => setNewTeamName(e.target.value)}
										placeholder={t("team.namePlaceholder")}
										required
									/>
								</label>
								<div className="row">
									<button className="button" type="submit" disabled={busy}>
										{teamCreateAttempt ? t("team.retryCreate") : t("team.create")}
									</button>
									<button
										className="button button-secondary"
										type="button"
										onClick={cancelTeamCreate}
									>
										{t("common.cancel")}
									</button>
								</div>
							</form>
						) : (
							<button className="button" onClick={startTeamCreate}>
								{t("team.createFirst")}
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
							{t("team.plan")} <span className="pill">{currentTeam.plan}</span>
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
							{t("team.newTeam")}
						</button>
					)}
				</div>

				{canManageTeam ? null : (
					<div className="notice" style={{ marginTop: 14 }}>
						{t("team.readOnly")}
					</div>
				)}

				{showCreateTeam && (
					<form
						onSubmit={handleCreateTeam}
						style={{ marginTop: "16px", paddingTop: "16px", borderTop: "1px solid var(--border)" }}
					>
						<label className="label">
							{t("team.newName")}
							<input
								className="input"
								type="text"
								readOnly={Boolean(teamCreateAttempt)}
								value={newTeamName}
								onChange={(e) => setNewTeamName(e.target.value)}
								placeholder={t("team.newNamePlaceholder")}
								required
							/>
						</label>
						<div className="row">
							<button className="button" type="submit" disabled={busy}>
								{teamCreateAttempt ? t("team.retryCreate") : t("team.create")}
							</button>
							<button className="button button-secondary" type="button" onClick={cancelTeamCreate}>
								{t("common.cancel")}
							</button>
						</div>
					</form>
				)}
			</div>

			{/* Members List */}
			<div className="card">
				<h3>
					{membersError ? t("team.members") : t("team.membersCount", { count: members.length })}
				</h3>

				{membersError ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						<b>{t("team.membersUnavailable")}</b>
						<div className="muted small" style={{ marginTop: 6 }}>
							{membersError}
						</div>
						<div className="muted small" style={{ marginTop: 6 }}>
							{t("team.membersUnavailableBody")}
						</div>
					</div>
				) : null}

				{!membersError && !memberEmailsAvailable ? (
					<div className="notice notice-warning" style={{ marginBottom: 14 }}>
						<b>{canManageTeam ? t("team.emailsUnavailable") : t("team.emailsRestricted")}</b>
						<div className="muted small" style={{ marginTop: 6 }}>
							{canManageTeam ? t("team.emailsUnavailableBody") : t("team.emailsRestrictedBody")}
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
								{t("team.email")}
								<input
									className="input"
									type="email"
									value={inviteEmail}
									onChange={(e) => setInviteEmail(e.target.value)}
									placeholder={t("team.emailPlaceholder")}
									required
								/>
							</label>
							<label className="label" style={{ margin: 0 }}>
								{t("team.role")}
								<select
									className="input"
									value={inviteRole}
									onChange={(e) => setInviteRole(e.target.value as TeamRole)}
									style={{ padding: "10px 13px" }}
								>
									{ASSIGNABLE_ROLES.map((role) => (
										<option key={role} value={role}>
											{t(ROLE_LABELS[role])}
										</option>
									))}
								</select>
							</label>
							<button className="button" type="submit" disabled={busy}>
								{t("team.invite")}
							</button>
						</div>
						<p className="muted small">{t(ROLE_DESCRIPTIONS[inviteRole])}</p>
						<p className="muted small">{t("team.inviteNote")}</p>
						{inviteLink && (
							<label>
								{t("team.inviteLink")}
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
							<h4>{t("team.pending")}</h4>
							<button
								className="button button-secondary"
								type="button"
								disabled={busy || loadingInvitations}
								onClick={() => void loadInvitations()}
							>
								{t("team.refreshInvites")}
							</button>
						</div>
						{invitationsError ? (
							<div className="notice notice-danger" role="alert">
								{invitationsError}
							</div>
						) : null}
						{loadingInvitations ? <p className="muted">{t("team.loadingInvites")}</p> : null}
						{!loadingInvitations && !invitationsError && invitations.length === 0 ? (
							<p className="muted">{t("team.noPending")}</p>
						) : null}
						{!loadingInvitations && !invitationsError && invitations.length > 0 ? (
							<table className="table">
								<thead>
									<tr>
										<th>{t("team.recipient")}</th>
										<th>{t("team.role")}</th>
										<th>{t("team.expires")}</th>
										<th className="right">{t("team.actions")}</th>
									</tr>
								</thead>
								<tbody>
									{invitations.map((invitation) => (
										<tr key={invitation.id}>
											<td>{invitation.email}</td>
											<td>{t(ROLE_LABELS[invitation.role])}</td>
											<td>{new Date(invitation.expires_at).toLocaleString()}</td>
											<td className="right">
												<button
													className="button button-secondary"
													type="button"
													disabled={busy}
													onClick={() => void handleInvitationAction(invitation, "resend")}
												>
													{t("team.replaceLink")}
												</button>{" "}
												<button
													className="button button-secondary"
													type="button"
													disabled={busy}
													onClick={() => void handleInvitationAction(invitation, "revoke")}
												>
													{t("team.revokeInvite")}
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
								<th>{t("team.member")}</th>
								<th>{t("team.role")}</th>
								{canManageTeam && <th className="right">{t("team.actions")}</th>}
							</tr>
						</thead>
						<tbody>
							{members.map((member) => (
								<tr key={member.id}>
									<td>
										<div className="row">
											<div>
												<div>{memberLabel(member, t)}</div>
												{member.invited_by && (
													<div className="small muted">{t("team.invitedBy")}</div>
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
															{t(ROLE_LABELS[role])}
														</option>
													),
												)}
											</select>
										) : (
											<span className="pill">{t(ROLE_LABELS[member.role])}</span>
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
													{t("team.remove")}
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
					<b>{t("team.error")}</b> {error}
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
