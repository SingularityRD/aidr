import { useState } from "react";
import { type TeamRole, useTeam } from "./team-provider";

const ROLE_LABELS: Record<TeamRole, string> = {
	admin: "Administrator",
	member: "Member",
	viewer: "Viewer",
};

const ROLE_DESCRIPTIONS: Record<TeamRole, string> = {
	admin: "Full access: manage team, members, policies, and billing",
	member: "Standard access: edit policies, view audit logs",
	viewer: "Read-only: view audit logs and team activity",
};

export function AdminPanel() {
	const {
		currentTeam,
		members,
		isLoading,
		error,
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
	const [status, setStatus] = useState<string | null>(null);

	async function handleInvite(e: React.FormEvent) {
		e.preventDefault();
		if (!inviteEmail.trim() || !currentTeam) return;

		setBusy(true);
		setStatus(null);

		try {
			await inviteMember(inviteEmail.trim(), inviteRole);
			setStatus(`Invitation sent to ${inviteEmail}`);
			setInviteEmail("");
		} catch (err) {
			setStatus(err instanceof Error ? err.message : "Failed to send invitation");
		} finally {
			setBusy(false);
		}
	}

	async function handleCreateTeam(e: React.FormEvent) {
		e.preventDefault();
		if (!newTeamName.trim()) return;

		setBusy(true);
		setStatus(null);

		try {
			await createTeam(newTeamName.trim());
			setStatus(`Team "${newTeamName}" created successfully`);
			setNewTeamName("");
			setShowCreateTeam(false);
		} catch (err) {
			setStatus(err instanceof Error ? err.message : "Failed to create team");
		} finally {
			setBusy(false);
		}
	}

	async function handleRemoveMember(userId: string, email: string) {
		if (!confirm(`Remove ${email} from the team?`)) return;

		setBusy(true);
		try {
			await removeMember(userId);
			setStatus(`${email} removed from team`);
		} catch (err) {
			setStatus(err instanceof Error ? err.message : "Failed to remove member");
		} finally {
			setBusy(false);
		}
	}

	async function handleRoleChange(userId: string, newRole: TeamRole) {
		setBusy(true);
		try {
			await updateMemberRole(userId, newRole);
			setStatus("Role updated successfully");
		} catch (err) {
			setStatus(err instanceof Error ? err.message : "Failed to update role");
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
				<p className="muted">You are not part of any team yet.</p>

				{showCreateTeam ? (
					<form onSubmit={handleCreateTeam}>
						<label className="label">
							Team Name
							<input
								className="input"
								type="text"
								value={newTeamName}
								onChange={(e) => setNewTeamName(e.target.value)}
								placeholder="e.g., Acme Security"
								required
							/>
						</label>
						<div className="row">
							<button className="button" type="submit" disabled={busy}>
								Create Team
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => setShowCreateTeam(false)}
							>
								Cancel
							</button>
						</div>
					</form>
				) : (
					<button className="button" onClick={() => setShowCreateTeam(true)}>
						Create Your First Team
					</button>
				)}

				{status && (
					<div className={`notice ${status.includes("Failed") ? "notice-danger" : ""}`}>
						{status}
					</div>
				)}
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
						<button
							className="button button-secondary"
							onClick={() => setShowCreateTeam(!showCreateTeam)}
						>
							+ New Team
						</button>
					)}
				</div>

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
								value={newTeamName}
								onChange={(e) => setNewTeamName(e.target.value)}
								placeholder="e.g., Security Team"
								required
							/>
						</label>
						<div className="row">
							<button className="button" type="submit" disabled={busy}>
								Create Team
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => setShowCreateTeam(false)}
							>
								Cancel
							</button>
						</div>
					</form>
				)}
			</div>

			{/* Members List */}
			<div className="card">
				<h3>Team Members ({members.length})</h3>

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
									<option value="admin">Admin</option>
									<option value="member">Member</option>
									<option value="viewer">Viewer</option>
								</select>
							</label>
							<button className="button" type="submit" disabled={busy}>
								Invite
							</button>
						</div>
						<p className="muted small">{ROLE_DESCRIPTIONS[inviteRole]}</p>
					</form>
				)}

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
										{member.avatar_url && (
											<img
												src={member.avatar_url}
												alt=""
												style={{ width: 32, height: 32, borderRadius: "50%" }}
											/>
										)}
										<div>
											<div>{member.email}</div>
											{member.invited_by && (
												<div className="small muted">Invited by team member</div>
											)}
										</div>
									</div>
								</td>
								<td>
									{canManageTeam ? (
										<select
											className="input"
											value={member.role}
											onChange={(e) =>
												void handleRoleChange(member.user_id, e.target.value as TeamRole)
											}
											style={{ padding: "6px 10px", minWidth: "120px" }}
											disabled={busy}
										>
											<option value="admin">{ROLE_LABELS.admin}</option>
											<option value="member">{ROLE_LABELS.member}</option>
											<option value="viewer">{ROLE_LABELS.viewer}</option>
										</select>
									) : (
										<span className="pill">{ROLE_LABELS[member.role]}</span>
									)}
								</td>
								{canManageTeam && (
									<td className="right">
										<button
											className="button button-secondary"
											style={{ padding: "6px 10px", fontSize: "12px" }}
											onClick={() => void handleRemoveMember(member.user_id, member.email)}
											disabled={busy}
										>
											Remove
										</button>
									</td>
								)}
							</tr>
						))}
					</tbody>
				</table>
			</div>

			{error && (
				<div className="notice notice-danger">
					<b>Error:</b> {error}
				</div>
			)}

			{status && (
				<div
					className={`notice ${status.includes("Failed") || status.includes("error") ? "notice-danger" : ""}`}
				>
					{status}
				</div>
			)}
		</div>
	);
}
