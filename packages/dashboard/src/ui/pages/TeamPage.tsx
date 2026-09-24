import { AdminPanel } from "../../enterprise/admin-panel";
import { TeamAuditPanel } from "../../enterprise/team-audit-panel";

/**
 * Team administration surface (AIDR-008).
 *
 * AdminPanel and its role gating already existed but nothing routed to it, so
 * team management was unreachable from the product. The route is
 * session-protected; the member-management controls inside AdminPanel are
 * additionally gated on the caller's role, and public.team_members carries the
 * same rules in row-level security so a non-admin cannot change membership by
 * calling the API directly either.
 */
export function TeamPage() {
	return (
		<div className="stack">
			<div className="card">
				<div className="pill" style={{ marginBottom: 8 }}>
					Administration
				</div>
				<h1>Team</h1>
				<p className="muted" style={{ maxWidth: 760 }}>
					Manage team membership and roles. Owners and administrators can invite, re-role and remove
					members; members and viewers get a read-only view of the same team.
				</p>
			</div>
			<AdminPanel />
			<TeamAuditPanel />
		</div>
	);
}
