import { AdminPanel } from "../../enterprise/admin-panel";
import { TeamAuditPanel } from "../../enterprise/team-audit-panel";
import { useT } from "../../i18n/I18nProvider";

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
	const t = useT();
	return (
		<div className="stack">
			<div className="card">
				<div className="pill" style={{ marginBottom: 8 }}>
					{t("team.pill")}
				</div>
				<h1>{t("nav.team")}</h1>
				<p className="muted" style={{ maxWidth: 760 }}>
					{t("team.intro")}
				</p>
			</div>
			<AdminPanel />
			<TeamAuditPanel />
		</div>
	);
}
