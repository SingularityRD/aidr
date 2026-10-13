import { useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { TeamProvider, useTeam } from "../enterprise/team-provider";
import { LanguageToggle, useT } from "../i18n/I18nProvider";
import { supabaseEnvError } from "../lib/supabase";
import { signOut } from "./session";
import { ThemeToggle } from "./ThemeToggle";
import { usePendingApprovalCount } from "./use-pending-approvals";

/**
 * Team navigation entries.
 *
 * "Team" is shown to every authenticated user because every role may read the
 * membership list ("Team Members" in AdminPanel is read-only for members and
 * viewers). "Policies" is hidden only once the caller's role is known to lack
 * policy-edit rights — while the role is still loading the link stays visible,
 * because hiding a capability on an unresolved role would make a slow or
 * failed lookup look like a permission decision. The page and row-level
 * security both re-check the permission, so link visibility is never the
 * control.
 */
function ManagedOutlet() {
	const { currentTeam, isLoading, error } = useTeam();
	const t = useT();
	if (isLoading) return <div role="status">{t("layout.resolvingTenant")}</div>;
	if (!currentTeam && error)
		return (
			<div role="alert">
				<p>{t("layout.teamLoadFailed")}</p>
				<p>{error}</p>
			</div>
		);
	// TeamProvider now bootstraps identity and gates BEFORE any protected table
	// read. Requiring currentTeam to discover the MFA policy deadlocked at AAL1.
	return <Outlet />;
}

function TeamNavLinks() {
	const { canEditPolicy, currentRole, roleResolved } = useTeam();
	const t = useT();

	return (
		<>
			<NavLink to="/team">{t("nav.team")}</NavLink>
			{currentRole === "owner" ? <NavLink to="/scim">{t("nav.scim")}</NavLink> : null}
			{currentRole === "owner" || currentRole === "admin" ? (
				<NavLink to="/retention">{t("nav.retention")}</NavLink>
			) : null}
			{currentRole === "owner" ? <NavLink to="/sso">{t("nav.sso")}</NavLink> : null}
			{!roleResolved || canEditPolicy ? (
				<NavLink to="/policies">{t("nav.policies")}</NavLink>
			) : null}
			{canEditPolicy ? <NavLink to="/siem">{t("nav.siem")}</NavLink> : null}
			{currentRole === "owner" || currentRole === "admin" ? (
				<NavLink to="/compliance">{t("nav.compliance")}</NavLink>
			) : null}
			{currentRole === "owner" || currentRole === "admin" ? (
				<NavLink to="/governance">{t("nav.governance")}</NavLink>
			) : null}
			{currentRole === "owner" || currentRole === "admin" ? (
				<NavLink to="/governance/detection-exceptions">{t("nav.detectionExceptions")}</NavLink>
			) : null}
			<NavLink to="/governance/register">{t("nav.aiRegister")}</NavLink>
		</>
	);
}

/**
 * Dashboard approvals link. The pending-count badge is read only for roles
 * that can decide, once the role is resolved (after the identity gate).
 */
function ApprovalsNavLink() {
	const { currentTeam, currentRole, roleResolved } = useTeam();
	const canDecide = roleResolved && (currentRole === "owner" || currentRole === "admin");
	const count = usePendingApprovalCount(canDecide && currentTeam ? currentTeam.id : null);
	const t = useT();
	return (
		<NavLink to="/approvals">
			{t("nav.approvals")}
			{count ? (
				<span
					className="badge badge-warning badge-plain nav-count"
					data-testid="approvals-pending-count"
				>
					<span className="sr-only">{t("layout.pendingCount")}</span>
					{count > 99 ? "99+" : count}
				</span>
			) : null}
		</NavLink>
	);
}

export function AppLayout() {
	const navigate = useNavigate();
	const [signingOut, setSigningOut] = useState(false);
	const t = useT();
	if (signingOut) return <div role="status">{t("layout.signingOut")}</div>;

	return (
		<TeamProvider>
			<div className="app">
				<a className="skip-link" href="#page-content">
					{t("layout.skip")}
				</a>
				<header className="console-topbar">
					<Link to="/" className="brand-link">
						<span className="brand-word" aria-hidden="true">
							AIDR
						</span>
						<span className="brand-sub" aria-hidden="true">
							{t("layout.controlPlane")}
						</span>
						<span className="sr-only">Singularity AIDR</span>
					</Link>
					<div className="header-actions">
						<LanguageToggle />
						<ThemeToggle />
					</div>
				</header>
				<main className="main">
					<nav className="navcard" aria-label={t("layout.navLabel")}>
						<NavLink to="/onboarding">{t("nav.connect")}</NavLink>
						<NavLink to="/downloads">{t("nav.downloads")}</NavLink>
						<NavLink to="/dashboard">{t("nav.dashboard")}</NavLink>
						<NavLink to="/billing">{t("nav.billing")}</NavLink>
						<NavLink to="/api-keys">{t("nav.apiKeys")}</NavLink>
						<NavLink to="/agents">{t("nav.agents")}</NavLink>
						<NavLink to="/events">{t("nav.events")}</NavLink>
						<NavLink to="/discovery">{t("nav.discovery")}</NavLink>
						<NavLink to="/posture">{t("nav.posture")}</NavLink>
						<NavLink to="/incidents">{t("nav.incidents")}</NavLink>
						<ApprovalsNavLink />
						<NavLink to="/privacy-guard">{t("nav.browserPrivacy")}</NavLink>
						<NavLink to="/autosecops">{t("nav.autosecops")}</NavLink>
						<NavLink to="/settings">{t("nav.settings")}</NavLink>
						<TeamNavLinks />
						<span className="navcard-signout">
							<button
								className="button button-secondary button-sm"
								type="button"
								onClick={async () => {
									setSigningOut(true);
									try {
										const result = await signOut();
										navigate(
											result.serverRevoked ? "/login" : "/login?signout=revocation-unconfirmed",
											{ replace: true },
										);
									} catch {
										navigate("/login?signout=local-failed", { replace: true });
									}
								}}
							>
								{t("layout.signOut")}
							</button>
						</span>
					</nav>
					{supabaseEnvError ? (
						<div className="notice notice-danger" style={{ marginBottom: 14 }}>
							<b>{t("layout.envIncomplete")}</b>
							<div className="muted small" style={{ marginTop: 6 }}>
								{supabaseEnvError}
							</div>
						</div>
					) : null}
					<div id="page-content" tabIndex={-1}>
						<ManagedOutlet />
					</div>
				</main>
			</div>
		</TeamProvider>
	);
}
