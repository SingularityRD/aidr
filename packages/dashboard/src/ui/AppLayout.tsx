import { useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { TeamProvider, useTeam } from "../enterprise/team-provider";
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
	if (isLoading) return <div role="status">Resolving the managed tenant…</div>;
	if (!currentTeam && error)
		return (
			<div role="alert">
				<p>Your team membership could not be loaded.</p>
				<p>{error}</p>
			</div>
		);
	// TeamProvider now bootstraps identity and gates BEFORE any protected table
	// read. Requiring currentTeam to discover the MFA policy deadlocked at AAL1.
	return <Outlet />;
}

function TeamNavLinks() {
	const { canEditPolicy, currentRole, roleResolved } = useTeam();

	return (
		<>
			<NavLink to="/team">Team</NavLink>
			{currentRole === "owner" ? <NavLink to="/scim">Directory provisioning</NavLink> : null}
			{currentRole === "owner" || currentRole === "admin" ? (
				<NavLink to="/retention">Legal holds & retention</NavLink>
			) : null}
			{currentRole === "owner" ? <NavLink to="/sso">Single sign-on</NavLink> : null}
			{!roleResolved || canEditPolicy ? <NavLink to="/policies">Policies</NavLink> : null}
			{canEditPolicy ? <NavLink to="/siem">SIEM export</NavLink> : null}
			{currentRole === "owner" || currentRole === "admin" ? (
				<NavLink to="/compliance">Compliance</NavLink>
			) : null}
			{currentRole === "owner" || currentRole === "admin" ? (
				<NavLink to="/governance">Governance</NavLink>
			) : null}
			{currentRole === "owner" || currentRole === "admin" ? (
				<NavLink to="/governance/detection-exceptions">Detection exceptions</NavLink>
			) : null}
			<NavLink to="/governance/register">AI register</NavLink>
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
	return (
		<NavLink to="/approvals">
			Approvals
			{count ? (
				<span
					className="badge badge-warning badge-plain nav-count"
					data-testid="approvals-pending-count"
				>
					<span className="sr-only">, pending: </span>
					{count > 99 ? "99+" : count}
				</span>
			) : null}
		</NavLink>
	);
}

export function AppLayout() {
	const navigate = useNavigate();
	const [signingOut, setSigningOut] = useState(false);
	if (signingOut) return <div role="status">Ending this browser session…</div>;

	return (
		<TeamProvider>
			<div className="app">
				<a className="skip-link" href="#page-content">
					Skip to content
				</a>
				<header className="console-topbar">
					<Link to="/" className="brand-link">
						<span className="brand-word" aria-hidden="true">
							AIDR
						</span>
						<span className="brand-sub" aria-hidden="true">
							Control plane
						</span>
						<span className="sr-only">Singularity AIDR</span>
					</Link>
					<div className="header-actions">
						<ThemeToggle />
					</div>
				</header>
				<main className="main">
					<nav className="navcard" aria-label="Dashboard">
						<NavLink to="/onboarding">Connect</NavLink>
						<NavLink to="/downloads">Downloads</NavLink>
						<NavLink to="/dashboard">Dashboard</NavLink>
						<NavLink to="/billing">Billing</NavLink>
						<NavLink to="/api-keys">API Keys</NavLink>
						<NavLink to="/agents">Agents</NavLink>
						<NavLink to="/events">Events</NavLink>
						<NavLink to="/discovery">Discovery</NavLink>
						<NavLink to="/posture">Posture</NavLink>
						<NavLink to="/incidents">Incidents</NavLink>
						<ApprovalsNavLink />
						<NavLink to="/privacy-guard">Browser Privacy</NavLink>
						<NavLink to="/autosecops">AutoSecOps</NavLink>
						<NavLink to="/settings">Settings</NavLink>
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
								Sign out
							</button>
						</span>
					</nav>
					{supabaseEnvError ? (
						<div className="notice notice-danger" style={{ marginBottom: 14 }}>
							<b>Dashboard environment is incomplete.</b>
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
