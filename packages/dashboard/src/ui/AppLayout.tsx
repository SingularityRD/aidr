import { useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { TeamProvider, useTeam } from "../enterprise/team-provider";
import { supabaseEnvError } from "../lib/supabase";
import { signOut } from "./session";
import { ThemeToggle } from "./ThemeToggle";

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
	if (!currentTeam && error) return <div role="alert"><p>Your team membership could not be loaded.</p><p>{error}</p></div>;
	// TeamProvider now bootstraps identity and gates BEFORE any protected table
	// read. Requiring currentTeam to discover the MFA policy deadlocked at AAL1.
	return <Outlet />;
}

function TeamNavLinks() {
	const { canEditPolicy, roleResolved } = useTeam();

	return (
		<>
			<NavLink to="/team">Team</NavLink>
			{!roleResolved || canEditPolicy ? <NavLink to="/policies">Policies</NavLink> : null}
		</>
	);
}

export function AppLayout() {
	const navigate = useNavigate();
	const [signOutError, setSignOutError] = useState<string | null>(null);

	return (
		<TeamProvider>
			<div className="app">
				<a className="skip-link" href="#main-content">
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
				<main className="main" id="main-content">
					<nav className="navcard" aria-label="Dashboard">
						<NavLink to="/onboarding">Connect</NavLink>
						<NavLink to="/dashboard">Dashboard</NavLink>
						<NavLink to="/billing">Billing</NavLink>
						<NavLink to="/api-keys">API Keys</NavLink>
						<NavLink to="/agents">Agents</NavLink>
						<NavLink to="/events">Events</NavLink>
						<NavLink to="/incidents">Incidents</NavLink>
						<NavLink to="/autosecops">AutoSecOps</NavLink>
						<NavLink to="/settings">Settings</NavLink>
						<TeamNavLinks />
						<span className="navcard-signout">
							<button
								className="button button-secondary button-sm"
								type="button"
								onClick={async () => {
									setSignOutError(null);
									try {
										await signOut();
										navigate("/login");
									} catch (cause) {
										setSignOutError(
											cause instanceof Error ? cause.message : "Sign out could not be completed.",
										);
									}
								}}
							>
								Sign out
							</button>
						</span>
					</nav>
					{signOutError ? (
						<div className="notice notice-danger" role="alert" style={{ marginBottom: 14 }}>
							{signOutError}
						</div>
					) : null}
					{supabaseEnvError ? (
						<div className="notice notice-danger" style={{ marginBottom: 14 }}>
							<b>Dashboard environment is incomplete.</b>
							<div className="muted small" style={{ marginTop: 6 }}>
								{supabaseEnvError}
							</div>
						</div>
					) : null}
					<ManagedOutlet />
				</main>
			</div>
		</TeamProvider>
	);
}
