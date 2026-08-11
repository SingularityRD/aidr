import { useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { TeamProvider } from "../enterprise/team-provider";
import { supabaseEnvError } from "../lib/supabase";
import { signOut } from "./session";
import { ThemeToggle } from "./ThemeToggle";

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
					<Outlet />
				</main>
			</div>
		</TeamProvider>
	);
}
