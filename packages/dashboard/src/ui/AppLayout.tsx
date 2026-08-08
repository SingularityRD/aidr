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
				<header className="topbar">
					<div className="brand">
						<Link to="/" className="brand-link">
							Singularity AIDR
						</Link>
					</div>
					<nav className="nav">
						<NavLink to="/onboarding">Onboarding</NavLink>
						<NavLink to="/agents">Agents</NavLink>
						<NavLink to="/autosecops">AutoSecOps</NavLink>
						<NavLink to="/incidents">Incidents</NavLink>
						<NavLink to="/api-keys">API Keys</NavLink>
						<NavLink to="/billing">Billing</NavLink>
					</nav>
					<div className="header-actions">
						<ThemeToggle />
						<button
							className="button button-secondary"
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
					</div>
				</header>
				<main className="main">
					{signOutError ? (
						<div className="notice notice-danger" role="alert">
							{signOutError}
						</div>
					) : null}
					{supabaseEnvError ? (
						<div className="notice notice-danger">
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
