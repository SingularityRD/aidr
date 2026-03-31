import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { supabaseEnvError } from "../lib/supabase";
import { signOut } from "./session";

export function AppLayout() {
	const navigate = useNavigate();

	return (
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
					<NavLink to="/incidents">Incidents</NavLink>
					<NavLink to="/api-keys">API Keys</NavLink>
					<NavLink to="/billing">Billing</NavLink>
				</nav>
				<button
					className="button button-secondary"
					type="button"
					onClick={async () => {
						await signOut();
						navigate("/login");
					}}
				>
					Sign out
				</button>
			</header>
			<main className="main">
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
	);
}
