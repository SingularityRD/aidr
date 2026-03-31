import { Link, NavLink, Outlet } from "react-router-dom";
import { supabaseEnvError } from "../lib/supabase";

export function PublicLayout() {
	return (
		<div className="app">
			<header className="topbar">
				<div className="brand">
					<Link to="/" className="brand-link">
						Singularity AIDR
					</Link>
				</div>
				<nav className="nav">
					<NavLink to="/pricing">Pricing</NavLink>
					<NavLink to="/pilot">Pilot</NavLink>
					<NavLink to="/demo">Demo</NavLink>
					<NavLink to="/waitlist">Waitlist</NavLink>
				</nav>
				<Link className="button button-secondary" to="/login">
					Sign in
				</Link>
			</header>
			<main className="main">
				{supabaseEnvError ? (
					<div className="notice notice-danger">
						<b>Dashboard is running without Supabase credentials.</b>
						<div className="muted small" style={{ marginTop: 6 }}>
							{supabaseEnvError}
						</div>
					</div>
				) : null}
				<Outlet />
			</main>
			<footer className="footer">
				<div className="muted small">
					© {new Date().getFullYear()} Singularity AIDR. Local-first AI agent detection and
					response.
				</div>
			</footer>
		</div>
	);
}
