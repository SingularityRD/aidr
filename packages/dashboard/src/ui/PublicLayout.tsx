import { Link, NavLink, Outlet } from "react-router-dom";
import { supabaseEnvError } from "../lib/supabase";
import { ThemeToggle } from "./ThemeToggle";

export function PublicLayout() {
	const showConfigWarning = Boolean(supabaseEnvError);

	return (
		<div className="app">
			<a className="skip-link" href="#page-content">
				Skip to content
			</a>
			<header className="nav-bar">
				<Link to="/" className="brand-link">
					<span className="brand-word" aria-hidden="true">
						AIDR
					</span>
					<span className="brand-sub" aria-hidden="true">
						Singularity
					</span>
					<span className="sr-only">Singularity AIDR</span>
				</Link>
				<nav className="nav" aria-label="Public">
					<NavLink to="/pricing">Editions</NavLink>
					<NavLink to="/pilot">Pilot</NavLink>
					<NavLink to="/login">Dashboard</NavLink>
				</nav>
				<div className="row">
					<Link className="button button-sm" to="/login">
						Sign in
					</Link>
					<ThemeToggle />
				</div>
			</header>
			<main className="main">
				{showConfigWarning ? (
					<div className="notice notice-danger" style={{ marginBottom: 16 }}>
						<b>Dashboard is running without Supabase credentials.</b>
						<div className="muted small" style={{ marginTop: 6 }}>
							{supabaseEnvError}
						</div>
					</div>
				) : null}
				<div id="page-content" tabIndex={-1}>
					<Outlet />
				</div>
			</main>
			<footer className="footer">
				<div className="muted small">
					&copy; {new Date().getFullYear()} Singularity AIDR. Local-first AI agent detection and
					response.
				</div>
				<nav className="footer-links" aria-label="Support and legal">
					<Link to="/support">Support</Link>
					<Link to="/status">Status</Link>
					<Link to="/privacy">Privacy</Link>
					<Link to="/security">Security</Link>
					<Link to="/terms">Terms</Link>
				</nav>
			</footer>
		</div>
	);
}
