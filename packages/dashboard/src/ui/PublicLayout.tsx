import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { supabaseEnvError } from "../lib/supabase";
import { useTheme } from "./ThemeProvider";

function DarkModeToggle() {
	const { theme, toggleTheme } = useTheme();

	return (
		<button
			onClick={toggleTheme}
			aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
			className="theme-toggle"
		>
			{theme === "light" ? (
				<svg
					width="18"
					height="18"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					strokeWidth="2"
					strokeLinecap="round"
					strokeLinejoin="round"
				>
					<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
				</svg>
			) : (
				<svg
					width="18"
					height="18"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					strokeWidth="2"
					strokeLinecap="round"
					strokeLinejoin="round"
				>
					<circle cx="12" cy="12" r="5" />
					<line x1="12" y1="1" x2="12" y2="3" />
					<line x1="12" y1="21" x2="12" y2="23" />
					<line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
					<line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
					<line x1="1" y1="12" x2="3" y2="12" />
					<line x1="21" y1="12" x2="23" y2="12" />
					<line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
					<line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
				</svg>
			)}
		</button>
	);
}

export function PublicLayout() {
	const location = useLocation();
	const showConfigWarning = Boolean(supabaseEnvError) && location.pathname !== "/demo";

	return (
		<div className="app">
			<header className="nav-bar">
				<div className="brand">
					<Link to="/" className="brand-link">
						Singularity AIDR
					</Link>
				</div>
				<nav className="nav">
					<NavLink to="/demo">Demo</NavLink>
					<NavLink to="/pricing">Pricing</NavLink>
					<NavLink to="/pilot">Pilot</NavLink>
					<NavLink to="/login">Dashboard</NavLink>
				</nav>
				<div className="row">
					<Link
						className="button button-secondary"
						to="/login"
						style={{ padding: "8px 14px", fontSize: "13px" }}
					>
						Sign in
					</Link>
					<DarkModeToggle />
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
				<Outlet />
			</main>
			<footer className="footer">
				<div className="muted small">
					&copy; {new Date().getFullYear()} Singularity AIDR. Local-first AI agent detection and
					response.
				</div>
				<div className="footer-links" aria-label="Support and legal">
					<Link to="/support">Support</Link>
					<Link to="/status">Status</Link>
					<Link to="/privacy">Privacy</Link>
					<Link to="/security">Security</Link>
					<Link to="/terms">Terms</Link>
				</div>
			</footer>
		</div>
	);
}
