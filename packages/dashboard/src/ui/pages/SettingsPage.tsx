import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { supabaseEnvError } from "../../lib/supabase";
import { getSession, signOut } from "../session";
import { useTheme } from "../ThemeProvider";

export function SettingsPage() {
	const navigate = useNavigate();
	const { theme, toggleTheme } = useTheme();
	const [email, setEmail] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		async function load() {
			try {
				const session = await getSession();
				if (!cancelled) setEmail(session?.user?.email ?? null);
			} catch (cause) {
				if (!cancelled) {
					setError(cause instanceof Error ? cause.message : "Unable to load your session.");
				}
			}
		}
		load();
		return () => {
			cancelled = true;
		};
	}, []);

	return (
		<div className="stack">
			<div className="card">
				<h1>Settings</h1>
				<p className="muted">Session, appearance, and privacy controls for this console.</p>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			<div className="card">
				<h2>Account</h2>
				<div className="session-box" style={{ marginTop: 10, maxWidth: 420 }}>
					<div className="muted small">Signed in as</div>
					<div className="mono" style={{ marginTop: 2, overflowWrap: "anywhere" }}>
						{email ?? "unknown"}
					</div>
				</div>
				<div className="row" style={{ marginTop: 12 }}>
					<button
						className="button button-secondary"
						type="button"
						onClick={async () => {
							setError(null);
							try {
								await signOut();
								navigate("/login");
							} catch (cause) {
								setError(
									cause instanceof Error ? cause.message : "Sign out could not be completed.",
								);
							}
						}}
					>
						Sign out of this session
					</button>
				</div>
			</div>

			<div className="card">
				<h2>Appearance</h2>
				<p className="muted">The console follows your stored preference, then your OS setting.</p>
				<div className="row" style={{ marginTop: 12 }}>
					<button
						className={`button ${theme === "light" ? "" : "button-secondary"}`}
						type="button"
						aria-pressed={theme === "light"}
						onClick={() => {
							if (theme !== "light") toggleTheme();
						}}
					>
						Light
					</button>
					<button
						className={`button ${theme === "dark" ? "" : "button-secondary"}`}
						type="button"
						aria-pressed={theme === "dark"}
						onClick={() => {
							if (theme !== "dark") toggleTheme();
						}}
					>
						Dark
					</button>
				</div>
			</div>

			<div className="card">
				<h2>Privacy &amp; data</h2>
				<p className="muted">
					AIDR performs local interception and redaction before telemetry leaves the device. Review
					the canonical deployment documents for retention and scope.
				</p>
				<div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to="/privacy">
						Privacy notice
					</Link>
					<Link className="button button-secondary button-sm" to="/security">
						Security
					</Link>
					<Link className="button button-secondary button-sm" to="/terms">
						Terms
					</Link>
					<Link className="button button-secondary button-sm" to="/support">
						Support
					</Link>
				</div>
			</div>

			{supabaseEnvError ? (
				<div className="notice notice-danger" role="alert">
					<b>Environment is incomplete.</b>
					<div className="muted small" style={{ marginTop: 6 }}>
						{supabaseEnvError}
					</div>
				</div>
			) : null}
		</div>
	);
}
