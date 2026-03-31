import { Link } from "react-router-dom";

export function LandingPage() {
	return (
		<div className="stack">
			<section className="hero">
				<div className="hero-inner">
					<div>
						<div className="pill">Edge-first AI Agent Detection and Response</div>
						<h1 className="hero-title">Protect your AI agent in minutes.</h1>
						<p className="hero-subtitle">
							Singularity AIDR inspects tool calls, plugin actions, package installs, and
							prompt-abuse patterns, then enforces <span className="mono">allow | ask | deny</span>{" "}
							locally.
						</p>
						<div className="row" style={{ marginTop: 14, flexWrap: "wrap" }}>
							<Link className="button" to="/pilot">
								Get Pilot Access
							</Link>
							<Link className="button button-secondary" to="/demo">
								Book Demo
							</Link>
							<Link className="button button-secondary" to="/waitlist">
								Join Waitlist
							</Link>
						</div>
						<p className="muted small" style={{ marginTop: 10 }}>
							Auth-first. Local enforcement. Offline-friendly after enrollment.
						</p>
					</div>

					<div className="card hero-card">
						<div className="muted small">What it catches</div>
						<ul className="list">
							<li>Download-and-execute chains</li>
							<li>Workspace escapes and sensitive path writes</li>
							<li>Risky package installs and lockfile drift</li>
							<li>Suspicious plugin behavior and integrity drift</li>
							<li>Prompt-injection attempts to disable protections</li>
						</ul>
						<div className="notice" style={{ marginTop: 12 }}>
							<div className="muted small">Pilot pricing</div>
							<div>
								<b>1 protected agent free</b>
							</div>
							<div className="muted small">$2 / month per additional agent (coming soon)</div>
							<div className="row" style={{ marginTop: 10 }}>
								<Link className="button button-secondary" to="/pricing">
									View Pricing
								</Link>
							</div>
						</div>
					</div>
				</div>
			</section>

			<section className="card">
				<h2>How it works</h2>
				<div className="cols">
					<div>
						<div className="muted small">1. Install</div>
						<div>
							Install the connector for your runtime (Claude Code, Cursor/VS Code, OpenClaw,
							OpenCode).
						</div>
					</div>
					<div>
						<div className="muted small">2. Authorize</div>
						<div>
							Authorize once in your browser using a short code (Google OAuth via Supabase).
						</div>
					</div>
					<div>
						<div className="muted small">3. Protect</div>
						<div>Your agent stays protected locally and reports incidents to the dashboard.</div>
					</div>
				</div>
			</section>
		</div>
	);
}
