import { Link } from "react-router-dom";

const launchLinks = [{ name: "Get Started", href: "/login", desc: "Managed control plane." }];

const highlights = [
	"Tool-call inspection: shell, file, network, MCP/plugin actions",
	"Local enforcement with managed visibility",
	"Auth-first model with offline grace after enrollment",
	"Prompt-install onboarding for Claude/Cursor/VS Code/OpenClaw/OpenCode",
];

const featurePillars = [
	{
		title: "Prompt-first setup",
		desc: "Install by prompt, then finish auth in the browser with zero key copying.",
	},
	{
		title: "Device authorization",
		desc: "Short-lived codes bootstrap enrollment and unlock managed protection safely.",
	},
	{
		title: "Incident correlation",
		desc: "Repeated denials, suspicious retries, and abuse patterns roll into one case.",
	},
	{
		title: "Package and plugin guard",
		desc: "Catch typosquats, lifecycle risk, integrity drift, and command surface exposure.",
	},
	{
		title: "Dashboard sync",
		desc: "Every protected agent reports health, incidents, and entitlement state centrally.",
	},
	{
		title: "Offline grace",
		desc: "Enrolled agents keep working when the network drops, within the signed cache window.",
	},
];

export function LandingPage() {
	return (
		<div className="stack">
			{/* Hero Section */}
			<section className="card">
				<div className="pill" style={{ marginBottom: 8 }}>
					Edge-first AI Agent Detection & Response
				</div>
				<h1
					style={{
						fontSize: "clamp(30px, 6vw, 56px)",
						lineHeight: 1.05,
						color: "var(--text-primary)",
						letterSpacing: "-0.02em",
						marginBottom: 10,
					}}
				>
					Launch-ready security layer for AI agents.
				</h1>
				<p style={{ color: "var(--text-secondary)", maxWidth: 760, lineHeight: "28px" }}>
					Singularity AIDR protects runtime actions, surfaces incidents, and gives managed
					visibility without forcing cloud-only enforcement. Install by prompt, authorize in
					browser, and go live in minutes.
				</p>
			</section>

			{/* Launch Links */}
			<section className="launch-links">
				{launchLinks.map((item) => (
					<Link key={item.name} to={item.href} className="launch-link">
						<div className="launch-link-title">{item.name}</div>
						<div className="launch-link-desc">{item.desc}</div>
					</Link>
				))}
			</section>

			{/* Security Showcase */}
			<section className="security-showcase">
				<div className="card">
					<div className="pill" style={{ marginBottom: 8 }}>
						Product Surface
					</div>
					<h2
						style={{
							fontSize: 30,
							lineHeight: 1.06,
							letterSpacing: "-0.03em",
							color: "var(--text-primary)",
							marginBottom: 10,
						}}
					>
						Security controls your agent can feel.
					</h2>
					<p style={{ color: "var(--text-secondary)", lineHeight: "26px", marginBottom: 14 }}>
						We keep the runtime lightweight, but the policy surface is deep. Singularity AIDR turns
						a single prompt into a protected agent, then keeps that agent visible with device auth,
						incident correlation, package and plugin guards, and seat-aware control.
					</p>
					<div className="bullet-list">
						{[
							"Prompt install in one shot, no manual key copying",
							"Local enforcement with dashboard-backed visibility",
							"Package, plugin, and prompt abuse detection",
							"Seat-aware onboarding for pilot and paid expansion",
						].map((item) => (
							<div key={item} className="bullet-item">
								<span className="bullet-dot" />
								<span style={{ color: "var(--text-secondary)" }}>{item}</span>
							</div>
						))}
					</div>
				</div>
				<div className="security-showcase-diagram">
					{/* Isometric diagram placeholder - matches landing page */}
					<div
						style={{
							width: 280,
							height: 200,
							background: "var(--bg-secondary)",
							borderRadius: 16,
							border: "1px solid var(--panel-border)",
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							color: "var(--text-secondary)",
							fontSize: 14,
						}}
					>
						<svg
							width="120"
							height="120"
							viewBox="0 0 120 120"
							fill="none"
							style={{ opacity: 0.6 }}
						>
							<rect
								x="20"
								y="40"
								width="40"
								height="40"
								rx="8"
								fill="var(--surface-soft)"
								stroke="var(--panel-border)"
								strokeWidth="1"
							/>
							<rect
								x="45"
								y="25"
								width="40"
								height="40"
								rx="8"
								fill="var(--panel-bg)"
								stroke="var(--accent)"
								strokeWidth="1.5"
							/>
							<rect
								x="60"
								y="55"
								width="40"
								height="40"
								rx="8"
								fill="var(--surface-soft)"
								stroke="var(--panel-border)"
								strokeWidth="1"
							/>
							<path d="M45 65L25 85" stroke="var(--accent)" strokeWidth="2" strokeDasharray="4 2" />
							<path d="M85 65L65 45" stroke="var(--accent)" strokeWidth="2" strokeDasharray="4 2" />
						</svg>
					</div>
				</div>
			</section>

			{/* Core Features */}
			<section className="card">
				<div className="pill" style={{ marginBottom: 16 }}>
					Core Features
				</div>
				<div className="feature-grid">
					{featurePillars.map((feature) => (
						<article key={feature.title} className="feature-card">
							<div className="feature-card-title">{feature.title}</div>
							<div className="feature-card-desc">{feature.desc}</div>
						</article>
					))}
				</div>
			</section>

			{/* Install CTA */}
			<section id="install" className="card" style={{ textAlign: "center" }}>
				<h2 style={{ fontSize: 24, marginBottom: 12 }}>Ready to protect your AI agents?</h2>
				<p className="muted" style={{ marginBottom: 16 }}>
					Get started and secure your first agent in minutes.
				</p>
				<div className="row" style={{ justifyContent: "center" }}>
					<Link className="button" to="/login">
						Get Started
					</Link>
				</div>
			</section>
		</div>
	);
}
