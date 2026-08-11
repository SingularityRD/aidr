import { Link } from "react-router-dom";

const launchLinks = [
	{ name: "Run Demo", href: "/demo", desc: "Controlled synthetic evaluation." },
	{ name: "Get Started", href: "/login", desc: "Managed control plane." },
	{ name: "View Pricing", href: "/pricing", desc: "Pilot, Pro and enterprise paths." },
	{ name: "Request Pilot", href: "/pilot", desc: "Start with an approval-gated pilot." },
];

const _highlights = [
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
			<section className="card hero-card">
				<div className="pill" style={{ marginBottom: 14 }}>
					Edge-first AI Agent Detection &amp; Response
				</div>
				<h1
					style={{
						fontSize: "clamp(30px, 6vw, 54px)",
						lineHeight: 1.04,
						letterSpacing: "-0.03em",
						marginBottom: 12,
					}}
				>
					Security layer for AI agents.
				</h1>
				<p style={{ color: "var(--text-secondary)", maxWidth: 720, lineHeight: "27px" }}>
					Singularity AIDR protects runtime actions, surfaces incidents, and gives managed
					visibility without forcing cloud-only enforcement. Install by prompt, authorize in
					browser, and review the guided setup for your supported runtime.
				</p>
				<div className="row" style={{ marginTop: 20 }}>
					<Link className="button button-lg" to="/login">
						Get Started
					</Link>
					<Link className="button button-secondary button-lg" to="/demo">
						Run the demo
					</Link>
				</div>
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
					<div className="pill" style={{ marginBottom: 12 }}>
						Product Surface
					</div>
					<h2
						style={{
							fontSize: 28,
							lineHeight: 1.08,
							letterSpacing: "-0.03em",
							marginBottom: 10,
						}}
					>
						Security controls your agent can feel.
					</h2>
					<p style={{ color: "var(--text-secondary)", lineHeight: "26px", marginBottom: 16 }}>
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
					{/* Enforcement-path diagram (decorative, token-driven) */}
					<svg
						width="340"
						height="240"
						viewBox="0 0 340 240"
						fill="none"
						role="img"
						aria-label="Diagram: agent tool calls pass through the AIDR policy layer before reaching commands, files, and the network"
					>
						<rect
							x="16"
							y="26"
							width="128"
							height="52"
							rx="12"
							fill="var(--surface-soft)"
							stroke="var(--panel-border)"
						/>
						<text
							x="80"
							y="49"
							textAnchor="middle"
							fontSize="12"
							fontWeight="600"
							fill="var(--text-primary)"
						>
							AI agent
						</text>
						<text x="80" y="66" textAnchor="middle" fontSize="10" fill="var(--text-secondary)">
							tool calls
						</text>

						<rect
							x="106"
							y="104"
							width="128"
							height="56"
							rx="12"
							fill="var(--accent-soft)"
							stroke="var(--accent)"
							strokeWidth="1.4"
						/>
						<text
							x="170"
							y="128"
							textAnchor="middle"
							fontSize="12"
							fontWeight="700"
							fill="var(--accent)"
						>
							AIDR policy layer
						</text>
						<text x="170" y="145" textAnchor="middle" fontSize="10" fill="var(--text-secondary)">
							allow · ask · deny
						</text>

						<rect
							x="196"
							y="184"
							width="128"
							height="42"
							rx="12"
							fill="var(--surface-soft)"
							stroke="var(--panel-border)"
						/>
						<text
							x="260"
							y="209"
							textAnchor="middle"
							fontSize="11"
							fontWeight="600"
							fill="var(--text-primary)"
						>
							commands · files · web
						</text>

						<path
							d="M96 78 L146 104"
							stroke="var(--accent)"
							strokeWidth="1.6"
							strokeDasharray="5 4"
						/>
						<path
							d="M196 160 L242 184"
							stroke="var(--accent)"
							strokeWidth="1.6"
							strokeDasharray="5 4"
						/>
						<circle cx="146" cy="104" r="3" fill="var(--accent)" />
						<circle cx="242" cy="184" r="3" fill="var(--accent)" />
					</svg>
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
			<section id="install" className="card hero-card" style={{ textAlign: "center" }}>
				<h2 style={{ fontSize: 24, marginBottom: 10 }}>Ready to protect your AI agents?</h2>
				<p className="muted" style={{ marginBottom: 18 }}>
					Get started and secure your first agent in minutes.
				</p>
				<div className="row" style={{ justifyContent: "center" }}>
					<Link className="button button-lg" to="/login">
						Get Started
					</Link>
				</div>
			</section>
		</div>
	);
}
