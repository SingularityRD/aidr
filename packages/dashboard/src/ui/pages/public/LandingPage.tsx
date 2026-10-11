import { Link } from "react-router-dom";
import {
	AGENT_CONNECTORS,
	AIG_AI_COMPONENTS,
	AIG_CVE_RULES_FLOOR,
	BROWSER_GUARD_BROWSERS,
	BROWSER_GUARD_SITES,
	POSTURE_MCP_RISK_CATEGORIES,
	POSTURE_SKILL_RISK_CODES,
	SHIPPED_THREAT_RULES,
	THREAT_RULE_FILES,
} from "./product-facts";

const launchLinks = [
	{ name: "Get started", href: "/login?returnTo=%2Fonboarding", desc: "Enroll a supported agent." },
	{ name: "Sign in", href: "/login?returnTo=%2Fdashboard", desc: "Open your workspace." },
	{ name: "View Editions", href: "/pricing", desc: "Compare editions and request a quote." },
	{ name: "Request Pilot", href: "/pilot", desc: "Start with an approval-gated pilot." },
];

const productLines = [
	{
		title: "AIDR for AI coding agents",
		desc: `Connectors for ${AGENT_CONNECTORS.join(", ")} check commands, file writes and URLs against ${SHIPPED_THREAT_RULES} YAML threat rules before the host acts. Includes an MCP gateway, an SDK and a CLI.`,
	},
	{
		title: "AIDR Browser Guard",
		desc: `A ${BROWSER_GUARD_BROWSERS.join(", ")} extension that masks personal data and secrets before prompts, pastes and files reach AI chat products.`,
	},
	{
		title: "AIDR Privacy engine",
		desc: "Turkish and English detection with checksum validation and an optional enterprise gateway. NER/OCR ships without a model and is not part of the first-release scope.",
	},
	{
		title: "AI Security Posture",
		desc: `AI infrastructure vulnerability scanning with ${AIG_AI_COMPONENTS} AI component fingerprints and ${AIG_CVE_RULES_FLOOR.toLocaleString("en-US")}+ CVE rules rated by severity and CVSS, MCP server risk analysis across ${POSTURE_MCP_RISK_CATEGORIES} risk categories, ${POSTURE_SKILL_RISK_CODES[0]}–${POSTURE_SKILL_RISK_CODES[POSTURE_SKILL_RISK_CODES.length - 1]} skill and plugin scanning, and a dashboard posture view. Uploads carry identifiers and digests only.`,
	},
];

const browserGuardPoints = [
	"TR/EN personal data: T.C. kimlik, IBAN, phone numbers, email addresses, payment cards",
	"Secrets and API keys, custom terms and exact-data-match fingerprints",
	"Reversible placeholders such as [EMAIL_1]; originals are restored only on your screen",
	"Administrator-managed policy and counts-only telemetry, never prompt text",
];

const deploymentOptions = [
	{
		title: "Local mode (free)",
		desc: "Connectors and Browser Guard evaluate on the device. No account needed for detection.",
	},
	{
		title: "Cloud",
		desc: "Hosted dashboard, device enrollment, central policy, audit export, SSO and SCIM.",
	},
	{
		title: "On-premises",
		desc: "Docker Compose or Kubernetes (Helm), including air-gapped installs with a signed offline license.",
	},
];

const featurePillars = [
	{
		title: "Guided setup",
		desc: "Set up a supported runtime; managed enrollment requires a deployed control plane.",
	},
	{
		title: "Device authorization",
		desc: "Short-lived codes support enrollment in a configured managed deployment.",
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
		desc: "Configured managed agents can send redacted verdicts to the dashboard.",
	},
	{
		title: "Offline grace",
		desc: "Enrolled agents can use signed cached state during a bounded outage.",
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
					Security layer for AI agents and AI chat.
				</h1>
				<p style={{ color: "var(--text-secondary)", maxWidth: 720, lineHeight: "27px" }}>
					Singularity AIDR inspects supported agent actions on the device and masks personal data
					before prompts reach AI chat products. Managed visibility and device enrollment require a
					configured control plane. Sign in to begin onboarding or request an assisted pilot for
					your runtime and deployment.
				</p>
				<div className="row" style={{ marginTop: 20 }}>
					<Link className="button button-lg" to="/pilot">
						Request a pilot
					</Link>
					<Link className="button button-secondary button-lg" to="/login?returnTo=%2Fonboarding">
						Get started
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

			{/* Product Lines */}
			<section className="card" aria-labelledby="product-lines-heading">
				<div className="pill" style={{ marginBottom: 12 }}>
					Product Lines
				</div>
				<h2 id="product-lines-heading" style={{ fontSize: 28, lineHeight: 1.08, marginBottom: 16 }}>
					One policy plane for agents and people.
				</h2>
				<div className="feature-grid">
					{productLines.map((line) => (
						<article key={line.title} className="feature-card">
							<div className="feature-card-title">{line.title}</div>
							<div className="feature-card-desc">{line.desc}</div>
						</article>
					))}
				</div>
			</section>

			{/* Browser Guard */}
			<section className="card" aria-labelledby="browser-guard-heading">
				<div className="pill" style={{ marginBottom: 12 }}>
					Browser Guard
				</div>
				<h2 id="browser-guard-heading" style={{ fontSize: 28, lineHeight: 1.08, marginBottom: 10 }}>
					Mask sensitive data before it reaches AI chat.
				</h2>
				<p style={{ color: "var(--text-secondary)", lineHeight: "26px", marginBottom: 16 }}>
					Works on {BROWSER_GUARD_SITES.join(", ")}. Detection runs in the browser; the AI provider
					receives placeholders.
				</p>
				<div className="bullet-list">
					{browserGuardPoints.map((item) => (
						<div key={item} className="bullet-item">
							<span className="bullet-dot" />
							<span style={{ color: "var(--text-secondary)" }}>{item}</span>
						</div>
					))}
				</div>
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
						Local detection, incident correlation, and package and plugin checks are available for
						supported runtimes: {AGENT_CONNECTORS.join(", ")}. The engine ships{" "}
						{SHIPPED_THREAT_RULES} YAML threat rules in {THREAT_RULE_FILES} files. Device enrollment
						and central visibility depend on the pilot deployment.
					</p>
					<div className="bullet-list">
						{[
							"Guided setup for supported runtimes",
							"Local enforcement; optional managed visibility",
							"Package, plugin, and prompt abuse detection",
							"Managed onboarding in configured pilot environments",
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

			{/* Deployment Options */}
			<section className="card" aria-labelledby="deployment-heading">
				<div className="pill" style={{ marginBottom: 12 }}>
					Deployment
				</div>
				<h2 id="deployment-heading" style={{ fontSize: 24, marginBottom: 16 }}>
					Run it where your data has to stay.
				</h2>
				<div className="feature-grid">
					{deploymentOptions.map((option) => (
						<article key={option.title} className="feature-card">
							<div className="feature-card-title">{option.title}</div>
							<div className="feature-card-desc">{option.desc}</div>
						</article>
					))}
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
					Start with an assisted pilot and validate installation and data flows in your environment.
				</p>
				<div className="row" style={{ justifyContent: "center" }}>
					<Link className="button button-lg" to="/pilot">
						Request a pilot
					</Link>
				</div>
			</section>
		</div>
	);
}
