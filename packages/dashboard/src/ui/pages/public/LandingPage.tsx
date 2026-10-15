import { Link } from "react-router-dom";
import type { DashboardMessageKey } from "../../../i18n/en";
import { type Translate, useRichT, useT } from "../../../i18n/I18nProvider";
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

const launchLinks: { name: DashboardMessageKey; href: string; desc: DashboardMessageKey }[] = [
	{ name: "ld.link.start", href: "/login?returnTo=%2Fonboarding", desc: "ld.link.startDesc" },
	{ name: "ld.link.signIn", href: "/login?returnTo=%2Fdashboard", desc: "ld.link.signInDesc" },
	{ name: "ld.link.editions", href: "/pricing", desc: "ld.link.editionsDesc" },
	{ name: "ld.link.pilot", href: "/pilot", desc: "ld.link.pilotDesc" },
];

function productLines(t: Translate): { title: string; desc: string }[] {
	return [
		{
			title: t("ld.line.agents"),
			desc: t("ld.line.agentsDesc", {
				connectors: AGENT_CONNECTORS.join(", "),
				rules: SHIPPED_THREAT_RULES,
			}),
		},
		{
			title: "AIDR Browser Guard",
			desc: t("ld.line.browserGuardDesc", { browsers: BROWSER_GUARD_BROWSERS.join(", ") }),
		},
		{
			title: t("ld.line.privacy"),
			desc: t("ld.line.privacyDesc"),
		},
		{
			title: t("ld.line.posture"),
			desc: t("ld.line.postureDesc", {
				components: AIG_AI_COMPONENTS,
				cves: AIG_CVE_RULES_FLOOR.toLocaleString("en-US"),
				categories: POSTURE_MCP_RISK_CATEGORIES,
				first: POSTURE_SKILL_RISK_CODES[0] ?? "",
				last: POSTURE_SKILL_RISK_CODES[POSTURE_SKILL_RISK_CODES.length - 1] ?? "",
			}),
		},
	];
}

const browserGuardPoints: DashboardMessageKey[] = ["ld.bg.1", "ld.bg.2", "ld.bg.3", "ld.bg.4"];

const deploymentOptions: { title: DashboardMessageKey; desc: DashboardMessageKey }[] = [
	{ title: "ld.dep.local", desc: "ld.dep.localDesc" },
	{ title: "ld.dep.cloud", desc: "ld.dep.cloudDesc" },
	{ title: "ld.dep.onprem", desc: "ld.dep.onpremDesc" },
];

const featurePillars: { title: DashboardMessageKey; desc: DashboardMessageKey }[] = [
	{ title: "ld.f.setup", desc: "ld.f.setupDesc" },
	{ title: "ld.f.device", desc: "ld.f.deviceDesc" },
	{ title: "ld.f.incidents", desc: "ld.f.incidentsDesc" },
	{ title: "ld.f.packages", desc: "ld.f.packagesDesc" },
	{ title: "ld.f.sync", desc: "ld.f.syncDesc" },
	{ title: "ld.f.offline", desc: "ld.f.offlineDesc" },
];

const surfacePoints: DashboardMessageKey[] = [
	"ld.surface.1",
	"ld.surface.2",
	"ld.surface.3",
	"ld.surface.4",
];

export function LandingPage() {
	const t = useT();
	const richT = useRichT();
	return (
		<div className="stack">
			{/* Hero Section */}
			<section className="card hero-card">
				<div className="pill" style={{ marginBottom: 14 }}>
					{t("ld.hero.pill")}
				</div>
				<h1
					style={{
						fontSize: "clamp(30px, 6vw, 54px)",
						lineHeight: 1.04,
						letterSpacing: "-0.03em",
						marginBottom: 12,
					}}
				>
					{t("ld.hero.title")}
				</h1>
				<p style={{ color: "var(--text-secondary)", maxWidth: 720, lineHeight: "27px" }}>
					{richT("ld.hero.lead", { brand: <span lang="en">Singularity AIDR</span> })}
				</p>
				<div className="row" style={{ marginTop: 20 }}>
					<Link className="button button-lg" to="/pilot">
						{t("ld.requestPilot")}
					</Link>
					<Link className="button button-secondary button-lg" to="/login?returnTo=%2Fonboarding">
						{t("ld.link.start")}
					</Link>
				</div>
			</section>

			{/* Launch Links */}
			<section className="launch-links">
				{launchLinks.map((item) => (
					<Link key={item.name} to={item.href} className="launch-link">
						<div className="launch-link-title">{t(item.name)}</div>
						<div className="launch-link-desc">{t(item.desc)}</div>
					</Link>
				))}
			</section>

			{/* Product Lines */}
			<section className="card" aria-labelledby="product-lines-heading">
				<div className="pill" style={{ marginBottom: 12 }}>
					{t("ld.lines.pill")}
				</div>
				<h2 id="product-lines-heading" style={{ fontSize: 28, lineHeight: 1.08, marginBottom: 16 }}>
					{t("ld.lines.title")}
				</h2>
				<div className="feature-grid">
					{productLines(t).map((line) => (
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
					{t("ld.bg.title")}
				</h2>
				<p style={{ color: "var(--text-secondary)", lineHeight: "26px", marginBottom: 16 }}>
					{t("ld.bg.lead", { sites: BROWSER_GUARD_SITES.join(", ") })}
				</p>
				<div className="bullet-list">
					{browserGuardPoints.map((item) => (
						<div key={item} className="bullet-item">
							<span className="bullet-dot" />
							<span style={{ color: "var(--text-secondary)" }}>{t(item)}</span>
						</div>
					))}
				</div>
			</section>

			{/* Security Showcase */}
			<section className="security-showcase">
				<div className="card">
					<div className="pill" style={{ marginBottom: 12 }}>
						{t("ld.surface.pill")}
					</div>
					<h2
						style={{
							fontSize: 28,
							lineHeight: 1.08,
							letterSpacing: "-0.03em",
							marginBottom: 10,
						}}
					>
						{t("ld.surface.title")}
					</h2>
					<p style={{ color: "var(--text-secondary)", lineHeight: "26px", marginBottom: 16 }}>
						{t("ld.surface.lead", {
							connectors: AGENT_CONNECTORS.join(", "),
							rules: SHIPPED_THREAT_RULES,
							files: THREAT_RULE_FILES,
						})}
					</p>
					<div className="bullet-list">
						{surfacePoints.map((item) => (
							<div key={item} className="bullet-item">
								<span className="bullet-dot" />
								<span style={{ color: "var(--text-secondary)" }}>{t(item)}</span>
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
						aria-label={t("ld.diagram.label")}
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
							{t("ld.diagram.agent")}
						</text>
						<text x="80" y="66" textAnchor="middle" fontSize="10" fill="var(--text-secondary)">
							{t("ld.diagram.calls")}
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
							{t("ld.diagram.layer")}
						</text>
						<text x="170" y="145" textAnchor="middle" fontSize="10" fill="var(--text-secondary)">
							{t("ld.diagram.decisions")}
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
							{t("ld.diagram.targets")}
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
					{t("ld.dep.pill")}
				</div>
				<h2 id="deployment-heading" style={{ fontSize: 24, marginBottom: 16 }}>
					{t("ld.dep.title")}
				</h2>
				<div className="feature-grid">
					{deploymentOptions.map((option) => (
						<article key={option.title} className="feature-card">
							<div className="feature-card-title">{t(option.title)}</div>
							<div className="feature-card-desc">{t(option.desc)}</div>
						</article>
					))}
				</div>
			</section>

			{/* Core Features */}
			<section className="card">
				<div className="pill" style={{ marginBottom: 16 }}>
					{t("ld.features.pill")}
				</div>
				<div className="feature-grid">
					{featurePillars.map((feature) => (
						<article key={feature.title} className="feature-card">
							<div className="feature-card-title">{t(feature.title)}</div>
							<div className="feature-card-desc">{t(feature.desc)}</div>
						</article>
					))}
				</div>
			</section>

			{/* Install CTA */}
			<section id="install" className="card hero-card" style={{ textAlign: "center" }}>
				<h2 style={{ fontSize: 24, marginBottom: 10 }}>{t("ld.cta.title")}</h2>
				<p className="muted" style={{ marginBottom: 18 }}>
					{t("ld.cta.lead")}
				</p>
				<div className="row" style={{ justifyContent: "center" }}>
					<Link className="button button-lg" to="/pilot">
						{t("ld.requestPilot")}
					</Link>
				</div>
			</section>
		</div>
	);
}
