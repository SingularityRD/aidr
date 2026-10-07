import { Link } from "react-router-dom";
import { safeExternalUrl } from "./external-url";

type InfoKind = "support" | "status" | "privacy" | "security" | "terms";

function ExternalAction({ href, label }: { href: string; label: string }) {
	return (
		<a className="button" href={href} target="_blank" rel="noreferrer">
			{label}
		</a>
	);
}

export function PublicInfoPage({ kind }: { kind: InfoKind }) {
	if (kind === "support") {
		const configuredSupportUrl = import.meta.env.VITE_SUPPORT_URL;
		const supportUrl = safeExternalUrl(configuredSupportUrl);
		const supportEmail = safeExternalUrl(
			import.meta.env.VITE_SUPPORT_EMAIL
				? `mailto:${import.meta.env.VITE_SUPPORT_EMAIL}`
				: undefined,
			true,
		);
		return (
			<div className="stack">
				<div className="card">
					<h1>Support</h1>
					<p className="muted">
						Use the configured support channel for product questions, onboarding help, or incident
						reports. Do not include API keys, enrollment tokens, customer content, or access tokens
						in a ticket.
					</p>
					<div className="row" style={{ marginTop: 16, flexWrap: "wrap" }}>
						{supportUrl ? <ExternalAction href={supportUrl} label="Open support channel" /> : null}
						{!supportUrl && !supportEmail ? (
							<div className="notice notice-danger" role="alert">
								No safe HTTPS support URL or approved support mailbox is configured. Do not promise
								a support SLA.
							</div>
						) : null}
						{supportEmail ? (
							<a className="button button-secondary" href={supportEmail}>
								Email support
							</a>
						) : null}
					</div>
					<div className="notice" style={{ marginTop: 16 }}>
						<b>Support commitment:</b> response schedule and escalation SLA are deployment-specific.
						Confirm those terms in your Order Form before relying on them.
					</div>
				</div>
				<div className="card">
					<h2>Safe diagnostics</h2>
					<p className="muted">
						When support asks for diagnostics, share only the redacted bundle produced by the
						documented workflow. Support access requires customer consent and must never require a
						raw secret.
					</p>
				</div>
			</div>
		);
	}

	if (kind === "status") {
		const statusUrl = safeExternalUrl(import.meta.env.VITE_STATUS_URL);
		return (
			<div className="stack">
				<div className="card">
					<h1>Service status</h1>
					{statusUrl ? (
						<>
							<p className="muted">
								Open the configured status link for deployment updates. This page does not monitor
								availability or verify when that destination was last updated.
							</p>
							<div className="row" style={{ marginTop: 16 }}>
								<ExternalAction href={statusUrl} label="Open status updates" />
							</div>
						</>
					) : (
						<div className="notice notice-danger" role="alert">
							No live status feed is configured for this deployment. Do not infer availability from
							this page.
						</div>
					)}
				</div>
			</div>
		);
	}

	if (kind === "terms") {
		const termsUrl = safeExternalUrl(import.meta.env.VITE_TERMS_URL);
		return (
			<div className="stack">
				<div className="card">
					<h1>Terms and order scope</h1>
					<p className="muted">
						The signed Order Form and deployment-specific terms control your scope, pricing,
						support, data region, retention, and offboarding obligations.
					</p>
					{termsUrl ? (
						<div className="row" style={{ marginTop: 16 }}>
							<ExternalAction href={termsUrl} label="Read terms" />
						</div>
					) : (
						<div className="notice notice-danger" role="alert">
							Terms URL is not configured. Do not sell or accept production data until legal terms
							are published and approved.
						</div>
					)}
				</div>
			</div>
		);
	}

	const label = kind === "privacy" ? "Privacy notice" : "Security";
	const configuredLink =
		kind === "privacy" ? import.meta.env.VITE_PRIVACY_URL : import.meta.env.VITE_SECURITY_URL;
	const externalLink = safeExternalUrl(configuredLink);
	return (
		<div className="stack">
			<div className="card">
				<h1>{label}</h1>
				<p className="muted">
					Review the configured deployment document before sending managed telemetry, AI Security
					Posture scan data, or customer content to this service.
				</p>
				{externalLink ? (
					<div className="row" style={{ marginTop: 16 }}>
						<ExternalAction href={externalLink} label={`Read ${label.toLowerCase()}`} />
					</div>
				) : (
					<div className="notice notice-danger" role="alert">
						{label} URL is not configured with a safe HTTPS URL. Do not claim this document is
						available.
					</div>
				)}
			</div>
			<div className="card">
				<p className="muted small">
					Need help deciding whether your deployment is in scope?{" "}
					<Link to="/support">Contact support</Link>.
				</p>
			</div>
		</div>
	);
}
