import { Link } from "react-router-dom";
import { useRichT, useT } from "../../../i18n/I18nProvider";
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
	const t = useT();
	const richT = useRichT();
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
					<h1>{t("pi.support")}</h1>
					<p className="muted">{t("pi.supportLead")}</p>
					<div className="row" style={{ marginTop: 16, flexWrap: "wrap" }}>
						{supportUrl ? <ExternalAction href={supportUrl} label={t("pi.openSupport")} /> : null}
						{!supportUrl && !supportEmail ? (
							<div className="notice notice-danger" role="alert">
								{t("pi.noSupport")}
							</div>
						) : null}
						{supportEmail ? (
							<a className="button button-secondary" href={supportEmail}>
								{t("pi.emailSupport")}
							</a>
						) : null}
					</div>
					<div className="notice" style={{ marginTop: 16 }}>
						{richT("pi.commitment", { lead: <b>{t("pi.commitmentLead")}</b> })}
					</div>
				</div>
				<div className="card">
					<h2>{t("pi.diagnostics")}</h2>
					<p className="muted">{t("pi.diagnosticsLead")}</p>
				</div>
			</div>
		);
	}

	if (kind === "status") {
		const statusUrl = safeExternalUrl(import.meta.env.VITE_STATUS_URL);
		return (
			<div className="stack">
				<div className="card">
					<h1>{t("pi.status")}</h1>
					{statusUrl ? (
						<>
							<p className="muted">{t("pi.statusLead")}</p>
							<div className="row" style={{ marginTop: 16 }}>
								<ExternalAction href={statusUrl} label={t("pi.openStatus")} />
							</div>
						</>
					) : (
						<div className="notice notice-danger" role="alert">
							{t("pi.noStatus")}
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
					<h1>{t("pi.terms")}</h1>
					<p className="muted">{t("pi.termsLead")}</p>
					{termsUrl ? (
						<div className="row" style={{ marginTop: 16 }}>
							<ExternalAction href={termsUrl} label={t("pi.readTerms")} />
						</div>
					) : (
						<div className="notice notice-danger" role="alert">
							{t("pi.noTerms")}
						</div>
					)}
				</div>
			</div>
		);
	}

	const privacy = kind === "privacy";
	const label = privacy ? t("pi.privacy") : t("pi.security");
	const configuredLink =
		kind === "privacy" ? import.meta.env.VITE_PRIVACY_URL : import.meta.env.VITE_SECURITY_URL;
	const externalLink = safeExternalUrl(configuredLink);
	return (
		<div className="stack">
			<div className="card">
				<h1>{label}</h1>
				<p className="muted">{t("pi.docLead")}</p>
				{externalLink ? (
					<div className="row" style={{ marginTop: 16 }}>
						<ExternalAction
							href={externalLink}
							label={privacy ? t("pi.readPrivacy") : t("pi.readSecurity")}
						/>
					</div>
				) : (
					<div className="notice notice-danger" role="alert">
						{privacy ? t("pi.noPrivacy") : t("pi.noSecurity")}
					</div>
				)}
			</div>
			<div className="card">
				<p className="muted small">
					{richT("pi.scope", { link: <Link to="/support">{t("pi.contactSupport")}</Link> })}
				</p>
			</div>
		</div>
	);
}
