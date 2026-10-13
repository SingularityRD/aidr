import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { useRichT, useT } from "../../i18n/I18nProvider";
import type { LinuxFamily, VisitorOs } from "../../lib/installers";
import {
	BrowserGuardCard,
	type BrowserGuardLinks,
	browserGuardLinks,
	ItDeploymentCard,
} from "../../onboarding/BrowserGuardDownloads";
import { DownloadCenter } from "../../onboarding/DownloadCenter";
import { InstallerDownloads } from "../../onboarding/InstallerDownloads";

export function DownloadsPage({
	links,
	visitorOs,
}: {
	/** Test seams; build configuration and the browser are used when absent. */
	links?: BrowserGuardLinks;
	visitorOs?: { os: VisitorOs; arch: "x64" | "arm64"; linux?: LinuxFamily };
} = {}) {
	const t = useT();
	const richT = useRichT();
	const { currentTeam, isLoading } = useTeam();
	const config = links ?? browserGuardLinks();
	if (isLoading) {
		return (
			<div className="card" role="status">
				{t("downloads.checkingTeam")}
			</div>
		);
	}
	return (
		<div className="stack">
			<div className="card">
				<h1>{t("nav.downloads")}</h1>
				<p className="muted">
					{t("downloads.intro", { team: currentTeam?.name ?? t("downloads.yourTeam") })}
				</p>
				<div className="row" style={{ flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to="/onboarding">
						{t("downloads.backToOnboarding")}
					</Link>
					<Link className="button button-secondary button-sm" to="/agents">
						{t("downloads.viewAgents")}
					</Link>
				</div>
			</div>
			<section className="card" aria-labelledby="installer-title">
				<h2 id="installer-title">{t("downloads.installer.title")}</h2>
				<p className="muted">{t("downloads.installer.intro")}</p>
				{currentTeam ? (
					<InstallerDownloads teamId={currentTeam.id} visitorOs={visitorOs} />
				) : (
					<p className="notice notice-warning">{t("downloads.noTeam")}</p>
				)}
			</section>
			<BrowserGuardCard links={config} />
			<ItDeploymentCard adminGuideUrl={config.adminGuideUrl} />
			<details className="card">
				<summary>
					<b>{t("downloads.advanced.title")}</b>
				</summary>
				<div className="notice notice-warning" role="note" style={{ marginTop: 12 }}>
					{richT("onb.manual.releaseKey", {
						command: <code>aidr setup --release-key &lt;key.pem&gt;</code>,
					})}
				</div>
				<div style={{ marginTop: 12 }}>
					<DownloadCenter teamId={currentTeam?.id ?? null} />
				</div>
			</details>
		</div>
	);
}
