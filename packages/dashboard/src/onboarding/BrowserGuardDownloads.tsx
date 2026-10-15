import { useT } from "../i18n/I18nProvider";
import { safeHttpsUrl } from "../lib/installers";

/** Firefox add-on ID, fixed in packages/browser-guard/scripts/build.mjs (GECKO_ID). */
export const BROWSER_GUARD_FIREFOX_ID = "browser-guard@singularityrd.com";
const CHROMIUM_ID = /^[a-p]{32}$/;

export interface BrowserGuardLinks {
	chromeUrl: string | null;
	edgeUrl: string | null;
	firefoxUrl: string | null;
	chromeId: string | null;
	edgeId: string | null;
	adminGuideUrl: string | null;
}

type Env = Record<string, string | boolean | undefined>;

/**
 * Store links, extension IDs and the administrator guide URL come only from build
 * configuration. A value that is missing or not an https URL (or a 32-letter
 * Chromium ID) is null, and the page hides that link instead of guessing.
 */
export function browserGuardLinks(env: Env = import.meta.env): BrowserGuardLinks {
	const id = (value: unknown) =>
		typeof value === "string" && CHROMIUM_ID.test(value.trim()) ? value.trim() : null;
	return {
		chromeUrl: safeHttpsUrl(env.VITE_BROWSER_GUARD_CHROME_URL),
		edgeUrl: safeHttpsUrl(env.VITE_BROWSER_GUARD_EDGE_URL),
		firefoxUrl: safeHttpsUrl(env.VITE_BROWSER_GUARD_FIREFOX_URL),
		chromeId: id(env.VITE_BROWSER_GUARD_CHROME_EXTENSION_ID),
		edgeId: id(env.VITE_BROWSER_GUARD_EDGE_EXTENSION_ID),
		adminGuideUrl: safeHttpsUrl(env.VITE_AIDR_ADMIN_GUIDE_URL),
	};
}

export function BrowserGuardCard({ links }: { links: BrowserGuardLinks }) {
	const t = useT();
	const stores = [
		[links.chromeUrl, t("downloads.bg.chrome")],
		[links.edgeUrl, t("downloads.bg.edge")],
		[links.firefoxUrl, t("downloads.bg.firefox")],
	].filter((entry): entry is [string, string] => entry[0] !== null);
	const ids = [
		[t("downloads.bg.chromeId"), links.chromeId],
		[t("downloads.bg.edgeId"), links.edgeId],
		[t("downloads.bg.firefoxId"), BROWSER_GUARD_FIREFOX_ID],
	].filter((entry): entry is [string, string] => entry[1] !== null);
	return (
		<section className="card" aria-labelledby="browser-guard-title">
			<h2 id="browser-guard-title">{t("downloads.bg.title")}</h2>
			<p className="muted">{t("downloads.bg.body")}</p>
			{stores.length > 0 ? (
				<div className="row" style={{ flexWrap: "wrap" }}>
					{stores.map(([href, label]) => (
						<a
							key={href}
							className="button button-secondary"
							href={href}
							target="_blank"
							rel="noreferrer"
						>
							{label}
						</a>
					))}
				</div>
			) : (
				<p className="notice notice-warning small">{t("downloads.bg.none")}</p>
			)}
			<h3>{t("downloads.bg.ids")}</h3>
			<dl className="small">
				{ids.map(([label, value]) => (
					<div key={label} className="row" style={{ flexWrap: "wrap" }}>
						<dt style={{ minWidth: 80 }}>{label}</dt>
						<dd className="mono" style={{ margin: 0, overflowWrap: "anywhere" }}>
							{value}
						</dd>
					</div>
				))}
			</dl>
		</section>
	);
}

export function ItDeploymentCard({ adminGuideUrl }: { adminGuideUrl: string | null }) {
	const t = useT();
	return (
		<section className="card" aria-labelledby="it-deployment-title">
			<h2 id="it-deployment-title">{t("downloads.it.title")}</h2>
			<p className="muted">{t("downloads.it.body")}</p>
			{adminGuideUrl ? (
				<a
					className="button button-secondary"
					href={adminGuideUrl}
					target="_blank"
					rel="noreferrer"
				>
					{t("downloads.it.guide")}
				</a>
			) : (
				<p className="small">{t("downloads.it.guideMissing")}</p>
			)}
		</section>
	);
}
