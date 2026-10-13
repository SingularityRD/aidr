import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { DashboardMessageKey } from "../i18n/en";
import { useRichT, useT } from "../i18n/I18nProvider";
import {
	checksumCommand,
	detectVisitorPlatform,
	type InstallerCatalog,
	type InstallerFile,
	loadInstallerCatalog,
	recommendedInstaller,
	requestInstallerDownload,
	type VisitorOs,
} from "../lib/installers";
import { formatBytes } from "./release-manifest";

type CatalogState =
	| { state: "loading" }
	| { state: "error"; code: string }
	| { state: "ready"; catalog: InstallerCatalog };

type DownloadState =
	| { state: "idle" }
	| { state: "preparing" }
	| { state: "error" }
	| { state: "started"; url: string; expiresAt: string };

function useCatalog(teamId: string, reload: number): CatalogState {
	const [state, setState] = useState<CatalogState>({ state: "loading" });
	useEffect(() => {
		let cancelled = false;
		setState({ state: "loading" });
		loadInstallerCatalog(teamId).then((result) => {
			if (cancelled) return;
			setState(
				result.ok
					? { state: "ready", catalog: result.value }
					: { state: "error", code: result.error },
			);
		});
		return () => {
			cancelled = true;
		};
	}, [teamId, reload]);
	return state;
}

const CATALOG_ERRORS: Record<string, DashboardMessageKey> = {
	entitlement_required: "downloads.error.entitlement",
	installers_unpublished: "downloads.error.unpublished",
	catalog_integrity_failed: "downloads.error.integrity",
	tenant_not_authorized: "downloads.error.forbidden",
	rate_limited: "downloads.error.rateLimited",
};

function CatalogError({ code, onRetry }: { code: string; onRetry: () => void }) {
	const t = useT();
	const message = t(CATALOG_ERRORS[code] ?? "downloads.error.generic");
	const retryable = !["entitlement_required", "tenant_not_authorized"].includes(code);
	return (
		<div
			className={`notice ${code === "installers_unpublished" ? "notice-warning" : "notice-danger"}`}
			data-installer-error={code}
		>
			<p style={{ margin: 0 }}>{message}</p>
			{retryable ? (
				<button
					className="button button-secondary button-sm"
					type="button"
					style={{ marginTop: 8 }}
					onClick={onRetry}
				>
					{t("downloads.retry")}
				</button>
			) : null}
		</div>
	);
}

function CopyCommand({ command, file }: { command: string; file: string }) {
	const t = useT();
	const [status, setStatus] = useState<"idle" | "copied" | "error">("idle");
	return (
		<div>
			<div className="row" style={{ alignItems: "flex-start", flexWrap: "wrap" }}>
				<pre
					className="mono"
					style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", flex: "1 1 260px", margin: 0 }}
				>
					{command}
				</pre>
				<button
					className="button button-secondary button-sm"
					type="button"
					aria-label={t("downloads.installer.copyChecksum", { file })}
					onClick={async () => {
						try {
							await navigator.clipboard.writeText(command);
							setStatus("copied");
						} catch {
							setStatus("error");
						}
					}}
				>
					{status === "copied" ? t("downloads.installer.copied") : t("downloads.installer.copy")}
				</button>
			</div>
			{status === "error" ? (
				<span className="muted small" role="alert">
					{t("downloads.installer.copyBlocked")}
				</span>
			) : null}
		</div>
	);
}

function platformLabel(t: ReturnType<typeof useT>, file: InstallerFile): string {
	const os = file.os === "windows" ? t("downloads.os.windows") : t("downloads.os.linux");
	return `${os} (${file.arch})`;
}

function InstallerEntry({
	teamId,
	version,
	file,
	recommended,
}: {
	teamId: string;
	version: string;
	file: InstallerFile;
	recommended: boolean;
}) {
	const t = useT();
	const richT = useRichT();
	const [download, setDownload] = useState<DownloadState>({ state: "idle" });

	async function start() {
		setDownload({ state: "preparing" });
		const result = await requestInstallerDownload(teamId, version, file.platform);
		if (!result.ok || result.value.sha256 !== file.sha256) {
			setDownload({ state: "error" });
			return;
		}
		setDownload({ state: "started", url: result.value.url, expiresAt: result.value.expiresAt });
		try {
			window.location.assign(result.value.url);
		} catch {
			// The direct link below stays available.
		}
	}

	return (
		<section
			className={recommended ? "notice notice-success" : "notice"}
			aria-label={platformLabel(t, file)}
			data-platform={file.platform}
			style={{ marginTop: 10 }}
		>
			<div className="row" style={{ flexWrap: "wrap", alignItems: "center", gap: 8 }}>
				<b>{platformLabel(t, file)}</b>
				{recommended ? (
					<span className="pill pill-success">{t("downloads.installer.recommended")}</span>
				) : null}
			</div>
			<div className="row" style={{ flexWrap: "wrap", alignItems: "center", marginTop: 8 }}>
				<button
					className={recommended ? "button" : "button button-secondary"}
					type="button"
					disabled={download.state === "preparing"}
					onClick={start}
				>
					{download.state === "preparing"
						? t("downloads.installer.preparing")
						: t("downloads.installer.download", { file: file.file })}
				</button>
				<span className="muted small">
					{t("downloads.installer.meta", { size: formatBytes(file.size), minOs: file.minimumOs })}
				</span>
			</div>
			{download.state === "started" ? (
				<p className="small" role="status">
					{richT("downloads.installer.started", {
						link: (
							<a href={download.url} rel="noopener noreferrer">
								{t("downloads.installer.directLink")}
							</a>
						),
						time: new Date(download.expiresAt).toLocaleTimeString(),
					})}
				</p>
			) : null}
			{download.state === "error" ? (
				<p className="small" role="alert">
					{t("downloads.error.download")}
				</p>
			) : null}
			<div className="muted small" style={{ marginTop: 8 }}>
				{t("downloads.installer.sha256")}
			</div>
			<code className="mono" style={{ overflowWrap: "anywhere" }}>
				{file.sha256}
			</code>
			<div className="muted small" style={{ marginTop: 8 }}>
				{t("downloads.installer.verify")}
			</div>
			<CopyCommand command={checksumCommand(file)} file={file.file} />
			<p className="muted small">{t("downloads.installer.verifyNote")}</p>
		</section>
	);
}

function ManagedEnrollment({
	teamId,
	controlPlaneUrl,
}: {
	teamId: string;
	controlPlaneUrl: string;
}) {
	const t = useT();
	return (
		<section
			className="notice"
			aria-labelledby="managed-enrollment-title"
			style={{ marginTop: 12 }}
		>
			<h3 id="managed-enrollment-title" style={{ marginTop: 0 }}>
				{t("downloads.managed.title")}
			</h3>
			<p className="small">{t("downloads.managed.body")}</p>
			<code className="mono" style={{ overflowWrap: "anywhere" }}>
				{controlPlaneUrl}
			</code>
			<div className="row" style={{ flexWrap: "wrap", marginTop: 10 }}>
				<Link
					className="button button-secondary button-sm"
					to={`/verify?team=${encodeURIComponent(teamId)}`}
				>
					{t("downloads.managed.verify")}
				</Link>
				<Link className="button button-secondary button-sm" to="/onboarding">
					{t("downloads.managed.advanced")}
				</Link>
			</div>
		</section>
	);
}

/**
 * The installer for the visitor's OS, highlighted, with the other platforms listed.
 * Links are minted one at a time by the `installer-download` function (entitlement
 * checked and audited); nothing here is downloadable without it.
 */
export function InstallerDownloads({
	teamId,
	visitorOs,
}: {
	teamId: string;
	/** Test seam; the browser is asked when absent. */
	visitorOs?: { os: VisitorOs; arch: "x64" | "arm64" };
}) {
	const t = useT();
	const [reload, setReload] = useState(0);
	const catalog = useCatalog(teamId, reload);
	const visitor = useMemo(() => visitorOs ?? detectVisitorPlatform(), [visitorOs]);

	if (catalog.state === "loading") {
		return (
			<p className="muted" role="status">
				{t("downloads.installer.loading")}
			</p>
		);
	}
	if (catalog.state === "error") {
		return (
			<>
				{visitor.os === "macos" ? <MacNote /> : null}
				<CatalogError code={catalog.code} onRetry={() => setReload((count) => count + 1)} />
			</>
		);
	}
	const { version, publishedAt, releaseNotesUrl, files, controlPlaneUrl } = catalog.catalog;
	const recommended = recommendedInstaller(files, visitor);
	const others = files.filter((file) => file !== recommended);
	return (
		<div>
			<p className="muted small">
				{t("downloads.installer.version", {
					version,
					date: new Date(publishedAt).toLocaleDateString(),
				})}
				{releaseNotesUrl ? (
					<>
						{" · "}
						<a href={releaseNotesUrl} target="_blank" rel="noreferrer">
							{t("downloads.installer.releaseNotes")}
						</a>
					</>
				) : null}
			</p>
			{visitor.os === "macos" ? <MacNote /> : null}
			{!recommended && visitor.os !== "macos" ? (
				<p className="notice notice-warning small">{t("downloads.installer.noMatch")}</p>
			) : null}
			{recommended ? (
				<InstallerEntry teamId={teamId} version={version} file={recommended} recommended />
			) : null}
			{others.length > 0 ? (
				<>
					<h3 style={{ marginBottom: 0 }}>{t("downloads.installer.other")}</h3>
					{others.map((file) => (
						<InstallerEntry
							key={file.platform}
							teamId={teamId}
							version={version}
							file={file}
							recommended={false}
						/>
					))}
				</>
			) : null}
			<ol className="small" style={{ marginTop: 12 }}>
				<li>{t("downloads.installer.step1")}</li>
				<li>{t("downloads.installer.step2")}</li>
				<li>{t("downloads.installer.step3")}</li>
			</ol>
			{controlPlaneUrl ? (
				<ManagedEnrollment teamId={teamId} controlPlaneUrl={controlPlaneUrl} />
			) : null}
		</div>
	);
}

function MacNote() {
	const t = useT();
	return (
		<p className="notice small" role="note">
			{t("downloads.installer.macos")}
		</p>
	);
}
