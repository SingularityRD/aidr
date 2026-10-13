import { useEffect, useRef, useState } from "react";
import { useT } from "../i18n/I18nProvider";
import { readErrorMessage } from "../lib/errors";
import { AdminAuditSection } from "./admin-audit-section";
import { useTeam } from "./team-provider";

const PAGE_SIZE = 25;

export function TeamAuditPanel() {
	const {
		currentTeam,
		canViewAudit,
		canManageTeam,
		auditLogs,
		auditLoaded,
		auditError,
		refreshAuditLogs,
		exportAuditLogs,
	} = useTeam();
	const t = useT();
	const [page, setPage] = useState(0);
	const [exporting, setExporting] = useState(false);
	const [exportError, setExportError] = useState<string | null>(null);
	const [download, setDownload] = useState<{
		teamId: string;
		format: "csv" | "json";
		url: string;
	} | null>(null);
	const selectedTeamId = useRef(currentTeam?.id);
	const mounted = useRef(true);
	selectedTeamId.current = currentTeam?.id;
	useEffect(() => {
		mounted.current = true;
		return () => {
			mounted.current = false;
		};
	}, []);

	useEffect(() => {
		return () => {
			if (download) URL.revokeObjectURL(download.url);
		};
	}, [download]);

	async function prepareExport(format: "csv" | "json") {
		if (!currentTeam || !canViewAudit || !canManageTeam) return;
		const teamId = currentTeam.id;
		const isCurrent = () => mounted.current && selectedTeamId.current === teamId;
		setExporting(true);
		setExportError(null);
		setDownload(null);
		try {
			const url = await exportAuditLogs(format);
			if (!isCurrent()) {
				URL.revokeObjectURL(url);
				return;
			}
			setDownload({ teamId, format, url });
		} catch (error) {
			if (isCurrent()) {
				setExportError(readErrorMessage(error, t("audit.exportUnavailable")));
			}
		} finally {
			if (isCurrent()) setExporting(false);
		}
	}

	const scopedLogs = auditLogs.filter((row) => row.team_id === currentTeam?.id);
	const pageCount = Math.max(1, Math.ceil(scopedLogs.length / PAGE_SIZE));
	const currentPage = Math.min(page, pageCount - 1);
	const rows = scopedLogs.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
	const readyDownload = download?.teamId === currentTeam?.id ? download : null;

	return (
		<section className="card" aria-labelledby="team-audit-heading">
			<h2 id="team-audit-heading">{t("audit.title")}</h2>
			<p className="muted">{t("audit.intro")}</p>
			{!currentTeam || !canViewAudit ? (
				<p className="muted">{t("audit.selectTeam")}</p>
			) : (
				<>
					<div className="button-row">
						<button type="button" onClick={() => void refreshAuditLogs()}>
							{t("audit.refresh")}
						</button>
						{canManageTeam && (
							<>
								<button
									type="button"
									disabled={exporting}
									onClick={() => void prepareExport("csv")}
								>
									{t("audit.prepareCsv")}
								</button>
								<button
									type="button"
									disabled={exporting}
									onClick={() => void prepareExport("json")}
								>
									{t("audit.prepareJson")}
								</button>
							</>
						)}
					</div>
					{!canManageTeam && <p className="muted">{t("audit.exportOwners")}</p>}
					{exportError && (
						<div className="notice notice-danger" role="alert">
							{exportError}
						</div>
					)}
					{readyDownload && (
						<p role="status">
							{t("audit.ready")}{" "}
							<a
								href={readyDownload.url}
								download={`aidr-audit-${readyDownload.teamId}.${readyDownload.format}`}
							>
								{t("audit.save")}
							</a>
						</p>
					)}
					{!auditLoaded ? (
						<p className="muted">{t("audit.loading")}</p>
					) : auditError ? (
						<div className="notice notice-danger" role="alert">
							{t("audit.unavailable")} {auditError}
						</div>
					) : scopedLogs.length === 0 ? (
						<p className="muted">{t("audit.empty")}</p>
					) : (
						<>
							<table>
								<thead>
									<tr>
										<th>{t("audit.time")}</th>
										<th>{t("audit.actor")}</th>
										<th>{t("audit.action")}</th>
									</tr>
								</thead>
								<tbody>
									{rows.map((row) => (
										<tr key={row.id}>
											<td>
												{Number.isFinite(row.timestamp)
													? new Date(row.timestamp).toLocaleString()
													: t("audit.timeUnavailable")}
											</td>
											<td>{row.user_email || row.user_id || t("audit.notRecorded")}</td>
											<td>{row.action}</td>
										</tr>
									))}
								</tbody>
							</table>
							<div className="button-row">
								<button
									type="button"
									disabled={currentPage === 0}
									onClick={() => setPage(currentPage - 1)}
								>
									{t("audit.prev")}
								</button>
								<span>{t("audit.pageOf", { page: currentPage + 1, count: pageCount })}</span>
								<button
									type="button"
									disabled={currentPage >= pageCount - 1}
									onClick={() => setPage(currentPage + 1)}
								>
									{t("audit.next")}
								</button>
							</div>
						</>
					)}
					<AdminAuditSection />
				</>
			)}
		</section>
	);
}
