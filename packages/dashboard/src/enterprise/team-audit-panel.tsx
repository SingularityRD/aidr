import { useEffect, useRef, useState } from "react";
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
				setExportError(readErrorMessage(error, "Audit export is unavailable."));
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
			<h2 id="team-audit-heading">Team audit</h2>
			<p className="muted">
				Recent audit entries for the selected team only. This view shows at most the latest 1,000
				entries; use the paginated export API for larger history. Browser export is capped at
				100,000 records or 64 MiB. No raw action input is shown here.
			</p>
			{!currentTeam || !canViewAudit ? (
				<p className="muted">Select an accessible team to view its audit records.</p>
			) : (
				<>
					<div className="button-row">
						<button type="button" onClick={() => void refreshAuditLogs()}>
							Refresh audit
						</button>
						{canManageTeam && (
							<>
								<button
									type="button"
									disabled={exporting}
									onClick={() => void prepareExport("csv")}
								>
									Prepare CSV export
								</button>
								<button
									type="button"
									disabled={exporting}
									onClick={() => void prepareExport("json")}
								>
									Prepare JSON export
								</button>
							</>
						)}
					</div>
					{!canManageTeam && (
						<p className="muted">Audit export is available to team owners and admins.</p>
					)}
					{exportError && (
						<div className="notice notice-danger" role="alert">
							{exportError}
						</div>
					)}
					{readyDownload && (
						<p role="status">
							Audit export is ready to download.{" "}
							<a
								href={readyDownload.url}
								download={`aidr-audit-${readyDownload.teamId}.${readyDownload.format}`}
							>
								Save audit export
							</a>
						</p>
					)}
					{!auditLoaded ? (
						<p className="muted">Loading audit records…</p>
					) : auditError ? (
						<div className="notice notice-danger" role="alert">
							Audit records are unavailable. {auditError}
						</div>
					) : scopedLogs.length === 0 ? (
						<p className="muted">No audit records for this team.</p>
					) : (
						<>
							<table>
								<thead>
									<tr>
										<th>Time</th>
										<th>Actor</th>
										<th>Action</th>
									</tr>
								</thead>
								<tbody>
									{rows.map((row) => (
										<tr key={row.id}>
											<td>
												{Number.isFinite(row.timestamp)
													? new Date(row.timestamp).toLocaleString()
													: "Time unavailable"}
											</td>
											<td>{row.user_email || row.user_id || "Not recorded"}</td>
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
									Previous audit page
								</button>
								<span>
									Page {currentPage + 1} of {pageCount}
								</span>
								<button
									type="button"
									disabled={currentPage >= pageCount - 1}
									onClick={() => setPage(currentPage + 1)}
								>
									Next audit page
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
