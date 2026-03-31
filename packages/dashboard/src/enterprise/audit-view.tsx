import { useMemo, useState } from "react";
import { useTeam } from "./team-provider";

export function AuditView() {
	const { auditLogs, isLoading, canViewAudit, exportAuditLogs, refreshAuditLogs } = useTeam();
	const [filter, setFilter] = useState("");
	const [actionFilter, setActionFilter] = useState<string>("all");
	const [decisionFilter, setDecisionFilter] = useState<string>("all");
	const [dateRange, setDateRange] = useState<{ from?: string; to?: string }>({});
	const [busy, setBusy] = useState(false);
	const [status, setStatus] = useState<string | null>(null);

	const filteredLogs = useMemo(() => {
		return auditLogs.filter((log) => {
			// Text filter
			if (filter) {
				const searchText = filter.toLowerCase();
				const matchText =
					log.action.toLowerCase().includes(searchText) ||
					log.user_email?.toLowerCase().includes(searchText) ||
					JSON.stringify(log.verdict).toLowerCase().includes(searchText);
				if (!matchText) return false;
			}

			// Action filter
			if (actionFilter !== "all" && log.action !== actionFilter) {
				return false;
			}

			// Decision filter
			if (decisionFilter !== "all" && log.verdict?.decision !== decisionFilter) {
				return false;
			}

			// Date range
			if (dateRange.from) {
				const fromDate = new Date(dateRange.from).getTime();
				if (log.timestamp < fromDate) return false;
			}
			if (dateRange.to) {
				const toDate = new Date(dateRange.to).getTime() + 24 * 60 * 60 * 1000;
				if (log.timestamp > toDate) return false;
			}

			return true;
		});
	}, [auditLogs, filter, actionFilter, decisionFilter, dateRange]);

	const uniqueActions = useMemo(() => {
		const actions = new Set(auditLogs.map((log) => log.action));
		return Array.from(actions).sort();
	}, [auditLogs]);

	async function handleExport(format: "csv" | "json") {
		setBusy(true);
		setStatus(null);

		try {
			const url = await exportAuditLogs(format);
			if (url) {
				// Trigger download
				const a = document.createElement("a");
				a.href = url;
				a.download = `audit-logs-${new Date().toISOString().split("T")[0]}.${format}`;
				a.click();
				setStatus(`Audit logs exported as ${format.toUpperCase()}`);
			}
		} catch (err) {
			setStatus(err instanceof Error ? err.message : "Export failed");
		} finally {
			setBusy(false);
		}
	}

	function formatDate(timestamp: number): string {
		return new Date(timestamp).toLocaleString();
	}

	function getDecisionBadge(decision?: string) {
		switch (decision) {
			case "allow":
				return (
					<span
						className="pill"
						style={{
							background: "rgba(11, 132, 104, 0.12)",
							borderColor: "rgba(11, 132, 104, 0.3)",
							color: "#0b8468",
						}}
					>
						Allow
					</span>
				);
			case "deny":
				return (
					<span
						className="pill"
						style={{
							background: "rgba(198, 43, 75, 0.12)",
							borderColor: "rgba(198, 43, 75, 0.3)",
							color: "#c62b4b",
						}}
					>
						Deny
					</span>
				);
			case "ask":
				return (
					<span
						className="pill"
						style={{
							background: "rgba(252, 109, 38, 0.12)",
							borderColor: "rgba(252, 109, 38, 0.3)",
							color: "#e24329",
						}}
					>
						Ask
					</span>
				);
			default:
				return <span className="pill">Unknown</span>;
		}
	}

	if (!canViewAudit) {
		return (
			<div className="card">
				<p className="muted">You don&apos;t have permission to view audit logs.</p>
			</div>
		);
	}

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between">
					<h2 style={{ margin: 0 }}>Audit Logs</h2>
					<div className="row">
						<button
							className="button button-secondary"
							onClick={() => void refreshAuditLogs()}
							disabled={busy}
						>
							Refresh
						</button>
						<button
							className="button button-secondary"
							onClick={() => void handleExport("csv")}
							disabled={busy || filteredLogs.length === 0}
						>
							Export CSV
						</button>
						<button
							className="button button-secondary"
							onClick={() => void handleExport("json")}
							disabled={busy || filteredLogs.length === 0}
						>
							Export JSON
						</button>
					</div>
				</div>

				<div className="row" style={{ flexWrap: "wrap", gap: "12px", marginTop: "16px" }}>
					<input
						className="input"
						type="text"
						placeholder="Search logs..."
						value={filter}
						onChange={(e) => setFilter(e.target.value)}
						style={{ flex: 1, minWidth: "200px" }}
					/>

					<select
						className="input"
						value={actionFilter}
						onChange={(e) => setActionFilter(e.target.value)}
						style={{ minWidth: "140px" }}
					>
						<option value="all">All Actions</option>
						{uniqueActions.map((action) => (
							<option key={action} value={action}>
								{action}
							</option>
						))}
					</select>

					<select
						className="input"
						value={decisionFilter}
						onChange={(e) => setDecisionFilter(e.target.value)}
						style={{ minWidth: "140px" }}
					>
						<option value="all">All Decisions</option>
						<option value="allow">Allow</option>
						<option value="deny">Deny</option>
						<option value="ask">Ask</option>
					</select>

					<input
						className="input"
						type="date"
						value={dateRange.from || ""}
						onChange={(e) => setDateRange((prev) => ({ ...prev, from: e.target.value }))}
						style={{ minWidth: "140px" }}
					/>
					<input
						className="input"
						type="date"
						value={dateRange.to || ""}
						onChange={(e) => setDateRange((prev) => ({ ...prev, to: e.target.value }))}
						style={{ minWidth: "140px" }}
					/>
				</div>

				<p className="muted small">
					Showing {filteredLogs.length} of {auditLogs.length} logs
				</p>
			</div>

			{isLoading ? (
				<div className="card">
					<p className="muted">Loading audit logs...</p>
				</div>
			) : filteredLogs.length === 0 ? (
				<div className="card">
					<p className="muted">No audit logs match your filters.</p>
				</div>
			) : (
				<div className="card" style={{ padding: 0, overflow: "hidden" }}>
					<table className="table">
						<thead>
							<tr>
								<th>Time</th>
								<th>User</th>
								<th>Action</th>
								<th>Tool</th>
								<th>Decision</th>
								<th>Confidence</th>
								<th>Threats</th>
							</tr>
						</thead>
						<tbody>
							{filteredLogs.slice(0, 100).map((log) => (
								<tr key={log.id}>
									<td className="mono" style={{ fontSize: "12px" }}>
										{formatDate(log.timestamp)}
									</td>
									<td>{log.user_email || "System"}</td>
									<td>
										<span className="pill">{log.action}</span>
									</td>
									<td className="mono" style={{ fontSize: "12px" }}>
										{log.verdict?.tool || "-"}
									</td>
									<td>{getDecisionBadge(log.verdict?.decision)}</td>
									<td>
										{log.verdict?.confidence ? (
											<span
												className="pill"
												style={{
													background:
														log.verdict.confidence > 0.9
															? "rgba(198, 43, 75, 0.12)"
															: log.verdict.confidence > 0.7
																? "rgba(252, 109, 38, 0.12)"
																: "rgba(11, 132, 104, 0.12)",
													color:
														log.verdict.confidence > 0.9
															? "#c62b4b"
															: log.verdict.confidence > 0.7
																? "#e24329"
																: "#0b8468",
												}}
											>
												{Math.round(log.verdict.confidence * 100)}%
											</span>
										) : (
											"-"
										)}
									</td>
									<td>
										{log.verdict?.threats && log.verdict.threats.length > 0 ? (
											<div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
												{log.verdict.threats.map((threat, i) => (
													<span
														key={i}
														className="pill"
														style={{ fontSize: "10px", padding: "2px 6px" }}
													>
														{threat}
													</span>
												))}
											</div>
										) : (
											"-"
										)}
									</td>
								</tr>
							))}
							{filteredLogs.length > 100 && (
								<tr>
									<td
										colSpan={7}
										className="muted"
										style={{ textAlign: "center", padding: "20px" }}
									>
										Showing first 100 logs. Use filters to narrow results.
									</td>
								</tr>
							)}
						</tbody>
					</table>
				</div>
			)}

			{status && (
				<div
					className={`notice ${status.includes("Failed") || status.includes("error") ? "notice-danger" : ""}`}
				>
					{status}
				</div>
			)}
		</div>
	);
}
