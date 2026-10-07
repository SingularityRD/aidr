import { useCallback, useEffect, useRef, useState } from "react";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { useTeam } from "./team-provider";

export const ADMIN_AUDIT_PAGE_SIZE = 25;

export interface AdminAuditRow {
	id: number;
	createdAt: string;
	actorUserId: string | null;
	targetUserId: string | null;
	action: string;
	detail: Record<string, unknown>;
}

type Cursor = { createdAt: string; id: number };

/** Strictly parse one RPC row; anything unexpected drops the whole page. */
function readRow(value: unknown): AdminAuditRow | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const row = value as Record<string, unknown>;
	if (
		typeof row.id !== "number" ||
		!Number.isSafeInteger(row.id) ||
		typeof row.created_at !== "string" ||
		!Number.isFinite(Date.parse(row.created_at)) ||
		typeof row.action !== "string" ||
		!(row.actor_user_id === null || typeof row.actor_user_id === "string") ||
		!(row.target_user_id === null || typeof row.target_user_id === "string")
	)
		return null;
	const detail =
		row.detail && typeof row.detail === "object" && !Array.isArray(row.detail)
			? (row.detail as Record<string, unknown>)
			: {};
	return {
		id: row.id,
		createdAt: row.created_at,
		actorUserId: row.actor_user_id as string | null,
		targetUserId: row.target_user_id as string | null,
		action: row.action,
		detail,
	};
}

export function readAdminAuditPage(value: unknown): AdminAuditRow[] | null {
	if (!Array.isArray(value) || value.length > ADMIN_AUDIT_PAGE_SIZE + 1) return null;
	const rows = value.map(readRow);
	return rows.every((row): row is AdminAuditRow => row !== null) ? rows : null;
}

function summarize(detail: Record<string, unknown>): string {
	const text = JSON.stringify(detail);
	return text === "{}" ? "" : text.length > 160 ? `${text.slice(0, 157)}…` : text;
}

/**
 * Administrative actions (policy, SSO, SCIM, retention, roles…) recorded in
 * admin_audit_logs, for owners and admins only. The server RPC re-checks the
 * role and the tenant on every page; this view only renders what it returns.
 */
export function AdminAuditSection() {
	const { currentTeam, canManageTeam, exportAuditLogs } = useTeam();
	const tenantId = currentTeam?.tenant_id ?? null;
	const [rows, setRows] = useState<AdminAuditRow[]>([]);
	const [hasMore, setHasMore] = useState(false);
	const [history, setHistory] = useState<Array<Cursor | null>>([null]);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [exportState, setExportState] = useState<{ url?: string; error?: string; busy?: boolean }>(
		{},
	);
	const selected = useRef(tenantId);
	selected.current = tenantId;

	const load = useCallback(
		async (cursor: Cursor | null) => {
			if (!tenantId) return;
			const requested = tenantId;
			setLoading(true);
			setError(null);
			try {
				const { data, error: rpcError } = await supabase.rpc("list_tenant_admin_audit_logs", {
					p_tenant_id: requested,
					// One extra row tells us whether an older page exists.
					p_limit: ADMIN_AUDIT_PAGE_SIZE + 1,
					...(cursor ? { p_before_created_at: cursor.createdAt, p_before_id: cursor.id } : {}),
				});
				if (selected.current !== requested) return;
				if (rpcError) throw rpcError;
				const page = readAdminAuditPage(data);
				if (!page) throw new Error("The administrative audit response was malformed.");
				setRows(page.slice(0, ADMIN_AUDIT_PAGE_SIZE));
				setHasMore(page.length > ADMIN_AUDIT_PAGE_SIZE);
			} catch (err) {
				if (selected.current !== requested) return;
				setRows([]);
				setHasMore(false);
				setError(readErrorMessage(err, "Administrative audit records are unavailable."));
			} finally {
				if (selected.current === requested) setLoading(false);
			}
		},
		[tenantId],
	);

	useEffect(() => {
		setHistory([null]);
		setExportState({});
		if (canManageTeam) void load(null);
	}, [load, canManageTeam]);

	if (!currentTeam || !canManageTeam) return null;

	const pageIndex = history.length - 1;
	const older = () => {
		const last = rows[rows.length - 1];
		if (!last) return;
		const cursor = { createdAt: last.createdAt, id: last.id };
		setHistory((current) => [...current, cursor]);
		void load(cursor);
	};
	const newer = () => {
		const next = history.slice(0, -1);
		setHistory(next);
		void load(next[next.length - 1] ?? null);
	};
	const exportAdmin = async (format: "csv" | "json") => {
		setExportState({ busy: true });
		try {
			const url = await exportAuditLogs(format, "admin");
			setExportState({ url });
		} catch (err) {
			setExportState({
				error: readErrorMessage(err, "Administrative audit export is unavailable."),
			});
		}
	};

	return (
		<section aria-labelledby="admin-audit-heading">
			<h3 id="admin-audit-heading">Administrative actions</h3>
			<p className="muted">
				Configuration and access changes (policies, SSO, SCIM, retention, roles) for this team.
				Visible to owners and admins only.
			</p>
			<div className="button-row">
				<button type="button" onClick={() => void load(history[pageIndex] ?? null)}>
					Refresh administrative audit
				</button>
				<button type="button" disabled={exportState.busy} onClick={() => void exportAdmin("csv")}>
					Export administrative CSV
				</button>
				<button type="button" disabled={exportState.busy} onClick={() => void exportAdmin("json")}>
					Export administrative JSON
				</button>
			</div>
			{exportState.error && (
				<div className="notice notice-danger" role="alert">
					{exportState.error}
				</div>
			)}
			{exportState.url && (
				<p role="status">
					<a href={exportState.url} download={`aidr-admin-audit-${currentTeam.id}`}>
						Save administrative audit export
					</a>
				</p>
			)}
			{loading ? (
				<p className="muted">Loading administrative actions…</p>
			) : error ? (
				<div className="notice notice-danger" role="alert">
					Administrative audit records are unavailable. {error}
				</div>
			) : rows.length === 0 ? (
				<p className="muted">No administrative actions recorded for this team.</p>
			) : (
				<table>
					<thead>
						<tr>
							<th>Time</th>
							<th>Actor</th>
							<th>Action</th>
							<th>Target</th>
							<th>Detail</th>
						</tr>
					</thead>
					<tbody>
						{rows.map((row) => (
							<tr key={row.id}>
								<td>{new Date(row.createdAt).toLocaleString()}</td>
								<td>{row.actorUserId ?? "System"}</td>
								<td>{row.action}</td>
								<td>{row.targetUserId ?? ""}</td>
								<td>
									<code>{summarize(row.detail)}</code>
								</td>
							</tr>
						))}
					</tbody>
				</table>
			)}
			<div className="button-row">
				<button type="button" disabled={loading || pageIndex === 0} onClick={newer}>
					Newer administrative actions
				</button>
				<span>Page {pageIndex + 1}</span>
				<button type="button" disabled={loading || !hasMore} onClick={older}>
					Older administrative actions
				</button>
			</div>
		</section>
	);
}
