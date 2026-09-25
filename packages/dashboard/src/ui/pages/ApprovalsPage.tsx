import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import {
	APPROVAL_REASON_MAX,
	type ApprovalDecision,
	type ApprovalRequest,
	type ApprovalStatus,
	decideApproval,
	formatCountdown,
	loadApprovals,
	rotateApprovalSigningKey,
} from "../../lib/approvals";

export const APPROVALS_REFRESH_MS = 15_000;
const CONTROL = /\p{Cc}/u;

/** Operator copy for the service's machine-readable approval errors. */
export function approvalErrorMessage(code: string): string {
	switch (code) {
		case "mfa_required":
			return "Multi-factor verification (AAL2) is required to decide approvals. Verify with your authenticator, then try again.";
		case "sso_required":
			return "This workspace requires single sign-on. Sign in with your identity provider, then try again.";
		case "approval_role_insufficient":
		case "approval_forbidden":
			return "Only owners and administrators can decide approvals.";
		case "approval_request_final":
			return "This request was already decided.";
		case "approval_request_expired":
			return "This request expired before it was decided. The agent's action stays blocked.";
		case "approval_request_not_found":
			return "This request is no longer available in this workspace.";
		case "approval_signing_key_changed":
			return "The signing key changed while deciding. Try again.";
		case "approval_signing_unavailable":
			return "The approval could not be signed. Nothing was approved; contact your platform operator.";
		case "invalid_reason":
			return `Enter a reason of 1 to ${APPROVAL_REASON_MAX} characters without control characters.`;
		case "rate_limited":
			return "Too many decisions. Wait a minute and try again.";
		case "session_revoked":
		case "invalid_access_token":
			return "Your session is no longer valid. Sign in again.";
		case "approvals_unavailable":
			return "Approval requests could not be loaded.";
		default:
			return "The approval service did not confirm the request. Nothing changed.";
	}
}

function stepUpPath(tenantId: string): string {
	return `/auth/dlp-step-up?tenant=${encodeURIComponent(tenantId)}&return=approvals`;
}

const STATUS_BADGE: Record<ApprovalStatus, string> = {
	pending: "badge badge-warning",
	approved: "badge badge-success",
	denied: "badge badge-error",
	expired: "badge badge-neutral",
};

function useClock(intervalMs: number): number {
	const [now, setNow] = useState(() => Date.now());
	useEffect(() => {
		const timer = setInterval(() => setNow(Date.now()), intervalMs);
		return () => clearInterval(timer);
	}, [intervalMs]);
	return now;
}

function formatTime(value: string | null): string {
	if (!value) return "—";
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : "—";
}

function agentLabel(request: ApprovalRequest): string {
	return request.agentRuntime ? `${request.iid} (${request.agentRuntime})` : request.iid;
}

interface Notice {
	tone: "success" | "error";
	message: string;
	code?: string;
}

function PendingCard({
	request,
	now,
	canDecide,
	busy,
	onDecide,
}: {
	request: ApprovalRequest;
	now: number;
	canDecide: boolean;
	busy: boolean;
	onDecide: (request: ApprovalRequest, decision: ApprovalDecision, reason: string) => void;
}) {
	const [reason, setReason] = useState("");
	const countdown = formatCountdown(request.expiresAt, now);
	const lapsed = countdown === "expired";
	const trimmed = reason.trim();
	const reasonValid =
		trimmed.length >= 1 && trimmed.length <= APPROVAL_REASON_MAX && !CONTROL.test(trimmed);
	const reasonId = `approval-reason-${request.id}`;

	return (
		<li
			className="card"
			data-testid="approval-pending"
			aria-label={`Approval request for ${request.tool}`}
		>
			<div
				className="row"
				style={{ justifyContent: "space-between", alignItems: "baseline", gap: 12 }}
			>
				<h3 style={{ margin: 0 }}>
					<span className="mono">{request.tool}</span>
				</h3>
				<span
					className={lapsed ? "badge badge-neutral" : "badge badge-warning"}
					data-testid="approval-countdown"
				>
					{lapsed ? "Expired" : `Expires in ${countdown}`}
				</span>
			</div>
			<dl className="stack" style={{ gap: 4, marginTop: 8 }}>
				<div>
					<dt className="muted small">Agent</dt>
					<dd className="mono">{agentLabel(request)}</dd>
				</div>
				<div>
					<dt className="muted small">Threats</dt>
					<dd>
						{request.threatIds.length === 0 ? (
							<span className="muted">None reported</span>
						) : (
							request.threatIds.map((id) => (
								<span
									key={id}
									className="badge badge-high badge-plain mono"
									style={{ marginRight: 6 }}
								>
									{id}
								</span>
							))
						)}
					</dd>
				</div>
				<div>
					<dt className="muted small">Summary (redacted by the connector)</dt>
					<dd>
						<p className="approval-summary">{request.summary || "No summary provided."}</p>
					</dd>
				</div>
				<div>
					<dt className="muted small">Requested</dt>
					<dd>{formatTime(request.createdAt)}</dd>
				</div>
			</dl>
			{canDecide && !lapsed ? (
				<form
					className="stack"
					style={{ marginTop: 12, maxWidth: 560 }}
					onSubmit={(event) => event.preventDefault()}
				>
					<label className="label" htmlFor={reasonId}>
						Reason (recorded in the audit log)
					</label>
					<textarea
						id={reasonId}
						className="input"
						rows={2}
						maxLength={APPROVAL_REASON_MAX}
						value={reason}
						onChange={(event) => setReason(event.target.value)}
						required
					/>
					<div className="row" style={{ gap: 8 }}>
						<button
							className="button"
							type="button"
							disabled={busy || !reasonValid}
							onClick={() => onDecide(request, "approve", trimmed)}
						>
							Approve
						</button>
						<button
							className="button button-danger"
							type="button"
							disabled={busy || !reasonValid}
							onClick={() => onDecide(request, "deny", trimmed)}
						>
							Deny
						</button>
					</div>
					<p className="muted small">
						An approval releases exactly one identical retry of this action on the requesting agent,
						and only within 15 minutes.
					</p>
				</form>
			) : null}
			{!canDecide ? (
				<p className="muted small" style={{ marginTop: 8 }}>
					Only owners and administrators can decide approvals.
				</p>
			) : null}
		</li>
	);
}

function HistoryTable({ rows }: { rows: ApprovalRequest[] }) {
	if (rows.length === 0) return <p className="muted">No decided or expired requests yet.</p>;
	return (
		<div className="table-wrap">
			<table className="table" data-testid="approval-history">
				<thead>
					<tr>
						<th scope="col">Requested</th>
						<th scope="col">Tool</th>
						<th scope="col">Agent</th>
						<th scope="col">Threats</th>
						<th scope="col">Outcome</th>
						<th scope="col">Decided</th>
						<th scope="col">Reason</th>
					</tr>
				</thead>
				<tbody>
					{rows.map((row) => (
						<tr key={row.id}>
							<td>{formatTime(row.createdAt)}</td>
							<td className="mono">{row.tool}</td>
							<td className="mono">{agentLabel(row)}</td>
							<td className="mono">{row.threatIds.join(", ") || "—"}</td>
							<td>
								<span className={STATUS_BADGE[row.status]}>{row.status}</span>
							</td>
							<td>{formatTime(row.decidedAt)}</td>
							<td>{row.reason ?? "—"}</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

function SigningKeySection({
	tenantId,
	onNotice,
}: {
	tenantId: string;
	onNotice: (notice: Notice) => void;
}) {
	const [confirming, setConfirming] = useState(false);
	const [busy, setBusy] = useState(false);

	async function rotate() {
		setBusy(true);
		const result = await rotateApprovalSigningKey(tenantId);
		setBusy(false);
		setConfirming(false);
		if (!result.ok) {
			onNotice({ tone: "error", message: approvalErrorMessage(result.error), code: result.error });
			return;
		}
		onNotice({
			tone: "success",
			message: `Approval signing key rotated. New key ${result.value.keyId}; the previous key stays published only for the lifetime of tokens it already signed.`,
		});
	}

	return (
		<div className="card">
			<h2>Approval signing key</h2>
			<p className="muted small">
				Approval tokens are signed with a per-workspace Ed25519 key held encrypted by the control
				plane. Connectors verify them with the public key delivered in their signed entitlement.
				Rotate the key if you suspect it was exposed.
			</p>
			{confirming ? (
				<div className="row" style={{ gap: 8 }}>
					<button
						className="button button-danger"
						type="button"
						disabled={busy}
						onClick={() => void rotate()}
					>
						Confirm rotation
					</button>
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => setConfirming(false)}
					>
						Cancel
					</button>
				</div>
			) : (
				<button
					className="button button-secondary"
					type="button"
					onClick={() => setConfirming(true)}
				>
					Rotate signing key
				</button>
			)}
		</div>
	);
}

function NoticeBanner({ notice, tenantId }: { notice: Notice; tenantId: string }) {
	const error = notice.tone === "error";
	return (
		<div
			className={`notice ${error ? "notice-danger" : "notice-success"}`}
			role={error ? "alert" : "status"}
		>
			{notice.message}
			{notice.code === "mfa_required" ? (
				<div style={{ marginTop: 8 }}>
					<Link className="button button-sm" to={stepUpPath(tenantId)}>
						Verify with authenticator
					</Link>
				</div>
			) : null}
		</div>
	);
}

type Tab = "pending" | "history";

function TabButton({
	id,
	current,
	label,
	onSelect,
}: {
	id: Tab;
	current: Tab;
	label: string;
	onSelect: (tab: Tab) => void;
}) {
	const selected = id === current;
	return (
		<button
			type="button"
			role="tab"
			aria-selected={selected}
			className={selected ? "button button-sm" : "button button-secondary button-sm"}
			onClick={() => onSelect(id)}
		>
			{label}
		</button>
	);
}

function PendingList({
	rows,
	now,
	canDecide,
	busy,
	onDecide,
}: {
	rows: ApprovalRequest[];
	now: number;
	canDecide: boolean;
	busy: boolean;
	onDecide: (request: ApprovalRequest, decision: ApprovalDecision, reason: string) => void;
}) {
	if (rows.length === 0) {
		return (
			<div className="card">
				<p className="muted">No pending approval requests.</p>
			</div>
		);
	}
	return (
		<ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
			{rows.map((row) => (
				<PendingCard
					key={row.id}
					request={row}
					now={now}
					canDecide={canDecide}
					busy={busy}
					onDecide={onDecide}
				/>
			))}
		</ul>
	);
}

/** Live pending requests, and everything else (decided, expired or lapsed). */
export function splitQueue(
	rows: ApprovalRequest[],
	now: number,
): { pending: ApprovalRequest[]; history: ApprovalRequest[] } {
	const live = (row: ApprovalRequest) =>
		row.status === "pending" && Date.parse(row.expiresAt) > now;
	return { pending: rows.filter(live), history: rows.filter((row) => !live(row)) };
}

export function ApprovalsPage() {
	const { currentTeam, currentRole, roleResolved } = useTeam();
	const tenantId = currentTeam?.id ?? null;
	const canDecide = roleResolved && (currentRole === "owner" || currentRole === "admin");
	const now = useClock(1000);
	const [tab, setTab] = useState<Tab>("pending");
	const [rows, setRows] = useState<ApprovalRequest[] | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [notice, setNotice] = useState<Notice | null>(null);
	const [busyId, setBusyId] = useState<string | null>(null);
	const request = useRef(0);

	const load = useCallback(async () => {
		if (!tenantId) return;
		const id = ++request.current;
		const result = await loadApprovals(tenantId);
		if (id !== request.current) return;
		if (result.ok) {
			setRows(result.value);
			setLoadError(null);
		} else {
			setLoadError(approvalErrorMessage(result.error));
		}
	}, [tenantId]);

	useEffect(() => {
		setRows(null);
		setLoadError(null);
		setNotice(null);
		void load();
		const timer = setInterval(() => void load(), APPROVALS_REFRESH_MS);
		return () => {
			request.current++;
			clearInterval(timer);
		};
	}, [load]);

	async function decide(target: ApprovalRequest, decision: ApprovalDecision, reason: string) {
		if (!tenantId) return;
		setBusyId(target.id);
		setNotice(null);
		const result = await decideApproval(tenantId, target.id, decision, reason);
		setBusyId(null);
		if (result.ok) {
			setNotice({
				tone: "success",
				message:
					result.value.status === "approved"
						? `Approved ${target.tool} on ${target.iid}. The connector can retry the identical action until ${formatTime(result.value.tokenExpiresAt)}.`
						: `Denied ${target.tool} on ${target.iid}. The action stays blocked.`,
			});
		} else {
			setNotice({ tone: "error", message: approvalErrorMessage(result.error), code: result.error });
		}
		await load();
	}

	if (!tenantId) {
		return (
			<div className="stack">
				<h1>Approvals</h1>
				<div className="card">Select a team to review approval requests.</div>
			</div>
		);
	}

	const { pending, history } = splitQueue(rows ?? [], now);

	return (
		<div className="stack">
			<div>
				<h1>Approvals</h1>
				<p className="muted">
					In managed mode a connector files a request here when a tool call is held for approval (an
					<span className="mono"> ask </span>verdict). The agent itself can never approve: decisions
					are made here by an owner or administrator with multi-factor verification, signed, and
					collected by the requesting connector.
				</p>
			</div>

			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}

			<div className="row" role="tablist" aria-label="Approval requests" style={{ gap: 8 }}>
				<TabButton
					id="pending"
					current={tab}
					label={`Pending (${rows ? pending.length : "…"})`}
					onSelect={setTab}
				/>
				<TabButton id="history" current={tab} label="History" onSelect={setTab} />
				<button
					className="button button-secondary button-sm"
					type="button"
					onClick={() => void load()}
				>
					Refresh
				</button>
			</div>

			{loadError ? (
				<div className="notice notice-danger" role="alert">
					{loadError}
				</div>
			) : null}
			{!rows && !loadError ? <p className="muted">Loading approval requests…</p> : null}

			{rows && tab === "pending" ? (
				<PendingList
					rows={pending}
					now={now}
					canDecide={canDecide}
					busy={busyId !== null}
					onDecide={(target, decision, reason) => void decide(target, decision, reason)}
				/>
			) : null}
			{rows && tab === "history" ? (
				<div className="card">
					<h2>History</h2>
					<HistoryTable rows={history} />
				</div>
			) : null}

			{canDecide ? <SigningKeySection tenantId={tenantId} onNotice={setNotice} /> : null}
		</div>
	);
}
