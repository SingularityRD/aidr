import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import {
	type DashboardLocale,
	englishT,
	type Translate,
	useDashboardLocale,
	useT,
} from "../../i18n/I18nProvider";
import {
	APPROVAL_REASON_MAX,
	type ApprovalDecision,
	type ApprovalQueue,
	type ApprovalRequest,
	type ApprovalSeparation,
	type ApprovalStatus,
	decideApproval,
	formatCountdown,
	loadApprovalSeparation,
	loadApprovals,
	rotateApprovalSigningKey,
	updateApprovalSeparation,
} from "../../lib/approvals";
import { describeRule, type RuleDescription } from "../../lib/rule-titles";

export const APPROVALS_REFRESH_MS = 15_000;
const CONTROL = /\p{Cc}/u;

/** Operator copy for the service's machine-readable approval errors. */
export function approvalErrorMessage(code: string, t: Translate = englishT): string {
	switch (code) {
		case "mfa_required":
			return t("approvals.error.mfaRequired");
		case "sso_required":
			return t("approvals.error.ssoRequired");
		case "approval_role_insufficient":
		case "approval_forbidden":
			return t("approvals.error.forbidden");
		case "approval_self_approval_forbidden":
			return t("approvals.error.selfApproval");
		case "approval_separation_four_eyes_required":
			return t("approvals.error.fourEyes");
		case "approval_settings_failed":
			return t("approvals.error.settingsFailed");
		case "approval_request_final":
			return t("approvals.error.final");
		case "approval_request_expired":
			return t("approvals.error.expired");
		case "approval_request_not_found":
			return t("approvals.error.notFound");
		case "approval_signing_key_changed":
			return t("approvals.error.keyChanged");
		case "approval_signing_unavailable":
			return t("approvals.error.signingUnavailable");
		case "invalid_reason":
			return t("approvals.error.invalidReason", { max: APPROVAL_REASON_MAX });
		case "rate_limited":
			return t("approvals.error.rateLimited");
		case "session_revoked":
		case "invalid_access_token":
			return t("approvals.error.session");
		case "approvals_unavailable":
			return t("approvals.error.unavailable");
		default:
			return t("approvals.error.generic");
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

const STATUS_LABEL: Record<ApprovalStatus, DashboardMessageKey> = {
	pending: "approvals.status.pending",
	approved: "approvals.status.approved",
	denied: "approvals.status.denied",
	expired: "approvals.status.expired",
};

const SEVERITY_LABEL: Record<string, DashboardMessageKey> = {
	critical: "common.severity.critical",
	high: "common.severity.high",
	medium: "common.severity.medium",
	low: "common.severity.low",
};

const SEVERITY_BADGE: Record<string, string> = {
	critical: "badge badge-critical",
	high: "badge badge-high",
	medium: "badge badge-medium",
	low: "badge badge-low",
};

function useClock(intervalMs: number): number {
	const [now, setNow] = useState(() => Date.now());
	useEffect(() => {
		const timer = setInterval(() => setNow(Date.now()), intervalMs);
		return () => clearInterval(timer);
	}, [intervalMs]);
	return now;
}

function formatTime(value: string | null, locale?: DashboardLocale): string {
	if (!value) return "—";
	const parsed = Date.parse(value);
	return Number.isFinite(parsed)
		? new Date(parsed).toLocaleString(locale === "tr" ? "tr-TR" : undefined)
		: "—";
}

function agentLabel(request: ApprovalRequest): string {
	return request.agentRuntime ? `${request.iid} (${request.agentRuntime})` : request.iid;
}

/**
 * The card heading: the first rule's title, else its category, else a
 * generic "held for review". Rule ids stay visible under "Why it was held".
 */
function cardTitle(rules: RuleDescription[], t: Translate): string {
	const first = rules[0];
	const name = first?.title ?? first?.category ?? t("approvals.card.fallbackTitle");
	return rules.length > 1
		? `${name} (${t("approvals.card.moreRules", { count: rules.length - 1 })})`
		: name;
}

/** The highest severity among the rules, for the heading badge. */
function topSeverity(rules: RuleDescription[]): string | null {
	const order = ["critical", "high", "medium", "low"];
	const found = rules
		.map((rule) => rule.severity)
		.filter((severity): severity is string => severity !== null && order.includes(severity))
		.sort((a, b) => order.indexOf(a) - order.indexOf(b));
	return found[0] ?? null;
}

interface Notice {
	tone: "success" | "error";
	message: string;
	code?: string;
}

function RuleList({ rules }: { rules: RuleDescription[] }) {
	const t = useT();
	if (rules.length === 0) return <span className="muted">{t("approvals.card.noRules")}</span>;
	return (
		<ul className="approval-rules">
			{rules.map((rule) => (
				<li key={rule.id}>
					<span>{rule.title ?? rule.category ?? t("approvals.card.unknownRule")}</span>{" "}
					<span className="badge badge-neutral badge-plain mono">{rule.id}</span>
				</li>
			))}
		</ul>
	);
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
	const t = useT();
	const locale = useDashboardLocale();
	const [reason, setReason] = useState("");
	const countdown = formatCountdown(request.expiresAt, now);
	const lapsed = countdown === "expired";
	const trimmed = reason.trim();
	const reasonValid =
		trimmed.length >= 1 && trimmed.length <= APPROVAL_REASON_MAX && !CONTROL.test(trimmed);
	const reasonId = `approval-reason-${request.id}`;
	const rules = request.threatIds.map((id) => describeRule(id, locale, t));
	const title = cardTitle(rules, t);
	const severity = topSeverity(rules);
	const severityLabel = severity ? SEVERITY_LABEL[severity] : undefined;

	return (
		<li
			className="card"
			id={`approval-${request.id}`}
			tabIndex={-1}
			data-testid="approval-pending"
			aria-label={t("approvals.card.label", { title })}
		>
			<div
				className="row"
				style={{ justifyContent: "space-between", alignItems: "baseline", gap: 12 }}
			>
				<h3 style={{ margin: 0 }}>{title}</h3>
				<span className="row" style={{ gap: 6 }}>
					{severity && severityLabel ? (
						<span className={SEVERITY_BADGE[severity]}>{t(severityLabel)}</span>
					) : null}
					<span
						className={lapsed ? "badge badge-neutral" : "badge badge-warning"}
						data-testid="approval-countdown"
					>
						{lapsed
							? t("approvals.status.expired")
							: t("approvals.card.expiresIn", { time: countdown })}
					</span>
				</span>
			</div>
			<dl className="stack" style={{ gap: 4, marginTop: 8 }}>
				<div>
					<dt className="muted small">{t("approvals.card.what")}</dt>
					<dd>
						<span className="muted small">
							{t("approvals.history.tool")}: <span className="mono">{request.tool}</span>
						</span>
						<p className="approval-summary">{request.summary || t("approvals.card.noSummary")}</p>
						<span className="muted small">{t("approvals.card.summaryNote")}</span>
					</dd>
				</div>
				<div>
					<dt className="muted small">{t("approvals.card.why")}</dt>
					<dd>
						<RuleList rules={rules} />
					</dd>
				</div>
				<div>
					<dt className="muted small">{t("approvals.card.agent")}</dt>
					<dd className="mono">{agentLabel(request)}</dd>
				</div>
				<div>
					<dt className="muted small">{t("approvals.card.requested")}</dt>
					<dd>{formatTime(request.createdAt, locale)}</dd>
				</div>
				<div>
					<dt className="muted small">{t("approvals.card.next")}</dt>
					<dd>{t("approvals.card.nextBody", { agent: request.iid })}</dd>
				</div>
			</dl>
			{canDecide && !lapsed ? (
				<form
					className="stack"
					style={{ marginTop: 12, maxWidth: 560 }}
					onSubmit={(event) => event.preventDefault()}
				>
					<label className="label" htmlFor={reasonId}>
						{t("approvals.card.reason")}
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
							{t("approvals.card.approve")}
						</button>
						<button
							className="button button-danger"
							type="button"
							disabled={busy || !reasonValid}
							onClick={() => onDecide(request, "deny", trimmed)}
						>
							{t("approvals.card.deny")}
						</button>
					</div>
				</form>
			) : null}
			{!canDecide ? (
				<p className="muted small" style={{ marginTop: 8 }}>
					{t("approvals.error.forbidden")}
				</p>
			) : null}
		</li>
	);
}

function HistoryTable({ rows }: { rows: ApprovalRequest[] }) {
	const t = useT();
	const locale = useDashboardLocale();
	if (rows.length === 0) return <p className="muted">{t("approvals.history.empty")}</p>;
	return (
		<div className="table-wrap">
			<table className="table" data-testid="approval-history">
				<thead>
					<tr>
						<th scope="col">{t("approvals.history.requested")}</th>
						<th scope="col">{t("approvals.history.action")}</th>
						<th scope="col">{t("approvals.history.tool")}</th>
						<th scope="col">{t("approvals.history.agent")}</th>
						<th scope="col">{t("approvals.history.rules")}</th>
						<th scope="col">{t("approvals.history.outcome")}</th>
						<th scope="col">{t("approvals.history.decided")}</th>
						<th scope="col">{t("approvals.history.reason")}</th>
					</tr>
				</thead>
				<tbody>
					{rows.map((row) => (
						<tr key={row.id}>
							<td>{formatTime(row.createdAt, locale)}</td>
							<td>
								{cardTitle(
									row.threatIds.map((id) => describeRule(id, locale, t)),
									t,
								)}
							</td>
							<td className="mono">{row.tool}</td>
							<td className="mono">{agentLabel(row)}</td>
							<td className="mono">{row.threatIds.join(", ") || "—"}</td>
							<td>
								<span className={STATUS_BADGE[row.status]}>{t(STATUS_LABEL[row.status])}</span>
							</td>
							<td>{formatTime(row.decidedAt, locale)}</td>
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
	const t = useT();
	const [confirming, setConfirming] = useState(false);
	const [busy, setBusy] = useState(false);

	async function rotate() {
		setBusy(true);
		const result = await rotateApprovalSigningKey(tenantId);
		setBusy(false);
		setConfirming(false);
		if (!result.ok) {
			onNotice({
				tone: "error",
				message: approvalErrorMessage(result.error, t),
				code: result.error,
			});
			return;
		}
		onNotice({
			tone: "success",
			message: t("approvals.key.rotated", { keyId: result.value.keyId }),
		});
	}

	return (
		<div className="card">
			<h2>{t("approvals.key.title")}</h2>
			<p className="muted small">{t("approvals.key.body")}</p>
			{confirming ? (
				<div className="row" style={{ gap: 8 }}>
					<button
						className="button button-danger"
						type="button"
						disabled={busy}
						onClick={() => void rotate()}
					>
						{t("approvals.key.confirm")}
					</button>
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => setConfirming(false)}
					>
						{t("approvals.key.cancel")}
					</button>
				</div>
			) : (
				<button
					className="button button-secondary"
					type="button"
					onClick={() => setConfirming(true)}
				>
					{t("approvals.key.rotate")}
				</button>
			)}
		</div>
	);
}

const SEPARATION_OPTIONS = [
	{ value: "plan", label: "approvals.separation.plan", setting: null },
	{ value: "required", label: "approvals.separation.required", setting: true },
	{ value: "allowed", label: "approvals.separation.allowed", setting: false },
] as const;

function separationValue(configured: boolean | null): string {
	return configured === null ? "plan" : configured ? "required" : "allowed";
}

/** Separation of duties: whether the requester may approve their own block. */
function SeparationOfDutiesSection({
	tenantId,
	onNotice,
}: {
	tenantId: string;
	onNotice: (notice: Notice) => void;
}) {
	const t = useT();
	const [state, setState] = useState<ApprovalSeparation | null>(null);
	const [failed, setFailed] = useState(false);
	const [busy, setBusy] = useState(false);

	useEffect(() => {
		let current = true;
		void loadApprovalSeparation(tenantId).then((result) => {
			if (!current) return;
			setFailed(!result.ok);
			setState(result.ok ? result.value : null);
		});
		return () => {
			current = false;
		};
	}, [tenantId]);

	async function change(value: string) {
		const option = SEPARATION_OPTIONS.find((candidate) => candidate.value === value);
		if (!option) return;
		setBusy(true);
		const result = await updateApprovalSeparation(tenantId, option.setting);
		setBusy(false);
		if (!result.ok) {
			onNotice({
				tone: "error",
				message: approvalErrorMessage(result.error, t),
				code: result.error,
			});
			return;
		}
		setState(result.value);
		onNotice({ tone: "success", message: t("approvals.separation.saved") });
	}

	return (
		<div className="card">
			<h2>{t("approvals.separation.title")}</h2>
			<p className="muted small">{t("approvals.separation.body")}</p>
			{failed ? (
				<p className="muted small">{t("approvals.separation.loadFailed")}</p>
			) : state ? (
				<>
					<label className="label">
						{t("approvals.separation.approver")}
						<select
							className="input"
							value={separationValue(state.configured)}
							disabled={busy}
							onChange={(e) => void change(e.target.value)}
						>
							{SEPARATION_OPTIONS.map((option) => (
								<option key={option.value} value={option.value}>
									{t(option.label)}
								</option>
							))}
						</select>
					</label>
					<p className="muted small" data-testid="approval-separation-effective">
						{state.effective
							? t("approvals.separation.effectiveRequired")
							: t("approvals.separation.effectiveAllowed")}
					</p>
				</>
			) : null}
		</div>
	);
}

function NoticeBanner({ notice, tenantId }: { notice: Notice; tenantId: string }) {
	const t = useT();
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
						{t("approvals.verifyMfa")}
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
	const t = useT();
	if (rows.length === 0) {
		return (
			<div className="card">
				<p className="muted">{t("approvals.empty")}</p>
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

/**
 * Live pending requests, and everything else (decided, expired or lapsed).
 * A pending row whose deadline passes between refreshes moves to history on
 * the clock tick rather than waiting for the next read.
 */
export function splitQueue(
	queue: Pick<ApprovalQueue, "pending" | "history">,
	now: number,
): { pending: ApprovalRequest[]; history: ApprovalRequest[] } {
	const live = (row: ApprovalRequest) =>
		row.status === "pending" && Date.parse(row.expiresAt) > now;
	const lapsed = queue.pending
		.filter((row) => !live(row))
		.map((row) => ({ ...row, status: "expired" as const }));
	const lapsedIds = new Set(lapsed.map((row) => row.id));
	const history = [...lapsed, ...queue.history.filter((row) => !lapsedIds.has(row.id))].sort(
		(a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt),
	);
	return { pending: queue.pending.filter(live), history };
}

/**
 * Keyed by tenant: switching team remounts the page, so a request or decision
 * still in flight for the previous tenant can never write into the new view.
 */
export function ApprovalsPage() {
	const { currentTeam } = useTeam();
	return <TenantApprovalsPage key={currentTeam?.id ?? "no-tenant"} />;
}

function TenantApprovalsPage() {
	const { currentTeam, currentRole, roleResolved } = useTeam();
	const t = useT();
	const locale = useDashboardLocale();
	const tenantId = currentTeam?.id ?? null;
	const canDecide = roleResolved && (currentRole === "owner" || currentRole === "admin");
	const now = useClock(1000);
	const [tab, setTab] = useState<Tab>("pending");
	const [rows, setRows] = useState<ApprovalQueue | null>(null);
	// The error code, not its text, so a language switch re-renders it.
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
			setLoadError(result.error);
		}
	}, [tenantId]);

	// A connector's block message links `/approvals?request=<id>`: bring that
	// request into view once the queue has loaded. The id only selects a card.
	const focusedRequest = useRef(false);
	useEffect(() => {
		if (!rows || focusedRequest.current) return;
		focusedRequest.current = true;
		const id = new URLSearchParams(window.location.search).get("request") ?? "";
		if (!/^[0-9a-f-]{36}$/i.test(id)) return;
		const card = document.getElementById(`approval-${id.toLowerCase()}`);
		card?.scrollIntoView?.({ block: "center" });
		card?.focus?.();
	}, [rows]);

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
						? t("approvals.decided.approved", {
								tool: target.tool,
								agent: target.iid,
								time: formatTime(result.value.tokenExpiresAt, locale),
							})
						: t("approvals.decided.denied", { tool: target.tool, agent: target.iid }),
			});
		} else {
			setNotice({
				tone: "error",
				message: approvalErrorMessage(result.error, t),
				code: result.error,
			});
		}
		await load();
	}

	if (!tenantId) {
		return (
			<div className="stack">
				<h1>{t("nav.approvals")}</h1>
				<div className="card">{t("approvals.noTeam")}</div>
			</div>
		);
	}

	const { pending, history } = splitQueue(rows ?? { pending: [], history: [] }, now);
	// The pending read is bounded by the server's live-request quota; say so if
	// the server ever reports more than was returned instead of hiding them.
	const pendingHidden = rows ? Math.max(0, rows.pendingTotal - rows.pending.length) : 0;

	return (
		<div className="stack">
			<div>
				<h1>{t("nav.approvals")}</h1>
				<p className="muted">{t("approvals.intro")}</p>
			</div>

			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}

			<div className="row" role="tablist" aria-label={t("approvals.tabs")} style={{ gap: 8 }}>
				<TabButton
					id="pending"
					current={tab}
					label={t("approvals.tab.pending", { count: rows ? pending.length : "…" })}
					onSelect={setTab}
				/>
				<TabButton
					id="history"
					current={tab}
					label={t("approvals.tab.history")}
					onSelect={setTab}
				/>
				<button
					className="button button-secondary button-sm"
					type="button"
					onClick={() => void load()}
				>
					{t("approvals.refresh")}
				</button>
			</div>

			{loadError ? (
				<div className="notice notice-danger" role="alert">
					{approvalErrorMessage(loadError, t)}
				</div>
			) : null}
			{!rows && !loadError ? <p className="muted">{t("approvals.loading")}</p> : null}

			{rows && tab === "pending" && pendingHidden > 0 ? (
				<div className="notice notice-warning" role="note" data-testid="approval-pending-truncated">
					{t(pendingHidden === 1 ? "approvals.truncated.one" : "approvals.truncated.other", {
						shown: rows.pending.length,
						hidden: pendingHidden,
					})}
				</div>
			) : null}
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
					<h2>{t("approvals.tab.history")}</h2>
					<HistoryTable rows={history} />
					{rows.historyTruncated ? (
						<p className="muted small" data-testid="approval-history-truncated">
							{t("approvals.historyTruncated", { count: rows.history.length })}
						</p>
					) : null}
				</div>
			) : null}

			{canDecide ? <SigningKeySection tenantId={tenantId} onNotice={setNotice} /> : null}
			{canDecide ? <SeparationOfDutiesSection tenantId={tenantId} onNotice={setNotice} /> : null}
		</div>
	);
}
