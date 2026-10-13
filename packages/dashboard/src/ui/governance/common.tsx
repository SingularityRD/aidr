import { useCallback, useEffect, useRef, useState } from "react";
import { Link, NavLink } from "react-router-dom";
import type { TeamMember } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { englishT, type Translate, useT } from "../../i18n/I18nProvider";
import { type GovernanceData, loadGovernance, stepUpPath } from "../../lib/ai-governance";
import type { DiffLine } from "../../lib/json-diff";

const REQUEST_STATUS: Record<string, DashboardMessageKey> = {
	pending: "gov.req.status.pending",
	approved: "gov.req.status.approved",
	rejected: "gov.req.status.rejected",
	cancelled: "gov.req.status.cancelled",
	revoked: "gov.req.status.revoked",
	expired: "gov.req.status.expired",
	superseded: "gov.req.status.superseded",
	failed: "gov.req.status.failed",
};

/** A request, exception or change status in the viewer's language. */
export function requestStatus(status: string, t: Translate): string {
	const key = Object.hasOwn(REQUEST_STATUS, status) ? REQUEST_STATUS[status] : undefined;
	return key ? t(key) : status;
}

export interface Notice {
	tone: "success" | "error";
	message: string;
	code?: string;
}

/** Shared tab bar for the three governance pages. */
export function GovernanceTabs() {
	const t = useT();
	return (
		<nav className="row" aria-label={t("gov.tabs")} style={{ gap: 8, flexWrap: "wrap" }}>
			<NavLink className="button button-secondary button-sm" to="/governance/register">
				{t("gov.tab.register")}
			</NavLink>
			<NavLink className="button button-secondary button-sm" to="/governance/requests">
				{t("gov.tab.requests")}
			</NavLink>
			<NavLink className="button button-secondary button-sm" to="/governance/change-control">
				{t("gov.tab.changeControl")}
			</NavLink>
		</nav>
	);
}

export function NoticeBanner({ notice, tenantId }: { notice: Notice; tenantId: string }) {
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
						{t("common.verifyMfa")}
					</Link>
				</div>
			) : null}
		</div>
	);
}

/** Load (and periodically refresh) the tenant's governance rows under RLS. */
export function useGovernanceData(tenantId: string | null, refreshMs = 30_000) {
	const [data, setData] = useState<GovernanceData | null>(null);
	const [error, setError] = useState<string | null>(null);
	const generation = useRef(0);
	// The tenant this hook currently serves. A reload captured by an older
	// closure (e.g. after an awaited action) must not paint the previous
	// tenant's rows into the new tenant's view.
	const currentTenant = useRef(tenantId);
	currentTenant.current = tenantId;
	const reload = useCallback(async () => {
		if (!tenantId || currentTenant.current !== tenantId) return;
		const id = ++generation.current;
		const result = await loadGovernance(tenantId);
		if (id !== generation.current || currentTenant.current !== tenantId) return;
		if (result.ok) {
			setData(result.value);
			setError(null);
		} else {
			setError(result.error);
		}
	}, [tenantId]);
	useEffect(() => {
		setData(null);
		setError(null);
		void reload();
		const timer = setInterval(() => void reload(), refreshMs);
		return () => {
			generation.current++;
			clearInterval(timer);
		};
	}, [reload, refreshMs]);
	return { data, error, reload };
}

export function useNow(intervalMs = 60_000): number {
	const [now, setNow] = useState(() => Date.now());
	useEffect(() => {
		const timer = setInterval(() => setNow(Date.now()), intervalMs);
		return () => clearInterval(timer);
	}, [intervalMs]);
	return now;
}

export function formatDate(value: string | null): string {
	if (!value) return "—";
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) ? new Date(parsed).toLocaleDateString() : "—";
}

export function formatTime(value: string | null): string {
	if (!value) return "—";
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : "—";
}

/** A member's email when the directory is readable, otherwise a short id. */
export function memberLabel(
	members: TeamMember[],
	userId: string | null,
	currentUserId?: string,
	t: Translate = englishT,
): string {
	if (!userId) return "—";
	if (userId === currentUserId) return t("gov.you");
	const member = members.find((item) => item.user_id === userId);
	return member?.email || `${userId.slice(0, 8)}…`;
}

export function DiffView({ lines, label }: { lines: DiffLine[]; label: string }) {
	const t = useT();
	if (lines.every((line) => line.kind === "same")) {
		return <p className="muted small">{t("gov.noDiff")}</p>;
	}
	return (
		<pre className="diff-view" aria-label={label} data-testid="policy-diff">
			{lines.map((line, index) => (
				<span
					// Line position is the identity of a diff row.
					key={index}
					className={
						line.kind === "add" ? "diff-add" : line.kind === "del" ? "diff-del" : undefined
					}
				>
					{line.kind === "add" ? "+ " : line.kind === "del" ? "- " : "  "}
					{line.text}
					{"\n"}
				</span>
			))}
		</pre>
	);
}

export function ReasonField({
	id,
	value,
	onChange,
	label,
	max = 500,
}: {
	id: string;
	value: string;
	onChange: (value: string) => void;
	label?: string;
	max?: number;
}) {
	const t = useT();
	return (
		<>
			<label className="label" htmlFor={id}>
				{label ?? t("gov.reason")}
			</label>
			<textarea
				id={id}
				className="input"
				rows={2}
				maxLength={max}
				value={value}
				onChange={(event) => onChange(event.target.value)}
			/>
		</>
	);
}

const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/;

export function validText(value: string, max: number): boolean {
	const trimmed = value.trim();
	return trimmed.length >= 1 && trimmed.length <= max && !CONTROL.test(trimmed);
}
