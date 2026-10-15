/**
 * UsageMetering - Dashboard widget for tracking agent usage against entitlements.
 *
 * Displays four key sections:
 * 1. Agent usage progress bar (current / allowed, color-coded by threshold)
 * 2. Usage trend over the last 7 days (mini bar chart)
 * 3. Billing status (subscription state, provider, period end)
 * 4. Upgrade prompt when usage ≥ 80 % of the allowance
 *
 * Data sources (all RLS-protected, authed user):
 * - `seat_usage` view → current_agents, allowed_agents, included_agents, extra_agents
 * - `subscriptions` table → status, provider, cancel_at_period_end, etc.
 * - `agents` table → created_at for daily trend computation
 *
 * A missing `seat_usage` view is an unavailable allowance, not a reason to
 * show persisted billing seats that may have passed their provider term.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useTeam } from "../enterprise/team-provider";
import { type Translate, useT } from "../i18n/I18nProvider";
import type { Database } from "../lib/database.types";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Normalised usage data from the effective seat_usage view. */
interface UsageData {
	currentAgents: number;
	allowedAgents: number;
	includedAgents: number;
	extraAgents: number;
}

/** One bucket in the 7-day trend chart. */
interface DailyTrend {
	/** ISO date string (YYYY-MM-DD). */
	date: string;
	/** Number of agents first seen on this date. */
	count: number;
}

/** Billing summary from the most recent subscription row. */
interface BillingInfo {
	status: string;
	provider: string;
	currentPeriodEnd: string | null;
	cancelAtPeriodEnd: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Usage ratio at or above which we show a warning prompt. */
const WARNING_THRESHOLD = 0.8;

/** Usage ratio at or above which we show a danger / over-limit prompt. */
const CRITICAL_THRESHOLD = 1.0;

/** Number of days for the trend chart. */
const TREND_DAYS = 7;

/** CSS colour values used for the progress bar at each threshold level. */
const BAR_COLOURS = {
	safe: "var(--success-500)",
	warning: "var(--warning-500)",
	critical: "var(--error-500)",
} as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return an array of the last N ISO date strings (YYYY-MM-DD) in
 * chronological order, ending with today.
 */
function getLastNDates(n: number): string[] {
	const dates: string[] = [];
	const today = new Date();
	for (let i = n - 1; i >= 0; i--) {
		const d = new Date(today);
		d.setDate(d.getDate() - i);
		dates.push(d.toISOString().slice(0, 10));
	}
	return dates;
}

/**
 * Choose a progress-bar colour based on the usage ratio.
 * - < 80 %  → safe (green)
 * - 80-99 % → warning (amber)
 * - ≥ 100 % → critical (red)
 */
function barColour(ratio: number): string {
	if (ratio >= CRITICAL_THRESHOLD) return BAR_COLOURS.critical;
	if (ratio >= WARNING_THRESHOLD) return BAR_COLOURS.warning;
	return BAR_COLOURS.safe;
}

/**
 * Human-readable label for a subscription status value.
 */
function formatSubscriptionStatus(status: string, t: Translate): string {
	switch (status) {
		case "active":
			return t("usage.status.active");
		case "paused":
			return t("usage.status.paused");
		case "cancelled":
			return t("usage.status.cancelled");
		case "past_due":
			return t("usage.status.pastDue");
		case "expired":
			return t("usage.status.expired");
		case "term_unverified":
			return t("usage.status.unverified");
		default:
			return status.charAt(0).toUpperCase() + status.slice(1);
	}
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/**
 * Colour-coded progress bar.
 *
 * Renders a horizontal bar where the filled portion represents the ratio of
 * `value` / `max`. The colour transitions from green → amber → red as the
 * ratio crosses the configured thresholds.
 */
function UsageBar({ value, max }: { value: number; max: number }) {
	const t = useT();
	const ratio = max > 0 ? value / max : 0;
	const pct = Math.min(ratio, 1) * 100;
	const colour = barColour(ratio);

	return (
		<div
			style={{
				width: "100%",
				height: 10,
				background: "var(--bg-tertiary)",
				borderRadius: "var(--radius-full)",
				overflow: "hidden",
				marginTop: "var(--space-2)",
			}}
			role="progressbar"
			aria-valuenow={value}
			aria-valuemin={0}
			aria-valuemax={max}
			aria-label={t("usage.barLabel", { value, max })}
		>
			<div
				style={{
					width: `${pct}%`,
					height: "100%",
					background: colour,
					borderRadius: "var(--radius-full)",
					transition: "width 300ms ease, background 300ms ease",
				}}
			/>
		</div>
	);
}

/**
 * Mini bar chart showing the last {@link TREND_DAYS} days of agent creation
 * activity. Each bar is proportional to the day's count relative to the
 * busiest day in the period.
 */
function TrendChart({ data }: { data: DailyTrend[] }) {
	const t = useT();
	const maxCount = Math.max(1, ...data.map((d) => d.count));

	return (
		<div
			style={{
				display: "flex",
				alignItems: "flex-end",
				gap: 4,
				height: 48,
				paddingTop: "var(--space-2)",
			}}
			aria-label={t("usage.trendLabel")}
			role="img"
		>
			{data.map((day) => {
				const heightPct = (day.count / maxCount) * 100;
				const dayLabel = new Date(day.date + "T00:00:00").toLocaleDateString(undefined, {
					weekday: "short",
				});
				return (
					<div
						key={day.date}
						style={{
							flex: 1,
							display: "flex",
							flexDirection: "column",
							alignItems: "center",
							gap: 2,
						}}
						title={
							day.count === 1
								? t("usage.dayAgent", { day: dayLabel })
								: t("usage.dayAgents", { day: dayLabel, count: day.count })
						}
					>
						<div
							style={{
								width: "100%",
								height: `${Math.max(heightPct, 4)}%`,
								minHeight: 4,
								background: day.count > 0 ? "var(--brand-400)" : "var(--bg-tertiary)",
								borderRadius: "2px 2px 0 0",
								transition: "height 300ms ease",
							}}
						/>
						<span
							style={{
								fontSize: 9,
								color: "var(--text-muted)",
								lineHeight: 1,
							}}
						>
							{dayLabel.charAt(0)}
						</span>
					</div>
				);
			})}
		</div>
	);
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

/**
 * UsageMetering fetches entitlement, agent, and subscription data for the
 * currently authenticated user and renders a compact widget suitable for a
 * dashboard overview page.
 *
 * @example
 * ```tsx
 * import { UsageMetering } from "../components/usage-metering";
 *
 * function DashboardPage() {
 *   return (
 *     <div className="stack">
 *       <UsageMetering />
 *       // other widgets …
 *     </div>
 *   );
 * }
 * ```
 */
// ── Data-loading helpers (module level to reduce cognitive complexity) ──

type UsageSetter = (u: UsageData | null) => void;
type TrendSetter = (t: DailyTrend[]) => void;
type BillingSetter = (b: BillingInfo | null) => void;
type ErrorSetter = (e: string | null) => void;

async function loadUsageData(
	tenantId: string,
	setUsage: UsageSetter,
	setError: ErrorSetter,
	cancelled: () => boolean,
	t: Translate,
) {
	const res = await supabase
		.from("seat_usage")
		.select("included_agents,extra_agents,allowed_agents,current_agents")
		.eq("tenant_id", tenantId)
		.maybeSingle();

	if (!res.error && res.data) {
		const row = res.data as Database["public"]["Tables"]["seat_usage"]["Row"];
		const values = [row.included_agents, row.extra_agents, row.allowed_agents, row.current_agents];
		if (
			!values.every((value) => Number.isSafeInteger(value) && value >= 0) ||
			row.allowed_agents !== row.included_agents + row.extra_agents
		) {
			if (!cancelled()) {
				setUsage(null);
				setError(t("usage.unavailable"));
			}
			return;
		}
		if (!cancelled()) {
			setUsage({
				currentAgents: row.current_agents,
				allowedAgents: row.allowed_agents,
				includedAgents: row.included_agents,
				extraAgents: row.extra_agents,
			});
		}
		return;
	}
	if (!cancelled()) {
		setUsage(null);
		setError(
			res.error ? readErrorMessage(res.error, t("usage.loadFailed")) : t("usage.unavailable"),
		);
	}
}

async function loadTrendData(
	tenantId: string,
	setTrend: TrendSetter,
	setError: ErrorSetter,
	cancelled: () => boolean,
) {
	const since = new Date();
	since.setDate(since.getDate() - TREND_DAYS);

	const { data: agents, error: agentsError } = await supabase
		.from("agents")
		.select("first_seen")
		.eq("tenant_id", tenantId)
		.gte("first_seen", since.toISOString());

	if (agentsError) {
		if (!cancelled()) setError(agentsError.message);
		return;
	}

	const buckets = new Map<string, number>();
	const dateKeys = getLastNDates(TREND_DAYS);
	for (const key of dateKeys) buckets.set(key, 0);

	const rows = (agents ?? []) as Pick<
		Database["public"]["Tables"]["agents"]["Row"],
		"first_seen"
	>[];
	for (const a of rows) {
		const key = a.first_seen.slice(0, 10);
		if (buckets.has(key)) {
			buckets.set(key, (buckets.get(key) ?? 0) + 1);
		}
	}

	if (!cancelled()) {
		setTrend(dateKeys.map((date) => ({ date, count: buckets.get(date) ?? 0 })));
	}
}

async function loadBillingData(
	tenantId: string,
	setBilling: BillingSetter,
	setError: ErrorSetter,
	cancelled: () => boolean,
) {
	const { data: subData, error: subError } = await supabase
		.from("subscriptions")
		.select("status,provider,extra_agents,current_period_end,cancel_at_period_end")
		.eq("tenant_id", tenantId)
		.order("updated_at", { ascending: false })
		.limit(1)
		.maybeSingle();

	if (subError) {
		if (!cancelled()) setError(subError.message);
		return;
	}

	if (subData) {
		const row = subData as Database["public"]["Tables"]["subscriptions"]["Row"];
		const providerTermRequired = row.provider === "stripe" || row.provider === "paddle";
		const termEnd = row.current_period_end ? Date.parse(row.current_period_end) : Number.NaN;
		const status =
			providerTermRequired &&
			(row.status === "active" || row.status === "trialing") &&
			(!Number.isFinite(termEnd) || termEnd <= Date.now())
				? "term_unverified"
				: row.status;
		if (!cancelled()) {
			setBilling({
				status,
				provider: row.provider,
				currentPeriodEnd: row.current_period_end,
				cancelAtPeriodEnd: row.cancel_at_period_end,
			});
		}
	}
}

// ── Sub-components for render sections ───────────────────────────────────

interface MeteringHeaderProps {
	billing: BillingInfo | null;
	usage: UsageData | null;
}

function MeteringHeader({ billing, usage }: MeteringHeaderProps) {
	const t = useT();
	if (billing) {
		const isActive = billing.status === "active";
		return (
			<span
				className={`pill ${isActive ? "pill-success" : "pill-warning"}`}
				style={{
					background: isActive ? "var(--success-50)" : "var(--warning-50)",
					color: isActive ? "var(--success-600)" : "var(--warning-600)",
					border: `1px solid ${isActive ? "var(--success-500)" : "var(--warning-500)"}`,
				}}
			>
				<span
					style={{
						width: 6,
						height: 6,
						borderRadius: "50%",
						background: isActive ? "var(--success-500)" : "var(--warning-500)",
						display: "inline-block",
					}}
				/>
				{formatSubscriptionStatus(billing.status, t)}
			</span>
		);
	}

	return (
		<span className="pill" style={{ background: "var(--bg-tertiary)", color: "var(--text-muted)" }}>
			{usage?.allowedAgents === 0 ? t("usage.noAccess") : t("usage.noSubscription")}
		</span>
	);
}

interface BillingSectionProps {
	billing: BillingInfo | null;
	usage: UsageData | null;
}

function BillingSection({ billing, usage }: BillingSectionProps) {
	const t = useT();
	if (billing) {
		return (
			<div
				style={{
					display: "grid",
					gridTemplateColumns: "1fr 1fr",
					gap: "var(--space-2)",
					marginBottom: "var(--space-3)",
					padding: "var(--space-3)",
					background: "var(--bg-tertiary)",
					borderRadius: "var(--radius-md)",
					fontSize: "var(--text-sm)",
				}}
			>
				<div>
					<div className="muted small">{t("billing.provider")}</div>
					<div className="mono" style={{ fontSize: "var(--text-xs)", marginTop: 2 }}>
						{billing.provider}
					</div>
				</div>
				<div>
					<div className="muted small">{t("billing.extraAgents")}</div>
					<div className="mono" style={{ fontSize: "var(--text-xs)", marginTop: 2 }}>
						{usage?.extraAgents ?? 0}
					</div>
				</div>
				{billing.currentPeriodEnd ? (
					<div style={{ gridColumn: "1 / -1" }}>
						<div className="muted small">{t("usage.currentPeriodEnds")}</div>
						<div className="mono" style={{ fontSize: "var(--text-xs)", marginTop: 2 }}>
							{new Date(billing.currentPeriodEnd).toLocaleDateString(undefined, {
								year: "numeric",
								month: "short",
								day: "numeric",
							})}
						</div>
					</div>
				) : null}
			</div>
		);
	}

	const included = usage?.includedAgents ?? 0;
	const allowed = usage?.allowedAgents ?? 0;
	return (
		<div
			style={{
				marginBottom: "var(--space-3)",
				padding: "var(--space-3)",
				background: "var(--bg-tertiary)",
				borderRadius: "var(--radius-md)",
				fontSize: "var(--text-sm)",
			}}
		>
			<div className="muted small">{t("plan.title")}</div>
			<div className="mono" style={{ fontSize: "var(--text-xs)", marginTop: 2 }}>
				{allowed === 0
					? t("usage.noAllocation")
					: allowed === 1
						? t("usage.allocationOne", { included })
						: t("usage.allocation", { allowed, included })}
			</div>
		</div>
	);
}

interface UpgradePromptProps {
	showCritical: boolean;
	showWarning: boolean;
	usageRatio: number;
}

function UpgradePrompt({ showCritical, showWarning, usageRatio }: UpgradePromptProps) {
	const t = useT();
	if (showCritical) {
		return (
			<div
				className="notice notice-danger"
				style={{
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					gap: "var(--space-2)",
				}}
			>
				<span>
					<b>{t("usage.overLimit")}</b> {t("usage.mayReject")}{" "}
					<span className="muted" style={{ fontSize: "var(--text-sm)" }}>
						{t("usage.addSeats")}
					</span>
				</span>
				<a className="btn btn-primary btn-sm" href="/billing" style={{ flexShrink: 0 }}>
					{t("usage.upgrade")}
				</a>
			</div>
		);
	}

	if (showWarning) {
		return (
			<div
				className="notice"
				style={{
					borderColor: "var(--warning-500)",
					background: "var(--warning-50)",
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					gap: "var(--space-2)",
				}}
			>
				<span>
					<b>{t("usage.approaching")}</b>{" "}
					<span className="muted" style={{ fontSize: "var(--text-sm)" }}>
						{t("usage.used", { percent: Math.round(usageRatio * 100) })}
					</span>
				</span>
				<a className="btn btn-primary btn-sm" href="/billing" style={{ flexShrink: 0 }}>
					{t("usage.upgrade")}
				</a>
			</div>
		);
	}

	return null;
}

function LoadingSkeleton() {
	return (
		<div className="card">
			<div className="stack" style={{ gap: "var(--space-4)" }}>
				<div
					style={{
						height: 20,
						width: "60%",
						background: "var(--bg-tertiary)",
						borderRadius: "var(--radius-sm)",
					}}
				/>
				<div
					style={{
						height: 10,
						width: "100%",
						background: "var(--bg-tertiary)",
						borderRadius: "var(--radius-full)",
					}}
				/>
				<div
					style={{
						height: 48,
						width: "100%",
						background: "var(--bg-tertiary)",
						borderRadius: "var(--radius-sm)",
					}}
				/>
			</div>
		</div>
	);
}

function ErrorBlock({ message }: { message: string }) {
	const t = useT();
	return (
		<div className="card">
			<h2 style={{ margin: 0, marginBottom: "var(--space-2)", fontSize: "var(--text-lg)" }}>
				{t("usage.title")}
			</h2>
			<div className="notice notice-danger">{message}</div>
		</div>
	);
}

// ── Orchestrator ─────────────────────────────────────────────────────────

interface DataSetters {
	setUsage: UsageSetter;
	setTrend: TrendSetter;
	setBilling: BillingSetter;
	setError: ErrorSetter;
	setIsLoading: (v: boolean) => void;
}

async function loadAllData(
	tenantId: string,
	{ setUsage, setTrend, setBilling, setError, setIsLoading }: DataSetters,
	isCancelled: () => boolean,
	t: Translate,
) {
	setIsLoading(true);
	setError(null);

	const promises = [
		loadUsageData(tenantId, setUsage, setError, isCancelled, t),
		loadTrendData(tenantId, setTrend, setError, isCancelled),
		loadBillingData(tenantId, setBilling, setError, isCancelled),
	];

	const results = await Promise.allSettled(promises);

	if (isCancelled()) return;

	for (const r of results) {
		if (r.status === "rejected") {
			setError(readErrorMessage(r.reason, t("usage.loadFailed")));
			break;
		}
	}

	setIsLoading(false);
}

// ── Main component ──────────────────────────────────────────────────────

export function UsageMetering() {
	const { currentTeam } = useTeam();
	const t = useT();
	if (!currentTeam) return <div className="card">{t("usage.noTeam")}</div>;
	return <TenantUsageMetering key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantUsageMetering({ tenantId }: { tenantId: string }) {
	const t = useT();
	// Read through a ref so a language switch re-renders without reloading data.
	const translator = useRef(t);
	translator.current = t;
	const [usage, setUsage] = useState<UsageData | null>(null);
	const [trend, setTrend] = useState<DailyTrend[]>([]);
	const [billing, setBilling] = useState<BillingInfo | null>(null);
	const [isLoading, setIsLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		const isCancelled = () => cancelled;

		const setters: DataSetters = { setUsage, setTrend, setBilling, setError, setIsLoading };
		loadAllData(tenantId, setters, isCancelled, translator.current);

		const interval = setInterval(
			() => loadAllData(tenantId, setters, isCancelled, translator.current),
			30_000,
		);
		return () => {
			cancelled = true;
			clearInterval(interval);
		};
	}, [tenantId]);

	const usageRatio = useMemo(() => {
		if (!usage || usage.allowedAgents <= 0) return 0;
		return usage.currentAgents / usage.allowedAgents;
	}, [usage]);

	const showWarning = useMemo(
		() => usageRatio >= WARNING_THRESHOLD && usageRatio < CRITICAL_THRESHOLD,
		[usageRatio],
	);

	const showCritical = useMemo(() => usageRatio >= CRITICAL_THRESHOLD, [usageRatio]);

	if (isLoading && !usage && !billing) {
		return <LoadingSkeleton />;
	}

	if (error && !usage) {
		return <ErrorBlock message={error} />;
	}

	const current = usage?.currentAgents ?? 0;
	const allowed = usage?.allowedAgents ?? 1;

	return (
		<div className="card" style={{ position: "relative" }}>
			<div
				style={{
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					marginBottom: "var(--space-4)",
				}}
			>
				<div>
					<h2 style={{ margin: 0, fontSize: "var(--text-lg)", fontWeight: 600 }}>
						{t("usage.title")}
					</h2>
					<p className="muted small" style={{ margin: "var(--space-1) 0 0" }}>
						{t("usage.subtitle")}
					</p>
				</div>
				<MeteringHeader billing={billing} usage={usage} />
			</div>

			{error ? (
				<div
					className="notice notice-danger"
					style={{ marginBottom: "var(--space-4)", fontSize: "var(--text-sm)" }}
				>
					{error}
				</div>
			) : null}

			<div style={{ marginBottom: "var(--space-4)" }}>
				<div
					style={{
						display: "flex",
						justifyContent: "space-between",
						alignItems: "baseline",
					}}
				>
					<span className="muted small">{t("usage.agentUsage")}</span>
					<span className="mono" style={{ fontSize: "var(--text-sm)" }}>
						{current}
						<span className="muted"> / {allowed}</span>
					</span>
				</div>
				<UsageBar value={current} max={allowed} />
			</div>

			<div style={{ marginBottom: "var(--space-4)" }}>
				<span className="muted small">{t("usage.newAgents", { days: TREND_DAYS })}</span>
				<TrendChart data={trend} />
			</div>

			<BillingSection billing={billing} usage={usage} />
			<UpgradePrompt
				showCritical={showCritical}
				showWarning={showWarning}
				usageRatio={usageRatio}
			/>
		</div>
	);
}
