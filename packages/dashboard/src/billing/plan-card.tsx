import { useEffect, useRef, useState } from "react";
import type { DashboardMessageKey } from "../i18n/en";
import { type Translate, useRichT, useT } from "../i18n/I18nProvider";
import {
	QUOTE_CONTACT_EMAIL,
	quoteRequestHref,
	safeCommercialLink,
	selfServiceCheckoutEnabled,
} from "./commercial";
import { newBillingRequestId, requestEnterpriseOrder } from "./enterprise-orders";
import {
	type BillingInterval,
	loadTenantPlan,
	PLAN_CATALOG,
	type PlanDefinition,
	type PlanId,
	planById,
	retentionTerms,
	seatTerms,
	type TenantPlan,
} from "./plans";
import { createCheckout } from "./stripe-client";

const SOURCE_LABELS: Record<TenantPlan["planSource"], DashboardMessageKey> = {
	stripe_subscription: "plan.source.stripe",
	team_record: "plan.source.record",
	default: "plan.source.default",
};

const PICKABLE_PLANS = PLAN_CATALOG.filter((plan) => plan.active && plan.id !== "free");

/**
 * Whether a plan may be bought by card here. All three must hold: the build
 * opted into self-service checkout, the catalog marks the plan self-serve and
 * cloud-deployable, and the tenant is on the cloud admission mode.
 */
function selfServeCheckoutAvailable(plan: PlanDefinition, tenantPlan: TenantPlan | null): boolean {
	return (
		selfServiceCheckoutEnabled &&
		plan.selfServe &&
		plan.deployment.includes("cloud") &&
		(plan.id === "team" || plan.id === "business") &&
		tenantPlan?.admission.mode === "cloud"
	);
}

function formatDate(value: string | null): string | null {
	if (!value) return null;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) ? new Date(parsed).toLocaleDateString() : null;
}

/** What the picker offers for the chosen plan, interval and seat count. */
function pickerState(
	selectedId: PlanId,
	interval: BillingInterval,
	seats: number,
	tenantPlan: TenantPlan | null,
) {
	const selected = planById(selectedId) ?? PICKABLE_PLANS[0];
	const intervals: readonly BillingInterval[] = selected?.billingIntervals ?? [];
	const effectiveInterval: BillingInterval | null = intervals.includes(interval)
		? interval
		: (intervals[0] ?? null);
	const minSeats = selected?.minSeats ?? 1;
	return {
		selected,
		intervals,
		effectiveInterval,
		minSeats,
		seatsValid: Number.isSafeInteger(seats) && seats >= minSeats && seats <= 10000,
		checkoutPath: selected ? selfServeCheckoutAvailable(selected, tenantPlan) : false,
	};
}

function submitLabel(busy: boolean, checkoutPath: boolean, t: Translate): string {
	if (busy) return t("plan.working");
	return checkoutPath ? t("plan.checkout") : t("plan.requestUpgrade");
}

function PlanStatus({
	loadState,
	tenantPlan,
}: {
	loadState: "loading" | "ready" | "unavailable";
	tenantPlan: TenantPlan | null;
}) {
	const t = useT();
	if (loadState === "loading") return <div className="muted small">{t("plan.loading")}</div>;
	if (loadState === "unavailable" || !tenantPlan) {
		return (
			<div className="notice notice-danger" role="status">
				{t("plan.loadFailed")}
			</div>
		);
	}
	return <CurrentPlanSummary tenantPlan={tenantPlan} />;
}

function IntervalSelect({
	intervals,
	value,
	onChange,
}: {
	intervals: readonly BillingInterval[];
	value: BillingInterval | null;
	onChange: (value: BillingInterval) => void;
}) {
	const t = useT();
	if (intervals.length === 0) return null;
	return (
		<label>
			{t("plan.billing")}
			<select
				className="input"
				value={value ?? ""}
				onChange={(event) => onChange(event.target.value as BillingInterval)}
			>
				{intervals.map((option) => (
					<option key={option} value={option}>
						{option === "monthly" ? t("plan.monthly") : t("plan.annual")}
					</option>
				))}
			</select>
		</label>
	);
}

function CurrentPlanSummary({ tenantPlan }: { tenantPlan: TenantPlan }) {
	const t = useT();
	const usagePercent =
		tenantPlan.allowedAgents > 0
			? Math.min(100, Math.round((tenantPlan.currentAgents / tenantPlan.allowedAgents) * 100))
			: 0;
	const expires = formatDate(tenantPlan.admission.expiresAt ?? null);
	return (
		<>
			<div className="grid" style={{ marginTop: 10 }}>
				<div className="stat-card">
					<div className="stat-label">{t("plan.current")}</div>
					<div className="stat-value">{tenantPlan.displayName}</div>
					<div className="muted small">{t(SOURCE_LABELS[tenantPlan.planSource])}</div>
				</div>
				<div className="stat-card">
					<div className="stat-label">{t("plan.inUse")}</div>
					<div className="stat-value">
						{tenantPlan.currentAgents} / {tenantPlan.allowedAgents}
					</div>
					<div className="muted small">
						{t("plan.perSeat", { count: tenantPlan.includedAgentsPerSeat })}
					</div>
				</div>
				<div className="stat-card">
					<div className="stat-label">{t("plan.admission")}</div>
					<div>
						<span
							className={
								tenantPlan.admission.status === "active"
									? "badge badge-success"
									: "badge badge-warning"
							}
						>
							{tenantPlan.admission.kind
								? `${tenantPlan.admission.kind} · ${tenantPlan.admission.status}`
								: tenantPlan.admission.status}
						</span>
					</div>
					{expires ? (
						<div className="muted small">{t("plan.termEnds", { date: expires })}</div>
					) : null}
				</div>
			</div>
			<div
				className="usage-bar"
				role="progressbar"
				aria-label={t("plan.usage")}
				aria-valuemin={0}
				aria-valuemax={tenantPlan.allowedAgents}
				aria-valuenow={tenantPlan.currentAgents}
				style={{ marginTop: 12 }}
			>
				<div className="usage-fill" style={{ width: `${usagePercent}%` }} />
			</div>
			<CapacityNotice tenantPlan={tenantPlan} />
			<SubscriptionLine subscription={tenantPlan.subscription} />
		</>
	);
}

function CapacityNotice({ tenantPlan }: { tenantPlan: TenantPlan }) {
	const t = useT();
	if (tenantPlan.allowedAgents === 0) {
		return (
			<div className="notice notice-danger" style={{ marginTop: 10 }}>
				{t("plan.noCapacity")}
			</div>
		);
	}
	if (tenantPlan.currentAgents > tenantPlan.allowedAgents) {
		return (
			<div className="notice notice-danger" style={{ marginTop: 10 }}>
				{t("plan.overCapacity")}
			</div>
		);
	}
	return null;
}

function SubscriptionLine({ subscription }: { subscription: TenantPlan["subscription"] }) {
	const t = useT();
	if (!subscription) return null;
	const periodEnd = formatDate(subscription.currentPeriodEnd ?? null);
	return (
		<div className="muted small" style={{ marginTop: 10 }}>
			{t("plan.cardLine", {
				plan: planById(subscription.planId)?.displayName ?? t("plan.planFallback"),
				seats: subscription.seats,
				interval:
					subscription.billingInterval === "monthly"
						? t("plan.monthly")
						: subscription.billingInterval === "yearly"
							? t("plan.annual")
							: subscription.billingInterval,
				status: subscription.status,
			})}
			{periodEnd ? t("plan.paidThrough", { date: periodEnd }) : ""}
		</div>
	);
}

function RequestStatus({
	outcome,
	safeCheckoutUrl,
	failure,
}: {
	outcome: string | null;
	safeCheckoutUrl: string | null;
	failure: string | null;
}) {
	const t = useT();
	return (
		<>
			{outcome ? (
				<div className="notice" role="status">
					{outcome}
				</div>
			) : null}
			{safeCheckoutUrl ? (
				<div className="row">
					<a className="button" href={safeCheckoutUrl} target="_blank" rel="noreferrer">
						{t("plan.openCheckout")}
					</a>
				</div>
			) : null}
			{failure ? (
				<div className="notice notice-danger" role="status">
					{failure}
				</div>
			) : null}
		</>
	);
}

/**
 * Current catalog plan, protected-agent usage against the admitted capacity,
 * and the plan picker. Choosing a plan either opens a server-created checkout
 * (self-service builds only) or files an upgrade request into the Finance
 * invoice flow. Neither action changes the plan here: the plan changes only
 * after a verified payment or an approved order is applied server-side.
 */
export function PlanCard({
	tenantId,
	canManageBilling,
}: {
	tenantId: string | undefined;
	canManageBilling: boolean;
}) {
	const t = useT();
	const richT = useRichT();
	const [tenantPlan, setTenantPlan] = useState<TenantPlan | null>(null);
	const [loadState, setLoadState] = useState<"loading" | "ready" | "unavailable">("loading");
	const [selectedId, setSelectedId] = useState<PlanId>("team");
	const [interval, setBillingInterval] = useState<BillingInterval>("yearly");
	const [seats, setSeats] = useState(3);
	const [requestId, setRequestId] = useState(newBillingRequestId);
	const [busy, setBusy] = useState(false);
	const [outcome, setOutcome] = useState<string | null>(null);
	const [failure, setFailure] = useState<string | null>(null);
	const [checkoutUrl, setCheckoutUrl] = useState<string | null>(null);
	const activeTenantRef = useRef(tenantId);
	activeTenantRef.current = tenantId;

	useEffect(() => {
		let cancelled = false;
		setTenantPlan(null);
		setLoadState("loading");
		setOutcome(null);
		setFailure(null);
		setCheckoutUrl(null);
		setRequestId(newBillingRequestId());
		if (!tenantId) {
			setLoadState("unavailable");
			return;
		}
		const active = tenantId;
		async function load() {
			try {
				const next = await loadTenantPlan(active);
				if (cancelled || activeTenantRef.current !== active) return;
				setTenantPlan(next);
				setLoadState("ready");
			} catch {
				if (cancelled || activeTenantRef.current !== active) return;
				setTenantPlan(null);
				setLoadState("unavailable");
			}
		}
		void load();
		const timer = window.setInterval(() => void load(), 30_000);
		return () => {
			cancelled = true;
			window.clearInterval(timer);
		};
	}, [tenantId]);

	const { selected, intervals, effectiveInterval, minSeats, seatsValid, checkoutPath } =
		pickerState(selectedId, interval, seats, tenantPlan);
	const safeCheckoutUrl = checkoutUrl ? safeCommercialLink(checkoutUrl) : null;
	const canAct = Boolean(
		tenantId &&
			canManageBilling &&
			selected &&
			seatsValid &&
			requestId &&
			!busy &&
			loadState === "ready",
	);

	function resetRequest() {
		setRequestId(newBillingRequestId());
		setOutcome(null);
		setFailure(null);
		setCheckoutUrl(null);
	}

	/** Opens a server-created card checkout (self-service builds only). */
	async function startCheckout(
		active: string,
		plan: "team" | "business",
		billing: BillingInterval,
		reqId: string,
	) {
		const result = await createCheckout("", "", seats, billing, undefined, active, reqId, plan);
		if (activeTenantRef.current !== active) return;
		setCheckoutUrl(result.checkoutUrl);
		setOutcome(t("plan.checkoutReady"));
	}

	/** Files an upgrade request into the Finance invoice flow. */
	async function requestUpgrade(active: string, plan: PlanDefinition, reqId: string) {
		const order = await requestEnterpriseOrder(active, {
			request_id: reqId,
			requested_agents: seats * plan.includedAgents,
			quote_reference: `plan-request:${plan.id}${effectiveInterval ? `:${effectiveInterval}` : ""}`,
		});
		if (activeTenantRef.current !== active) return;
		setOutcome(
			t("plan.upgradeSent", {
				plan: plan.displayName,
				seats,
				status:
					order.status === "pending_finance"
						? t("billing.orders.pending")
						: order.status.replaceAll("_", " "),
			}),
		);
		setRequestId(newBillingRequestId());
	}

	async function submit() {
		if (!canAct || !tenantId || !selected || !requestId) return;
		const active = tenantId;
		setBusy(true);
		setOutcome(null);
		setFailure(null);
		try {
			if (
				checkoutPath &&
				effectiveInterval &&
				(selected.id === "team" || selected.id === "business")
			) {
				await startCheckout(active, selected.id, effectiveInterval, requestId);
			} else {
				await requestUpgrade(active, selected, requestId);
			}
		} catch {
			if (activeTenantRef.current !== active) return;
			// Keep the request ID so a retry of the same request stays idempotent.
			setFailure(checkoutPath ? t("plan.checkoutFailed") : t("plan.upgradeRejected"));
		} finally {
			if (activeTenantRef.current === active) setBusy(false);
		}
	}

	return (
		<div className="card" aria-label={t("plan.cardLabel")}>
			<h2>{t("plan.title")}</h2>
			<PlanStatus loadState={loadState} tenantPlan={tenantPlan} />

			<h3 style={{ marginTop: 20 }}>{t("plan.change")}</h3>
			<p className="muted small">
				{t("plan.quoteNotice")}{" "}
				{richT("plan.quoteContact", {
					email: <a href={quoteRequestHref()}>{QUOTE_CONTACT_EMAIL}</a>,
				})}
				{checkoutPath ? t("plan.checkoutAmount") : "."}
			</p>
			{!canManageBilling ? (
				<div className="notice">{t("plan.ownerOnly")}</div>
			) : (
				<fieldset className="stack" aria-label={t("plan.picker")} style={{ border: 0, padding: 0 }}>
					<div className="row" role="radiogroup" aria-label={t("plan.title")}>
						{PICKABLE_PLANS.map((plan) => (
							<label key={plan.id} className="row" style={{ gap: 6 }}>
								<input
									type="radio"
									name="plan-picker"
									value={plan.id}
									checked={selectedId === plan.id}
									onChange={() => {
										setSelectedId(plan.id);
										setSeats((current) => Math.max(current, plan.minSeats));
										resetRequest();
									}}
								/>
								<span>
									{plan.displayName}
									<span className="muted small">
										{" "}
										({seatTerms(plan, t)} · {retentionTerms(plan, t)})
									</span>
								</span>
							</label>
						))}
					</div>
					<div className="row">
						<label>
							{t("plan.developerSeats")}
							<input
								className="input"
								type="number"
								min={minSeats}
								max={10000}
								step={1}
								value={seats}
								onChange={(event) => {
									setSeats(Number(event.target.value));
									resetRequest();
								}}
							/>
						</label>
						<IntervalSelect
							intervals={intervals}
							value={effectiveInterval}
							onChange={(value) => {
								setBillingInterval(value);
								resetRequest();
							}}
						/>
						<button
							className="button"
							type="button"
							disabled={!canAct}
							onClick={() => void submit()}
						>
							{submitLabel(busy, checkoutPath, t)}
						</button>
					</div>
					{!seatsValid ? (
						<div className="muted small">
							{t("plan.minSeats", { plan: selected?.displayName ?? "", count: minSeats })}
						</div>
					) : null}
					{!checkoutPath ? <div className="muted small">{t("plan.financeNote")}</div> : null}
					<RequestStatus outcome={outcome} safeCheckoutUrl={safeCheckoutUrl} failure={failure} />
				</fieldset>
			)}
		</div>
	);
}
