import { useEffect, useRef, useState } from "react";
import { safeCommercialLink, selfServiceCheckoutEnabled } from "./commercial";
import { newBillingRequestId, requestEnterpriseOrder } from "./enterprise-orders";
import {
	headlinePrice,
	LIST_PRICE_NOTICE,
	loadTenantPlan,
	PLAN_CATALOG,
	type PlanDefinition,
	type PlanId,
	planById,
	priceTerms,
	type TenantPlan,
} from "./plans";
import { createCheckout } from "./stripe-client";

type Interval = "monthly" | "yearly";

const SOURCE_LABELS: Record<TenantPlan["planSource"], string> = {
	stripe_subscription: "Verified card subscription",
	team_record: "Billing record",
	default: "Default plan",
};

const PICKABLE_PLANS = PLAN_CATALOG.filter((plan) => plan.active && plan.id !== "free");

function intervalsFor(plan: PlanDefinition): Interval[] {
	const intervals: Interval[] = [];
	if (plan.priceMonthlyCents !== null) intervals.push("monthly");
	if (plan.priceYearlyCents !== null) intervals.push("yearly");
	return intervals;
}

/**
 * Whether a plan may be bought by card here. All three must hold: the build
 * opted into self-service checkout, the catalog marks the plan self-serve and
 * cloud-deployable, and the tenant is on the cloud admission mode.
 */
export function selfServeCheckoutAvailable(
	plan: PlanDefinition,
	tenantPlan: TenantPlan | null,
): boolean {
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
	const [tenantPlan, setTenantPlan] = useState<TenantPlan | null>(null);
	const [loadState, setLoadState] = useState<"loading" | "ready" | "unavailable">("loading");
	const [selectedId, setSelectedId] = useState<PlanId>("team");
	const [interval, setBillingInterval] = useState<Interval>("yearly");
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

	const selected = planById(selectedId) ?? PICKABLE_PLANS[0];
	const intervals = selected ? intervalsFor(selected) : [];
	const effectiveInterval: Interval | null = intervals.includes(interval)
		? interval
		: (intervals[0] ?? null);
	const minSeats = selected?.minSeats ?? 1;
	const seatsValid = Number.isSafeInteger(seats) && seats >= minSeats && seats <= 10000;
	const checkoutPath = selected ? selfServeCheckoutAvailable(selected, tenantPlan) : false;
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
				const result = await createCheckout(
					"",
					"",
					seats,
					effectiveInterval,
					undefined,
					active,
					requestId,
					selected.id,
				);
				if (activeTenantRef.current !== active) return;
				setCheckoutUrl(result.checkoutUrl);
				setOutcome(
					"Checkout is ready. The plan changes only after the payment provider confirms an active subscription.",
				);
			} else {
				const order = await requestEnterpriseOrder(active, {
					request_id: requestId,
					requested_agents: seats * selected.includedAgents,
					quote_reference: `plan-request:${selected.id}${effectiveInterval ? `:${effectiveInterval}` : ""}`,
				});
				if (activeTenantRef.current !== active) return;
				setOutcome(
					`Upgrade request for ${selected.displayName} (${seats} developer seats) was sent to Finance review as ${order.status.replaceAll("_", " ")}. Your plan is unchanged until an approved order is applied.`,
				);
				setRequestId(newBillingRequestId());
			}
		} catch {
			if (activeTenantRef.current !== active) return;
			// Keep the request ID so a retry of the same request stays idempotent.
			setFailure(
				checkoutPath
					? "Checkout could not be prepared. Retry, or request the upgrade through Finance."
					: "The upgrade request was not accepted. Retry or contact the approved sales channel.",
			);
		} finally {
			if (activeTenantRef.current === active) setBusy(false);
		}
	}

	const usagePercent =
		tenantPlan && tenantPlan.allowedAgents > 0
			? Math.min(100, Math.round((tenantPlan.currentAgents / tenantPlan.allowedAgents) * 100))
			: 0;
	const expires = formatDate(tenantPlan?.admission.expiresAt ?? null);
	const periodEnd = formatDate(tenantPlan?.subscription?.currentPeriodEnd ?? null);

	return (
		<div className="card" aria-label="Current plan">
			<h2>Plan</h2>
			{loadState === "loading" ? (
				<div className="muted small">Loading plan…</div>
			) : loadState === "unavailable" || !tenantPlan ? (
				<div className="notice notice-danger" role="status">
					Plan information could not be loaded for this tenant. No plan or usage figure is shown
					until it can be read.
				</div>
			) : (
				<>
					<div className="grid" style={{ marginTop: 10 }}>
						<div className="stat-card">
							<div className="stat-label">Current plan</div>
							<div className="stat-value">{tenantPlan.displayName}</div>
							<div className="muted small">{SOURCE_LABELS[tenantPlan.planSource]}</div>
						</div>
						<div className="stat-card">
							<div className="stat-label">Protected agents in use</div>
							<div className="stat-value">
								{tenantPlan.currentAgents} / {tenantPlan.allowedAgents}
							</div>
							<div className="muted small">
								{tenantPlan.includedAgentsPerSeat} agent per seat on this plan
							</div>
						</div>
						<div className="stat-card">
							<div className="stat-label">Admission</div>
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
							{expires ? <div className="muted small">Term ends {expires}</div> : null}
						</div>
					</div>
					<div
						className="usage-bar"
						role="progressbar"
						aria-label="Protected agent usage"
						aria-valuemin={0}
						aria-valuemax={tenantPlan.allowedAgents}
						aria-valuenow={tenantPlan.currentAgents}
						style={{ marginTop: 12 }}
					>
						<div className="usage-fill" style={{ width: `${usagePercent}%` }} />
					</div>
					{tenantPlan.allowedAgents === 0 ? (
						<div className="notice notice-danger" style={{ marginTop: 10 }}>
							This tenant has no admitted protected-agent capacity. New agents are rejected by the
							control plane until a trial, licence or paid plan is active.
						</div>
					) : tenantPlan.currentAgents > tenantPlan.allowedAgents ? (
						<div className="notice notice-danger" style={{ marginTop: 10 }}>
							More agents are connected than the plan admits; additional agents may be rejected.
						</div>
					) : null}
					{tenantPlan.subscription ? (
						<div className="muted small" style={{ marginTop: 10 }}>
							Card subscription: {planById(tenantPlan.subscription.planId)?.displayName ?? "Plan"} ·{" "}
							{tenantPlan.subscription.seats} seats · {tenantPlan.subscription.billingInterval} ·{" "}
							{tenantPlan.subscription.status}
							{periodEnd ? ` · paid through ${periodEnd}` : ""}
						</div>
					) : null}
				</>
			)}

			<h3 style={{ marginTop: 20 }}>Change plan</h3>
			<p className="muted small">{LIST_PRICE_NOTICE}</p>
			{!canManageBilling ? (
				<div className="notice">Plan changes are limited to tenant owners and admins.</div>
			) : (
				<fieldset className="stack" aria-label="Plan picker" style={{ border: 0, padding: 0 }}>
					<div className="row" role="radiogroup" aria-label="Plan">
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
									{plan.displayName} — {headlinePrice(plan)}
									<span className="muted small"> ({priceTerms(plan)})</span>
								</span>
							</label>
						))}
					</div>
					<div className="row">
						<label>
							Developer seats
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
						{intervals.length > 0 ? (
							<label>
								Billing
								<select
									className="input"
									value={effectiveInterval ?? ""}
									onChange={(event) => {
										setBillingInterval(event.target.value as Interval);
										resetRequest();
									}}
								>
									{intervals.map((value) => (
										<option key={value} value={value}>
											{value === "monthly" ? "Monthly" : "Annual"}
										</option>
									))}
								</select>
							</label>
						) : null}
						<button
							className="button"
							type="button"
							disabled={!canAct}
							onClick={() => void submit()}
						>
							{busy ? "Working…" : checkoutPath ? "Continue to checkout" : "Request upgrade"}
						</button>
					</div>
					{!seatsValid ? (
						<div className="muted small">
							{selected?.displayName} requires at least {minSeats} developer seats.
						</div>
					) : null}
					{!checkoutPath ? (
						<div className="muted small">
							This request is reviewed by Finance and invoiced; it does not change the plan until an
							approved order is applied.
						</div>
					) : null}
					{outcome ? (
						<div className="notice" role="status">
							{outcome}
						</div>
					) : null}
					{safeCheckoutUrl ? (
						<div className="row">
							<a className="button" href={safeCheckoutUrl} target="_blank" rel="noreferrer">
								Open secure checkout
							</a>
						</div>
					) : null}
					{failure ? (
						<div className="notice notice-danger" role="status">
							{failure}
						</div>
					) : null}
				</fieldset>
			)}
		</div>
	);
}
