import { useEffect, useRef, useState } from "react";
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
	QUOTE_NOTICE,
	retentionTerms,
	seatTerms,
	type TenantPlan,
} from "./plans";
import { createCheckout } from "./stripe-client";

const SOURCE_LABELS: Record<TenantPlan["planSource"], string> = {
	stripe_subscription: "Verified card subscription",
	team_record: "Billing record",
	default: "Default plan",
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

function submitLabel(busy: boolean, checkoutPath: boolean): string {
	if (busy) return "Working…";
	return checkoutPath ? "Continue to checkout" : "Request upgrade";
}

function PlanStatus({
	loadState,
	tenantPlan,
}: {
	loadState: "loading" | "ready" | "unavailable";
	tenantPlan: TenantPlan | null;
}) {
	if (loadState === "loading") return <div className="muted small">Loading plan…</div>;
	if (loadState === "unavailable" || !tenantPlan) {
		return (
			<div className="notice notice-danger" role="status">
				Plan information could not be loaded for this tenant. No plan or usage figure is shown until
				it can be read.
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
	if (intervals.length === 0) return null;
	return (
		<label>
			Billing
			<select
				className="input"
				value={value ?? ""}
				onChange={(event) => onChange(event.target.value as BillingInterval)}
			>
				{intervals.map((option) => (
					<option key={option} value={option}>
						{option === "monthly" ? "Monthly" : "Annual"}
					</option>
				))}
			</select>
		</label>
	);
}

function CurrentPlanSummary({ tenantPlan }: { tenantPlan: TenantPlan }) {
	const usagePercent =
		tenantPlan.allowedAgents > 0
			? Math.min(100, Math.round((tenantPlan.currentAgents / tenantPlan.allowedAgents) * 100))
			: 0;
	const expires = formatDate(tenantPlan.admission.expiresAt ?? null);
	return (
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
			<CapacityNotice tenantPlan={tenantPlan} />
			<SubscriptionLine subscription={tenantPlan.subscription} />
		</>
	);
}

function CapacityNotice({ tenantPlan }: { tenantPlan: TenantPlan }) {
	if (tenantPlan.allowedAgents === 0) {
		return (
			<div className="notice notice-danger" style={{ marginTop: 10 }}>
				This tenant has no admitted protected-agent capacity. New agents are rejected by the control
				plane until a trial, licence or paid plan is active.
			</div>
		);
	}
	if (tenantPlan.currentAgents > tenantPlan.allowedAgents) {
		return (
			<div className="notice notice-danger" style={{ marginTop: 10 }}>
				More agents are connected than the plan admits; additional agents may be rejected.
			</div>
		);
	}
	return null;
}

function SubscriptionLine({ subscription }: { subscription: TenantPlan["subscription"] }) {
	if (!subscription) return null;
	const periodEnd = formatDate(subscription.currentPeriodEnd ?? null);
	return (
		<div className="muted small" style={{ marginTop: 10 }}>
			Card subscription: {planById(subscription.planId)?.displayName ?? "Plan"} ·{" "}
			{subscription.seats} seats · {subscription.billingInterval} · {subscription.status}
			{periodEnd ? ` · paid through ${periodEnd}` : ""}
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
						Open secure checkout
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
		setOutcome(
			"Checkout is ready. The plan changes only after the payment provider confirms an active subscription.",
		);
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
			`Upgrade request for ${plan.displayName} (${seats} developer seats) was sent to Finance review as ${order.status.replaceAll("_", " ")}. Your plan is unchanged until an approved order is applied.`,
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
			setFailure(
				checkoutPath
					? "Checkout could not be prepared. Retry, or request the upgrade through Finance."
					: "The upgrade request was not accepted. Retry or contact the approved sales channel.",
			);
		} finally {
			if (activeTenantRef.current === active) setBusy(false);
		}
	}

	return (
		<div className="card" aria-label="Current plan">
			<h2>Plan</h2>
			<PlanStatus loadState={loadState} tenantPlan={tenantPlan} />

			<h3 style={{ marginTop: 20 }}>Change plan</h3>
			<p className="muted small">
				{QUOTE_NOTICE} For a quote, contact <a href={quoteRequestHref()}>{QUOTE_CONTACT_EMAIL}</a>
				{checkoutPath
					? "; a card checkout shows the amount on the payment provider's page before you pay."
					: "."}
			</p>
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
									{plan.displayName}
									<span className="muted small">
										{" "}
										({seatTerms(plan)} · {retentionTerms(plan)})
									</span>
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
							{submitLabel(busy, checkoutPath)}
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
					<RequestStatus outcome={outcome} safeCheckoutUrl={safeCheckoutUrl} failure={failure} />
				</fieldset>
			)}
		</div>
	);
}
