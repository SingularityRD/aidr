import { useEffect, useRef, useState } from "react";
import {
	getInvoiceContactHref,
	safeCommercialLink,
	selfServiceCheckoutEnabled,
} from "../../billing/commercial";
import {
	type EnterpriseOrder,
	listEnterpriseOrders,
	newBillingRequestId,
	requestEnterpriseOrder,
} from "../../billing/enterprise-orders";
import { createCheckout } from "../../billing/stripe-client";
import { useTeam } from "../../enterprise/team-provider";
import { supabase } from "../../lib/supabase";

type EntitlementsRow = { included_agents: number; extra_agents: number };
type SeatUsageRow = {
	included_agents: number;
	extra_agents: number;
	allowed_agents: number;
	current_agents: number;
};
type SubscriptionRow = {
	provider: string;
	provider_subscription_id: string;
	status: string;
	extra_agents: number;
	current_period_end: string | null;
	cancel_at_period_end: boolean;
	updated_at: string;
};

export function BillingPage() {
	const { currentTeam, currentRole } = useTeam();
	const tenantId = currentTeam?.id;
	const canManageBilling = currentRole === "owner" || currentRole === "admin";
	const activeTenantRef = useRef(tenantId);
	activeTenantRef.current = tenantId;
	const activeBillingRoleRef = useRef(canManageBilling);
	activeBillingRoleRef.current = canManageBilling;
	const ordersRevision = useRef(0);
	const [entitlements, setEntitlements] = useState<EntitlementsRow | null>(null);
	const [agentCount, setAgentCount] = useState<number>(0);
	const [subscription, setSubscription] = useState<SubscriptionRow | null>(null);
	const [checkoutUrl, setCheckoutUrl] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [checkoutBusy, setCheckoutBusy] = useState(false);
	const [checkoutSeats, setCheckoutSeats] = useState(1);
	const [checkoutRequestId, setCheckoutRequestId] = useState(newBillingRequestId);
	const [orders, setOrders] = useState<EnterpriseOrder[]>([]);
	const [ordersLoaded, setOrdersLoaded] = useState(false);
	const [orderError, setOrderError] = useState<string | null>(null);
	const [orderBusy, setOrderBusy] = useState(false);
	const [requestedAgents, setRequestedAgents] = useState(1);
	const [quoteReference, setQuoteReference] = useState("");
	const [orderRequestId, setOrderRequestId] = useState(newBillingRequestId);

	useEffect(() => {
		let cancelled = false;
		setEntitlements(null);
		setSubscription(null);
		setAgentCount(0);
		setCheckoutUrl(null);
		setCheckoutBusy(false);
		setCheckoutRequestId(newBillingRequestId());
		if (!tenantId) return;
		const activeTenantId = tenantId;

		async function load() {
			setError(null);

			const [seatRes, subRes] = await Promise.all([
				(async () => {
					const res = await supabase
						.from("seat_usage")
						.select("included_agents,extra_agents,allowed_agents,current_agents")
						.eq("tenant_id", activeTenantId)
						.maybeSingle();
					if (!res.error) return res;
					// Back-compat only when the view is genuinely absent. Network,
					// permission, and data errors must stay visible instead of silently
					// switching to an untrusted legacy calculation.
					const legacyViewMissing =
						res.error.code === "PGRST205" ||
						res.error.code === "42P01" ||
						/seat_usage[\s\S]*(?:not exist|missing)/i.test(res.error.message);
					if (!legacyViewMissing) return res;
					const [entRes, agentsRes] = await Promise.all([
						supabase
							.from("entitlements")
							.select("included_agents,extra_agents")
							.eq("tenant_id", activeTenantId)
							.maybeSingle(),
						supabase
							.from("agents")
							.select("id", { count: "exact", head: true })
							.eq("tenant_id", activeTenantId),
					]);
					if (entRes.error) return { data: null, error: entRes.error } as typeof res;
					const ent = (entRes.data ?? null) as EntitlementsRow | null;
					const included = Number(ent?.included_agents ?? 1);
					const extra = Number(ent?.extra_agents ?? 0);
					return {
						data: {
							included_agents: included,
							extra_agents: extra,
							allowed_agents: included + extra,
							current_agents: Number(agentsRes.count ?? 0),
						},
						error: null,
					} as unknown as typeof res;
				})(),
				supabase
					.from("subscriptions")
					.select(
						"provider,provider_subscription_id,status,extra_agents,current_period_end,cancel_at_period_end,updated_at",
					)
					.eq("tenant_id", activeTenantId)
					.order("updated_at", { ascending: false })
					.limit(1)
					.maybeSingle(),
			]);

			if (cancelled) return;

			if (seatRes.error) {
				setError(seatRes.error.message);
				setEntitlements(null);
				setAgentCount(0);
			} else {
				const row = (seatRes.data ?? null) as SeatUsageRow | null;
				setEntitlements(
					row
						? {
								included_agents: Number(row.included_agents ?? 1),
								extra_agents: Number(row.extra_agents ?? 0),
							}
						: null,
				);
				setAgentCount(Number(row?.current_agents ?? 0));
			}

			if (subRes.error) setError(subRes.error.message);
			else setSubscription((subRes.data ?? null) as SubscriptionRow | null);
		}

		load();
		const t = setInterval(load, 8000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, [tenantId]);

	useEffect(() => {
		let cancelled = false;
		ordersRevision.current += 1;
		setOrders([]);
		setOrdersLoaded(false);
		setOrderError(null);
		setOrderBusy(false);
		setRequestedAgents(1);
		setQuoteReference("");
		setOrderRequestId(newBillingRequestId());
		if (!tenantId || !canManageBilling) return;
		const activeTenantId = tenantId;
		async function loadOrders() {
			const revision = ++ordersRevision.current;
			try {
				const rows = await listEnterpriseOrders(activeTenantId);
				if (!cancelled && revision === ordersRevision.current) {
					setOrders(rows);
					setOrdersLoaded(true);
					setOrderError(null);
				}
			} catch {
				if (!cancelled && revision === ordersRevision.current) {
					setOrdersLoaded(true);
					setOrderError(
						"Enterprise order status is unavailable. Contact the approved sales channel.",
					);
				}
			}
		}
		void loadOrders();
		const timer = setInterval(() => void loadOrders(), 30_000);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	}, [tenantId, canManageBilling]);

	const included = Number(entitlements?.included_agents ?? 1);
	const extra = Number(entitlements?.extra_agents ?? 0);
	const allowed = Math.max(0, included + extra);
	const overLimit = allowed > 0 && agentCount > allowed;

	const safeCheckoutUrl = selfServiceCheckoutEnabled ? safeCommercialLink(checkoutUrl) : null;
	const invoiceUrl = getInvoiceContactHref();
	const alreadyPending = orders.some(
		(order) =>
			order.status === "pending_finance" &&
			order.requested_agents === requestedAgents &&
			(order.quote_reference ?? "") === quoteReference.trim(),
	);
	const canSubmitOrder = Boolean(
		tenantId &&
			canManageBilling &&
			invoiceUrl &&
			orderRequestId &&
			!alreadyPending &&
			!orderBusy &&
			Number.isSafeInteger(requestedAgents) &&
			requestedAgents >= 1 &&
			requestedAgents <= 100000,
	);
	const canBeginCheckout = Boolean(
		tenantId &&
			canManageBilling &&
			checkoutRequestId &&
			!checkoutBusy &&
			Number.isSafeInteger(checkoutSeats) &&
			checkoutSeats >= 1 &&
			checkoutSeats <= 10000,
	);
	function isCurrentBillingTenant(expectedTenantId: string): boolean {
		return activeTenantRef.current === expectedTenantId && activeBillingRoleRef.current;
	}
	async function submitEnterpriseOrder() {
		if (!canSubmitOrder || !tenantId || !orderRequestId) return;
		ordersRevision.current += 1;
		setOrderBusy(true);
		setOrderError(null);
		try {
			const order = await requestEnterpriseOrder(tenantId, {
				request_id: orderRequestId,
				requested_agents: requestedAgents,
				...(quoteReference.trim() ? { quote_reference: quoteReference.trim() } : {}),
			});
			if (!isCurrentBillingTenant(tenantId)) return;
			// A list read started during submission may not contain this new request.
			ordersRevision.current += 1;
			setOrders((previous) => [order, ...previous.filter((entry) => entry.id !== order.id)]);
			setOrdersLoaded(true);
			setOrderError(null);
			setOrderRequestId(newBillingRequestId());
		} catch {
			if (!isCurrentBillingTenant(tenantId)) return;
			// Keep the request ID so a retry of the same order is idempotent.
			setOrderError(
				"Enterprise order request was not accepted. Retry or contact the approved sales channel.",
			);
		} finally {
			if (isCurrentBillingTenant(tenantId)) setOrderBusy(false);
		}
	}
	async function beginCheckout() {
		if (!canBeginCheckout || !tenantId || !checkoutRequestId) return;
		setCheckoutBusy(true);
		setError(null);
		try {
			const result = await createCheckout(
				"",
				"",
				checkoutSeats,
				"monthly",
				undefined,
				tenantId,
				checkoutRequestId,
			);
			if (!isCurrentBillingTenant(tenantId)) return;
			setCheckoutUrl(result.checkoutUrl);
			setCheckoutRequestId(newBillingRequestId());
		} catch (cause) {
			if (!isCurrentBillingTenant(tenantId)) return;
			setError(cause instanceof Error ? cause.message : "Checkout could not be created");
		} finally {
			if (isCurrentBillingTenant(tenantId)) setCheckoutBusy(false);
		}
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>Billing</h1>
				<p className="muted">
					Seat allowances and price are fixed by the approved enterprise order; this dashboard does
					not advertise a self-service price.
				</p>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			<div className="card">
				<h2>Subscription</h2>
				{subscription ? (
					<div className="notice">
						<div className="grid">
							<div className="stat-card">
								<div className="stat-label">Provider</div>
								<div className="mono">{subscription.provider}</div>
							</div>
							<div className="stat-card">
								<div className="stat-label">Status</div>
								<div>
									<span
										className={
											subscription.status === "active"
												? "badge badge-success"
												: "badge badge-warning"
										}
									>
										{subscription.status}
									</span>
								</div>
							</div>
							<div className="stat-card">
								<div className="stat-label">Extra agents</div>
								<div className="mono">{subscription.extra_agents}</div>
							</div>
						</div>
						{subscription.current_period_end ? (
							<div className="muted small" style={{ marginTop: 8 }}>
								Period end:{" "}
								<span className="mono">
									{new Date(subscription.current_period_end).toLocaleString()}
								</span>
							</div>
						) : null}
						{subscription.cancel_at_period_end ? (
							<div className="notice notice-danger" style={{ marginTop: 8 }}>
								Cancellation scheduled at period end.
							</div>
						) : null}
					</div>
				) : (
					<div className="notice">
						<div className="muted">No subscription record is available for this tenant.</div>
					</div>
				)}

				{safeCheckoutUrl ? (
					<div className="row" style={{ marginTop: 12 }}>
						<a className="button" href={safeCheckoutUrl} target="_blank" rel="noreferrer">
							Upgrade seats
						</a>
					</div>
				) : selfServiceCheckoutEnabled ? (
					<div className="row" style={{ marginTop: 12 }}>
						<label>
							Extra agents
							<input
								className="input"
								type="number"
								min={1}
								max={10000}
								value={checkoutSeats}
								onChange={(event) => {
									setCheckoutSeats(Number(event.target.value));
									setCheckoutRequestId(newBillingRequestId());
								}}
							/>
						</label>
						<button
							className="button"
							type="button"
							disabled={!canBeginCheckout}
							onClick={() => void beginCheckout()}
						>
							{checkoutBusy ? "Preparing checkout…" : "Review monthly subscription"}
						</button>
					</div>
				) : (
					<div className="notice" style={{ marginTop: 12 }}>
						Self-service checkout is disabled for the direct-GA release. Seat changes are
						provisioned only after an approved enterprise order is reconciled.
					</div>
				)}
			</div>

			<div className="card">
				<h2>Enterprise / manual invoice</h2>
				<p className="muted">
					For annual commitments, procurement review, or a manually invoiced deployment, use the
					configured sales channel. This page does not grant entitlements until an approved order is
					reconciled.
				</p>
				{invoiceUrl ? (
					<div className="row" style={{ marginTop: 12 }}>
						<a
							className="button button-secondary"
							href={invoiceUrl}
							target={invoiceUrl.startsWith("mailto:") ? undefined : "_blank"}
							rel={invoiceUrl.startsWith("mailto:") ? undefined : "noreferrer"}
						>
							Request enterprise invoice
						</a>
					</div>
				) : (
					<div className="notice notice-danger" role="alert">
						Sales/invoice contact is not configured for this deployment. Do not promise an
						enterprise invoice workflow until Finance and Sales publish the approved channel.
					</div>
				)}
				<h3 style={{ marginTop: 20 }}>Enterprise order requests</h3>
				<p className="muted">
					A request enters Finance review. It does not confirm payment, issue an invoice, or change
					protected-agent entitlement.
				</p>
				{!canManageBilling ? (
					<div className="notice">
						Only a tenant owner or admin can view and submit enterprise order requests.
					</div>
				) : null}
				{orderError ? (
					<div className="notice notice-danger" role="alert">
						{orderError}
					</div>
				) : null}
				{canManageBilling && orders.length > 0 ? (
					<div className="stack" aria-label="Enterprise order requests">
						{orders.map((order) => (
							<div className="notice" key={order.id}>
								<strong>{order.requested_agents} protected agents</strong>
								{" · "}
								{order.status.replaceAll("_", " ")}
								{order.quote_reference ? <span> · Quote {order.quote_reference}</span> : null}
								<div className="muted small">
									Requested {new Date(order.created_at).toLocaleString()}
								</div>
							</div>
						))}
					</div>
				) : !orderError && canManageBilling && !ordersLoaded ? (
					<div className="muted small">Loading enterprise order requests…</div>
				) : !orderError && canManageBilling ? (
					<div className="muted small">No enterprise order requests recorded for this tenant.</div>
				) : null}
				{invoiceUrl && tenantId && canManageBilling ? (
					<div className="row" style={{ marginTop: 12 }}>
						<label>
							Requested protected agents
							<input
								className="input"
								type="number"
								min={1}
								max={100000}
								step={1}
								value={requestedAgents}
								onChange={(event) => {
									setRequestedAgents(Number(event.target.value));
									setOrderRequestId(newBillingRequestId());
								}}
							/>
						</label>
						<label>
							Quote reference (optional)
							<input
								className="input"
								type="text"
								maxLength={120}
								value={quoteReference}
								onChange={(event) => {
									setQuoteReference(event.target.value);
									setOrderRequestId(newBillingRequestId());
								}}
							/>
						</label>
						<button
							className="button button-secondary"
							type="button"
							disabled={!canSubmitOrder}
							onClick={() => void submitEnterpriseOrder()}
						>
							{alreadyPending
								? "Request pending Finance review"
								: orderBusy
									? "Submitting…"
									: "Submit for Finance review"}
						</button>
					</div>
				) : null}
			</div>

			<div className="card">
				<h2>Seats</h2>
				<div className="grid" style={{ marginTop: 10 }}>
					<div className="stat-card">
						<div className="stat-label">Included</div>
						<div className="stat-value">{included}</div>
					</div>
					<div className="stat-card">
						<div className="stat-label">Extra</div>
						<div className="stat-value">{extra}</div>
					</div>
					<div className="stat-card">
						<div className="stat-label">Allowed</div>
						<div className="stat-value">{allowed}</div>
					</div>
					<div className="stat-card">
						<div className="stat-label">Connected</div>
						<div className="stat-value">{agentCount}</div>
					</div>
				</div>

				<div className="notice" style={{ marginTop: 14 }}>
					<div className="muted small">
						Commercial amount: <span className="mono">Quoted in approved order</span>
					</div>
					{overLimit ? (
						<div className="notice notice-danger" style={{ marginTop: 10 }}>
							Over limit: new agents may be rejected by the ingest function until an approved order
							is reconciled.
						</div>
					) : null}
				</div>
			</div>

			<div className="card">
				<h2>Support</h2>
				<p className="muted">
					Finance must confirm payment and reconcile an approved enterprise order before the seat
					count changes. If a reconciled order has not updated the count, contact the configured
					sales channel.
				</p>
			</div>
		</div>
	);
}
