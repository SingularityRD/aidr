import { useEffect, useRef, useState } from "react";
import {
	cancelSettlement,
	loadBillingPortal,
	type PortalSnapshot,
	projectedSeats,
	requestSeats,
	type SettlementStatus,
} from "../../billing/billing-portal";
import {
	getSalesContactHref,
	safeCommercialLink,
	selfServiceCheckoutEnabled,
} from "../../billing/commercial";
import {
	type EnterpriseOrder,
	listEnterpriseOrders,
	newBillingRequestId,
	requestEnterpriseOrder,
} from "../../billing/enterprise-orders";
import { type InvoiceApproval, listInvoiceApprovals } from "../../billing/invoice-approvals";
import { PlanCard } from "../../billing/plan-card";
import {
	RECONCILIATION_LABELS,
	type ReconciliationRow,
	reconcileApprovedOrders,
} from "../../billing/reconciliation";
import { CheckoutSessionExpiredError, createCheckout } from "../../billing/stripe-client";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
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
	const [seatUsageUnavailable, setSeatUsageUnavailable] = useState(true);
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
	// Recorded finance approvals. `null` means "not read", which the
	// reconciliation table must render as unavailable rather than as "nothing
	// approved"; an empty array is a real, recorded answer.
	const [approvals, setApprovals] = useState<InvoiceApproval[] | null>(null);

	useEffect(() => {
		let cancelled = false;
		setEntitlements(null);
		setSubscription(null);
		setAgentCount(0);
		setSeatUsageUnavailable(true);
		setCheckoutUrl(null);
		setCheckoutBusy(false);
		setCheckoutRequestId(newBillingRequestId());
		if (!tenantId) return;
		const activeTenantId = tenantId;

		async function load() {
			setError(null);

			const [seatRes, subRes] = await Promise.all([
				supabase
					.from("seat_usage")
					.select("included_agents,extra_agents,allowed_agents,current_agents")
					.eq("tenant_id", activeTenantId)
					.maybeSingle(),
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
				setSeatUsageUnavailable(true);
				setError(readErrorMessage(seatRes.error, "Failed to load seat usage"));
				setEntitlements(null);
				setAgentCount(0);
			} else {
				const row = (seatRes.data ?? null) as SeatUsageRow | null;
				if (
					!row ||
					![row.included_agents, row.extra_agents, row.allowed_agents, row.current_agents].every(
						(value) => Number.isSafeInteger(value) && value >= 0,
					) ||
					row.allowed_agents !== row.included_agents + row.extra_agents
				) {
					setSeatUsageUnavailable(true);
					setError("Seat usage is unavailable for this tenant");
					setEntitlements(null);
					setAgentCount(0);
				} else {
					setSeatUsageUnavailable(false);
					setEntitlements({ included_agents: row.included_agents, extra_agents: row.extra_agents });
					setAgentCount(row.current_agents);
				}
			}

			if (subRes.error) setError(readErrorMessage(subRes.error, "Failed to load subscription"));
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
		setApprovals(null);
		if (!tenantId || !canManageBilling) return;
		const activeTenantId = tenantId;
		async function loadOrders() {
			const revision = ++ordersRevision.current;
			const current = () => !cancelled && revision === ordersRevision.current;
			try {
				const rows = await listEnterpriseOrders(activeTenantId);
				if (current()) {
					setOrders(rows);
					setOrdersLoaded(true);
					setOrderError(null);
				}
			} catch {
				if (current()) {
					setOrdersLoaded(false);
					setOrderError(
						"Enterprise order status is unavailable. Contact the approved sales channel.",
					);
				}
			}
			// A failed approval read must not be presented as "nothing was
			// approved": approvals stay `null` and the reconciliation table
			// reports itself unavailable.
			try {
				const recorded = await listInvoiceApprovals(activeTenantId);
				if (current()) setApprovals(recorded);
			} catch {
				if (current()) setApprovals(null);
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
	const overLimit = !seatUsageUnavailable && allowed > 0 && agentCount > allowed;
	const providerTermEnd = subscription?.current_period_end
		? Date.parse(subscription.current_period_end)
		: Number.NaN;
	const providerTermUnverified =
		subscription !== null &&
		(subscription.provider === "stripe" || subscription.provider === "paddle") &&
		(subscription.status === "active" || subscription.status === "trialing") &&
		(!Number.isFinite(providerTermEnd) || providerTermEnd <= Date.now());

	const safeCheckoutUrl = selfServiceCheckoutEnabled ? safeCommercialLink(checkoutUrl) : null;
	const invoiceUrl = getSalesContactHref();
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
			ordersLoaded &&
			!alreadyPending &&
			!orderBusy &&
			Number.isSafeInteger(requestedAgents) &&
			requestedAgents >= 1 &&
			requestedAgents <= 100000,
	);
	const canBeginCheckout = Boolean(
		tenantId &&
			canManageBilling &&
			!seatUsageUnavailable &&
			entitlements &&
			checkoutRequestId &&
			!checkoutBusy &&
			Number.isSafeInteger(checkoutSeats) &&
			checkoutSeats >= 1 &&
			checkoutSeats <= 10000,
	);
	// The intake ledger can only ever report `pending_finance`, so an order with
	// a recorded finance decision is shown as paid from that decision instead of
	// from a ledger status it is structurally unable to carry.
	const approvalByOrderId = new Map(
		(approvals ?? []).map((approval) => [approval.orderId, approval]),
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
			if (cause instanceof CheckoutSessionExpiredError) {
				setCheckoutUrl(null);
				setCheckoutRequestId(newBillingRequestId());
			}
			setError(readErrorMessage(cause, "Checkout could not be created"));
		} finally {
			if (isCurrentBillingTenant(tenantId)) setCheckoutBusy(false);
		}
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>Billing</h1>
				<p className="muted">
					Seat allowances come from the tenant's admitted plan: a verified card subscription or an
					approved enterprise order. Catalog prices are list prices; a quote or order governs.
				</p>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			<PlanCard tenantId={tenantId} canManageBilling={canManageBilling} />

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
											subscription.status === "active" && !providerTermUnverified
												? "badge badge-success"
												: "badge badge-warning"
										}
									>
										{providerTermUnverified ? "Term expired or unverified" : subscription.status}
									</span>
								</div>
							</div>
							<div className="stat-card">
								<div className="stat-label">Recorded extra agents</div>
								<div className="mono">{subscription.extra_agents}</div>
							</div>
						</div>
						<div className="muted small" style={{ marginTop: 8 }}>
							The subscription quantity is a recorded provider value, not the current effective seat
							allowance. See Seats below for the effective limit.
						</div>
						{providerTermUnverified ? (
							<div className="notice notice-danger" style={{ marginTop: 8 }}>
								The provider term has expired or cannot be verified. Recorded extra agents are not
								included in the effective allowance shown under Seats.
							</div>
						) : null}
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

			<SubscriptionPortalCard
				tenantId={tenantId}
				canManageBilling={canManageBilling}
				approvals={approvals}
			/>

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
								{approvalByOrderId.has(order.id)
									? "approved · paid"
									: order.status.replaceAll("_", " ")}
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
						<div className="stat-value">{seatUsageUnavailable ? "Unavailable" : included}</div>
					</div>
					<div className="stat-card">
						<div className="stat-label">Extra</div>
						<div className="stat-value">{seatUsageUnavailable ? "Unavailable" : extra}</div>
					</div>
					<div className="stat-card">
						<div className="stat-label">Allowed</div>
						<div className="stat-value">{seatUsageUnavailable ? "Unavailable" : allowed}</div>
					</div>
					<div className="stat-card">
						<div className="stat-label">Connected</div>
						<div className="stat-value">{seatUsageUnavailable ? "Unavailable" : agentCount}</div>
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

const SETTLEMENT_LABELS: Record<SettlementStatus, string> = {
	quote_issued: "Quote issued",
	order_placed: "Order placed",
	settlement_pending: "Settlement pending",
	settled: "Settled",
	cancelled: "Cancelled",
	refunded: "Refunded",
};

function formatMinor(amountMinor: number, currency: string): string {
	if (!Number.isSafeInteger(amountMinor)) return "unknown";
	const sign = amountMinor < 0 ? "-" : "";
	const absolute = Math.abs(amountMinor);
	return `${sign}${currency} ${Math.floor(absolute / 100)}.${String(absolute % 100).padStart(2, "0")}`;
}

/**
 * A recorded amount is either exactly what the ledger/approval stored or
 * explicitly absent. It is never rendered as zero, because zero would be a
 * commercial figure nobody approved.
 */
function formatRecordedAmount(amountMinor: number | null, currency: string | null): string {
	if (amountMinor === null || currency === null) return "Not recorded";
	return formatMinor(amountMinor, currency);
}

function reconciliationBadgeClass(status: ReconciliationRow["status"]): string {
	return status === "matched" ? "badge badge-success" : "badge badge-warning";
}

/**
 * One reconciliation line. An unrecorded figure is rendered as "Not recorded"
 * and never as zero, and the tax cell is always explicitly absent: this ledger
 * stores no tax figure at all.
 */
function ReconciliationTableRow({ row }: { row: ReconciliationRow }) {
	return (
		<tr>
			<td>
				<div className="mono">{row.orderId ? row.orderId.slice(0, 12) : "No approved order"}</div>
				{row.approvedAt ? (
					<div className="muted small">Approved {new Date(row.approvedAt).toLocaleString()}</div>
				) : null}
			</td>
			<td className="mono">{row.quoteReference ?? "Not recorded"}</td>
			<td>{row.approver ?? "Not recorded"}</td>
			<td className="right mono">{row.approvedAgents ?? "Not recorded"}</td>
			<td className="right mono">{formatRecordedAmount(row.approvedAmountMinor, row.currency)}</td>
			<td className="right muted">Not recorded</td>
			<td className="mono small">
				{row.settlementIds.length > 0 ? row.settlementIds.join(", ") : "None"}
			</td>
			<td className="right mono">{formatRecordedAmount(row.settledAmountMinor, row.currency)}</td>
			<td className="right mono">
				{row.settledSeats === null ? "Not recorded" : row.settledSeats}
			</td>
			<td>
				<span className={reconciliationBadgeClass(row.status)}>
					{RECONCILIATION_LABELS[row.status]}
				</span>
				<div className="muted small">{row.reason}</div>
			</td>
		</tr>
	);
}

/**
 * Approved-order reconciliation surface. An unread approval list or an unread
 * ledger is reported as unavailable instead of being shown as an empty (and
 * therefore apparently clean) reconciliation.
 */
function ReconciliationSection({
	approvals,
	snapshot,
}: {
	approvals: InvoiceApproval[] | null;
	snapshot: PortalSnapshot | null;
}) {
	const rows = snapshot
		? reconcileApprovedOrders({ approvals: approvals ?? [], settlements: snapshot.settlements })
		: [];
	return (
		<>
			<h3 style={{ marginTop: 20 }}>Approved order reconciliation</h3>
			<p className="muted small">
				Each recorded finance approval is matched to the settled settlements that quote the same
				reference. A settled settlement no approval claims is marked unmatched; a settlement that
				exceeds what was approved is marked over limit. Matching is by the quote reference recorded
				by Finance — nothing here prices a settlement.
			</p>
			{approvals === null ? (
				<div className="notice notice-danger" role="status" style={{ marginTop: 8 }}>
					Reconciliation is unavailable: the recorded finance approvals could not be read. Treat
					every settled settlement as unreconciled until this is resolved.
				</div>
			) : snapshot === null ? (
				<div className="notice notice-danger" role="status" style={{ marginTop: 8 }}>
					Reconciliation is unavailable: the settlement ledger could not be read.
				</div>
			) : rows.length === 0 ? (
				<div className="muted small" style={{ marginTop: 8 }}>
					No approved order and no settled settlement is on record for this tenant.
				</div>
			) : (
				<div className="table-wrap" style={{ marginTop: 8 }}>
					<table className="table" aria-label="Approved order reconciliation">
						<thead>
							<tr>
								<th>Approved order</th>
								<th>Quote</th>
								<th>Approved by</th>
								<th className="right">Approved agents</th>
								<th className="right">Approved amount</th>
								<th className="right">Tax</th>
								<th>Settled settlement ids</th>
								<th className="right">Settled amount</th>
								<th className="right">Settled seats</th>
								<th>Status</th>
							</tr>
						</thead>
						<tbody>
							{rows.map((row) => (
								<ReconciliationTableRow key={row.key} row={row} />
							))}
						</tbody>
					</table>
				</div>
			)}
			<p className="muted small" style={{ marginTop: 8 }}>
				Approved amounts are exactly what Finance recorded; a figure that was not recorded is shown
				as “Not recorded”, never as zero. No tax rate and no catalogue price is recorded here, so
				none is displayed or derived.
			</p>
		</>
	);
}

/**
 * Self-service subscription portal.
 *
 * Read-only until the operator asks for a change, and every change carries a
 * fresh request id so a retry is idempotent server-side. A failed call clears
 * the success line rather than leaving a stale confirmation on screen. It also
 * carries the approved-order reconciliation, because the settlement ledger and
 * the approved orders only mean something when they are read together.
 */
function SubscriptionPortalCard({
	tenantId,
	canManageBilling,
	approvals,
}: {
	tenantId: string | undefined;
	canManageBilling: boolean;
	approvals: InvoiceApproval[] | null;
}) {
	type PortalRecovery =
		| { action: "request_seats"; requestId: string; seats: number; sku: string }
		| { action: "cancel"; requestId: string; settlementId: string };
	const recoveryFromError = (error: unknown): PortalRecovery | null => {
		if (
			!error ||
			typeof error !== "object" ||
			(error as { name?: unknown }).name !== "BillingRecoveryError"
		) {
			return null;
		}
		const value = error as {
			requestId?: unknown;
			action?: unknown;
			detail?: { recovery_payload?: unknown };
		};
		if (typeof value.requestId !== "string") return null;
		const payload = value.detail?.recovery_payload;
		if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
		const operation = payload as Record<string, unknown>;
		if (
			value.action === "request_seats" &&
			Number.isSafeInteger(operation.seats) &&
			(operation.seats as number) >= 1 &&
			(operation.seats as number) <= 10000 &&
			typeof operation.sku === "string" &&
			/^[a-z][a-z0-9_.-]{1,63}$/.test(operation.sku)
		)
			return {
				action: "request_seats",
				requestId: value.requestId,
				seats: operation.seats as number,
				sku: operation.sku,
			};
		if (
			value.action === "cancel" &&
			typeof operation.settlement_id === "string" &&
			/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
				operation.settlement_id,
			)
		)
			return {
				action: "cancel",
				requestId: value.requestId,
				settlementId: operation.settlement_id,
			};
		return null;
	};
	const [snapshot, setSnapshot] = useState<PortalSnapshot | null>(null);
	const [portalError, setPortalError] = useState<string | null>(null);
	const [portalNotice, setPortalNotice] = useState<string | null>(null);
	const [portalLoaded, setPortalLoaded] = useState(false);
	const [busy, setBusy] = useState(false);
	const [seats, setSeats] = useState(1);
	const [seatRequestId, setSeatRequestId] = useState(newBillingRequestId);
	const [cancelRequestId, setCancelRequestId] = useState(newBillingRequestId);
	const [recovery, setRecovery] = useState<PortalRecovery | null>(null);
	const activeTenantRef = useRef(tenantId);
	activeTenantRef.current = tenantId;

	const refresh = async (active: string): Promise<void> => {
		try {
			const next = await loadBillingPortal(active);
			if (activeTenantRef.current !== active) return;
			if (next.tenantId !== active) throw new Error("Unexpected billing tenant");
			setSnapshot(next);
		} catch {
			if (activeTenantRef.current !== active) return;
			setSnapshot(null);
			setPortalError(
				"The provider confirmed the change, but the settlement ledger could not be refreshed. Reload this page before another billing change.",
			);
		}
	};

	useEffect(() => {
		let cancelled = false;
		setSnapshot(null);
		setPortalError(null);
		setPortalNotice(null);
		setPortalLoaded(false);
		setRecovery(null);
		setSeatRequestId(newBillingRequestId());
		setCancelRequestId(newBillingRequestId());
		if (!tenantId || !canManageBilling) {
			setPortalLoaded(true);
			return;
		}
		void (async () => {
			try {
				const next = await loadBillingPortal(tenantId);
				if (cancelled || activeTenantRef.current !== tenantId) return;
				setSnapshot(next);
			} catch (loadError) {
				if (cancelled || activeTenantRef.current !== tenantId) return;
				setPortalError(readErrorMessage(loadError, "The billing portal is unavailable"));
			} finally {
				if (!cancelled) setPortalLoaded(true);
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [tenantId, canManageBilling]);

	async function applySeatChange(
		input = {
			requestId: seatRequestId,
			seats,
			sku: "aidr.agent.seat",
		},
		retrying = false,
	) {
		const active = tenantId;
		const { requestId } = input;
		if (
			typeof active !== "string" ||
			typeof requestId !== "string" ||
			busy ||
			(recovery && !retrying)
		)
			return;
		setBusy(true);
		setPortalNotice(null);
		setPortalError(null);
		try {
			const result = await requestSeats(active, requestId, input.seats, input.sku);
			if (activeTenantRef.current !== active) return;
			setRecovery(null);
			setSeats(input.seats);
			setPortalNotice(
				result.action === "noop"
					? `Provider already reports ${result.providerQuantity} seats.`
					: `Provider now reports ${result.providerQuantity} seats (${result.action} ${result.delta > 0 ? "+" : ""}${result.delta}).`,
			);
			setSeatRequestId(newBillingRequestId());
			await refresh(active);
		} catch (changeError) {
			if (activeTenantRef.current !== active) return;
			const pending = recoveryFromError(changeError);
			if (pending) {
				setRecovery(pending);
				setPortalError(
					"The provider result is indeterminate. Retry the exact original request before making a different billing change.",
				);
			} else {
				setPortalError(readErrorMessage(changeError, "The seat change was not accepted"));
			}
		} finally {
			if (activeTenantRef.current === active) setBusy(false);
		}
	}

	async function cancelOpenSettlement(
		settlementId: string,
		requestId = cancelRequestId,
		retrying = false,
	) {
		const active = tenantId;
		if (
			typeof active !== "string" ||
			typeof requestId !== "string" ||
			busy ||
			(recovery && !retrying)
		)
			return;
		setBusy(true);
		setPortalNotice(null);
		setPortalError(null);
		try {
			await cancelSettlement(active, requestId, settlementId);
			if (activeTenantRef.current !== active) return;
			setRecovery(null);
			setPortalNotice("The subscription was cancelled.");
			setCancelRequestId(newBillingRequestId());
			await refresh(active);
		} catch (cancelError) {
			if (activeTenantRef.current !== active) return;
			const pending = recoveryFromError(cancelError);
			if (pending) {
				setRecovery(pending);
				setPortalError(
					"The provider result is indeterminate. Retry the exact original request before making a different billing change.",
				);
			} else {
				setPortalError(readErrorMessage(cancelError, "The cancellation was not accepted"));
			}
		} finally {
			if (activeTenantRef.current === active) setBusy(false);
		}
	}

	const seatsFromLedger = snapshot ? projectedSeats(snapshot) : null;
	const cancellable = snapshot
		? snapshot.settlements
				.filter(
					(row) =>
						row.sequence ===
						Math.max(
							...snapshot.settlements
								.filter((other) => other.settlementId === row.settlementId)
								.map((other) => other.sequence),
						),
				)
				.filter((row) => ["settled", "settlement_pending", "order_placed"].includes(row.status))
		: [];

	return (
		<div className="card">
			<h2>Subscription portal</h2>
			<p className="muted">
				Seats are read from the settlement ledger, which the billing provider writes after a
				verified event. Requesting a seat change here updates the provider first and only then
				reloads the ledger.
			</p>
			{!tenantId || !canManageBilling ? (
				<div className="notice" style={{ marginTop: 12 }}>
					<div className="muted">
						The subscription portal is limited to a tenant owner or admin.
					</div>
				</div>
			) : !portalLoaded ? (
				<div className="muted small" style={{ marginTop: 12 }}>
					Loading subscription ledger…
				</div>
			) : (
				<>
					{portalError ? (
						<div
							className="notice notice-danger"
							style={{ marginTop: 12 }}
							role="status"
							aria-live="assertive"
							aria-label="Subscription portal error"
						>
							{portalError}
						</div>
					) : null}
					{portalNotice ? (
						<div className="notice" style={{ marginTop: 12 }} role="status">
							{portalNotice}
						</div>
					) : null}
					{recovery ? (
						<div className="notice notice-danger" style={{ marginTop: 12 }}>
							<div>
								An earlier provider write could not be confirmed. Only its exact persisted request
								can be retried safely.
							</div>
							<div className="muted small mono">Original request {recovery.requestId}</div>
							<button
								className="button button-secondary"
								type="button"
								disabled={busy}
								onClick={() =>
									void (recovery.action === "request_seats"
										? applySeatChange(recovery, true)
										: cancelOpenSettlement(recovery.settlementId, recovery.requestId, true))
								}
							>
								{recovery.action === "request_seats"
									? `Retry original request: ${recovery.seats} seats`
									: "Retry original cancellation"}
							</button>
						</div>
					) : null}
					{snapshot && !snapshot.selfService ? (
						<div className="notice notice-danger" style={{ marginTop: 12 }}>
							Self-service billing is not enabled for this deployment. Seat changes require an
							approved enterprise order.
						</div>
					) : null}
					<div className="stat" style={{ marginTop: 12 }}>
						<div className="stat-label">Settled seats</div>
						<div className="stat-value">
							{seatsFromLedger === null ? "No settlement evidence" : seatsFromLedger}
						</div>
					</div>
					{snapshot && snapshot.settlements.length > 0 ? (
						<div className="stack" aria-label="Settlement ledger" style={{ marginTop: 12 }}>
							{snapshot.settlements.map((row) => (
								<div
									className="notice"
									key={`${row.settlementId}-${row.sequence}`}
									style={{ marginTop: 8 }}
								>
									<div className="row" style={{ justifyContent: "space-between" }}>
										<strong>{SETTLEMENT_LABELS[row.status]}</strong>
										<span className="mono small">
											{formatMinor(row.settledAmountMinor, row.currency)}
										</span>
									</div>
									<div className="muted small">
										{row.lines.map((line) => `${line.sku} × ${line.quantity}`).join(", ") ||
											"No line items"}
									</div>
									<div className="muted small">
										Occurred {row.occurredAt || "unknown"} · sequence {row.sequence}
									</div>
									<div className="muted small mono" title={row.receiptHash}>
										Receipt {row.receiptHash.slice(0, 16)}…
									</div>
									{snapshot.selfService &&
									row.status === "settled" &&
									cancellable.some((entry) => entry.settlementId === row.settlementId) ? (
										<div className="row" style={{ marginTop: 8 }}>
											<button
												className="button button-secondary"
												type="button"
												disabled={busy || recovery !== null || !cancelRequestId}
												onClick={() => void cancelOpenSettlement(row.settlementId)}
											>
												Cancel subscription
											</button>
										</div>
									) : null}
								</div>
							))}
						</div>
					) : snapshot ? (
						<div className="muted small" style={{ marginTop: 12 }}>
							No settlement is on record for this tenant. A seat count is not zero until a settled
							settlement exists.
						</div>
					) : (
						<div className="muted small" style={{ marginTop: 12 }}>
							Settlement ledger is unavailable.
						</div>
					)}
					<ReconciliationSection approvals={approvals} snapshot={snapshot} />
					{snapshot?.selfService ? (
						<div className="row" style={{ marginTop: 12 }}>
							<label>
								Seats
								<input
									className="input"
									type="number"
									min={1}
									max={10000}
									value={seats}
									aria-label="Requested seats"
									onChange={(event) => {
										setSeats(Number(event.target.value));
										setSeatRequestId(newBillingRequestId());
									}}
								/>
							</label>
							<button
								className="button"
								type="button"
								disabled={
									busy ||
									recovery !== null ||
									!seatRequestId ||
									!Number.isSafeInteger(seats) ||
									seats < 1 ||
									seats > 10000
								}
								onClick={() => void applySeatChange()}
							>
								{busy ? "Applying…" : "Apply seat change"}
							</button>
						</div>
					) : null}
				</>
			)}
			<p className="muted small" style={{ marginTop: 12 }}>
				Receipts shown here are produced locally from verified provider events. They are not an
				audited statement and are not marked externally validated.
			</p>
		</div>
	);
}
