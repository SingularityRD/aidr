import { useEffect, useState } from "react";
import {
	getInvoiceContactHref,
	safeCommercialLink,
	selfServiceCheckoutEnabled,
} from "../../billing/commercial";
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
	const [entitlements, setEntitlements] = useState<EntitlementsRow | null>(null);
	const [agentCount, setAgentCount] = useState<number>(0);
	const [subscription, setSubscription] = useState<SubscriptionRow | null>(null);
	const [checkoutUrl, setCheckoutUrl] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;

		async function load() {
			setError(null);

			const [seatRes, subRes] = await Promise.all([
				(async () => {
					const res = await supabase
						.from("seat_usage")
						.select("included_agents,extra_agents,allowed_agents,current_agents")
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
						supabase.from("entitlements").select("included_agents,extra_agents").maybeSingle(),
						supabase.from("agents").select("id", { count: "exact", head: true }),
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
					.order("updated_at", { ascending: false })
					.limit(1)
					.maybeSingle(),
			]);
			const checkoutRes = selfServiceCheckoutEnabled
				? await supabase.functions.invoke("billing-checkout", { method: "GET" })
				: null;

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

			if (checkoutRes && !checkoutRes.error) {
				const data = (checkoutRes.data ?? {}) as { checkout_url?: string };
				setCheckoutUrl(typeof data.checkout_url === "string" ? data.checkout_url : null);
			} else if (!selfServiceCheckoutEnabled) {
				setCheckoutUrl(null);
			}
		}

		load();
		const t = setInterval(load, 8000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, []);

	const included = Number(entitlements?.included_agents ?? 1);
	const extra = Number(entitlements?.extra_agents ?? 0);
	const allowed = Math.max(0, included + extra);
	const overLimit = allowed > 0 && agentCount > allowed;

	const safeCheckoutUrl = selfServiceCheckoutEnabled ? safeCommercialLink(checkoutUrl) : null;
	const invoiceUrl = getInvoiceContactHref();

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
							<div>
								<div className="muted small">Provider</div>
								<div className="mono">{subscription.provider}</div>
							</div>
							<div>
								<div className="muted small">Status</div>
								<div className="mono">{subscription.status}</div>
							</div>
							<div>
								<div className="muted small">Extra agents</div>
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
						<div className="muted">No active subscription found yet.</div>
					</div>
				)}

				{safeCheckoutUrl ? (
					<div className="row" style={{ marginTop: 12 }}>
						<a className="button" href={safeCheckoutUrl} target="_blank" rel="noreferrer">
							Upgrade seats
						</a>
					</div>
				) : selfServiceCheckoutEnabled ? (
					<div className="muted small" style={{ marginTop: 12 }}>
						Checkout is not configured.
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
			</div>

			<div className="card">
				<h2>Seats</h2>
				<div className="grid">
					<div>
						<div className="muted small">Included</div>
						<div className="mono">{included}</div>
					</div>
					<div>
						<div className="muted small">Extra</div>
						<div className="mono">{extra}</div>
					</div>
					<div>
						<div className="muted small">Allowed</div>
						<div className="mono">{allowed}</div>
					</div>
				</div>

				<div className="notice">
					<div className="muted small">Current connected agents</div>
					<div className="mono">{agentCount}</div>
					<div className="muted small" style={{ marginTop: 8 }}>
						Commercial amount: <span className="mono">Quoted in approved order</span>
					</div>
					{overLimit ? (
						<div className="notice notice-danger">
							Over limit: new agents may be rejected by the ingest function until an approved order
							is reconciled.
						</div>
					) : null}
				</div>
			</div>

			<div className="card">
				<h2>Support</h2>
				<p className="muted">
					If your seat count does not update after purchase, wait a few minutes for the billing
					webhook to reconcile entitlements, then refresh. Manual entitlement grants are available
					for support escalations.
				</p>
			</div>
		</div>
	);
}
