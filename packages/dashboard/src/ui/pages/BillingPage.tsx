import { useEffect, useMemo, useState } from "react";
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

const USD_PER_EXTRA_AGENT_PER_MONTH = 2;

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

			const [seatRes, subRes, checkoutRes] = await Promise.all([
				(async () => {
					const res = await supabase
						.from("seat_usage")
						.select("included_agents,extra_agents,allowed_agents,current_agents")
						.maybeSingle();
					if (!res.error) return res;
					// Back-compat if the view hasn't been deployed yet.
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
				supabase.functions.invoke("billing-checkout", { method: "GET" }),
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

			if (!checkoutRes.error) {
				const data = (checkoutRes.data ?? {}) as { checkout_url?: string };
				setCheckoutUrl(typeof data.checkout_url === "string" ? data.checkout_url : null);
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

	const monthlyEstimateUsd = useMemo(() => {
		// Commercial model: first agent is free, each additional is $2/mo.
		const billable = Math.max(0, agentCount - 1);
		return billable * USD_PER_EXTRA_AGENT_PER_MONTH;
	}, [agentCount]);

	return (
		<div className="stack">
			<div className="card">
				<h1>Billing</h1>
				<p className="muted">
					1 agent is free. Additional agents are <b>${USD_PER_EXTRA_AGENT_PER_MONTH}/month</b> each.
				</p>
				{error ? <div className="notice notice-danger">{error}</div> : null}
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

				{checkoutUrl ? (
					<div className="row" style={{ marginTop: 12 }}>
						<a className="button" href={checkoutUrl} target="_blank" rel="noreferrer">
							Upgrade seats
						</a>
					</div>
				) : (
					<div className="muted small" style={{ marginTop: 12 }}>
						Checkout is not configured.
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
						Estimated monthly total (based on connected agents):{" "}
						<span className="mono">${monthlyEstimateUsd}</span>
					</div>
					{overLimit ? (
						<div className="notice notice-danger">
							Over limit: new agents may be rejected by the ingest function until you upgrade seats.
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
