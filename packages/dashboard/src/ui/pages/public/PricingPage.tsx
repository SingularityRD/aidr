import { Link } from "react-router-dom";
import {
	QUOTE_CONTACT_EMAIL,
	quoteRequestHref,
	selfServiceCheckoutEnabled,
} from "../../../billing/commercial";
import {
	DEPLOYMENT_LABELS,
	PLAN_FEATURE_LABELS,
	type PlanDefinition,
	retentionTerms,
	seatTerms,
} from "../../../billing/plans";
import { PUBLIC_PLANS, QUOTE_NOTE } from "./product-facts";

/** Self-serve signup applies only when the build enables online checkout. */
function selfServePlan(plan: PlanDefinition): boolean {
	return plan.id !== "free" && plan.selfServe && selfServiceCheckoutEnabled;
}

function QuoteLink({ edition }: { edition?: string }) {
	return (
		<a
			className="button"
			href={quoteRequestHref(edition)}
			aria-label={edition ? `Contact sales about ${edition}` : undefined}
		>
			Contact sales
		</a>
	);
}

function PlanActions({ plan }: { plan: PlanDefinition }) {
	if (plan.id === "free") {
		return (
			<Link className="button button-secondary" to="/login?returnTo=%2Fonboarding">
				Start with Free
			</Link>
		);
	}
	return (
		<>
			<QuoteLink edition={plan.displayName} />
			{selfServePlan(plan) ? (
				<Link className="button button-secondary" to="/login?returnTo=%2Fbilling">
					Choose {plan.displayName}
				</Link>
			) : (
				<Link className="button button-secondary" to="/pilot">
					Request scope review
				</Link>
			)}
		</>
	);
}

/**
 * Public Editions page, served at /pricing because that route may be linked
 * externally. It compares the editions and routes every paid one to a quote:
 * prices are not published (product-owner decision), so no amount, currency or
 * per-seat figure is rendered here.
 */
export function PricingPage() {
	return (
		<div className="stack">
			<div className="card">
				<div className="muted small" lang="tr">
					Paketler
				</div>
				<h1>Editions</h1>
				<p className="muted">
					Paid editions are licensed per developer seat, and each seat admits one protected agent
					installation (<span className="mono">iid</span>). Local detection runs on the developer
					machine in every edition.{" "}
					{selfServiceCheckoutEnabled
						? "Orders are placed through checkout or an approved written quote."
						: "Orders require an approved written quote; self-service checkout is not offered."}{" "}
					The cloud trial is 14 days for one agent.
				</p>
				<div className="notice" role="note" style={{ marginTop: 10 }}>
					{QUOTE_NOTE} Request a quote from <a href={quoteRequestHref()}>{QUOTE_CONTACT_EMAIL}</a>.
				</div>
				<div className="row" style={{ marginTop: 12 }}>
					<QuoteLink />
					<span className="muted small" lang="tr">
						Teklif alın
					</span>
				</div>
			</div>

			<div className="plan-grid" aria-label="Editions">
				{PUBLIC_PLANS.map((plan) => (
					<section
						className={plan.id === "team" ? "card referral-card" : "card"}
						key={plan.id}
						aria-labelledby={`plan-${plan.id}`}
					>
						<div className="row space-between">
							<h2 id={`plan-${plan.id}`}>{plan.displayName}</h2>
							{plan.id === "free" ? null : selfServePlan(plan) ? (
								<span className="badge recommended">Self-serve</span>
							) : (
								<span className="badge">Sales-assisted</span>
							)}
						</div>
						<div className="muted small">
							{plan.id === "free" ? "No account needed for local detection" : "Quote-based"}
						</div>
						<ul className="list">
							<li>{seatTerms(plan)}</li>
							<li>
								{plan.deployment.map((deployment) => DEPLOYMENT_LABELS[deployment]).join(" or ")}{" "}
								deployment
							</li>
							<li>{retentionTerms(plan)}</li>
							{plan.features.map((feature) => (
								<li key={feature}>{PLAN_FEATURE_LABELS[feature]}</li>
							))}
						</ul>
						<div className="row" style={{ marginTop: 12 }}>
							<PlanActions plan={plan} />
						</div>
					</section>
				))}
			</div>

			<div className="card referral-card">
				<div className="row space-between">
					<h2>Pilot</h2>
					<span className="badge recommended">Review required</span>
				</div>
				<ul className="list">
					<li>Agent count and deployment scope agreed in writing</li>
					<li>Dashboard access only within an accepted evaluation scope</li>
					<li>Support and data-retention terms agreed before enrollment</li>
				</ul>
				<p className="muted">
					Paid plans become active only after verified payment or an approved order, and seat limits
					are enforced by the control plane.
				</p>
				<div className="row" style={{ marginTop: 12 }}>
					<Link className="button" to="/pilot">
						Request pilot review
					</Link>
				</div>
			</div>

			<div className="card">
				<h2>Enterprise and on-premises</h2>
				<p className="muted">
					On-premises, Kubernetes and air-gapped deployments require an agreed scope,
					Finance-approved quote, and written support terms before a paid order.
				</p>
				<div className="row">
					<QuoteLink edition="Enterprise" />
					<Link className="button button-secondary" to="/pilot">
						Request scope review
					</Link>
				</div>
			</div>
		</div>
	);
}
