import { Link } from "react-router-dom";
import { selfServiceCheckoutEnabled } from "../../../billing/commercial";
import {
	DEPLOYMENT_LABELS,
	headlinePrice,
	PLAN_FEATURE_LABELS,
	type PlanDefinition,
	priceTerms,
	retentionTerms,
	seatTerms,
} from "../../../billing/plans";
import { LIST_PRICE_NOTE, PUBLIC_PLANS } from "./product-facts";

/** Self-serve signup applies only when the build enables online checkout. */
function selfServePlan(plan: PlanDefinition): boolean {
	return plan.id !== "free" && plan.selfServe && selfServiceCheckoutEnabled;
}

function PlanAction({ plan }: { plan: PlanDefinition }) {
	if (plan.id === "free") {
		return (
			<Link className="button button-secondary" to="/login?returnTo=%2Fonboarding">
				Start with Free
			</Link>
		);
	}
	if (selfServePlan(plan)) {
		return (
			<Link className="button" to="/login?returnTo=%2Fbilling">
				Choose {plan.displayName}
			</Link>
		);
	}
	return (
		<Link className="button button-secondary" to="/pilot">
			Request scope review
		</Link>
	);
}

export function PricingPage() {
	return (
		<div className="stack">
			<div className="card">
				<h1>Pricing</h1>
				<p className="muted">
					Plans are priced per developer seat, and each seat admits one protected agent installation
					(<span className="mono">iid</span>). Local detection runs on the developer machine on
					every plan.{" "}
					{selfServiceCheckoutEnabled
						? "Orders are placed through checkout or an approved written quote."
						: "Orders require an approved written quote; self-service checkout is not offered."}{" "}
					The cloud trial is 14 days for one agent.
				</p>
				<div className="notice" role="note" style={{ marginTop: 10 }}>
					{LIST_PRICE_NOTE}
				</div>
			</div>

			<div className="plan-grid" aria-label="Plans">
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
						<div className="price">{headlinePrice(plan)}</div>
						<div className="muted small">{priceTerms(plan)}</div>
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
							<PlanAction plan={plan} />
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
					<Link className="button button-secondary" to="/pilot">
						Request scope review
					</Link>
				</div>
			</div>
		</div>
	);
}
