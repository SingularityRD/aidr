import { Link } from "react-router-dom";
import {
	DEPLOYMENT_LABELS,
	headlinePrice,
	LIST_PRICE_NOTICE,
	PLAN_CATALOG,
	PLAN_FEATURE_LABELS,
	type PlanDefinition,
	priceTerms,
	retentionTerms,
	seatTerms,
} from "../../../billing/plans";

function PlanAction({ plan }: { plan: PlanDefinition }) {
	if (plan.id === "free") {
		return (
			<Link className="button button-secondary" to="/login?returnTo=%2Fonboarding">
				Start with Free
			</Link>
		);
	}
	if (plan.selfServe) {
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
	const plans = PLAN_CATALOG.filter((plan) => plan.active).sort(
		(a, b) => a.sortOrder - b.sortOrder,
	);
	return (
		<div className="stack">
			<div className="card">
				<h1>Pricing</h1>
				<p className="muted">
					Plans are priced per developer seat, and each seat admits one protected agent installation
					(<span className="mono">iid</span>). Local detection runs on the developer machine on
					every plan.
				</p>
				<div className="notice" role="note" style={{ marginTop: 10 }}>
					{LIST_PRICE_NOTICE}
				</div>
			</div>

			<div className="plan-grid" aria-label="Plans">
				{plans.map((plan) => (
					<section
						className={plan.id === "team" ? "card referral-card" : "card"}
						key={plan.id}
						aria-labelledby={`plan-${plan.id}`}
					>
						<div className="row space-between">
							<h2 id={`plan-${plan.id}`}>{plan.displayName}</h2>
							{plan.selfServe && plan.id !== "free" ? (
								<span className="badge recommended">Self-serve</span>
							) : plan.id === "free" ? null : (
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

			<div className="card">
				<h2>Pilot and evaluation</h2>
				<p className="muted">
					A scoped evaluation can be agreed in writing before any paid plan. Paid plans become
					active only after verified payment or an approved order, and seat limits are enforced by
					the control plane.
				</p>
				<div className="row">
					<Link className="button button-secondary" to="/pilot">
						Request pilot review
					</Link>
				</div>
			</div>
		</div>
	);
}
