import { Link } from "react-router-dom";
import { selfServiceCheckoutEnabled } from "../../../billing/commercial";
import { LIST_PRICE_NOTE, PUBLIC_PLANS } from "./product-facts";

export function PricingPage() {
	return (
		<div className="stack">
			<div className="card">
				<h1>Pricing</h1>
				<p className="muted">
					One seat covers a person's AI coding agents and Browser Guard. {LIST_PRICE_NOTE}{" "}
					{selfServiceCheckoutEnabled
						? "Orders are placed through checkout or an approved written quote."
						: "Orders require an approved written quote; self-service checkout is not offered."}{" "}
					The cloud trial is 14 days for one agent, and agent installations (
					<span className="mono">iid</span>) are counted for a scoped evaluation.
				</p>
			</div>

			<div className="cols">
				{PUBLIC_PLANS.map((plan) => (
					<section
						key={plan.name}
						className="card referral-card"
						aria-labelledby={`plan-${plan.name}`}
					>
						<h2 id={`plan-${plan.name}`}>{plan.name}</h2>
						<div className="price">{plan.price}</div>
						<p className="muted">{plan.terms}</p>
						<ul className="list">
							{plan.features.map((feature) => (
								<li key={feature}>{feature}</li>
							))}
						</ul>
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
