import { Link } from "react-router-dom";

export function PricingPage() {
	return (
		<div className="stack">
			<div className="card">
				<h1>Pricing</h1>
				<p className="muted">
					Pricing and scope require an approved written quote. Agent installations (
					<span className="mono">iid</span>) are counted for a scoped evaluation; no public price or
					self-service checkout is offered.
				</p>
			</div>

			<div className="cols">
				<div className="card referral-card">
					<div className="row space-between">
						<h2>Pilot</h2>
						<span className="badge recommended">Review required</span>
					</div>
					<div className="price">By approval</div>
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
			</div>

			<div className="card">
				<h2>Enterprise</h2>
				<p className="muted">
					Larger deployments require an agreed scope, Finance-approved quote, and written support
					terms before a paid order.
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
