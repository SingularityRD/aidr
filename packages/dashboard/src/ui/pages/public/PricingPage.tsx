import { Link } from "react-router-dom";

export function PricingPage() {
	return (
		<div className="stack">
			<div className="card">
				<h1>Pricing</h1>
				<p className="muted">
					Simple pricing aligned to the thing you actually protect: the number of connected agent
					installations (<span className="mono">iid</span>).
				</p>
			</div>

			<div className="cols">
				<div className="card">
					<h2>Free (Pilot)</h2>
					<div className="price">$0</div>
					<ul className="list">
						<li>1 protected agent included</li>
						<li>Dashboard access</li>
						<li>Core detections and local enforcement</li>
						<li>Offline grace after enrollment</li>
					</ul>
					<div className="row" style={{ marginTop: 12 }}>
						<Link className="button" to="/pilot">
							Get Pilot Access
						</Link>
					</div>
				</div>

				<div className="card">
					<h2>Pro (Soon)</h2>
					<div className="price">$2</div>
					<div className="muted small">per additional protected agent / month</div>
					<ul className="list" style={{ marginTop: 10 }}>
						<li>Extra agents as quantity</li>
						<li>Premium intel packs</li>
						<li>Advanced correlation and visibility</li>
					</ul>
					<div className="notice">
						We’re starting with a free pilot to validate the onboarding and reduce false positives.
					</div>
				</div>
			</div>

			<div className="card">
				<h2>Enterprise</h2>
				<p className="muted">
					Need larger fleets, org-wide policy distribution, or dedicated support? Let’s talk.
				</p>
				<div className="row">
					<Link className="button button-secondary" to="/demo">
						Book Demo
					</Link>
				</div>
			</div>
		</div>
	);
}
