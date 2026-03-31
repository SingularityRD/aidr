import { Link } from "react-router-dom";

export function DemoPage() {
	return (
		<div className="stack">
			<div className="card">
				<h1>Book a demo</h1>
				<p className="muted">
					We’ll walk through real blocked tool calls, incident timelines, plugin/package findings,
					and the enrollment flow for your runtime.
				</p>
				<div className="notice">
					For now: send a message with your use case, runtime, and threat model. We’ll reply with a
					time slot.
				</div>
				<div className="row" style={{ marginTop: 12 }}>
					<Link className="button" to="/waitlist">
						Join Waitlist
					</Link>
					<Link className="button button-secondary" to="/pilot">
						Request Pilot
					</Link>
				</div>
			</div>
		</div>
	);
}
