import { Link } from "react-router-dom";

export function NotFoundPage() {
	return (
		<main className="main">
			<div
				className="card"
				role="alert"
				aria-live="polite"
				style={{ maxWidth: 520, margin: "48px auto", textAlign: "center" }}
			>
				<p className="eyebrow">404</p>
				<h1>Page not found</h1>
				<p className="muted">The link may be stale or the page may have moved.</p>
				<div className="row" style={{ justifyContent: "center", marginTop: 18 }}>
					<Link className="button" to="/">
						Back to home
					</Link>
				</div>
			</div>
		</main>
	);
}
