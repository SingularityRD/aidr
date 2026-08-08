import { Link } from "react-router-dom";

export function NotFoundPage() {
	return (
		<main className="main">
			<div className="card" role="alert" aria-live="polite">
				<p className="eyebrow">404</p>
				<h1>Page not found</h1>
				<p className="muted">The link may be stale or the page may have moved.</p>
				<Link className="button" to="/">
					Back to home
				</Link>
			</div>
		</main>
	);
}
