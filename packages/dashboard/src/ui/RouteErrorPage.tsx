import { isRouteErrorResponse, Link, useRouteError } from "react-router-dom";

function errorMessage(error: unknown): string {
	if (isRouteErrorResponse(error)) {
		if (error.status === 404) return "This dashboard page does not exist.";
		return "The dashboard could not complete this request.";
	}
	return "The dashboard could not complete this request.";
}

export function RouteErrorPage() {
	const error = useRouteError();
	const message = errorMessage(error);

	return (
		<div
			className="card"
			role="alert"
			aria-live="assertive"
			style={{ maxWidth: 560, margin: "48px auto" }}
		>
			<p className="eyebrow">Error</p>
			<h1>Something went wrong</h1>
			<div className="notice notice-danger" style={{ marginTop: 10 }}>
				{message}
			</div>
			<div className="row" style={{ marginTop: 16, flexWrap: "wrap" }}>
				<button className="button" type="button" onClick={() => window.location.reload()}>
					Retry
				</button>
				<Link className="button button-secondary" to="/">
					Back to home
				</Link>
			</div>
		</div>
	);
}
