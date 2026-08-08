import { isRouteErrorResponse, Link, useRouteError } from "react-router-dom";

function errorMessage(error: unknown): string {
	if (isRouteErrorResponse(error)) {
		if (error.status === 404) return "This dashboard page does not exist.";
		if (typeof error.data === "string") return error.data;
		return `${error.status} ${error.statusText}`.trim();
	}
	if (error instanceof Error && error.message) return error.message;
	return "The dashboard could not complete this request.";
}

export function RouteErrorPage() {
	const error = useRouteError();
	const message = errorMessage(error);

	return (
		<div className="card" role="alert" aria-live="assertive">
			<h1>Something went wrong</h1>
			<p className="muted">{message}</p>
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
