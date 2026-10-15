import { isRouteErrorResponse, Link, useRouteError } from "react-router-dom";
import { useT } from "../i18n/I18nProvider";

export function RouteErrorPage() {
	const error = useRouteError();
	const t = useT();
	const message =
		isRouteErrorResponse(error) && error.status === 404 ? t("error.notFound") : t("error.generic");

	return (
		<div
			className="card"
			role="alert"
			aria-live="assertive"
			style={{ maxWidth: 560, margin: "48px auto" }}
		>
			<p className="eyebrow">{t("error.eyebrow")}</p>
			<h1>{t("error.title")}</h1>
			<div className="notice notice-danger" style={{ marginTop: 10 }}>
				{message}
			</div>
			<div className="row" style={{ marginTop: 16, flexWrap: "wrap" }}>
				<button className="button" type="button" onClick={() => window.location.reload()}>
					{t("error.retry")}
				</button>
				<Link className="button button-secondary" to="/">
					{t("common.backHome")}
				</Link>
			</div>
		</div>
	);
}
