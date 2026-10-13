import { Link } from "react-router-dom";
import { useT } from "../i18n/I18nProvider";

export function NotFoundPage() {
	const t = useT();
	return (
		<main className="main">
			<div
				className="card"
				role="alert"
				aria-live="polite"
				style={{ maxWidth: 520, margin: "48px auto", textAlign: "center" }}
			>
				<p className="eyebrow">404</p>
				<h1>{t("notFound.title")}</h1>
				<p className="muted">{t("notFound.body")}</p>
				<div className="row" style={{ justifyContent: "center", marginTop: 18 }}>
					<Link className="button" to="/">
						{t("common.backHome")}
					</Link>
				</div>
			</div>
		</main>
	);
}
