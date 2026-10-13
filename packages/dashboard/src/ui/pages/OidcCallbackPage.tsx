import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { completeOidcFlow } from "../../auth/oidc-sso";
import { useT } from "../../i18n/I18nProvider";
import { ShieldIcon } from "../icons";
import { sanitizeReturnTo } from "../return-to";

function scrubCallbackUrl() {
	const clean = new URL(window.location.href);
	clean.search = "";
	clean.hash = "";
	window.history.replaceState(window.history.state, "", clean.toString());
}

/** IdP redirect target. The authorization code is consumed exactly once and removed from the URL first. */
export function OidcCallbackPage() {
	const t = useT();
	const navigate = useNavigate();
	const { search } = useLocation();
	const [error, setError] = useState<string | null>(null);
	// True when the generic failure text should be shown in the viewer's language.
	const [failed, setFailed] = useState(false);
	const started = useRef(false);
	const active = useRef(false);

	useEffect(() => {
		active.current = true;
		// StrictMode replays effects; a code and state can only be redeemed once.
		if (started.current)
			return () => {
				active.current = false;
			};
		started.current = true;
		scrubCallbackUrl();
		completeOidcFlow(search)
			.then((result) => {
				if (!active.current) return;
				if (!result.ok) {
					setError(result.message);
					return;
				}
				navigate(sanitizeReturnTo(result.mode === "link" ? "/sso" : result.returnTo), {
					replace: true,
				});
			})
			.catch(() => {
				if (active.current) setFailed(true);
			});
		return () => {
			active.current = false;
		};
	}, [navigate, search]);

	return (
		<div className="auth-screen">
			<div className="auth-card">
				<div className="auth-brand">
					<span className="brand-mark">
						<ShieldIcon size={26} />
					</span>
					<div>
						<h1 className="auth-title">{t("nav.sso")}</h1>
					</div>
				</div>
				{error || failed ? (
					<div role="alert">
						<p>{error ?? t("oidc.failed")}</p>
						<Link to="/login">{t("oidc.backToSignIn")}</Link>
					</div>
				) : (
					<p role="status">{t("oidc.completing")}</p>
				)}
			</div>
		</div>
	);
}
