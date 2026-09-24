import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";
import { sanitizeReturnTo, takePostAuthReturnTo } from "../return-to";

function scrubCallbackUrl() {
	const clean = new URL(window.location.href);
	clean.search = "";
	clean.hash = "";
	window.history.replaceState(window.history.state, "", clean.toString());
}

function missingCodeVerifier(error: unknown): boolean {
	return Boolean(
		error &&
			typeof error === "object" &&
			"code" in error &&
			error.code === "pkce_code_verifier_not_found",
	);
}

export function AuthCallbackPage() {
	const navigate = useNavigate();
	const [error, setError] = useState<string | null>(null);
	const started = useRef(false);
	const active = useRef(false);

	useEffect(() => {
		active.current = true;
		// StrictMode replays effects. The callback URL and its PKCE code must
		// be consumed once, while the first exchange can still finish.
		if (started.current)
			return () => {
				active.current = false;
			};
		started.current = true;
		setError(null);

		function done() {
			const to = sanitizeReturnTo(takePostAuthReturnTo());
			if (active.current) navigate(to, { replace: true });
		}

		async function run() {
			let inviteSessionAttempted = false;
			try {
				const callback = new URL(window.location.href);
				const code = callback.searchParams.get("code");
				const fragment = new URLSearchParams(callback.hash.slice(1));
				const invite =
					!code &&
					!callback.searchParams.has("token_hash") &&
					(fragment.get("type") === "invite" || callback.searchParams.get("type") === "invite");
				const isRecoveryCallback =
					callback.searchParams.get("type") === "recovery" ||
					callback.searchParams.has("token_hash") ||
					callback.hash.length > 1;
				scrubCallbackUrl();
				if (invite) {
					const accessToken = fragment.get("access_token") ?? "";
					const refreshToken = fragment.get("refresh_token") ?? "";
					if (
						accessToken.length > 8192 ||
						accessToken.split(".").length !== 3 ||
						refreshToken.length < 20 ||
						refreshToken.length > 8192 ||
						/\s/.test(accessToken + refreshToken)
					)
						throw new Error("invalid_invite_session");
					inviteSessionAttempted = true;
					const accepted = await supabase.auth.setSession({
						access_token: accessToken,
						refresh_token: refreshToken,
					});
					const session = accepted.data.session;
					const verified = session ? await supabase.auth.getUser(session.access_token) : null;
					if (
						accepted.error ||
						!session ||
						verified?.error ||
						!verified?.data.user ||
						verified.data.user.id !== session.user.id
					) {
						throw new Error("invalid_invite_session");
					}
					done();
					return;
				}
				if (isRecoveryCallback || !code) {
					await supabase.auth.signOut({ scope: "local" });
					throw new Error("unsupported_callback");
				}
				const exchanged = await supabase.auth.exchangeCodeForSession(code);
				if (exchanged.error || !exchanged.data.session)
					throw exchanged.error ?? new Error("no_session");
				done();
			} catch (cause) {
				scrubCallbackUrl();
				if (inviteSessionAttempted) {
					try {
						await supabase.auth.signOut({ scope: "local" });
					} catch {
						// Keep the callback failed even if local Auth cleanup is unavailable.
					}
				}
				if (active.current) {
					setError(
						missingCodeVerifier(cause)
							? "Open the sign-in link in the browser where you requested it, or request a new link."
							: "Authentication could not be completed.",
					);
				}
			}
		}

		void run();
		return () => {
			active.current = false;
		};
	}, [navigate]);

	return (
		<div className="auth-screen">
			<div className="auth-card" role="status" aria-live="polite">
				<div className="auth-brand">
					<span className="brand-mark">
						<ShieldIcon size={26} />
					</span>
					<div>
						<h1 className="auth-title">Signing in…</h1>
						<p className="auth-subtitle">Completing Supabase authentication.</p>
					</div>
				</div>
				{error ? null : (
					<div className="row" style={{ justifyContent: "center" }}>
						<span className="spinner" aria-hidden="true" />
					</div>
				)}
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
				{error ? (
					<div
						className="row"
						style={{ marginTop: 14, flexWrap: "wrap", justifyContent: "center" }}
					>
						<button
							className="button button-secondary"
							type="button"
							onClick={() => navigate("/login")}
						>
							Return to sign in
						</button>
					</div>
				) : null}
			</div>
		</div>
	);
}
