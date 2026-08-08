import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { sanitizeReturnTo, takePostAuthReturnTo } from "../return-to";

export function AuthCallbackPage() {
	const navigate = useNavigate();
	const [error, setError] = useState<string | null>(null);
	const [timedOut, setTimedOut] = useState(false);
	const [attempt, setAttempt] = useState(0);

	useEffect(() => {
		let cancelled = false;
		let unsub: (() => void) | null = null;
		let timeoutId: number | null = null;
		setError(null);
		setTimedOut(false);

		function done() {
			const to = sanitizeReturnTo(takePostAuthReturnTo());
			if (!cancelled) navigate(to, { replace: true });
		}

		async function run() {
			try {
				const hasCode = new URLSearchParams(window.location.search).has("code");
				if (hasCode) {
					const { error: exchangeError } = await supabase.auth.exchangeCodeForSession(
						window.location.href,
					);
					if (exchangeError) throw exchangeError;
				}

				// Covers both OAuth code exchange and magic-link flows.
				const sess = await supabase.auth.getSession();
				if (sess.error) throw sess.error;
				if (sess.data.session) {
					done();
					return;
				}

				const { data: sub } = supabase.auth.onAuthStateChange((_event, session) => {
					if (session) done();
				});
				unsub = () => sub.subscription.unsubscribe();
				timeoutId = window.setTimeout(() => {
					unsub?.();
					unsub = null;
					if (!cancelled) {
						setTimedOut(true);
						setError(
							"Authentication did not complete within 10 seconds. Retry or return to sign in.",
						);
					}
				}, 10_000);
			} catch (cause) {
				if (!cancelled) {
					setTimedOut(false);
					setError(
						cause instanceof Error ? cause.message : "Authentication could not be completed.",
					);
				}
			}
		}

		run();
		return () => {
			cancelled = true;
			if (timeoutId != null) window.clearTimeout(timeoutId);
			unsub?.();
		};
	}, [navigate, attempt]);

	return (
		<main className="main">
			<div className="card">
				<h1>Signing in…</h1>
				<p className="muted">Completing Supabase authentication.</p>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
				{timedOut ? (
					<div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
						<button
							className="button"
							type="button"
							onClick={() => setAttempt((value) => value + 1)}
						>
							Retry authentication
						</button>
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
		</main>
	);
}
