import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { takePostAuthReturnTo } from "../return-to";

export function AuthCallbackPage() {
	const navigate = useNavigate();
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		let unsub: (() => void) | null = null;
		let timeoutId: number | null = null;

		function done() {
			const returnTo = takePostAuthReturnTo();
			const to = returnTo?.startsWith("/") ? returnTo : "/onboarding";
			if (!cancelled) navigate(to, { replace: true });
		}

		async function run() {
			try {
				const hasCode = new URLSearchParams(location.search).has("code");
				if (hasCode) {
					const { error: exErr } = await supabase.auth.exchangeCodeForSession(location.href);
					if (exErr) {
						if (!cancelled) setError(exErr.message);
						return;
					}
				}

				// Wait for the session to be established (covers both OAuth code exchange and magic-link flows).
				const sess = await supabase.auth.getSession();
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
				}, 10_000);
			} catch (e) {
				if (!cancelled) setError(String(e));
			}
		}

		run();
		return () => {
			cancelled = true;
			if (timeoutId != null) window.clearTimeout(timeoutId);
			unsub?.();
		};
	}, [navigate]);

	return (
		<div className="card">
			<h1>Signing in…</h1>
			<p className="muted">Completing Supabase authentication.</p>
			{error ? <div className="notice notice-danger">{error}</div> : null}
		</div>
	);
}
