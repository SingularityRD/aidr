import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { setPostAuthReturnTo } from "../return-to";
import { getSession } from "../session";

export function LoginPage() {
	const navigate = useNavigate();
	const [searchParams] = useSearchParams();
	const [email, setEmail] = useState("");
	const [status, setStatus] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const trimmedEmail = useMemo(() => email.trim(), [email]);
	const redirectTo = `${location.origin}/auth/callback`;
	const returnTo = (searchParams.get("returnTo") ?? "").trim();

	useEffect(() => {
		let cancelled = false;
		async function run() {
			const session = await getSession();
			if (!cancelled && session) navigate("/onboarding", { replace: true });
		}
		run();
		return () => {
			cancelled = true;
		};
	}, [navigate]);

	return (
		<div className="card">
			<h1>Sign in</h1>
			<p className="muted">Continue with Google. Email magic link is available as a fallback.</p>

			<div className="row">
				<button
					className="button"
					type="button"
					disabled={busy}
					onClick={async () => {
						setBusy(true);
						setStatus(null);
						try {
							if (returnTo) setPostAuthReturnTo(returnTo);
							const { error } = await supabase.auth.signInWithOAuth({
								provider: "google",
								options: {
									redirectTo,
								},
							});
							if (error) setStatus(error.message);
						} finally {
							setBusy(false);
						}
					}}
				>
					Continue with Google
				</button>
			</div>

			<label className="label">
				Email
				<input
					className="input"
					type="email"
					value={email}
					onChange={(e) => setEmail(e.target.value)}
					placeholder="you@company.com"
					autoComplete="email"
				/>
			</label>

			<div className="row">
				<button
					className="button"
					type="button"
					disabled={busy || !trimmedEmail}
					onClick={async () => {
						setBusy(true);
						setStatus(null);
						try {
							if (returnTo) setPostAuthReturnTo(returnTo);
							const { error } = await supabase.auth.signInWithOtp({
								email: trimmedEmail,
								options: { emailRedirectTo: redirectTo },
							});
							if (error) {
								setStatus(error.message);
							} else {
								setStatus("Magic link sent. Check your email.");
							}
						} finally {
							setBusy(false);
						}
					}}
				>
					Send magic link
				</button>

				<button
					className="button button-secondary"
					type="button"
					onClick={async () => {
						const session = await getSession();
						if (session) navigate(returnTo || "/onboarding");
						else setStatus("Not signed in yet.");
					}}
				>
					I’m signed in
				</button>
			</div>

			{status ? <div className="notice">{status}</div> : null}
		</div>
	);
}
