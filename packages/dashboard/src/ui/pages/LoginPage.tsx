import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { getSession } from "../session";

export function LoginPage() {
	const navigate = useNavigate();
	const [email, setEmail] = useState("");
	const [status, setStatus] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const trimmedEmail = useMemo(() => email.trim(), [email]);

	return (
		<div className="card">
			<h1>Sign in</h1>
			<p className="muted">Email magic link via Supabase Auth.</p>

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
							const { error } = await supabase.auth.signInWithOtp({
								email: trimmedEmail,
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
						if (session) navigate("/agents");
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

