import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { readFunctionError } from "../../auth/oidc-sso";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";

/**
 * Identity-provider outage recovery. Spends one single-use owner recovery code
 * to suspend OIDC enforcement; it signs nobody in. The owner then signs in with
 * a password (and MFA, when required) and repairs the provider settings.
 */
export function OidcBreakGlassPage() {
	const [email, setEmail] = useState("");
	const [code, setCode] = useState("");
	const [busy, setBusy] = useState(false);
	const [status, setStatus] = useState<{ kind: "ok" | "error"; message: string } | null>(null);

	async function submit(event: FormEvent) {
		event.preventDefault();
		if (busy || !email.trim() || !code.trim()) return;
		setBusy(true);
		setStatus(null);
		try {
			const { data, error } = await supabase.functions.invoke<unknown>("oidc-sso", {
				body: {
					action: "break_glass_suspend_enforcement",
					email: email.trim(),
					recovery_code: code.trim(),
				},
			});
			if (!error && (data as { ok?: unknown } | null)?.ok === true) {
				setCode("");
				setStatus({
					kind: "ok",
					message:
						"Single sign-on enforcement was suspended and the event was audited. Sign in with your password to repair the identity provider settings.",
				});
				return;
			}
			const details = await readFunctionError(error, data);
			setStatus({
				kind: "error",
				message:
					details.error === "rate_limited"
						? "Too many attempts. Wait ten minutes and try again."
						: details.error === "recovery_unavailable"
							? "Recovery is temporarily unavailable. Try again later."
							: "The recovery code is invalid or expired.",
			});
		} catch {
			setStatus({
				kind: "error",
				message: "Recovery is temporarily unavailable. Try again later.",
			});
		} finally {
			setBusy(false);
		}
	}

	return (
		<div className="auth-screen">
			<div className="auth-card">
				<div className="auth-brand">
					<span className="brand-mark">
						<ShieldIcon size={26} />
					</span>
					<div>
						<h1 className="auth-title">Suspend SSO enforcement</h1>
						<p className="auth-subtitle">
							For tenant owners when the identity provider is unavailable.
						</p>
					</div>
				</div>
				<form onSubmit={(event) => void submit(event)}>
					<label className="label" htmlFor="sso-bg-email">
						Owner email
					</label>
					<input
						id="sso-bg-email"
						type="email"
						autoComplete="username"
						value={email}
						onChange={(event) => setEmail(event.target.value)}
					/>
					<label className="label" htmlFor="sso-bg-code">
						Recovery code
					</label>
					<input
						id="sso-bg-code"
						autoComplete="off"
						value={code}
						onChange={(event) => setCode(event.target.value)}
					/>
					<button className="button" type="submit" disabled={busy || !email.trim() || !code.trim()}>
						Suspend enforcement
					</button>
				</form>
				{status ? (
					<p role={status.kind === "error" ? "alert" : "status"}>{status.message}</p>
				) : null}
				<p className="muted small">
					The code is single-use and the action is audited. <Link to="/login">Back to sign-in</Link>
				</p>
			</div>
		</div>
	);
}
