import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";

type Mode = "email" | "break-glass";

export function RecoveryPage() {
	const navigate = useNavigate();
	const [params] = useSearchParams();
	const [mode, setMode] = useState<Mode>("email");
	const [hasSession, setHasSession] = useState(false);
	const [email, setEmail] = useState("");
	const [recoveryCode, setRecoveryCode] = useState("");
	const [newPassword, setNewPassword] = useState("");
	const [confirmPassword, setConfirmPassword] = useState("");
	const [recoveryLink, setRecoveryLink] = useState<string | null>(null);
	const [status, setStatus] = useState<string | null>(null);
	const [success, setSuccess] = useState(false);
	const [busy, setBusy] = useState(false);
	const grantId = params.get("grant");

	useEffect(() => {
		let cancelled = false;
		supabase.auth.getSession().then(({ data }) => {
			if (!cancelled) setHasSession(Boolean(data.session));
		});
		const { data } = supabase.auth.onAuthStateChange((event, session) => {
			if (!cancelled && (event === "PASSWORD_RECOVERY" || session)) setHasSession(Boolean(session));
		});
		return () => {
			cancelled = true;
			data.subscription.unsubscribe();
		};
	}, []);

	async function invoke(body: Record<string, unknown>) {
		const result = await supabase.functions.invoke("identity-security", { body });
		if (result.error) throw result.error;
		if (result.data?.ok !== true) throw new Error("Identity operation was not confirmed.");
		return result.data as Record<string, unknown> | null;
	}

	async function requestReset() {
		if (busy || !email.trim()) return;
		setBusy(true);
		setSuccess(false);
		setStatus(null);
		try {
			await invoke({ action: "request_password_reset", email: email.trim() });
			setSuccess(true);
			setStatus(
				"If this account is enabled, the configured authentication provider will send recovery instructions.",
			);
		} catch {
			setStatus("Password recovery is temporarily unavailable. Contact your administrator.");
		} finally {
			setBusy(false);
		}
	}

	async function useBreakGlass() {
		if (busy || !email.trim() || !recoveryCode.trim()) return;
		setBusy(true);
		setSuccess(false);
		setStatus(null);
		setRecoveryLink(null);
		try {
			const data = await invoke({
				action: "break_glass_recover",
				email: email.trim(),
				recovery_code: recoveryCode.trim(),
			});
			const link = data?.recovery_link;
			if (typeof link !== "string" || !link.startsWith("http")) throw new Error("invalid_link");
			setRecoveryCode("");
			setRecoveryLink(link);
			setSuccess(true);
			setStatus(
				"The one-time code was consumed. Continue now; this recovery link expires shortly.",
			);
		} catch {
			setRecoveryCode("");
			setStatus("The recovery code is invalid, expired, or recovery is unavailable.");
		} finally {
			setBusy(false);
		}
	}

	async function completeRecovery() {
		if (busy || !newPassword || newPassword !== confirmPassword) {
			if (newPassword !== confirmPassword) setStatus("The password confirmation does not match.");
			return;
		}
		setBusy(true);
		setSuccess(false);
		setStatus(null);
		try {
			await invoke({
				action: "complete_password_recovery",
				new_password: newPassword,
				...(grantId ? { grant_id: grantId } : {}),
			});
			setNewPassword("");
			setConfirmPassword("");
			setSuccess(true);
			setStatus("Password updated and sessions revoked. Sign in again with the new password.");
			window.setTimeout(() => navigate("/login", { replace: true }), 800);
		} catch {
			setNewPassword("");
			setConfirmPassword("");
			setStatus("This recovery session is invalid or expired. Request a new recovery link.");
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
						<h1 className="auth-title">Recover your AIDR account</h1>
						<p className="auth-subtitle">Use provider recovery or a pre-issued break-glass code.</p>
					</div>
				</div>

				{hasSession ? (
					<form
						onSubmit={(event) => {
							event.preventDefault();
							void completeRecovery();
						}}
					>
						<label className="label" htmlFor="recovery-password">
							New password
						</label>
						<input
							id="recovery-password"
							className="input"
							type="password"
							required
							minLength={14}
							maxLength={128}
							autoComplete="new-password"
							value={newPassword}
							onChange={(event) => setNewPassword(event.target.value)}
						/>
						<label className="label" htmlFor="recovery-password-confirm">
							Confirm new password
						</label>
						<input
							id="recovery-password-confirm"
							className="input"
							type="password"
							required
							minLength={14}
							maxLength={128}
							autoComplete="new-password"
							value={confirmPassword}
							onChange={(event) => setConfirmPassword(event.target.value)}
						/>
						<button
							className="button auth-submit"
							type="submit"
							disabled={busy || !newPassword || !confirmPassword}
						>
							{busy ? "Updating…" : "Update password and revoke sessions"}
						</button>
					</form>
				) : (
					<>
						<div className="row" style={{ marginBottom: 14 }}>
							<button
								className={`button ${mode === "email" ? "" : "button-secondary"}`}
								type="button"
								aria-pressed={mode === "email"}
								onClick={() => {
									setMode("email");
									setStatus(null);
								}}
							>
								Email recovery
							</button>
							<button
								className={`button ${mode === "break-glass" ? "" : "button-secondary"}`}
								type="button"
								aria-pressed={mode === "break-glass"}
								onClick={() => {
									setMode("break-glass");
									setStatus(null);
								}}
							>
								Break-glass code
							</button>
						</div>
						<form
							onSubmit={(event) => {
								event.preventDefault();
								void (mode === "email" ? requestReset() : useBreakGlass());
							}}
						>
							<label className="label" htmlFor="recovery-email">
								Email address
							</label>
							<input
								id="recovery-email"
								className="input"
								type="email"
								required
								autoComplete="username"
								value={email}
								onChange={(event) => setEmail(event.target.value)}
							/>
							{mode === "break-glass" ? (
								<>
									<label className="label" htmlFor="recovery-code">
										One-time recovery code
									</label>
									<input
										id="recovery-code"
										className="input mono"
										type="password"
										required
										autoComplete="one-time-code"
										value={recoveryCode}
										onChange={(event) => setRecoveryCode(event.target.value)}
									/>
								</>
							) : null}
							<button
								className="button auth-submit"
								type="submit"
								disabled={busy || !email.trim() || (mode === "break-glass" && !recoveryCode.trim())}
							>
								{busy
									? "Please wait…"
									: mode === "email"
										? "Request recovery"
										: "Use one-time code"}
							</button>
						</form>
					</>
				)}

				{status ? (
					<div
						role="alert"
						className={`auth-status ${success ? "auth-status-ok" : "auth-status-error"}`}
					>
						{status}
					</div>
				) : null}
				{recoveryLink ? (
					<a className="button auth-submit" href={recoveryLink} rel="noreferrer">
						Continue password recovery
					</a>
				) : null}
				<div className="auth-footer">
					<Link to="/login">← Return to sign in</Link>
				</div>
				<div className="auth-note">
					<ShieldIcon size={13} /> Break-glass codes are single-use and are never retrievable again.
				</div>
			</div>
		</div>
	);
}
