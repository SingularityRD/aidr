import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Turnstile } from "../../components/Turnstile";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";
import { sanitizeReturnTo, setPostAuthReturnTo } from "../return-to";
import { getSession } from "../session";

export function LoginPage() {
	const navigate = useNavigate();
	const [params] = useSearchParams();
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [status, setStatus] = useState<string | null>(null);
	const [sent, setSent] = useState(false);
	const [busy, setBusy] = useState(false);
	const [captchaToken, setCaptchaToken] = useState<string | null>(null);
	const methods = window.__AIDR_CONFIG__?.authMethods ?? ["google", "github", "magic-link"];
	const passwordEnabled = methods.includes("password");
	const magicEnabled = methods.includes("magic-link");
	const emailEnabled = passwordEnabled || magicEnabled;
	const providers = (["google", "github", "azure"] as const).filter((provider) =>
		methods.includes(provider),
	);
	const captchaConfigured = Boolean(import.meta.env.VITE_TURNSTILE_SITE_KEY);
	const captchaReady = !captchaConfigured || Boolean(captchaToken);
	const redirectTo = `${location.origin}/auth/callback`;
	const returnTo = sanitizeReturnTo(params.get("returnTo"));
	const handleVerify = useCallback((token: string) => setCaptchaToken(token), []);
	const handleExpire = useCallback(() => setCaptchaToken(null), []);

	useEffect(() => {
		let cancelled = false;
		getSession()
			.then((session) => {
				if (!cancelled && session) navigate(returnTo, { replace: true });
			})
			.catch(() => {
				if (!cancelled) setStatus("Unable to check your session. Please try again.");
			});
		return () => {
			cancelled = true;
		};
	}, [navigate, returnTo]);

	async function signIn(method: "password" | "magic-link") {
		if (busy || !captchaReady) return;
		setBusy(true);
		setStatus(null);
		setSent(false);
		try {
			const token = captchaConfigured ? (captchaToken ?? undefined) : undefined;
			if (method === "password") {
				const { error } = await supabase.auth.signInWithPassword({
					email: email.trim(),
					password,
					options: { captchaToken: token },
				});
				if (error) {
					setStatus("Sign-in failed. Check your email and password or contact your administrator.");
					return;
				}
				navigate(returnTo, { replace: true });
			} else {
				setPostAuthReturnTo(returnTo);
				const { error } = await supabase.auth.signInWithOtp({
					email: email.trim(),
					options: { emailRedirectTo: redirectTo, captchaToken: token, shouldCreateUser: false },
				});
				if (error) {
					setStatus("Unable to send a sign-in link. Contact your administrator.");
					return;
				}
				setSent(true);
				setStatus("If this account is enabled, a sign-in link has been sent. Check your inbox.");
			}
		} catch {
			setStatus("Sign-in is unavailable. Please try again.");
		} finally {
			setPassword("");
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
						<h1 className="auth-title">Welcome to AIDR</h1>
						<p className="auth-subtitle">Sign in to protect your AI agents</p>
					</div>
				</div>
				{providers.map((provider) => (
					<button
						key={provider}
						type="button"
						className="auth-provider"
						disabled={busy}
						onClick={async () => {
							setBusy(true);
							setStatus(null);
							setSent(false);
							try {
								setPostAuthReturnTo(returnTo);
								const { error } = await supabase.auth.signInWithOAuth({
									provider,
									options: { redirectTo },
								});
								if (error)
									setStatus("This sign-in provider is unavailable. Contact your administrator.");
							} catch {
								setStatus("Sign-in is unavailable. Please try again.");
							} finally {
								setBusy(false);
							}
						}}
					>
						Continue with {provider === "google" ? "Google" : provider === "github" ? "GitHub" : "Microsoft Entra ID"}
					</button>
				))}
				{providers.length > 0 && emailEnabled && (
					<div className="auth-divider">or continue with email</div>
				)}
				{emailEnabled && (
					<form
						onSubmit={(event) => {
							event.preventDefault();
							void signIn(passwordEnabled ? "password" : "magic-link");
						}}
					>
						<label className="label" htmlFor="login-email">
							Email address
						</label>
						<input
							id="login-email"
							className="input"
							type="email"
							required
							value={email}
							onChange={(event) => setEmail(event.target.value)}
							placeholder="you@company.com"
							autoComplete="username"
						/>
						{passwordEnabled && (
							<>
								<label className="label" htmlFor="login-password">
									Password
								</label>
								<input
									id="login-password"
									className="input"
									type="password"
									required
									value={password}
									onChange={(event) => setPassword(event.target.value)}
									autoComplete="current-password"
									maxLength={128}
								/>
							</>
						)}
						{captchaConfigured && (
							<Turnstile onVerify={handleVerify} onError={handleExpire} onExpire={handleExpire} />
						)}
						<button
							type="submit"
							className="button auth-submit"
							disabled={busy || !email.trim() || !captchaReady || (passwordEnabled && !password)}
						>
							{busy ? "Please wait…" : passwordEnabled ? "Sign in" : "Send magic link"}
						</button>
						{passwordEnabled && magicEnabled && (
							<button
								className="button button-secondary"
								type="button"
								disabled={busy || !email.trim() || !captchaReady}
								onClick={() => void signIn("magic-link")}
							>
								Email a sign-in link
							</button>
						)}
						{passwordEnabled && (
							<div className="auth-footer">
								<Link to="/auth/recover">Forgot password or lost your second factor?</Link>
							</div>
						)}
					</form>
				)}
				{methods.length === 0 && (
					<p role="alert">Sign-in has not been configured. Contact your administrator.</p>
				)}
				{status && (
					<div
						role="alert"
						className={`auth-status ${sent ? "auth-status-ok" : "auth-status-error"}`}
					>
						{status}
					</div>
				)}
				<div className="auth-footer">
					<Link to="/">← Back to home</Link>
				</div>
				<div className="auth-note">
					<ShieldIcon size={13} />
					Use the account provided by your administrator.
				</div>
			</div>
		</div>
	);
}
