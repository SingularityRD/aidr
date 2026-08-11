import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Turnstile } from "../../components/Turnstile";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";
import { setPostAuthReturnTo } from "../return-to";
import { getSession } from "../session";

export function LoginPage() {
	const navigate = useNavigate();
	const [searchParams] = useSearchParams();
	const [email, setEmail] = useState("");
	const [status, setStatus] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [captchaToken, setCaptchaToken] = useState<string | null>(null);
	const [captchaVerified, setCaptchaVerified] = useState(false);

	const trimmedEmail = useMemo(() => email.trim(), [email]);
	const captchaConfigured = Boolean(import.meta.env.VITE_TURNSTILE_SITE_KEY);
	const captchaReady = !captchaConfigured || captchaVerified;
	const redirectTo = `${location.origin}/auth/callback`;
	const returnTo = (searchParams.get("returnTo") ?? "").trim();
	const handleCaptchaVerify = useCallback((token: string) => {
		setCaptchaToken(token);
		setCaptchaVerified(true);
	}, []);
	const handleCaptchaError = useCallback(() => {
		setCaptchaVerified(false);
		setCaptchaToken(null);
	}, []);
	const handleCaptchaExpire = useCallback(() => {
		setCaptchaVerified(false);
		setCaptchaToken(null);
	}, []);

	useEffect(() => {
		let cancelled = false;
		async function run() {
			try {
				const session = await getSession();
				if (!cancelled && session) navigate("/onboarding", { replace: true });
			} catch (cause) {
				if (!cancelled)
					setStatus(cause instanceof Error ? cause.message : "Unable to check your session.");
			}
		}
		run();
		return () => {
			cancelled = true;
		};
	}, [navigate]);

	const statusIsSuccess = Boolean(status?.includes("sent"));

	return (
		<div className="auth-screen">
			<div className="auth-card">
				{/* Brand */}
				<div className="auth-brand">
					<span className="brand-mark">
						<ShieldIcon size={26} />
					</span>
					<div>
						<h1 className="auth-title">Welcome to AIDR</h1>
						<p className="auth-subtitle">Sign in to protect your AI agents</p>
					</div>
				</div>

				{/* Google Sign In */}
				<button
					type="button"
					className="auth-provider"
					disabled={busy}
					onClick={async () => {
						setBusy(true);
						setStatus(null);
						try {
							if (returnTo) setPostAuthReturnTo(returnTo);
							const { error } = await supabase.auth.signInWithOAuth({
								provider: "google",
								options: { redirectTo },
							});
							if (error) {
								if (error.message.includes("Unsupported provider")) {
									setStatus(
										"Google OAuth is not enabled in Supabase. Please enable it in Supabase Dashboard → Authentication → Providers → Google.",
									);
								} else {
									setStatus(error.message);
								}
							}
						} catch (cause) {
							setStatus(cause instanceof Error ? cause.message : "Google sign-in is unavailable.");
						} finally {
							setBusy(false);
						}
					}}
				>
					<svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
						<path
							fill="#4285F4"
							d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
						/>
						<path
							fill="#34A853"
							d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
						/>
						<path
							fill="#FBBC05"
							d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
						/>
						<path
							fill="#EA4335"
							d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
						/>
					</svg>
					Continue with Google
				</button>

				{/* GitHub Sign In */}
				<button
					type="button"
					className="auth-provider"
					disabled={busy}
					onClick={async () => {
						setBusy(true);
						setStatus(null);
						try {
							if (returnTo) setPostAuthReturnTo(returnTo);
							const { error } = await supabase.auth.signInWithOAuth({
								provider: "github",
								options: { redirectTo },
							});
							if (error) {
								if (error.message.includes("Unsupported provider")) {
									setStatus(
										"GitHub OAuth is not enabled in Supabase. Please enable it in Supabase Dashboard → Authentication → Providers → GitHub.",
									);
								} else {
									setStatus(error.message);
								}
							}
						} catch (cause) {
							setStatus(cause instanceof Error ? cause.message : "GitHub sign-in is unavailable.");
						} finally {
							setBusy(false);
						}
					}}
				>
					<svg
						width="18"
						height="18"
						viewBox="0 0 24 24"
						fill="currentColor"
						aria-hidden="true"
						focusable="false"
					>
						<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
					</svg>
					Continue with GitHub
				</button>

				{/* Divider */}
				<div className="auth-divider">or continue with email</div>

				{/* Email Input */}
				<div>
					<label className="label" htmlFor="login-email">
						Email address
					</label>
					<input
						id="login-email"
						className="input"
						type="email"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						placeholder="you@company.com"
						autoComplete="email"
					/>
				</div>

				{/* CAPTCHA Verification */}
				<Turnstile
					onVerify={handleCaptchaVerify}
					onError={handleCaptchaError}
					onExpire={handleCaptchaExpire}
				/>

				{/* Magic Link Button */}
				<button
					type="button"
					className="button auth-submit"
					disabled={busy || !trimmedEmail || !captchaReady}
					onClick={async () => {
						setBusy(true);
						setStatus(null);
						try {
							if (returnTo) setPostAuthReturnTo(returnTo);
							const { error } = await supabase.auth.signInWithOtp({
								email: trimmedEmail,
								options: {
									emailRedirectTo: redirectTo,
									captchaToken: captchaConfigured ? captchaToken || undefined : undefined,
								},
							});
							if (error) {
								setStatus(error.message);
							} else {
								setStatus("Magic link sent! Check your inbox.");
							}
						} catch (cause) {
							setStatus(
								cause instanceof Error ? cause.message : "Magic-link sign-in is unavailable.",
							);
						} finally {
							setBusy(false);
						}
					}}
				>
					{busy ? "Sending..." : "Send magic link"}
				</button>

				{/* Status Message */}
				{status && (
					<div
						role="alert"
						className={`auth-status ${statusIsSuccess ? "auth-status-ok" : "auth-status-error"}`}
					>
						{status}
					</div>
				)}

				{/* Back to Home */}
				<div className="auth-footer">
					<Link to="/">← Back to home</Link>
				</div>

				{/* Security Note */}
				<div className="auth-note">
					<ShieldIcon size={13} />
					Secure authentication powered by Supabase
				</div>
			</div>
		</div>
	);
}
