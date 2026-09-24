import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Turnstile } from "../../components/Turnstile";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";
import { sanitizeReturnTo, setPostAuthReturnTo } from "../return-to";
import { getSession } from "../session";

type SamlLoginProvider = { providerId: string; label: string } | { domain: string; label: string };

export function LoginPage() {
	const navigate = useNavigate();
	const [params] = useSearchParams();
	const [email, setEmail] = useState("");
	const [workspaceName, setWorkspaceName] = useState("");
	const [password, setPassword] = useState("");
	const [confirmPassword, setConfirmPassword] = useState("");
	const [registering, setRegistering] = useState(false);
	const [status, setStatus] = useState<string | null>(null);
	const [sent, setSent] = useState(false);
	const [busy, setBusy] = useState(false);
	const [captchaToken, setCaptchaToken] = useState<string | null>(null);
	const [captchaGeneration, setCaptchaGeneration] = useState(0);
	const methods = window.__AIDR_CONFIG__?.authMethods ?? ["google", "github", "magic-link"];
	const passwordEnabled = methods.includes("password");
	const cloudSignupEnabled = window.__AIDR_CONFIG__?.signupMode === "cloud" && passwordEnabled;
	const magicEnabled = methods.includes("magic-link");
	const emailEnabled = passwordEnabled || magicEnabled;
	const providers = (["google", "github", "azure"] as const).filter((provider) =>
		methods.includes(provider),
	);
	const samlProviderId = window.__AIDR_CONFIG__?.samlProviderId;
	const samlDomain = window.__AIDR_CONFIG__?.samlDomain;
	const samlProviders: SamlLoginProvider[] = window.__AIDR_CONFIG__?.samlProviders ?? (samlProviderId
		? [{ providerId: samlProviderId, label: "company SSO" }]
		: samlDomain ? [{ domain: samlDomain, label: "company SSO" }] : []);
	const samlEnabled = samlProviders.length > 0;
	const captchaConfigured = Boolean(import.meta.env.VITE_TURNSTILE_SITE_KEY);
	const captchaReady = !captchaConfigured || Boolean(captchaToken);
	const redirectTo = `${location.origin}/auth/callback`;
	const returnTo = sanitizeReturnTo(params.get("returnTo"));
	const signOutStatus = params.get("signout");
	const handleVerify = useCallback((token: string) => setCaptchaToken(token), []);
	const handleExpire = useCallback(() => setCaptchaToken(null), []);
	function resetCaptcha() {
		if (!captchaConfigured) return;
		setCaptchaToken(null);
		setCaptchaGeneration((generation) => generation + 1);
	}

	useEffect(() => {
		if (signOutStatus) return;
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
	}, [navigate, returnTo, signOutStatus]);

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
					setStatus(
						error.status === 429
							? "Email delivery is temporarily limited. Please try again later."
							: "Unable to send a sign-in link. Contact your administrator.",
					);
					return;
				}
				setSent(true);
				setStatus("If this account is enabled, check your inbox for a sign-in link.");
			}
		} catch {
			setStatus("Sign-in is unavailable. Please try again.");
		} finally {
			setPassword("");
			resetCaptcha();
			setBusy(false);
		}
	}

	async function register() {
		if (busy || !cloudSignupEnabled || !captchaReady) return;
		const name = workspaceName.trim();
		if (!name || name.length > 200 || /[\x00-\x1f\x7f]/.test(workspaceName)) {
			setStatus("Enter a team name of up to 200 characters without control characters.");
			return;
		}
		if (password !== confirmPassword) {
			setStatus("Passwords do not match.");
			return;
		}
		setBusy(true);
		setStatus(null);
		setSent(false);
		try {
			setPostAuthReturnTo("/onboarding");
			const { data, error } = await supabase.auth.signUp({
				email: email.trim(),
				password,
				options: {
					emailRedirectTo: redirectTo,
					captchaToken: captchaConfigured ? (captchaToken ?? undefined) : undefined,
					data: { workspace_name: name },
				},
			});
			if (error || !data.user) {
				setStatus(
					error?.status === 429
						? "Email delivery is temporarily limited. Please try again later."
						: "Unable to create an account. Check the password requirements or contact support.",
				);
				return;
			}
			if (data.session) {
				await supabase.auth.signOut({ scope: "local" });
				setStatus("Email confirmation is not enabled. Account registration is unavailable.");
				return;
			}
			setSent(true);
			setStatus(
				"If this address is eligible, check your inbox for a confirmation link. Open it in this browser to continue setup.",
			);
		} catch {
			setStatus("Account registration is unavailable. Please try again later.");
		} finally {
			setPassword("");
			setConfirmPassword("");
			resetCaptcha();
			setBusy(false);
		}
	}

	async function signInWithSaml(provider: SamlLoginProvider) {
		setBusy(true);
		setStatus(null);
		try {
			setPostAuthReturnTo(returnTo);
			const { data, error } = await supabase.auth.signInWithSSO({
				...("providerId" in provider
					? { providerId: provider.providerId }
					: { domain: provider.domain }),
				options: { redirectTo },
			});
			const target = data?.url ? new URL(data.url) : null;
			const safeProtocol =
				target?.protocol === "https:" ||
				(target?.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname));
			if (error || !target || !safeProtocol || target.username || target.password) {
				setStatus("Company sign-in is unavailable. Contact your administrator.");
				return;
			}
			window.location.assign(target.href);
		} catch {
			setStatus("Company sign-in is unavailable. Contact your administrator.");
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
						<h1 className="auth-title">Welcome to AIDR</h1>
						<p className="auth-subtitle">
							{registering
								? "Create an account to protect your AI agents"
								: "Sign in to protect your AI agents"}
						</p>
					</div>
				</div>
				{signOutStatus === "revocation-unconfirmed" ? (
					<p role="alert">
						This browser signed out, but revocation of other sessions could not be confirmed.
						Contact your administrator if those sessions must be ended.
					</p>
				) : signOutStatus === "local-failed" ? (
					<p role="alert">
						This browser sign-out could not be confirmed. Close this tab and ask your administrator
						to revoke active sessions.
					</p>
				) : null}
				{!registering &&
					providers.map((provider) => (
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
										options: {
											redirectTo,
											...(provider === "azure" ? { scopes: "openid profile email" } : {}),
										},
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
							Continue with{" "}
							{provider === "google"
								? "Google"
								: provider === "github"
									? "GitHub"
									: "Microsoft Entra ID"}
						</button>
					))}
				{!registering &&
					samlProviders.map((provider) => (
						<button
							key={"providerId" in provider ? provider.providerId : provider.domain}
							type="button"
							className="auth-provider"
							disabled={busy}
							onClick={() => void signInWithSaml(provider)}
						>
							Continue with {provider.label}
						</button>
					))}
				{!registering && (providers.length > 0 || samlEnabled) && emailEnabled && (
					<div className="auth-divider">or continue with email</div>
				)}
				{emailEnabled && (
					<form
						onSubmit={(event) => {
							event.preventDefault();
							void (registering ? register() : signIn(passwordEnabled ? "password" : "magic-link"));
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
						{registering && cloudSignupEnabled && (
							<>
								<label className="label" htmlFor="register-workspace-name">
									Team or organization name
								</label>
								<input
									id="register-workspace-name"
									className="input"
									required
									maxLength={200}
									value={workspaceName}
									onChange={(event) => setWorkspaceName(event.target.value)}
									autoComplete="organization"
								/>
							</>
						)}
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
									autoComplete={registering ? "new-password" : "current-password"}
									maxLength={128}
								/>
								{registering && (
									<>
										<label className="label" htmlFor="register-confirm-password">
											Confirm password
										</label>
										<input
											id="register-confirm-password"
											className="input"
											type="password"
											required
											value={confirmPassword}
											onChange={(event) => setConfirmPassword(event.target.value)}
											autoComplete="new-password"
											maxLength={128}
										/>
									</>
								)}
							</>
						)}
						{captchaConfigured && (
							<Turnstile
								key={captchaGeneration}
								onVerify={handleVerify}
								onError={handleExpire}
								onExpire={handleExpire}
							/>
						)}
						<button
							type="submit"
							className="button auth-submit"
							disabled={
								busy ||
								!email.trim() ||
								!captchaReady ||
								(passwordEnabled && !password) ||
								(registering && !workspaceName.trim()) ||
								(registering && !confirmPassword)
							}
						>
							{busy
								? "Please wait…"
								: registering
									? "Create account"
									: passwordEnabled
										? "Sign in"
										: "Send magic link"}
						</button>
						{!registering && passwordEnabled && magicEnabled && (
							<button
								className="button button-secondary"
								type="button"
								disabled={busy || !email.trim() || !captchaReady}
								onClick={() => void signIn("magic-link")}
							>
								Email a sign-in link
							</button>
						)}
						{!registering && passwordEnabled && (
							<div className="auth-footer">
								<Link to="/auth/recover">Forgot password or lost your second factor?</Link>
							</div>
						)}
						{cloudSignupEnabled && (
							<div className="auth-footer">
								<button
									className="button button-secondary"
									type="button"
									disabled={busy}
									onClick={() => {
										setRegistering(!registering);
										setPassword("");
										setConfirmPassword("");
										setStatus(null);
										setSent(false);
									}}
								>
									{registering
										? "Already have an account? Sign in"
										: "New to AIDR? Create an account"}
								</button>
							</div>
						)}
					</form>
				)}
				{methods.length === 0 && !samlEnabled && (
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
					{cloudSignupEnabled
						? "Confirm your email before setting up a workspace."
						: "Use the account provided by your administrator."}
				</div>
			</div>
		</div>
	);
}
