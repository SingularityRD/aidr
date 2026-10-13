import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { redirectToIdp, startOidcFlow } from "../../auth/oidc-sso";
import { Turnstile } from "../../components/Turnstile";
import { LanguageToggle, useT } from "../../i18n/I18nProvider";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";
import { sanitizeReturnTo, setPostAuthReturnTo } from "../return-to";
import { getSession } from "../session";

type SamlLoginProvider = { providerId: string; label: string } | { domain: string; label: string };

export function LoginPage() {
	const navigate = useNavigate();
	const t = useT();
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
	const samlProviders: SamlLoginProvider[] =
		window.__AIDR_CONFIG__?.samlProviders ??
		(samlProviderId
			? [{ providerId: samlProviderId, label: t("login.companySso") }]
			: samlDomain
				? [{ domain: samlDomain, label: t("login.companySso") }]
				: []);
	const samlEnabled = samlProviders.length > 0;
	const oidcEnabled = window.__AIDR_CONFIG__?.oidcSso === true;
	const [ssoEmail, setSsoEmail] = useState("");
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
				if (!cancelled) setStatus(t("login.sessionCheckFailed"));
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
					setStatus(t("login.passwordFailed"));
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
					setStatus(error.status === 429 ? t("login.emailLimited") : t("login.linkFailed"));
					return;
				}
				setSent(true);
				setStatus(t("login.linkSent"));
			}
		} catch {
			setStatus(t("login.unavailable"));
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
			setStatus(t("login.teamNameInvalid"));
			return;
		}
		if (password !== confirmPassword) {
			setStatus(t("login.passwordMismatch"));
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
				setStatus(error?.status === 429 ? t("login.emailLimited") : t("login.registerFailed"));
				return;
			}
			if (data.session) {
				await supabase.auth.signOut({ scope: "local" });
				setStatus(t("login.confirmationDisabled"));
				return;
			}
			setSent(true);
			setStatus(t("login.registerSent"));
		} catch {
			setStatus(t("login.registerUnavailable"));
		} finally {
			setPassword("");
			setConfirmPassword("");
			resetCaptcha();
			setBusy(false);
		}
	}

	async function signInWithOidc() {
		if (!ssoEmail.trim()) return;
		setBusy(true);
		setStatus(null);
		try {
			const started = await startOidcFlow({ email: ssoEmail, returnTo, t });
			if (!started.ok) {
				setStatus(started.message);
				return;
			}
			setPostAuthReturnTo(returnTo);
			redirectToIdp(started.url);
		} catch {
			setStatus(t("login.companyUnavailable"));
		} finally {
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
				(target?.protocol === "http:" &&
					["localhost", "127.0.0.1", "[::1]"].includes(target.hostname));
			if (error || !target || !safeProtocol || target.username || target.password) {
				setStatus(t("login.companyUnavailable"));
				return;
			}
			window.location.assign(target.href);
		} catch {
			setStatus(t("login.companyUnavailable"));
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
						<h1 className="auth-title">{t("login.welcome")}</h1>
						<p className="auth-subtitle">
							{registering ? t("login.subtitleRegister") : t("login.subtitleSignIn")}
						</p>
					</div>
				</div>
				{signOutStatus === "revocation-unconfirmed" ? (
					<p role="alert">{t("login.revocationUnconfirmed")}</p>
				) : signOutStatus === "local-failed" ? (
					<p role="alert">{t("login.localSignOutFailed")}</p>
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
									if (error) setStatus(t("login.providerUnavailable"));
								} catch {
									setStatus(t("login.unavailable"));
								} finally {
									setBusy(false);
								}
							}}
						>
							{t("login.continueWith", {
								provider:
									provider === "google"
										? "Google"
										: provider === "github"
											? "GitHub"
											: "Microsoft Entra ID",
							})}
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
							{t("login.continueWith", { provider: provider.label })}
						</button>
					))}
				{!registering && oidcEnabled && (
					<form
						aria-label={t("login.ssoFormLabel")}
						onSubmit={(event) => {
							event.preventDefault();
							void signInWithOidc();
						}}
					>
						<label className="label" htmlFor="sso-email">
							{t("login.ssoEmailLabel")}
						</label>
						<input
							id="sso-email"
							type="email"
							autoComplete="username"
							value={ssoEmail}
							onChange={(event) => setSsoEmail(event.target.value)}
						/>
						<button type="submit" className="auth-provider" disabled={busy || !ssoEmail.trim()}>
							{t("login.ssoContinue")}
						</button>
					</form>
				)}
				{!registering && (providers.length > 0 || samlEnabled || oidcEnabled) && emailEnabled && (
					<div className="auth-divider">{t("login.orEmail")}</div>
				)}
				{emailEnabled && (
					<form
						onSubmit={(event) => {
							event.preventDefault();
							void (registering ? register() : signIn(passwordEnabled ? "password" : "magic-link"));
						}}
					>
						<label className="label" htmlFor="login-email">
							{t("login.email")}
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
									{t("login.teamName")}
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
									{t("login.password")}
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
											{t("login.confirmPassword")}
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
								? t("login.wait")
								: registering
									? t("login.createAccount")
									: passwordEnabled
										? t("login.signIn")
										: t("login.sendMagicLink")}
						</button>
						{!registering && passwordEnabled && magicEnabled && (
							<button
								className="button button-secondary"
								type="button"
								disabled={busy || !email.trim() || !captchaReady}
								onClick={() => void signIn("magic-link")}
							>
								{t("login.emailLink")}
							</button>
						)}
						{!registering && passwordEnabled && (
							<div className="auth-footer">
								<Link to="/auth/recover">{t("login.forgot")}</Link>
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
									{registering ? t("login.haveAccount") : t("login.newAccount")}
								</button>
							</div>
						)}
					</form>
				)}
				{methods.length === 0 && !samlEnabled && !oidcEnabled && (
					<p role="alert">{t("login.notConfigured")}</p>
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
					<Link to="/">{t("login.backHome")}</Link>
					<LanguageToggle />
				</div>
				<div className="auth-note">
					<ShieldIcon size={13} />
					{cloudSignupEnabled ? t("login.noteConfirm") : t("login.noteAdmin")}
				</div>
			</div>
		</div>
	);
}
