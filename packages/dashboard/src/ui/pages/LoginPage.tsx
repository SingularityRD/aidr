import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Turnstile } from "../../components/Turnstile";
import { supabase } from "../../lib/supabase";
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
		<div
			style={{
				minHeight: "100vh",
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				padding: "24px",
				background: "linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%)",
			}}
		>
			<div
				style={{
					width: "100%",
					maxWidth: "440px",
					background: "var(--bg-primary)",
					borderRadius: "16px",
					padding: "48px",
					boxShadow: "0 4px 24px rgba(0,0,0,0.08)",
					border: "1px solid var(--border-color)",
				}}
			>
				{/* Brand / Logo */}
				<div style={{ textAlign: "center", marginBottom: "32px" }}>
					<div
						style={{
							width: "64px",
							height: "64px",
							margin: "0 auto 16px",
							background: "linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)",
							borderRadius: "16px",
							display: "flex",
							alignItems: "center",
							justifyContent: "center",
							fontSize: "32px",
						}}
					>
						🛡️
					</div>
					<h1
						style={{
							fontSize: "28px",
							fontWeight: 700,
							color: "var(--text-primary)",
							marginBottom: "8px",
						}}
					>
						Welcome to AIDR
					</h1>
					<p style={{ color: "var(--text-secondary)", fontSize: "15px" }}>
						Sign in to protect your AI agents
					</p>
				</div>

				{/* Google Sign In */}
				<button
					type="button"
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
									setStatus("Google OAuth is not enabled in Supabase. Please enable it in Supabase Dashboard → Authentication → Providers → Google.");
								} else {
									setStatus(error.message);
								}
							}
						} finally {
							setBusy(false);
						}
					}}
					style={{
						width: "100%",
						padding: "14px 24px",
						background: "#ffffff",
						border: "1px solid #e5e7eb",
						borderRadius: "10px",
						fontSize: "15px",
						fontWeight: 500,
						color: "#374151",
						cursor: busy ? "not-allowed" : "pointer",
						opacity: busy ? 0.7 : 1,
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						gap: "12px",
						transition: "all 0.2s ease",
					}}
					onMouseEnter={(e) => {
						if (!busy) {
							e.currentTarget.style.borderColor = "#d1d5db";
							e.currentTarget.style.boxShadow = "0 2px 8px rgba(0,0,0,0.08)";
						}
					}}
					onMouseLeave={(e) => {
						e.currentTarget.style.borderColor = "#e5e7eb";
						e.currentTarget.style.boxShadow = "none";
					}}
				>
					<svg width="20" height="20" viewBox="0 0 24 24">
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
									setStatus("GitHub OAuth is not enabled in Supabase. Please enable it in Supabase Dashboard → Authentication → Providers → GitHub.");
								} else {
									setStatus(error.message);
								}
							}
						} finally {
							setBusy(false);
						}
					}}
					style={{
						width: "100%",
						padding: "14px 24px",
						background: "#24292e",
						border: "1px solid #24292e",
						borderRadius: "10px",
						fontSize: "15px",
						fontWeight: 500,
						color: "#ffffff",
						cursor: busy ? "not-allowed" : "pointer",
						opacity: busy ? 0.7 : 1,
						display: "flex",
						alignItems: "center",
						justifyContent: "center",
						gap: "12px",
						marginTop: "10px",
						transition: "all 0.2s ease",
					}}
					onMouseEnter={(e) => {
						if (!busy) {
							e.currentTarget.style.background = "#1b1f23";
							e.currentTarget.style.transform = "translateY(-1px)";
						}
					}}
					onMouseLeave={(e) => {
						e.currentTarget.style.background = "#24292e";
						e.currentTarget.style.transform = "none";
					}}
				>
					<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
						<path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
					</svg>
					Continue with GitHub
				</button>

				{/* Divider */}
				<div
					style={{
						display: "flex",
						alignItems: "center",
						margin: "24px 0",
						color: "var(--text-muted)",
						fontSize: "13px",
					}}
				>
					<div
						style={{
							flex: 1,
							height: "1px",
							background: "var(--border-color)",
						}}
					/>
					<span style={{ padding: "0 16px" }}>or continue with email</span>
					<div
						style={{
							flex: 1,
							height: "1px",
							background: "var(--border-color)",
						}}
					/>
				</div>

				{/* Email Input */}
				<div style={{ marginBottom: "16px" }}>
					<label
						style={{
							display: "block",
							fontSize: "14px",
							fontWeight: 500,
							color: "var(--text-primary)",
							marginBottom: "8px",
						}}
					>
						Email address
					</label>
					<input
						type="email"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						placeholder="you@company.com"
						autoComplete="email"
						style={{
							width: "100%",
							padding: "12px 16px",
							fontSize: "15px",
							border: "1px solid var(--border-color)",
							borderRadius: "10px",
							background: "var(--bg-secondary)",
							color: "var(--text-primary)",
							outline: "none",
							transition: "border-color 0.2s ease",
						}}
						onFocus={(e) => {
							e.currentTarget.style.borderColor = "#4f46e5";
						}}
						onBlur={(e) => {
							e.currentTarget.style.borderColor = "var(--border-color)";
						}}
					/>
				</div>

				{/* CAPTCHA Verification */}
				<Turnstile
					onVerify={(token) => {
						setCaptchaToken(token);
						setCaptchaVerified(true);
					}}
					onError={() => {
						setCaptchaVerified(false);
						setCaptchaToken(null);
					}}
					onExpire={() => {
						setCaptchaVerified(false);
						setCaptchaToken(null);
					}}
				/>

				{/* Magic Link Button */}
				<button
					type="button"
					disabled={busy || !trimmedEmail || !captchaVerified}
					onClick={async () => {
						setBusy(true);
						setStatus(null);
						try {
							if (returnTo) setPostAuthReturnTo(returnTo);
							const { error } = await supabase.auth.signInWithOtp({
								email: trimmedEmail,
								options: { 
									emailRedirectTo: redirectTo,
									captchaToken: captchaToken || undefined,
								},
							});
							if (error) {
								setStatus(error.message);
							} else {
								setStatus("Magic link sent! Check your inbox.");
							}
						} finally {
							setBusy(false);
						}
					}}
					style={{
						width: "100%",
						padding: "14px 24px",
						background: "linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)",
						border: "none",
						borderRadius: "10px",
						fontSize: "15px",
						fontWeight: 600,
						color: "#ffffff",
						cursor: busy || !trimmedEmail || !captchaVerified ? "not-allowed" : "pointer",
						opacity: busy || !trimmedEmail || !captchaVerified ? 0.6 : 1,
						transition: "all 0.2s ease",
					}}
					onMouseEnter={(e) => {
						if (!busy && trimmedEmail) {
							e.currentTarget.style.transform = "translateY(-1px)";
							e.currentTarget.style.boxShadow = "0 4px 12px rgba(79, 70, 229, 0.4)";
						}
					}}
					onMouseLeave={(e) => {
						e.currentTarget.style.transform = "none";
						e.currentTarget.style.boxShadow = "none";
					}}
				>
					{busy ? "Sending..." : "Send magic link"}
				</button>

				{/* Status Message */}
				{status && (
					<div
						style={{
							marginTop: "16px",
							padding: "12px 16px",
							background: status.includes("sent")
								? "rgba(34, 197, 94, 0.1)"
								: "rgba(239, 68, 68, 0.1)",
							border: `1px solid ${status.includes("sent") ? "rgba(34, 197, 94, 0.2)" : "rgba(239, 68, 68, 0.2)"}`,
							borderRadius: "8px",
							fontSize: "14px",
							color: status.includes("sent") ? "#16a34a" : "#dc2626",
							textAlign: "center",
						}}
					>
						{status}
					</div>
				)}

				{/* Back to Home */}
				<div
					style={{
						marginTop: "24px",
						textAlign: "center",
					}}
				>
					<Link
						to="/"
						style={{
							fontSize: "14px",
							color: "var(--text-secondary)",
							textDecoration: "none",
							transition: "color 0.2s ease",
						}}
						onMouseEnter={(e) => {
							e.currentTarget.style.color = "var(--text-primary)";
						}}
						onMouseLeave={(e) => {
							e.currentTarget.style.color = "var(--text-secondary)";
						}}
					>
						← Back to home
					</Link>
				</div>

				{/* Security Note */}
				<div
					style={{
						marginTop: "32px",
						paddingTop: "24px",
						borderTop: "1px solid var(--border-color)",
						textAlign: "center",
						fontSize: "13px",
						color: "var(--text-muted)",
					}}
				>
					🔒 Secure authentication powered by Supabase
				</div>
			</div>
		</div>
	);
}
