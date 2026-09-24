import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";

type Mode = "email" | "break-glass";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN_HASH_RE = /^[0-9a-f]{64}$/i;
const RECOVERY_VERIFIER_RE = /^[A-Za-z0-9_-]{43}$/;
const RECOVERY_TRANSACTION_TTL_MS = 10 * 60_000;
const RECOVERY_HANDOFF_TTL_MS = 2 * 60_000;
export const RECOVERY_TRANSACTION_STORAGE_KEY = "aidr.dashboard.recovery.transaction.v1";
export const RECOVERY_HANDOFF_STORAGE_KEY = "aidr.dashboard.recovery.handoff.v1";

type RecoveryTransaction = { email: string; verifier: string; expiresAt: number };
type RecoveryHandoff = RecoveryTransaction & { proofId: string; issuedAt: number };

function removeSessionRecoveryTransaction() {
	window.sessionStorage.removeItem(RECOVERY_TRANSACTION_STORAGE_KEY);
}

function purgeRecoveryTransaction() {
	removeSessionRecoveryTransaction();
	window.localStorage.removeItem(RECOVERY_HANDOFF_STORAGE_KEY);
}

function persistRecoveryTransaction(email: string, verifier: string): RecoveryTransaction {
	const transaction: RecoveryTransaction = {
		email,
		verifier,
		expiresAt: Date.now() + RECOVERY_TRANSACTION_TTL_MS,
	};
	window.sessionStorage.setItem(RECOVERY_TRANSACTION_STORAGE_KEY, JSON.stringify(transaction));
	return transaction;
}

function publishRecoveryHandoff(transaction: RecoveryTransaction) {
	const issuedAt = Date.now();
	const handoff: RecoveryHandoff = {
		...transaction,
		proofId: crypto.randomUUID(),
		issuedAt,
		expiresAt: Math.min(transaction.expiresAt, issuedAt + RECOVERY_HANDOFF_TTL_MS),
	};
	const serialized = JSON.stringify(handoff);
	window.localStorage.setItem(RECOVERY_HANDOFF_STORAGE_KEY, serialized);
	window.setTimeout(() => {
		if (window.localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY) === serialized) {
			window.localStorage.removeItem(RECOVERY_HANDOFF_STORAGE_KEY);
		}
	}, RECOVERY_HANDOFF_TTL_MS);
}

export function loadRecoveryTransaction(now = Date.now()): RecoveryTransaction | null {
	try {
		const value = JSON.parse(
			window.sessionStorage.getItem(RECOVERY_TRANSACTION_STORAGE_KEY) ?? "null",
		) as Partial<RecoveryTransaction> | null;
		if (
			!value ||
			typeof value.email !== "string" ||
			!value.email.trim() ||
			value.email.length > 254 ||
			typeof value.verifier !== "string" ||
			!RECOVERY_VERIFIER_RE.test(value.verifier) ||
			typeof value.expiresAt !== "number" ||
			!Number.isFinite(value.expiresAt) ||
			value.expiresAt <= now ||
			value.expiresAt > now + RECOVERY_TRANSACTION_TTL_MS
		) {
			removeSessionRecoveryTransaction();
			return null;
		}
		return { email: value.email, verifier: value.verifier, expiresAt: value.expiresAt };
	} catch {
		removeSessionRecoveryTransaction();
		return null;
	}
}

export function claimRecoveryHandoff(now = Date.now()): RecoveryTransaction | null {
	const serialized = window.localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY);
	window.localStorage.removeItem(RECOVERY_HANDOFF_STORAGE_KEY);
	try {
		const value = JSON.parse(serialized ?? "null") as Partial<RecoveryHandoff> | null;
		if (
			!value ||
			typeof value.proofId !== "string" ||
			!UUID_RE.test(value.proofId) ||
			typeof value.issuedAt !== "number" ||
			!Number.isFinite(value.issuedAt) ||
			value.issuedAt > now + 5_000 ||
			value.issuedAt < now - RECOVERY_HANDOFF_TTL_MS ||
			typeof value.expiresAt !== "number" ||
			!Number.isFinite(value.expiresAt) ||
			value.expiresAt <= now ||
			value.expiresAt > value.issuedAt + RECOVERY_HANDOFF_TTL_MS ||
			typeof value.email !== "string" ||
			!value.email.trim() ||
			value.email.length > 254 ||
			typeof value.verifier !== "string" ||
			!RECOVERY_VERIFIER_RE.test(value.verifier)
		)
			return null;
		const transaction = {
			email: value.email,
			verifier: value.verifier,
			expiresAt: value.expiresAt,
		};
		window.sessionStorage.setItem(RECOVERY_TRANSACTION_STORAGE_KEY, JSON.stringify(transaction));
		return transaction;
	} catch {
		return null;
	}
}

export function normalizeRecoveryTokenHash(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const tokenHash = value.trim().toLowerCase();
	return TOKEN_HASH_RE.test(tokenHash) ? tokenHash : null;
}

async function createRecoveryProof(): Promise<{
	verifier: string;
	challenge: string;
}> {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	const verifier = btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
	return { verifier, challenge: await recoveryChallengeForVerifier(verifier) };
}

async function recoveryChallengeForVerifier(verifier: string): Promise<string> {
	const digest = new Uint8Array(
		await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
	);
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function terminalRecoveryError(message: string) {
	return Object.assign(new Error(message), { status: 401 });
}

function isTerminalRecoveryError(error: unknown): boolean {
	if (!error || typeof error !== "object") return false;
	const value = error as { status?: unknown; context?: { status?: unknown } };
	const status = typeof value.status === "number" ? value.status : value.context?.status;
	return typeof status === "number" && status >= 400 && status < 500;
}

function normalizeGrantId(value: unknown): string | null {
	return typeof value === "string" && UUID_RE.test(value) ? value.toLowerCase() : null;
}

export function isRecoveryOtpSession(value: unknown): boolean {
	const accessToken =
		value && typeof value === "object" && "access_token" in value
			? (value as { access_token?: unknown }).access_token
			: null;
	if (typeof accessToken !== "string") return false;
	const encoded = accessToken.split(".")[1];
	if (!encoded) return false;
	try {
		const payload = JSON.parse(
			atob(
				encoded
					.replace(/-/g, "+")
					.replace(/_/g, "/")
					.padEnd(Math.ceil(encoded.length / 4) * 4, "="),
			),
		) as { amr?: unknown; session_id?: unknown };
		return (
			normalizeGrantId(payload.session_id) !== null &&
			Array.isArray(payload.amr) &&
			payload.amr.some((entry) => {
				if (entry === "otp") return true;
				return Boolean(
					entry &&
						typeof entry === "object" &&
						!Array.isArray(entry) &&
						(entry as { method?: unknown }).method === "otp",
				);
			})
		);
	} catch {
		return false;
	}
}

export function RecoveryPage() {
	const navigate = useNavigate();
	const [mode, setMode] = useState<Mode>("email");
	const [hasSession, setHasSession] = useState(false);
	const [email, setEmail] = useState("");
	const [emailCode, setEmailCode] = useState("");
	const [emailRequested, setEmailRequested] = useState(false);
	const [recoveryCode, setRecoveryCode] = useState("");
	const [newPassword, setNewPassword] = useState("");
	const [confirmPassword, setConfirmPassword] = useState("");
	const [status, setStatus] = useState<string | null>(null);
	const [success, setSuccess] = useState(false);
	const [busy, setBusy] = useState(false);
	const [recoveryVerifier, setRecoveryVerifier] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		const incoming = new URL(window.location.href);
		if (
			incoming.searchParams.has("token_hash") ||
			incoming.searchParams.has("type") ||
			incoming.hash
		) {
			const clean = new URL(window.location.href);
			clean.searchParams.delete("token_hash");
			clean.searchParams.delete("type");
			clean.searchParams.delete("grant");
			clean.hash = "";
			window.history.replaceState(window.history.state, "", clean.toString());
			purgeRecoveryTransaction();
			void clearLocalRecoverySession();
			setStatus("Enter the one-time code from your recovery email to continue.");
			return;
		}

		const transaction = loadRecoveryTransaction() ?? claimRecoveryHandoff();
		if (!transaction) return;
		setEmail(transaction.email);
		setRecoveryVerifier(transaction.verifier);
		setEmailRequested(true);
		setStatus("Enter the one-time code from your recovery email to continue.");
		void (async () => {
			const current = await supabase.auth.getSession();
			if (cancelled || current.error || !current.data.session) return;
			if (!isRecoveryOtpSession(current.data.session)) {
				await clearLocalRecoverySession();
				return;
			}
			try {
				await bindRecoveryGrant(current.data.session, transaction.verifier);
				if (!cancelled) {
					setHasSession(true);
					setStatus(null);
				}
			} catch (error) {
				if (isTerminalRecoveryError(error)) {
					purgeRecoveryTransaction();
					await clearLocalRecoverySession();
				}
				if (!cancelled) {
					if (isTerminalRecoveryError(error)) {
						setRecoveryVerifier(null);
						setEmailRequested(false);
						setStatus("This recovery session is invalid or expired. Request a new recovery link.");
					} else {
						setStatus("Recovery is temporarily unavailable. Reload this tab to retry safely.");
					}
				}
			}
		})();
		return () => {
			cancelled = true;
		};
	}, []);

	async function invoke(body: Record<string, unknown>, accessToken?: string) {
		const result = await supabase.functions.invoke("identity-security", {
			body,
			...(accessToken ? { headers: { Authorization: `Bearer ${accessToken}` } } : {}),
		});
		if (result.error) throw result.error;
		if (result.data?.ok !== true)
			throw terminalRecoveryError("Identity operation was not confirmed.");
		return result.data as Record<string, unknown> | null;
	}

	async function bindRecoveryGrant(session: unknown, verifier: string) {
		if (!isRecoveryOtpSession(session)) throw terminalRecoveryError("invalid_recovery_session");
		const accessToken = (session as { access_token: string }).access_token;
		await invoke(
			{ action: "bind_password_recovery_grant", recovery_verifier: verifier },
			accessToken,
		);
	}

	async function clearLocalRecoverySession() {
		try {
			await supabase.auth.signOut({ scope: "local" });
		} catch {
			// The server-side one-time grant still prevents password recovery.
		}
	}

	async function requestReset() {
		if (busy || !email.trim()) return;
		setBusy(true);
		setSuccess(false);
		setStatus(null);
		try {
			const proof = recoveryVerifier
				? {
						verifier: recoveryVerifier,
						challenge: await recoveryChallengeForVerifier(recoveryVerifier),
					}
				: await createRecoveryProof();
			const transaction = persistRecoveryTransaction(email.trim(), proof.verifier);
			publishRecoveryHandoff(transaction);
			setRecoveryVerifier(proof.verifier);
			await invoke({
				action: "request_password_reset",
				email: email.trim(),
				recovery_challenge: proof.challenge,
			});
			setEmailCode("");
			setRecoveryVerifier(proof.verifier);
			setEmailRequested(true);
			setSuccess(true);
			setStatus(
				"If this account is enabled, the configured authentication provider will send a one-time recovery code. Keep this browser tab open; it can be reloaded for 10 minutes.",
			);
		} catch (error) {
			if (isTerminalRecoveryError(error)) {
				purgeRecoveryTransaction();
				setRecoveryVerifier(null);
			}
			setStatus("Password recovery is temporarily unavailable. Contact your administrator.");
		} finally {
			setBusy(false);
		}
	}

	async function verifyEmailCode() {
		const token = emailCode.trim();
		if (busy || !email.trim() || !token || token.length > 128 || !recoveryVerifier) return;
		setBusy(true);
		setSuccess(false);
		setStatus(null);
		let session: unknown;
		try {
			const result = await supabase.auth.verifyOtp({
				email: email.trim(),
				token,
				type: "recovery",
			});
			if (result.error || !result.data.session) throw new Error("invalid_code");
			session = result.data.session;
		} catch {
			await clearLocalRecoverySession();
			setEmailCode("");
			setStatus("The recovery code is invalid or expired.");
			setBusy(false);
			return;
		}
		try {
			await bindRecoveryGrant(session, recoveryVerifier);
			setEmailCode("");
			setHasSession(true);
		} catch (error) {
			if (isTerminalRecoveryError(error)) {
				purgeRecoveryTransaction();
				setRecoveryVerifier(null);
				setEmailRequested(false);
				await clearLocalRecoverySession();
				setStatus("The recovery session is invalid or expired.");
			} else {
				setStatus("Recovery is temporarily unavailable. Reload this tab to retry safely.");
			}
		} finally {
			setBusy(false);
		}
	}

	async function useBreakGlass() {
		if (busy || !email.trim() || !recoveryCode.trim()) return;
		setBusy(true);
		setSuccess(false);
		setStatus(null);
		try {
			const proof = recoveryVerifier
				? {
						verifier: recoveryVerifier,
						challenge: await recoveryChallengeForVerifier(recoveryVerifier),
					}
				: await createRecoveryProof();
			const transaction = persistRecoveryTransaction(email.trim(), proof.verifier);
			publishRecoveryHandoff(transaction);
			setRecoveryVerifier(proof.verifier);
			const data = await invoke({
				action: "break_glass_recover",
				email: email.trim(),
				recovery_code: recoveryCode.trim(),
				recovery_challenge: proof.challenge,
			});
			const tokenHash = normalizeRecoveryTokenHash(data?.recovery_token_hash);
			if (!tokenHash || data?.recovery_type !== "recovery") {
				throw terminalRecoveryError("invalid_recovery_token");
			}
			const result = await supabase.auth.verifyOtp({ token_hash: tokenHash, type: "recovery" });
			if (result.error) throw result.error;
			if (!result.data.session) throw terminalRecoveryError("invalid_recovery_token");
			await bindRecoveryGrant(result.data.session, proof.verifier);
			setRecoveryCode("");
			setRecoveryVerifier(proof.verifier);
			setHasSession(true);
		} catch (error) {
			if (isTerminalRecoveryError(error)) {
				await clearLocalRecoverySession();
				purgeRecoveryTransaction();
				setRecoveryCode("");
				setRecoveryVerifier(null);
				setStatus("The recovery code is invalid or expired.");
			} else {
				setStatus("Recovery is temporarily unavailable. Retry to resume safely.");
			}
		} finally {
			setBusy(false);
		}
	}

	async function completeRecovery() {
		if (busy || !recoveryVerifier || !newPassword || newPassword !== confirmPassword) {
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
				recovery_verifier: recoveryVerifier,
			});
			await clearLocalRecoverySession();
			purgeRecoveryTransaction();
			setRecoveryVerifier(null);
			setNewPassword("");
			setConfirmPassword("");
			setSuccess(true);
			setStatus("Password updated and sessions revoked. Sign in again with the new password.");
			window.setTimeout(() => navigate("/login", { replace: true }), 800);
		} catch (error) {
			if (isTerminalRecoveryError(error)) {
				await clearLocalRecoverySession();
				purgeRecoveryTransaction();
				setRecoveryVerifier(null);
				setNewPassword("");
				setConfirmPassword("");
				setStatus("This recovery session is invalid or expired. Request a new recovery link.");
			} else {
				setStatus("Recovery is temporarily unavailable. Retry to resume safely.");
			}
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
									setEmailRequested(false);
									purgeRecoveryTransaction();
									setRecoveryVerifier(null);
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
									setEmailRequested(false);
									purgeRecoveryTransaction();
									setRecoveryVerifier(null);
									setStatus(null);
								}}
							>
								Break-glass code
							</button>
						</div>
						<form
							onSubmit={(event) => {
								event.preventDefault();
								void (mode === "email"
									? emailRequested
										? verifyEmailCode()
										: requestReset()
									: useBreakGlass());
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
										maxLength={64}
										onChange={(event) => setRecoveryCode(event.target.value)}
									/>
								</>
							) : emailRequested ? (
								<>
									<label className="label" htmlFor="email-recovery-code">
										One-time recovery code
									</label>
									<input
										id="email-recovery-code"
										className="input mono"
										type="password"
										required
										maxLength={128}
										autoComplete="one-time-code"
										value={emailCode}
										onChange={(event) => setEmailCode(event.target.value)}
									/>
								</>
							) : null}
							<button
								className="button auth-submit"
								type="submit"
								disabled={
									busy ||
									!email.trim() ||
									(mode === "break-glass" && !recoveryCode.trim()) ||
									(mode === "email" && emailRequested && !emailCode.trim())
								}
							>
								{busy
									? "Please wait…"
									: mode === "email"
										? emailRequested
											? "Verify recovery code"
											: "Request recovery"
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
