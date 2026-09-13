import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { useTeam } from "../../enterprise/team-provider";

type Runtime = "claude-code" | "cursor" | "vscode" | "openclaw" | "opencode";

type DeviceStartResult = {
	verification_url: string;
	user_code: string;
	device_code: string;
	expires_at: string;
	interval_seconds?: number;
};

type DevicePollResult =
	| { status: "authorization_pending" }
	| {
			status: "authorized";
			enrollment_token?: string | null;
			enrollment_token_expires_at?: string | null;
	  }
	| { status: "expired" };

function maskSecret(secret: string): string {
	if (secret.length <= 4) return "•".repeat(secret.length);
	return `${"•".repeat(Math.max(8, secret.length - 4))}${secret.slice(-4)}`;
}

/**
 * Device authorization URLs come from an edge function. Treat them as
 * untrusted input and keep malformed or dangerous values on the local verify
 * route instead of rendering a javascript/data/protocol-relative link.
 */
function safeVerificationUrl(raw: string, userCode: string, teamId: string): string {
	const candidate = raw.trim();
	const fallback = `/verify?code=${encodeURIComponent(userCode)}&team=${encodeURIComponent(teamId)}`;
	if (!candidate || candidate.startsWith("//")) return fallback;
	try {
		const parsed = new URL(candidate, window.location.origin);
		if (
			!parsed.username &&
			!parsed.password &&
			(parsed.origin === window.location.origin || parsed.protocol === "https:")
		) {
			if (parsed.origin === window.location.origin && parsed.pathname === "/verify") {
				parsed.searchParams.set("code", userCode);
				parsed.searchParams.set("team", teamId);
			}
			return parsed.toString();
		}
	} catch {
		// Keep the local verify route as the only fallback for malformed input.
	}
	return fallback;
}

function promptForRuntime(runtime: Runtime): string {
	const common = [
		"You are installing Singularity AIDR (AI Agent Detection and Response).",
		"Goal: enable protection and then link this installation to my account via the device authorization flow.",
		"",
		"Rules:",
		"- Do not exfiltrate secrets.",
		"- Prefer the official install path for this runtime.",
		"- If you need authorization: show me the short code + verification URL and wait.",
		"",
	].join("\n");

	if (runtime === "claude-code") {
		return [
			common,
			"Runtime: Claude Code",
			"Install:",
			"- /plugin install aidr@aidr",
			"After install, start a session so AIDR can request authorization.",
		].join("\n");
	}

	if (runtime === "openclaw") {
		return [
			common,
			"Runtime: OpenClaw",
			"Install:",
			"- openclaw plugins install @singularityrd/aidr-openclaw",
		].join("\n");
	}

	if (runtime === "opencode") {
		return [
			common,
			"Runtime: OpenCode",
			"Install:",
			"- Link the plugin directory in OpenCode config.",
		].join("\n");
	}

	if (runtime === "cursor") {
		return [
			common,
			"Runtime: Cursor",
			"Install:",
			"- Install the Singularity AIDR extension (VSIX) for Cursor, then run “Enable protection”.",
		].join("\n");
	}

	return [
		common,
		"Runtime: VS Code",
		"Install:",
		"- Install the Singularity AIDR extension (VSIX) for VS Code, then run “Enable protection”.",
	].join("\n");
}

export function OnboardingPage() {
	const { currentTeam, currentRole, isLoading, roleResolved, error: teamError } = useTeam();
	if (isLoading || (currentTeam && !roleResolved)) {
		return <div className="card" role="status">Checking team access…</div>;
	}
	if (!currentTeam || !currentRole) {
		return <div className="card" role="alert">{teamError ?? "Select a team to enroll an agent."}</div>;
	}
	return <TeamOnboarding key={currentTeam.id} teamId={currentTeam.id} teamName={currentTeam.name} canEnroll={["owner", "admin", "member"].includes(currentRole)} />;
}
function TeamOnboarding({ teamId, teamName, canEnroll }: { teamId: string; teamName: string; canEnroll: boolean }) {
	const [runtime, setRuntime] = useState<Runtime>("claude-code");
	const [pilotStatus, setPilotStatus] = useState<string>("loading");
	const [pilotReload, setPilotReload] = useState(0);
	const [device, setDevice] = useState<DeviceStartResult | null>(null);
	const [poll, setPoll] = useState<DevicePollResult | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [promptCopyStatus, setPromptCopyStatus] = useState<"idle" | "copied" | "error">("idle");
	const [showEnrollmentToken, setShowEnrollmentToken] = useState(false);
	const [copiedEnrollmentToken, setCopiedEnrollmentToken] = useState(false);

	const prompt = useMemo(() => promptForRuntime(runtime), [runtime]);
	const requestedInterval = device?.interval_seconds;
	const intervalSeconds = typeof requestedInterval === "number" && Number.isFinite(requestedInterval)
		? Math.max(2, Math.min(10, requestedInterval)) : 5;

	useEffect(() => {
		let cancelled = false;
		async function load() {
			try {
				const res = await supabase.functions.invoke("pilot-status", { method: "GET", headers: { "X-AIDR-Tenant-ID": teamId } });
				if (cancelled) return;
				if (res.error || res.data?.ok !== true) {
					setPilotStatus("unknown");
					return;
				}
				const data = (res.data ?? {}) as Record<string, unknown>;
				setPilotStatus(typeof data.status === "string" ? String(data.status) : "unknown");
			} catch {
				if (!cancelled) setPilotStatus("unknown");
			}
		}
		load();
		return () => {
			cancelled = true;
		};
	}, [teamId, pilotReload]);

	useEffect(() => {
		let cancelled = false;
		let timer: number | null = null;
		let nextDelayMs = intervalSeconds * 1000;

		async function tick() {
			if (!device || cancelled) return;
			const expiresAtMs = Date.parse(device.expires_at);
			if (!Number.isFinite(expiresAtMs) || Date.now() >= expiresAtMs) {
				setDevice(null);
				setPoll({ status: "expired" });
				setError("This authorization code expired. Generate a new code to continue.");
				return;
			}

			let shouldRetry = true;
			try {
				const res = await supabase.functions.invoke("device-poll", {
					method: "POST",
					body: { device_code: device.device_code },
				});
				if (cancelled) return;
				if (res.error || res.data?.ok !== true) {
					setPoll(null);
					const status = (res.error as { context?: { status?: number } } | null)?.context?.status;
					if (status === 401 || status === 403 || status === 409) {
						setDevice(null);
						setError("Authorization could not continue. This code was rejected or already used. Generate a new code.");
						shouldRetry = false;
					} else {
						setError("We could not check authorization yet. Retrying automatically.");
						nextDelayMs = Math.min(Math.max(nextDelayMs * 2, intervalSeconds * 1000), 30_000);
					}
				} else {
					const data = (res.data ?? {}) as Record<string, unknown>;
					const status = String(data.status ?? "unknown");
					// Back-compat: server may return "approved" for the final state.
					if (status === "authorized" || status === "approved") {
						const enrollmentToken =
							typeof data.enrollment_token === "string" && data.enrollment_token.length > 0 ? data.enrollment_token : null;
						const enrollmentTokenExpiresAt =
							typeof data.expires_at === "string" ? data.expires_at : null;
						if (!enrollmentToken || !enrollmentTokenExpiresAt || !Number.isFinite(Date.parse(enrollmentTokenExpiresAt)) || Date.parse(enrollmentTokenExpiresAt) <= Date.now()) {
							setDevice(null);
							setPoll(null);
							setError("Authorization completed, but no usable enrollment token was returned. Generate a new code.");
						} else {
							setPoll({
								status: "authorized",
								enrollment_token: enrollmentToken,
								enrollment_token_expires_at: enrollmentTokenExpiresAt,
							});
							setError(null);
						}
						shouldRetry = false;
					} else if (status === "authorization_pending" || status === "pending") {
						setPoll({ status: "authorization_pending" });
						setError(null);
						nextDelayMs = intervalSeconds * 1000;
					} else if (status === "expired") {
						setPoll({ status: "expired" });
						setDevice(null);
						setError("This authorization code expired. Generate a new code to continue.");
						shouldRetry = false;
						} else {
						setDevice(null);
						setPoll(null);
						setError(
							"The authorization service returned an unknown state. Please generate a new code.",
						);
						shouldRetry = false;
					}
				}
			} catch {
				if (!cancelled) {
					setError("We could not check authorization yet. Retrying automatically.");
					nextDelayMs = Math.min(Math.max(nextDelayMs * 2, intervalSeconds * 1000), 30_000);
				}
			}

			if (!cancelled && shouldRetry) {
				const remainingMs = expiresAtMs - Date.now();
				if (remainingMs <= 0) {
					setPoll({ status: "expired" });
					setDevice(null);
					setError("This authorization code expired. Generate a new code to continue.");
					return;
				}
				timer = window.setTimeout(tick, Math.min(nextDelayMs, remainingMs));
			}
		}

		if (device) {
			timer = window.setTimeout(tick, 500);
		}

		return () => {
			cancelled = true;
			if (timer != null) window.clearTimeout(timer);
		};
	}, [device, intervalSeconds]);

	useEffect(() => {
		const token = poll?.status === "authorized" ? poll.enrollment_token : null;
		const expiresAt = poll?.status === "authorized" ? poll.enrollment_token_expires_at : null;
		if (!token || !expiresAt) return;
		const expiresAtMs = Date.parse(expiresAt);
		const clearToken = () => {
			setPoll({ status: "expired" });
			setDevice(null);
			setShowEnrollmentToken(false);
			setCopiedEnrollmentToken(false);
			setError("The enrollment token expired. Generate a new authorization code.");
		};
		if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
			clearToken();
			return;
		}
		const timer = window.setTimeout(clearToken, expiresAtMs - Date.now());
		return () => window.clearTimeout(timer);
	}, [
		poll?.status === "authorized" ? poll.enrollment_token : null,
		poll?.status === "authorized" ? poll.enrollment_token_expires_at : null,
	]);

	const canAuthorize = pilotStatus === "approved" && canEnroll;

	return (
		<div className="stack">
			<div className="card">
				<h1>Onboarding</h1>
				<p style={{ overflowWrap: "anywhere" }}>Team: {teamName}</p>
				{!canEnroll ? <div className="notice notice-warning" role="alert">Your role cannot enroll agents for this team.</div> : null}
				<p className="muted">
					Choose your runtime and copy the install prompt. When your agent shows a code, verify it for this team.
				</p>
				{pilotStatus !== "approved" ? (
					<div className="notice notice-warning">
						<div className="muted small">Pilot status</div>
						<div className="mono" style={{ marginTop: 4 }}>
							{pilotStatus}
						</div>
						{pilotStatus === "loading" ? <div role="status">Checking pilot access…</div> : null}
						{pilotStatus === "unknown" ? <div role="alert">Pilot access could not be checked. Retry before generating a code.</div> : null}
						{pilotStatus !== "loading" ? (
							<div className="row" style={{ marginTop: 10 }}>
								{pilotStatus === "unknown" ? <button className="button button-secondary button-sm" type="button" onClick={() => { setPilotStatus("loading"); setPilotReload((count) => count + 1); }}>Retry status</button> : null}
								<Link className="button button-secondary button-sm" to="/pilot">
									View / request pilot
								</Link>
							</div>
						) : null}
					</div>
				) : null}
			</div>

			<div className="cols">
				<div className="card">
					<h2>1) Choose runtime</h2>
					<div className="row" style={{ flexWrap: "wrap" }}>
						{(
							[
								["claude-code", "Claude Code"],
								["cursor", "Cursor"],
								["vscode", "VS Code"],
								["openclaw", "OpenClaw"],
								["opencode", "OpenCode"],
							] as Array<[Runtime, string]>
						).map(([id, label]) => (
							<button
								key={id}
								className={`button ${runtime === id ? "" : "button-secondary"}`}
								type="button"
								onClick={() => { setRuntime(id); setPromptCopyStatus("idle"); }}
								aria-pressed={runtime === id}
							>
								{label}
							</button>
						))}
					</div>

					<div className="notice" style={{ marginTop: 12 }}>
						<label className="muted small" htmlFor="onboarding-agent-prompt">Prompt to give your agent</label>
						<textarea
							id="onboarding-agent-prompt"
							className="input mono"
							style={{ minHeight: 220, resize: "vertical" }}
							readOnly
							value={prompt}
						/>
						<button className="button button-secondary button-sm" type="button" onClick={async () => {
							try { await navigator.clipboard.writeText(prompt); setPromptCopyStatus("copied"); }
							catch { setPromptCopyStatus("error"); }
						}}>{promptCopyStatus === "copied" ? "Prompt copied" : "Copy prompt"}</button>
						{promptCopyStatus === "error" ? <div role="alert">Clipboard access was blocked. Select the prompt above and copy it manually.</div> : null}
						<div className="muted small" style={{ marginTop: 10 }}>
							This prompt focuses the agent on install + authorization without asking you to
							manually copy API keys.
						</div>
					</div>
				</div>

				<div className="card">
					<h2>2) Authorize</h2>
					<p className="muted">
						Use the verify page for a code shown by your agent. Generate a code here only if you need a manual enrollment token.
					</p>

					<div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
						<button
							className="button"
							type="button"
							disabled={busy || !canAuthorize}
							onClick={async () => {
								setBusy(true);
								setError(null);
								setDevice(null);
								setPoll(null);
								setShowEnrollmentToken(false);
								setCopiedEnrollmentToken(false);
								try {
									const res = await supabase.functions.invoke("device-start", { method: "POST" });
									if (res.error || res.data?.ok !== true) {
										setError(res.error?.message ?? "The authorization service did not confirm a code.");
										return;
									}
									const data = (res.data ?? {}) as Record<string, unknown>;
									const userCode = String(data.user_code ?? "");
									const result: DeviceStartResult = {
										verification_url: safeVerificationUrl(
											String(data.verification_url ?? "/verify"), userCode, teamId,
										),
										user_code: userCode,
										device_code: String(data.device_code ?? ""),
										expires_at: String(data.expires_at ?? ""),
										interval_seconds:
											typeof data.interval_seconds === "number" ? data.interval_seconds : undefined,
									};
									if (
										!result.device_code ||
										!result.user_code ||
										!Number.isFinite(Date.parse(result.expires_at)) ||
										Date.parse(result.expires_at) <= Date.now()
									) {
										setError(
											"The authorization service returned an incomplete code. Please retry.",
										);
										return;
									}
									setDevice(result);
								} catch (cause) {
									setError(
										cause instanceof Error
											? cause.message
											: "Could not start authorization. Please retry.",
									);
								} finally {
									setBusy(false);
								}
							}}
						>
							{busy ? "Generating code…" : "Generate code"}
						</button>
						<Link className="button button-secondary" to={`/verify?team=${encodeURIComponent(teamId)}`}>
							Open verify page
						</Link>
						{device ? (
							<button
								className="button button-secondary"
								type="button"
								onClick={() => {
									setDevice(null);
									setPoll(null);
									setShowEnrollmentToken(false);
									setCopiedEnrollmentToken(false);
									setError(null);
								}}
							>
								Cancel authorization
							</button>
						) : null}
					</div>

					{device ? (
						<div className="notice">
							<div className="muted small">Your code</div>
							<div
								className="mono"
								style={{
									fontSize: 26,
									fontWeight: 650,
									letterSpacing: "0.14em",
									color: "var(--accent)",
									margin: "4px 0 2px",
								}}
							>
								{device.user_code}
							</div>
							<div className="muted small" style={{ marginTop: 8 }}>
								Verification URL
							</div>
							<div className="mono" style={{ overflowWrap: "anywhere" }}>{device.verification_url}</div>
							<div className="muted small" style={{ marginTop: 8 }}>
								Expires:{" "}
								<span className="mono">
									{device.expires_at ? new Date(device.expires_at).toLocaleString() : "soon"}
								</span>
							</div>

							<div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
								<a
									className="button"
									href={device.verification_url}
									target="_blank"
									rel="noreferrer"
								>
									Authorize in browser
								</a>
								<Link
									className="button button-secondary"
									to={`/verify?code=${encodeURIComponent(device.user_code)}&team=${encodeURIComponent(teamId)}`}
								>
									I already opened it
								</Link>
							</div>

						{poll?.status === "authorization_pending" ? (
								<div className="muted small" role="status" style={{ marginTop: 12 }}>
									Waiting for authorization…
								</div>
							) : null}

							{poll?.status === "authorized" ? (
								<div className="notice" style={{ marginTop: 12 }}>
									<div>
										<b>Authorized.</b> Use the enrollment token below in your local runtime setup, then check the Agents page to confirm protection.
									</div>
									{poll.enrollment_token ? (
										<div className="muted small" style={{ marginTop: 8 }}>
											Fallback enrollment token (advanced; copy once, then clear it from this
											screen):
											{poll.enrollment_token_expires_at ? (
												<div style={{ marginTop: 4 }}>
													Expires at {new Date(poll.enrollment_token_expires_at).toLocaleString()}
												</div>
											) : null}
											<div className="row" style={{ marginTop: 6 }}>
												<input
													className="input mono"
													style={{ flex: "1 1 260px" }}
													readOnly
													type={showEnrollmentToken ? "text" : "password"}
													value={
														showEnrollmentToken
															? poll.enrollment_token
															: maskSecret(poll.enrollment_token)
													}
													aria-label="Enrollment token"
													autoComplete="off"
												/>
												<button
													className="button button-secondary"
													type="button"
													onClick={() => setShowEnrollmentToken((visible) => !visible)}
												>
													{showEnrollmentToken ? "Hide" : "Reveal"}
												</button>
												<button
													className="button button-secondary"
													type="button"
													onClick={async () => {
														try {
															await navigator.clipboard.writeText(poll.enrollment_token ?? "");
															setCopiedEnrollmentToken(true);
														} catch {
															setError(
																"Clipboard access was blocked. Reveal the token and copy it manually.",
															);
														}
													}}
												>
													{copiedEnrollmentToken ? "Copied" : "Copy"}
												</button>
												<button
													className="button button-secondary"
													type="button"
													onClick={() => {
														setPoll((current) =>
															current?.status === "authorized"
																? { ...current, enrollment_token: null }
																: current,
														);
														setShowEnrollmentToken(false);
														setCopiedEnrollmentToken(false);
													}}
												>
													Clear
												</button>
											</div>
										</div>
									) : null}
									{poll.enrollment_token ? null : (
										<div className="muted small" style={{ marginTop: 8 }}>
											The enrollment token was cleared from this screen. Generate a new code if setup still needs one.
										</div>
									)}
									<div className="row" style={{ marginTop: 12 }}>
										<Link className="button button-secondary" to="/agents">
											View agents
										</Link>
										<Link className="button button-secondary" to="/incidents">
											View incidents
										</Link>
									</div>
								</div>
							) : null}

							{poll?.status === "expired" ? (
								<div className="notice notice-danger" role="alert" style={{ marginTop: 12 }}>
									Authorization expired. Generate a new code and try again.
								</div>
							) : null}
						</div>
					) : null}

					{error ? (
						<div className="notice notice-danger" role="alert">
							{error}
						</div>
					) : null}
				</div>
			</div>
		</div>
	);
}
