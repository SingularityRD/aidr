import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { useRichT, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import { DownloadCenter, useReleaseManifest } from "../../onboarding/DownloadCenter";
import { InstallerDownloads } from "../../onboarding/InstallerDownloads";
import type { ReleaseManifest } from "../../onboarding/release-manifest";
import { CODEX_HOOKS_TOML } from "../../onboarding/runtime-catalog";
import {
	clearPendingTeamCreate,
	type PendingTeamCreate,
	readPendingTeamCreate,
	savePendingTeamCreate,
} from "../pending-team-create";
import {
	type GaLegal,
	readGaLegal,
	readTenantAdmission,
	type TenantAdmission,
} from "../tenant-admission";

type Runtime = "claude-code" | "cursor" | "vscode" | "codex" | "openclaw" | "opencode";

const RUNTIMES: ReadonlyArray<[Runtime, string]> = [
	["claude-code", "Claude Code"],
	["cursor", "Cursor"],
	["vscode", "VS Code"],
	["codex", "Codex"],
	["openclaw", "OpenClaw"],
	["opencode", "OpenCode"],
];

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

/** The exact release version of a connector, when this deployment publishes a manifest. */
function releaseVersion(manifest: ReleaseManifest | null, runtime: Runtime): string | null {
	return manifest?.artifacts.find((artifact) => artifact.id === runtime)?.version ?? null;
}

// i18n-exempt: instructions for the AI tool stay in English so it follows the
// rules and commands word for word; the page explains this in both languages.
function promptForRuntime(runtime: Runtime, version: string | null): string {
	const pinned = version ?? "<APPROVED_VERSION>";
	const common = [
		"You are installing Singularity AIDR (AI Agent Detection and Response).",
		"Goal: enable protection and then link this installation to my account via the device authorization flow.",
		"",
		"Rules:",
		"- Do not exfiltrate secrets.",
		"- Prefer the official install path for this runtime.",
		version
			? `- Install exactly version ${version} and verify its SHA-256 against the release record before installing. Never install an unverified or "latest" version.`
			: '- Stop and ask me for the approved exact version and its independently verified publisher-signed release record. Never install an unverified or "latest" version.',
		"- This manual install needs the release verification key. Ask me for the key file from the administrator and run `aidr setup --release-key <key.pem>` once before the first session; until then AIDR blocks every tool call. (The Windows/Linux installer provisions the key itself.)",
		"- If you need authorization: show me the short code + verification URL and wait.",
		"",
	].join("\n");

	if (runtime === "claude-code") {
		return [
			common,
			"Runtime: Claude Code",
			"Install:",
			`- Extract the signed aidr-claude-plugin ${pinned} release artifact.`,
			"- /plugin marketplace add /absolute/path/to/extracted/aidr-claude-plugin",
			"- /plugin install aidr@aidr",
			"After install, start a session so AIDR can request authorization.",
		].join("\n");
	}

	if (runtime === "codex") {
		return [
			common,
			"Runtime: Codex CLI",
			"Install:",
			"- Have the administrator configure private @singularityrd registry access through their secret manager; never ask for or display the token.",
			`- npm install --global @singularityrd/aidr-codex@${pinned}`,
			"- Ask the administrator for the signed runtime configuration and place it at ~/.singularity-aidr/config.json; without it the hook refuses to start.",
			"- Add these hooks to ~/.codex/config.toml:",
			CODEX_HOOKS_TOML,
			"- In Codex, review and trust the three hooks with /hooks.",
		].join("\n");
	}

	if (runtime === "openclaw") {
		return [
			common,
			"Runtime: OpenClaw",
			"Install:",
			"- Have the administrator configure private @singularityrd registry access through their secret manager; never ask for or display the token.",
			`- openclaw plugins install npm:@singularityrd/aidr-openclaw@${pinned}`,
			"- Restart the OpenClaw gateway and confirm the installed plugin version before device authorization.",
		].join("\n");
	}

	if (runtime === "opencode") {
		return [
			common,
			"Runtime: OpenCode",
			"Install:",
			"- Have the administrator configure private @singularityrd registry access through their secret manager; never ask for or display the token.",
			`- Set ~/.config/opencode/package.json dependency @singularityrd/aidr-opencode to exactly ${pinned}.`,
			"- Add @singularityrd/aidr-opencode to the plugin array in ~/.config/opencode/opencode.json.",
			"- Restart OpenCode and confirm the installed plugin version before device authorization.",
		].join("\n");
	}

	if (runtime === "cursor") {
		return [
			common,
			"Runtime: Cursor",
			"Install:",
			`- Install the Singularity AIDR ${pinned} extension (VSIX) for Cursor, then run “Enable protection”.`,
		].join("\n");
	}

	return [
		common,
		"Runtime: VS Code",
		"Install:",
		`- Install the Singularity AIDR ${pinned} extension (VSIX) for VS Code, then run “Enable protection”.`,
	].join("\n");
}

export function OnboardingPage() {
	const {
		currentTeam,
		currentRole,
		isLoading,
		roleResolved,
		error: teamError,
		currentUserId,
		createTeam,
	} = useTeam();
	const t = useT();
	if (isLoading || (currentTeam && !roleResolved)) {
		return (
			<div className="card" role="status">
				{t("onb.checkingTeam")}
			</div>
		);
	}
	if (!currentTeam || !currentRole) {
		if (!currentTeam && !teamError && window.__AIDR_CONFIG__?.signupMode === "cloud") {
			return <CreateTrialTeam key={currentUserId} userId={currentUserId} createTeam={createTeam} />;
		}
		return (
			<div className="card" role="alert">
				{teamError ?? t("onb.selectTeam")}
			</div>
		);
	}
	return (
		<TeamOnboarding
			key={currentTeam.id}
			teamId={currentTeam.id}
			teamName={currentTeam.name}
			canEnroll={["owner", "admin", "member"].includes(currentRole)}
			isOwner={currentRole === "owner"}
		/>
	);
}

function CreateTrialTeam({
	userId,
	createTeam,
}: {
	userId: string;
	createTeam: (name: string, requestId: string) => Promise<void>;
}) {
	const t = useT();
	const [name, setName] = useState("");
	const [busy, setBusy] = useState(false);
	const [attempt, setAttempt] = useState<PendingTeamCreate | null>(null);
	const [storageError, setStorageError] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);
	const busyRef = useRef(false);
	useEffect(() => {
		try {
			const pending = readPendingTeamCreate(userId, window.localStorage);
			setAttempt(pending);
			setName(pending?.name ?? "");
			setStorageError(null);
			setError(null);
		} catch (cause) {
			setAttempt(null);
			setName("");
			setStorageError(readErrorMessage(cause, t("onb.create.storageFailed")));
		}
	}, [userId]);
	const requestedName = attempt?.name ?? name.trim();
	const validName = requestedName.length > 0 && requestedName.length <= 200;
	return (
		<div className="card">
			<h1>{t("onb.create.title")}</h1>
			<p className="muted">{t("onb.create.body")}</p>
			<form
				onSubmit={async (event) => {
					event.preventDefault();
					if (!validName || busyRef.current || busy || storageError) return;
					busyRef.current = true;
					setBusy(true);
					setError(null);
					try {
						const storedRequest = readPendingTeamCreate(userId, window.localStorage);
						const request = storedRequest ??
							attempt ?? {
								requestId: crypto.randomUUID(),
								name: name.trim(),
							};
						if (!storedRequest) {
							savePendingTeamCreate(userId, request, window.localStorage);
							setAttempt(request);
							setName(request.name);
						} else if (storedRequest) {
							setAttempt(storedRequest);
							setName(storedRequest.name);
						}
						await createTeam(request.name, request.requestId);
						clearPendingTeamCreate(userId, request.requestId, window.localStorage);
						setAttempt(null);
						setName("");
					} catch {
						setError(t("onb.create.unconfirmed"));
					} finally {
						busyRef.current = false;
						setBusy(false);
					}
				}}
			>
				<label className="label">
					{t("onb.create.teamName")}
					<input
						className="input"
						required
						maxLength={200}
						readOnly={Boolean(attempt)}
						value={attempt?.name ?? name}
						onChange={(event) => setName(event.target.value)}
					/>
				</label>
				<button
					className="button"
					type="submit"
					disabled={!validName || busy || Boolean(storageError)}
				>
					{busy
						? t("onb.create.creating")
						: attempt
							? t("onb.create.retry")
							: t("onb.create.submit")}
				</button>
			</form>
			{storageError ? (
				<div className="notice notice-danger" role="alert">
					{storageError}
				</div>
			) : null}
			{error ? (
				<div className="notice notice-danger" role="alert">
					{error}
				</div>
			) : null}
		</div>
	);
}

function TeamOnboarding({
	teamId,
	teamName,
	canEnroll,
	isOwner,
}: {
	teamId: string;
	teamName: string;
	canEnroll: boolean;
	isOwner: boolean;
}) {
	const [runtime, setRuntime] = useState<Runtime>("claude-code");
	const [pilotStatus, setPilotStatus] = useState<string>("loading");
	const [pilotReload, setPilotReload] = useState(0);
	const [admission, setAdmission] = useState<TenantAdmission | null>(null);
	const [legal, setLegal] = useState<GaLegal | null>(null);
	const [acceptedLegal, setAcceptedLegal] = useState(false);
	const [trialBusy, setTrialBusy] = useState(false);
	const [device, setDevice] = useState<DeviceStartResult | null>(null);
	const [poll, setPoll] = useState<DevicePollResult | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [promptCopyStatus, setPromptCopyStatus] = useState<"idle" | "copied" | "error">("idle");
	const [showEnrollmentToken, setShowEnrollmentToken] = useState(false);
	const [copiedEnrollmentToken, setCopiedEnrollmentToken] = useState(false);
	const t = useT();
	const richT = useRichT();
	const releaseManifest = useReleaseManifest();
	const manifest = releaseManifest.state === "ready" ? releaseManifest.manifest : null;
	const runtimeVersion = releaseVersion(manifest, runtime);

	const prompt = useMemo(
		() => promptForRuntime(runtime, runtimeVersion),
		[runtime, runtimeVersion],
	);
	const requestedInterval = device?.interval_seconds;
	const intervalSeconds =
		typeof requestedInterval === "number" && Number.isFinite(requestedInterval)
			? Math.max(2, Math.min(10, requestedInterval))
			: 5;

	useEffect(() => {
		let cancelled = false;
		async function load() {
			try {
				const res = await supabase.functions.invoke("pilot-status", {
					method: "GET",
					headers: { "X-AIDR-Tenant-ID": teamId },
				});
				if (cancelled) return;
				if (res.error || res.data?.ok !== true) {
					setPilotStatus("unknown");
					setAdmission(null);
					setLegal(null);
					return;
				}
				const data = (res.data ?? {}) as Record<string, unknown>;
				setPilotStatus(typeof data.status === "string" ? String(data.status) : "unknown");
				setAdmission(readTenantAdmission(data.admission));
				setLegal(readGaLegal(data.legal));
				setAcceptedLegal(false);
			} catch {
				if (!cancelled) {
					setPilotStatus("unknown");
					setAdmission(null);
					setLegal(null);
				}
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
				setError(t("onb.code.expired"));
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
						setError(t("onb.code.rejected"));
						shouldRetry = false;
					} else {
						setError(t("onb.code.retrying"));
						nextDelayMs = Math.min(Math.max(nextDelayMs * 2, intervalSeconds * 1000), 30_000);
					}
				} else {
					const data = (res.data ?? {}) as Record<string, unknown>;
					const status = String(data.status ?? "unknown");
					// Back-compat: server may return "approved" for the final state.
					if (status === "authorized" || status === "approved") {
						const enrollmentToken =
							typeof data.enrollment_token === "string" && data.enrollment_token.length > 0
								? data.enrollment_token
								: null;
						const enrollmentTokenExpiresAt =
							typeof data.expires_at === "string" ? data.expires_at : null;
						if (
							!enrollmentToken ||
							!enrollmentTokenExpiresAt ||
							!Number.isFinite(Date.parse(enrollmentTokenExpiresAt)) ||
							Date.parse(enrollmentTokenExpiresAt) <= Date.now()
						) {
							setDevice(null);
							setPoll(null);
							setError(t("onb.code.noToken"));
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
						setError(t("onb.code.expired"));
						shouldRetry = false;
					} else {
						setDevice(null);
						setPoll(null);
						setError(t("onb.code.unknownState"));
						shouldRetry = false;
					}
				}
			} catch {
				if (!cancelled) {
					setError(t("onb.code.retrying"));
					nextDelayMs = Math.min(Math.max(nextDelayMs * 2, intervalSeconds * 1000), 30_000);
				}
			}

			if (!cancelled && shouldRetry) {
				const remainingMs = expiresAtMs - Date.now();
				if (remainingMs <= 0) {
					setPoll({ status: "expired" });
					setDevice(null);
					setError(t("onb.code.expired"));
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
			setError(t("onb.token.expired"));
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

	const canAuthorize = admission?.status === "active" && canEnroll;
	const accessUnknown = pilotStatus === "unknown" || (pilotStatus !== "loading" && !admission);

	async function startTrial() {
		if (
			!isOwner ||
			admission?.mode !== "cloud" ||
			!admission.trial_available ||
			!legal?.configured ||
			!legal.terms ||
			!legal.privacy ||
			!acceptedLegal ||
			trialBusy
		)
			return;
		setTrialBusy(true);
		setError(null);
		try {
			const res = await supabase.functions.invoke("pilot-status", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": teamId },
				body: {
					action: "start_trial",
					accepted: true,
					terms: { version: legal.terms.version, sha256: legal.terms.sha256 },
					privacy: { version: legal.privacy.version, sha256: legal.privacy.sha256 },
				},
			});
			const updated = readTenantAdmission(res.data?.admission);
			if (res.error || res.data?.ok !== true || updated?.status !== "active") {
				throw new Error(t("onb.trial.unconfirmed"));
			}
			setAdmission(updated);
		} catch (cause) {
			setError(readErrorMessage(cause, t("onb.trial.unavailable")));
			setAcceptedLegal(false);
			setPilotStatus("loading");
			setAdmission(null);
			setLegal(null);
			setPilotReload((count) => count + 1);
		} finally {
			setTrialBusy(false);
		}
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>{t("nav.onboarding")}</h1>
				<p style={{ overflowWrap: "anywhere" }}>{t("onb.team", { name: teamName })}</p>
				{!canEnroll ? (
					<div className="notice notice-warning" role="alert">
						{t("onb.cannotEnroll")}
					</div>
				) : null}
				<p className="muted">{t("onb.intro")}</p>
				{admission?.status !== "active" ? (
					<div className="notice notice-warning">
						<div className="muted small">{t("onb.access")}</div>
						<div className="mono" style={{ marginTop: 4 }}>
							{admission?.status ?? (accessUnknown ? "unknown" : pilotStatus)}
						</div>
						{pilotStatus === "loading" ? <div role="status">{t("onb.accessChecking")}</div> : null}
						{accessUnknown ? <div role="alert">{t("onb.accessUnknown")}</div> : null}
						{admission?.mode === "cloud" && admission.trial_available && isOwner ? (
							legal?.configured && legal.terms && legal.privacy ? (
								<div style={{ marginTop: 10 }}>
									<label>
										<input
											type="checkbox"
											checked={acceptedLegal}
											onChange={(event) => setAcceptedLegal(event.target.checked)}
										/>{" "}
										{richT("onb.legal", {
											terms: (
												<a href={legal.terms.url} target="_blank" rel="noreferrer">
													{t("onb.legal.terms", { version: legal.terms.version })}
												</a>
											),
											privacy: (
												<a href={legal.privacy.url} target="_blank" rel="noreferrer">
													{t("onb.legal.privacy", { version: legal.privacy.version })}
												</a>
											),
										})}
									</label>
									<div className="row" style={{ marginTop: 10 }}>
										<button
											className="button"
											type="button"
											disabled={trialBusy || !acceptedLegal}
											onClick={startTrial}
										>
											{trialBusy ? t("onb.trial.starting") : t("onb.trial.start")}
										</button>
									</div>
								</div>
							) : (
								<div role="alert">{t("onb.trial.needsLegal")}</div>
							)
						) : null}
						{admission?.mode === "cloud" && !admission.trial_available ? (
							<div role="status">
								{legal?.configured === false ? t("onb.trial.awaitsLegal") : t("onb.trial.none")}
							</div>
						) : null}
						{pilotStatus !== "loading" ? (
							<div className="row" style={{ marginTop: 10 }}>
								{accessUnknown ? (
									<button
										className="button button-secondary button-sm"
										type="button"
										onClick={() => {
											setPilotStatus("loading");
											setAdmission(null);
											setLegal(null);
											setAcceptedLegal(false);
											setPilotReload((count) => count + 1);
										}}
									>
										{t("onb.retryStatus")}
									</button>
								) : null}
								{admission?.mode === "pilot" ? (
									<Link className="button button-secondary button-sm" to="/pilot">
										{t("onb.pilot")}
									</Link>
								) : null}
							</div>
						) : null}
					</div>
				) : admission.access_kind === "trial" ? (
					<div className="notice" role="status">
						{t("onb.trial.active", { count: admission.allowed_agents })}
						{admission.expires_at
							? t("onb.trial.ends", { time: new Date(admission.expires_at).toLocaleString() })
							: ""}
					</div>
				) : null}
			</div>

			<section className="card" aria-labelledby="onboarding-install-title">
				<h2 id="onboarding-install-title">{t("onboarding.install.title")}</h2>
				<p className="muted">
					{t("onboarding.install.body")}{" "}
					<Link to="/downloads">{t("onboarding.install.allDownloads")}</Link>
				</p>
				<InstallerDownloads teamId={teamId} />
			</section>

			<details className="card">
				<summary>
					<b>{t("onboarding.advanced.summary")}</b>
				</summary>
				<p className="muted small">{t("onboarding.advanced.body")}</p>
				<div className="notice notice-warning" role="note" data-testid="onboarding-release-key">
					{richT("onb.manual.releaseKey", {
						command: <code>aidr setup --release-key &lt;key.pem&gt;</code>,
					})}
				</div>
				<div className="cols">
					<div className="card">
						<h2>{t("onb.manual.runtime")}</h2>
						<div className="row" style={{ flexWrap: "wrap" }}>
							{RUNTIMES.map(([id, label]) => (
								<button
									key={id}
									className={`button ${runtime === id ? "" : "button-secondary"}`}
									type="button"
									onClick={() => {
										setRuntime(id);
										setPromptCopyStatus("idle");
									}}
									aria-pressed={runtime === id}
								>
									{label}
								</button>
							))}
						</div>

						<div className="notice" style={{ marginTop: 12 }}>
							<label className="muted small" htmlFor="onboarding-agent-prompt">
								{t("onb.manual.prompt")}
							</label>
							<textarea
								id="onboarding-agent-prompt"
								className="input mono"
								style={{ minHeight: 220, resize: "vertical" }}
								readOnly
								value={prompt}
							/>
							<button
								className="button button-secondary button-sm"
								type="button"
								onClick={async () => {
									try {
										await navigator.clipboard.writeText(prompt);
										setPromptCopyStatus("copied");
									} catch {
										setPromptCopyStatus("error");
									}
								}}
							>
								{promptCopyStatus === "copied"
									? t("onb.manual.promptCopied")
									: t("onb.manual.copyPrompt")}
							</button>
							{promptCopyStatus === "error" ? (
								<div role="alert">{t("onb.manual.copyBlocked")}</div>
							) : null}
							<div className="muted small" style={{ marginTop: 10 }}>
								{t("onb.manual.promptNote")}
							</div>
							{runtimeVersion ? null : (
								<div className="muted small" style={{ marginTop: 6 }}>
									{t("onb.manual.noVersion")}
								</div>
							)}
						</div>
					</div>

					<div className="card">
						<h2>{t("onb.manual.download")}</h2>
						<p className="muted">
							{richT("onb.manual.downloadBody", {
								link: <Link to="/downloads">{t("onb.manual.allDownloads")}</Link>,
							})}
						</p>
						<DownloadCenter
							teamId={teamId}
							only={[runtime]}
							headingLevel={3}
							manifestState={releaseManifest}
						/>
					</div>

					<div className="card">
						<h2>{t("onb.manual.authorize")}</h2>
						<p className="muted">{t("onb.manual.authorizeBody")}</p>

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
											setError(readErrorMessage(res.error, t("onb.code.notConfirmed")));
											return;
										}
										const data = (res.data ?? {}) as Record<string, unknown>;
										const userCode = String(data.user_code ?? "");
										const result: DeviceStartResult = {
											verification_url: safeVerificationUrl(
												String(data.verification_url ?? "/verify"),
												userCode,
												teamId,
											),
											user_code: userCode,
											device_code: String(data.device_code ?? ""),
											expires_at: String(data.expires_at ?? ""),
											interval_seconds:
												typeof data.interval_seconds === "number"
													? data.interval_seconds
													: undefined,
										};
										if (
											!result.device_code ||
											!result.user_code ||
											!Number.isFinite(Date.parse(result.expires_at)) ||
											Date.parse(result.expires_at) <= Date.now()
										) {
											setError(t("onb.code.incomplete"));
											return;
										}
										setDevice(result);
									} catch (cause) {
										setError(readErrorMessage(cause, t("onb.code.startFailed")));
									} finally {
										setBusy(false);
									}
								}}
							>
								{busy ? t("onb.code.generating") : t("onb.code.generate")}
							</button>
							<Link
								className="button button-secondary"
								to={`/verify?team=${encodeURIComponent(teamId)}`}
							>
								{t("onb.code.openVerify")}
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
									{t("onb.code.cancel")}
								</button>
							) : null}
						</div>

						{device ? (
							<div className="notice">
								<div className="muted small">{t("onb.code.yours")}</div>
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
									{t("onb.code.url")}
								</div>
								<div className="mono" style={{ overflowWrap: "anywhere" }}>
									{device.verification_url}
								</div>
								<div className="muted small" style={{ marginTop: 8 }}>
									{t("onb.code.expires")}{" "}
									<span className="mono">
										{device.expires_at
											? new Date(device.expires_at).toLocaleString()
											: t("onb.code.soon")}
									</span>
								</div>

								<div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
									<a
										className="button"
										href={device.verification_url}
										target="_blank"
										rel="noreferrer"
									>
										{t("onb.code.authorizeBrowser")}
									</a>
									<Link
										className="button button-secondary"
										to={`/verify?code=${encodeURIComponent(device.user_code)}&team=${encodeURIComponent(teamId)}`}
									>
										{t("onb.code.alreadyOpened")}
									</Link>
								</div>

								{poll?.status === "authorization_pending" ? (
									<div className="muted small" role="status" style={{ marginTop: 12 }}>
										{t("onb.code.waiting")}
									</div>
								) : null}

								{poll?.status === "authorized" ? (
									<div className="notice" style={{ marginTop: 12 }}>
										<div>
											<b>{t("onb.code.authorized")}</b> {t("onb.code.authorizedBody")}
										</div>
										{poll.enrollment_token ? (
											<div className="muted small" style={{ marginTop: 8 }}>
												{t("onb.token.fallback")}
												{poll.enrollment_token_expires_at ? (
													<div style={{ marginTop: 4 }}>
														{t("onb.token.expiresAt", {
															time: new Date(poll.enrollment_token_expires_at).toLocaleString(),
														})}
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
														aria-label={t("onb.token.label")}
														autoComplete="off"
													/>
													<button
														className="button button-secondary"
														type="button"
														onClick={() => setShowEnrollmentToken((visible) => !visible)}
													>
														{showEnrollmentToken ? t("onb.token.hide") : t("onb.token.reveal")}
													</button>
													<button
														className="button button-secondary"
														type="button"
														onClick={async () => {
															try {
																await navigator.clipboard.writeText(poll.enrollment_token ?? "");
																setCopiedEnrollmentToken(true);
															} catch {
																setError(t("onb.token.copyBlocked"));
															}
														}}
													>
														{copiedEnrollmentToken ? t("onb.token.copied") : t("onb.token.copy")}
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
														{t("onb.token.clear")}
													</button>
												</div>
											</div>
										) : null}
										{poll.enrollment_token ? null : (
											<div className="muted small" style={{ marginTop: 8 }}>
												{t("onb.token.cleared")}
											</div>
										)}
										<div className="row" style={{ marginTop: 12 }}>
											<Link className="button button-secondary" to="/agents">
												{t("onb.viewAgents")}
											</Link>
											<Link className="button button-secondary" to="/incidents">
												{t("onb.viewIncidents")}
											</Link>
										</div>
									</div>
								) : null}

								{poll?.status === "expired" ? (
									<div className="notice notice-danger" role="alert" style={{ marginTop: 12 }}>
										{t("onb.code.expiredRetry")}
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
			</details>
		</div>
	);
}
