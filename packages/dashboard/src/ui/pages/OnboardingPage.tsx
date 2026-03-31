import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../../lib/supabase";

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
	| { status: "authorized"; enrollment_token?: string | null };

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
	const [runtime, setRuntime] = useState<Runtime>("claude-code");
	const [pilotStatus, setPilotStatus] = useState<string>("loading");
	const [device, setDevice] = useState<DeviceStartResult | null>(null);
	const [poll, setPoll] = useState<DevicePollResult | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const prompt = useMemo(() => promptForRuntime(runtime), [runtime]);
	const intervalSeconds = Math.max(2, Math.min(10, Number(device?.interval_seconds ?? 5)));

	useEffect(() => {
		let cancelled = false;
		async function load() {
			const res = await supabase.functions.invoke("pilot-status", { method: "GET" });
			if (cancelled) return;
			if (res.error) {
				setPilotStatus("unknown");
				return;
			}
			const data = (res.data ?? {}) as Record<string, unknown>;
			setPilotStatus(typeof data.status === "string" ? String(data.status) : "unknown");
		}
		load();
		return () => {
			cancelled = true;
		};
	}, []);

	useEffect(() => {
		let cancelled = false;
		let t: number | null = null;

		async function tick() {
			if (!device) return;
			try {
				const res = await supabase.functions.invoke("device-poll", {
					method: "POST",
					body: { device_code: device.device_code },
				});
				if (cancelled) return;
				if (res.error) {
					setPoll(null);
					setError(res.error.message);
					return;
				}
				const data = (res.data ?? {}) as Record<string, unknown>;
				const status = String(data.status ?? "authorization_pending");
				// Back-compat: server may return "approved" for the final state.
				if (status === "authorized" || status === "approved") {
					setPoll({
						status: "authorized",
						enrollment_token:
							typeof data.enrollment_token === "string" ? data.enrollment_token : null,
					});
					return;
				}
				setPoll({ status: "authorization_pending" });
			} catch (e) {
				if (!cancelled) setError(String(e));
			}
			t = window.setTimeout(tick, intervalSeconds * 1000);
		}

		if (device) {
			t = window.setTimeout(tick, 500);
		}

		return () => {
			cancelled = true;
			if (t != null) window.clearTimeout(t);
		};
	}, [device, intervalSeconds]);

	const canAuthorize = pilotStatus === "approved";

	return (
		<div className="stack">
			<div className="card">
				<h1>Onboarding</h1>
				<p className="muted">
					Pick your runtime, paste the prompt into your agent, then authorize once in your browser.
				</p>
				{pilotStatus !== "approved" ? (
					<div className="notice">
						<div className="muted small">Pilot status</div>
						<div className="mono">{pilotStatus}</div>
						{pilotStatus !== "loading" ? (
							<div className="row" style={{ marginTop: 10 }}>
								<Link className="button button-secondary" to="/pilot">
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
								onClick={() => setRuntime(id)}
							>
								{label}
							</button>
						))}
					</div>

					<div className="notice" style={{ marginTop: 12 }}>
						<div className="muted small">Prompt to give your agent</div>
						<textarea
							className="input mono"
							style={{ minHeight: 220, resize: "vertical" }}
							readOnly
							value={prompt}
						/>
						<div className="muted small" style={{ marginTop: 10 }}>
							This prompt focuses the agent on install + authorization without asking you to
							manually copy API keys.
						</div>
					</div>
				</div>

				<div className="card">
					<h2>2) Authorize</h2>
					<p className="muted">
						Generate a short code, then sign in and authorize in your browser. Your runtime will
						complete enrollment automatically.
					</p>

					<div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
						<button
							className="button"
							type="button"
							disabled={busy || !canAuthorize}
							onClick={async () => {
								setBusy(true);
								setError(null);
								setPoll(null);
								try {
									const res = await supabase.functions.invoke("device-start", { method: "POST" });
									if (res.error) {
										setError(res.error.message);
										return;
									}
									const data = (res.data ?? {}) as Record<string, unknown>;
									const result: DeviceStartResult = {
										verification_url: String(data.verification_url ?? "/verify"),
										user_code: String(data.user_code ?? ""),
										device_code: String(data.device_code ?? ""),
										expires_at: String(data.expires_at ?? ""),
										interval_seconds:
											typeof data.interval_seconds === "number" ? data.interval_seconds : undefined,
									};
									setDevice(result);
								} finally {
									setBusy(false);
								}
							}}
						>
							Generate code
						</button>
						<Link className="button button-secondary" to="/verify">
							Open verify page
						</Link>
					</div>

					{device ? (
						<div className="notice">
							<div className="muted small">Your code</div>
							<div className="mono" style={{ fontSize: 18 }}>
								{device.user_code}
							</div>
							<div className="muted small" style={{ marginTop: 8 }}>
								Verification URL
							</div>
							<div className="mono">{device.verification_url}</div>
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
									to={`/verify?code=${encodeURIComponent(device.user_code)}`}
								>
									I already opened it
								</Link>
							</div>

							{poll?.status === "authorization_pending" ? (
								<div className="muted small" style={{ marginTop: 12 }}>
									Waiting for authorization…
								</div>
							) : null}

							{poll?.status === "authorized" ? (
								<div className="notice" style={{ marginTop: 12 }}>
									<div>
										<b>Authorized.</b> Start your agent runtime now. It will complete enrollment and
										enable protection.
									</div>
									{poll.enrollment_token ? (
										<div className="muted small" style={{ marginTop: 8 }}>
											Fallback enrollment token (advanced):
											<div className="mono" style={{ marginTop: 6 }}>
												{poll.enrollment_token}
											</div>
										</div>
									) : null}
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
						</div>
					) : null}

					{error ? <div className="notice notice-danger">{error}</div> : null}
				</div>
			</div>
		</div>
	);
}
