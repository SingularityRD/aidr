import { useCallback, useEffect, useMemo, useState } from "react";
import { supabase } from "../../lib/supabase";

type ApiKeyRow = {
	id: string;
	label: string | null;
	revoked: boolean;
	created_at: string;
};

type EnrollmentTokenRow = {
	id: string;
	label: string | null;
	expires_at: string;
	consumed_at: string | null;
	created_at: string;
};

type InvokeOptions = {
	method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
};

function maskSecret(secret: string): string {
	if (secret.length <= 4) return "•".repeat(secret.length);
	return `${"•".repeat(Math.max(8, secret.length - 4))}${secret.slice(-4)}`;
}

export function ApiKeysPage() {
	const [pilotStatus, setPilotStatus] = useState<string>("loading");
	const [keys, setKeys] = useState<ApiKeyRow[]>([]);
	const [label, setLabel] = useState("");
	const [createdKey, setCreatedKey] = useState<string | null>(null);
	const [showCreatedKey, setShowCreatedKey] = useState(false);
	const [copiedKey, setCopiedKey] = useState(false);

	const [enrollTokens, setEnrollTokens] = useState<EnrollmentTokenRow[]>([]);
	const [enrollLabel, setEnrollLabel] = useState("");
	const [createdEnrollToken, setCreatedEnrollToken] = useState<string | null>(null);
	const [showCreatedEnrollToken, setShowCreatedEnrollToken] = useState(false);
	const [copiedEnrollToken, setCopiedEnrollToken] = useState(false);

	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const trimmedLabel = useMemo(() => label.trim(), [label]);
	const trimmedEnrollLabel = useMemo(() => enrollLabel.trim(), [enrollLabel]);

	const load = useCallback(async () => {
		setError(null);
		const invoke = async (name: string, options: InvokeOptions) => {
			try {
				return await supabase.functions.invoke(name, options);
			} catch (cause) {
				return {
					data: null,
					error:
						cause instanceof Error ? cause : new Error("The dashboard service is unavailable."),
				};
			}
		};
		const [pilotRes, keysRes, enrollRes] = await Promise.all([
			invoke("pilot-status", { method: "GET" }),
			invoke("api-keys", { method: "GET" }),
			invoke("enrollment-tokens", { method: "GET" }),
		]);

		if (pilotRes.error) {
			setPilotStatus("unknown");
			setError(pilotRes.error.message);
		} else {
			const data = (pilotRes.data ?? {}) as Record<string, unknown>;
			setPilotStatus(typeof data.status === "string" ? String(data.status) : "unknown");
		}

		const pilotData = (pilotRes.data ?? {}) as Record<string, unknown>;
		const approved =
			!pilotRes.error && typeof pilotData.status === "string" && pilotData.status === "approved";
		if (!approved) {
			setKeys([]);
			setEnrollTokens([]);
			return;
		}

		if (keysRes.error) {
			setError(keysRes.error.message);
			return;
		}
		const keysData = (keysRes.data ?? {}) as { keys?: ApiKeyRow[] };
		setKeys((keysData.keys ?? []) as ApiKeyRow[]);

		if (enrollRes.error) {
			setError(enrollRes.error.message);
			return;
		}
		const enrollData = (enrollRes.data ?? {}) as { tokens?: EnrollmentTokenRow[] };
		setEnrollTokens((enrollData.tokens ?? []) as EnrollmentTokenRow[]);
	}, []);

	useEffect(() => {
		load();
	}, [load]);

	const approved = pilotStatus === "approved";

	return (
		<div className="stack">
			<div className="card">
				<h1>API Keys</h1>
				<p className="muted">Advanced: keys and enrollment tokens for manual setups and support.</p>

				{approved ? null : (
					<div className="notice">
						<div className="muted small">Pilot status</div>
						<div className="mono">{pilotStatus}</div>
						<div className="muted small" style={{ marginTop: 8 }}>
							You must be approved for the pilot before creating keys or enrolling devices. Use the
							Onboarding flow instead.
						</div>
					</div>
				)}

				<label className="label">
					Label (optional)
					<input
						className="input"
						value={label}
						onChange={(e) => setLabel(e.target.value)}
						placeholder="work-laptop, build-server, etc."
					/>
				</label>

				<div className="row">
					<button
						className="button"
						type="button"
						disabled={busy || !approved}
						onClick={async () => {
							setBusy(true);
							setError(null);
							setCreatedKey(null);
							setShowCreatedKey(false);
							setCopiedKey(false);
							try {
								const res = await supabase.functions.invoke("api-keys", {
									method: "POST",
									body: { action: "create", label: trimmedLabel || null },
								});
								if (res.error) {
									setError(res.error.message);
									return;
								}
								const data = (res.data ?? {}) as { api_key?: string };
								if (!data.api_key) {
									setError("Failed to create API key.");
									return;
								}
								setCreatedKey(data.api_key);
								setLabel("");
								await load();
							} catch (cause) {
								setError(
									cause instanceof Error
										? cause.message
										: "API key creation is unavailable. Please retry.",
								);
							} finally {
								setBusy(false);
							}
						}}
					>
						Generate key
					</button>
					<button
						className="button button-secondary"
						type="button"
						disabled={!approved}
						onClick={async () => {
							await load();
						}}
					>
						Refresh
					</button>
				</div>

				{createdKey ? (
					<div className="notice">
						<div className="muted small">Copy this key now (shown once):</div>
						<div className="row" style={{ marginTop: 6 }}>
							<input
								className="input mono"
								style={{ flex: "1 1 260px" }}
								readOnly
								type={showCreatedKey ? "text" : "password"}
								value={showCreatedKey ? createdKey : maskSecret(createdKey)}
								aria-label="New API key"
								autoComplete="off"
							/>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => setShowCreatedKey((visible) => !visible)}
							>
								{showCreatedKey ? "Hide" : "Reveal"}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={async () => {
									try {
										await navigator.clipboard.writeText(createdKey);
										setCopiedKey(true);
									} catch {
										setError("Clipboard access was blocked. Reveal the key and copy it manually.");
									}
								}}
							>
								{copiedKey ? "Copied" : "Copy"}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => {
									setCreatedKey(null);
									setShowCreatedKey(false);
									setCopiedKey(false);
								}}
							>
								Clear
							</button>
						</div>
					</div>
				) : null}
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			<div className="card">
				<h2>Enrollment Tokens</h2>
				<p className="muted">
					Enrollment tokens are one-time, short-lived credentials used to bootstrap an agent without
					manually copying an API key. They are stored as SHA-256 hashes only.
				</p>

				<label className="label">
					Label (optional)
					<input
						className="input"
						value={enrollLabel}
						onChange={(e) => setEnrollLabel(e.target.value)}
						placeholder="workstation-1, ci-runner, etc."
					/>
				</label>

				<div className="row">
					<button
						className="button"
						type="button"
						disabled={busy || !approved}
						onClick={async () => {
							setBusy(true);
							setError(null);
							setCreatedEnrollToken(null);
							setShowCreatedEnrollToken(false);
							setCopiedEnrollToken(false);
							try {
								const res = await supabase.functions.invoke("enrollment-tokens", {
									method: "POST",
									body: { action: "create", label: trimmedEnrollLabel || null },
								});
								if (res.error) {
									setError(res.error.message);
									return;
								}
								const data = (res.data ?? {}) as { enrollment_token?: string };
								if (!data.enrollment_token) {
									setError("Failed to create enrollment token.");
									return;
								}

								setCreatedEnrollToken(data.enrollment_token);
								setEnrollLabel("");
								await load();
							} catch (cause) {
								setError(
									cause instanceof Error
										? cause.message
										: "Enrollment token creation is unavailable. Please retry.",
								);
							} finally {
								setBusy(false);
							}
						}}
					>
						Generate enrollment token
					</button>
				</div>

				{createdEnrollToken ? (
					<div className="notice">
						<div className="muted small">Copy this token now (shown once):</div>
						<div className="row" style={{ marginTop: 6 }}>
							<input
								className="input mono"
								style={{ flex: "1 1 260px" }}
								readOnly
								type={showCreatedEnrollToken ? "text" : "password"}
								value={showCreatedEnrollToken ? createdEnrollToken : maskSecret(createdEnrollToken)}
								aria-label="New enrollment token"
								autoComplete="off"
							/>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => setShowCreatedEnrollToken((visible) => !visible)}
							>
								{showCreatedEnrollToken ? "Hide" : "Reveal"}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={async () => {
									try {
										await navigator.clipboard.writeText(createdEnrollToken);
										setCopiedEnrollToken(true);
									} catch {
										setError(
											"Clipboard access was blocked. Reveal the token and copy it manually.",
										);
									}
								}}
							>
								{copiedEnrollToken ? "Copied" : "Copy"}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => {
									setCreatedEnrollToken(null);
									setShowCreatedEnrollToken(false);
									setCopiedEnrollToken(false);
								}}
							>
								Clear
							</button>
						</div>
					</div>
				) : null}
			</div>

			<div className="card">
				<h2>Issued keys</h2>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Label</th>
								<th>Created</th>
								<th>Status</th>
								<th className="right">
									<span className="sr-only">Actions</span>
								</th>
							</tr>
						</thead>
						<tbody>
							{keys.map((k) => (
								<tr key={k.id}>
									<td>{k.label ?? <span className="muted">(no label)</span>}</td>
									<td className="mono">{new Date(k.created_at).toLocaleString()}</td>
									<td>
										<span className={k.revoked ? "badge badge-error" : "badge badge-success"}>
											{k.revoked ? "revoked" : "active"}
										</span>
									</td>
									<td className="right">
										<button
											className="button button-secondary button-sm"
											type="button"
											disabled={k.revoked}
											onClick={async () => {
												setBusy(true);
												setError(null);
												try {
													const res = await supabase.functions.invoke("api-keys", {
														method: "POST",
														body: { action: "revoke", id: k.id },
													});
													if (res.error) setError(res.error.message);
													await load();
												} catch (cause) {
													setError(
														cause instanceof Error
															? cause.message
															: "API key revocation is unavailable.",
													);
												} finally {
													setBusy(false);
												}
											}}
										>
											Revoke
										</button>
									</td>
								</tr>
							))}
							{keys.length === 0 ? (
								<tr>
									<td colSpan={4} className="muted">
										No keys yet.
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
			</div>

			<div className="card">
				<h2>Issued enrollment tokens</h2>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Label</th>
								<th>Created</th>
								<th>Expires</th>
								<th>Status</th>
								<th className="right">
									<span className="sr-only">Actions</span>
								</th>
							</tr>
						</thead>
						<tbody>
							{enrollTokens.map((t) => (
								<tr key={t.id}>
									<td>{t.label ?? <span className="muted">(no label)</span>}</td>
									<td className="mono">{new Date(t.created_at).toLocaleString()}</td>
									<td className="mono">{new Date(t.expires_at).toLocaleString()}</td>
									<td>
										{t.consumed_at ? (
											<span className="badge badge-neutral">consumed</span>
										) : Date.now() > Date.parse(t.expires_at) ? (
											<span className="badge badge-warning">expired</span>
										) : (
											<span className="badge badge-success">active</span>
										)}
									</td>
									<td className="right">
										<button
											className="button button-secondary button-sm"
											type="button"
											disabled={busy}
											onClick={async () => {
												setBusy(true);
												setError(null);
												try {
													const { error: delErr } = await supabase.functions.invoke(
														"enrollment-tokens",
														{
															method: "POST",
															body: { action: "delete", id: t.id },
														},
													);
													if (delErr) setError(delErr.message);
													await load();
												} catch (cause) {
													setError(
														cause instanceof Error
															? cause.message
															: "Enrollment token deletion is unavailable.",
													);
												} finally {
													setBusy(false);
												}
											}}
										>
											Delete
										</button>
									</td>
								</tr>
							))}
							{enrollTokens.length === 0 ? (
								<tr>
									<td colSpan={5} className="muted">
										No enrollment tokens yet.
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	);
}
