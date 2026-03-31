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

export function ApiKeysPage() {
	const [pilotStatus, setPilotStatus] = useState<string>("loading");
	const [keys, setKeys] = useState<ApiKeyRow[]>([]);
	const [label, setLabel] = useState("");
	const [createdKey, setCreatedKey] = useState<string | null>(null);

	const [enrollTokens, setEnrollTokens] = useState<EnrollmentTokenRow[]>([]);
	const [enrollLabel, setEnrollLabel] = useState("");
	const [createdEnrollToken, setCreatedEnrollToken] = useState<string | null>(null);

	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const trimmedLabel = useMemo(() => label.trim(), [label]);
	const trimmedEnrollLabel = useMemo(() => enrollLabel.trim(), [enrollLabel]);

	const load = useCallback(async () => {
		setError(null);
		const [pilotRes, keysRes, enrollRes] = await Promise.all([
			supabase.functions.invoke("pilot-status", { method: "GET" }),
			supabase.functions.invoke("api-keys", { method: "GET" }),
			supabase.functions.invoke("enrollment-tokens", { method: "GET" }),
		]);

		if (pilotRes.error) {
			setPilotStatus("unknown");
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
						<div className="mono">{createdKey}</div>
					</div>
				) : null}
				{error ? <div className="notice notice-danger">{error}</div> : null}
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
						<div className="mono">{createdEnrollToken}</div>
					</div>
				) : null}
			</div>

			<div className="card">
				<table className="table">
					<thead>
						<tr>
							<th>Label</th>
							<th>Created</th>
							<th>Status</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{keys.map((k) => (
							<tr key={k.id}>
								<td>{k.label ?? <span className="muted">(no label)</span>}</td>
								<td className="mono">{new Date(k.created_at).toLocaleString()}</td>
								<td>{k.revoked ? "revoked" : "active"}</td>
								<td className="right">
									<button
										className="button button-secondary"
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

			<div className="card">
				<table className="table">
					<thead>
						<tr>
							<th>Label</th>
							<th>Created</th>
							<th>Expires</th>
							<th>Status</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{enrollTokens.map((t) => (
							<tr key={t.id}>
								<td>{t.label ?? <span className="muted">(no label)</span>}</td>
								<td className="mono">{new Date(t.created_at).toLocaleString()}</td>
								<td className="mono">{new Date(t.expires_at).toLocaleString()}</td>
								<td>
									{t.consumed_at
										? "consumed"
										: Date.now() > Date.parse(t.expires_at)
											? "expired"
											: "active"}
								</td>
								<td className="right">
									<button
										className="button button-secondary"
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
	);
}
