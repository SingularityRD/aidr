import { useCallback, useEffect, useMemo, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import { readTenantAdmission, type TenantAdmission } from "../tenant-admission";

type ApiKeyRow = {
	id: string;
	label: string | null;
	revoked: boolean;
	created_at: string;
	scope?: string | null;
	install_limit?: number | null;
};

/**
 * Key types issued by /v1/api-keys. A Browser Guard key can only report
 * counts-only privacy scans for up to `install_limit` browser installations;
 * it is the key to put in browser management policy, which users can read.
 */
const BROWSER_GUARD_KEY_SCOPE = "ingest:browser_guard";
const DEFAULT_INSTALL_LIMIT = 100;
const MAX_INSTALL_LIMIT = 100_000;
type KeyType = "tenant" | typeof BROWSER_GUARD_KEY_SCOPE;

/** `/api-keys?type=browser_guard` preselects the Browser Guard key type. */
function requestedKeyType(): KeyType {
	try {
		return new URLSearchParams(window.location.search).get("type") === "browser_guard"
			? BROWSER_GUARD_KEY_SCOPE
			: "tenant";
	} catch {
		return "tenant";
	}
}

function parseInstallLimit(value: string): number | null {
	if (!/^\d{1,6}$/.test(value.trim())) return null;
	const limit = Number(value.trim());
	return limit >= 1 && limit <= MAX_INSTALL_LIMIT ? limit : null;
}

function createKeyBody(
	keyType: KeyType,
	label: string,
	installLimit: number | null,
): Record<string, unknown> {
	const body = { action: "create", label: label || null };
	return keyType === BROWSER_GUARD_KEY_SCOPE
		? { ...body, scope: BROWSER_GUARD_KEY_SCOPE, install_limit: installLimit }
		: body;
}

const CREATED_KEY_NOTICE: Record<KeyType, string | null> = {
	tenant: null,
	[BROWSER_GUARD_KEY_SCOPE]:
		"Copy this Browser Guard key now (shown once) and paste it into the managed policy's telemetry.apiKey.",
};

function keyTypeLabel(key: ApiKeyRow): string {
	if (key.scope === BROWSER_GUARD_KEY_SCOPE) {
		return typeof key.install_limit === "number"
			? `Browser Guard ingest · up to ${key.install_limit.toLocaleString()} installs`
			: "Browser Guard ingest";
	}
	return "Tenant";
}

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
	const { currentTeam, currentRole } = useTeam();
	if (!currentTeam) return <div className="card">Select a team to manage its credentials.</div>;
	return (
		<TenantApiKeys
			key={currentTeam.id}
			tenantId={currentTeam.id}
			teamName={currentTeam.name}
			canWrite={currentRole !== null && ["owner", "admin", "member"].includes(currentRole)}
			canIssueIngestKey={currentRole === "owner" || currentRole === "admin"}
		/>
	);
}

function TenantApiKeys({
	tenantId,
	teamName,
	canWrite,
	canIssueIngestKey,
}: {
	tenantId: string;
	teamName: string;
	canWrite: boolean;
	canIssueIngestKey: boolean;
}) {
	const [admission, setAdmission] = useState<TenantAdmission | null>(null);
	const [accessStatus, setAccessStatus] = useState<string>("loading");
	const [keys, setKeys] = useState<ApiKeyRow[]>([]);
	const [label, setLabel] = useState("");
	const [keyType, setKeyType] = useState<KeyType>(requestedKeyType);
	const [installLimitInput, setInstallLimitInput] = useState(String(DEFAULT_INSTALL_LIMIT));
	const [createdKey, setCreatedKey] = useState<string | null>(null);
	const [createdKeyNotice, setCreatedKeyNotice] = useState<string | null>(null);
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
	const browserKey = keyType === BROWSER_GUARD_KEY_SCOPE;
	const installLimit = useMemo(() => parseInstallLimit(installLimitInput), [installLimitInput]);
	const createAllowed = browserKey ? canIssueIngestKey && installLimit !== null : canWrite;
	const trimmedEnrollLabel = useMemo(() => enrollLabel.trim(), [enrollLabel]);

	const load = useCallback(async () => {
		setError(null);
		const invoke = async (
			name: "pilot-status" | "api-keys" | "enrollment-tokens",
			options: InvokeOptions,
		) => {
			try {
				return await supabase.functions.invoke(name, {
					...options,
					headers: { "X-AIDR-Tenant-ID": tenantId },
				});
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

		if (pilotRes.error || pilotRes.data?.ok !== true) {
			setAdmission(null);
			setAccessStatus("unknown");
			setError(readErrorMessage(pilotRes.error, "Workspace access response is invalid."));
		} else {
			const data = (pilotRes.data ?? {}) as Record<string, unknown>;
			const updated = readTenantAdmission(data.admission);
			setAdmission(updated);
			setAccessStatus(updated?.status ?? "unknown");
		}

		const pilotData = (pilotRes.data ?? {}) as Record<string, unknown>;
		const approved =
			!pilotRes.error &&
			pilotData.ok === true &&
			readTenantAdmission(pilotData.admission)?.status === "active";
		if (!approved) {
			setKeys([]);
			setEnrollTokens([]);
			return;
		}

		if (keysRes.error || keysRes.data?.ok !== true || !Array.isArray(keysRes.data?.keys)) {
			setKeys([]);
			setEnrollTokens([]);
			setError(readErrorMessage(keysRes.error, "API key list response is invalid."));
			return;
		}
		setKeys(keysRes.data.keys as ApiKeyRow[]);

		if (enrollRes.error || enrollRes.data?.ok !== true || !Array.isArray(enrollRes.data?.tokens)) {
			setEnrollTokens([]);
			setError(readErrorMessage(enrollRes.error, "Enrollment token list response is invalid."));
			return;
		}
		setEnrollTokens(enrollRes.data.tokens as EnrollmentTokenRow[]);
	}, [tenantId]);

	useEffect(() => {
		load();
	}, [load]);

	const rotateKey = async (id: string) => {
		setBusy(true);
		setError(null);
		try {
			const res = await supabase.functions.invoke("api-keys", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": tenantId },
				body: { action: "renew", id },
			});
			if (res.error || res.data?.ok !== true) {
				throw new Error(readErrorMessage(res.error, "API key rotation was not confirmed."));
			}
			const data = (res.data ?? {}) as {
				api_key?: string;
				previous_secret_valid_until?: string | null;
			};
			if (!data.api_key) throw new Error("API key rotation was not confirmed.");
			setCreatedKey(data.api_key);
			setShowCreatedKey(false);
			setCopiedKey(false);
			const overlapEnd = data.previous_secret_valid_until
				? Date.parse(data.previous_secret_valid_until)
				: Number.NaN;
			setCreatedKeyNotice(
				Number.isFinite(overlapEnd)
					? `Copy this new key now (shown once). The previous key remains valid until ${new Date(overlapEnd).toLocaleString()}.`
					: "Copy this new key now (shown once). The previous key is no longer valid.",
			);
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, "API key rotation is unavailable."));
		} finally {
			setBusy(false);
		}
	};

	const approved = admission?.status === "active";

	return (
		<div className="stack">
			<div className="card">
				<h1>API Keys</h1>
				<p>Team: {teamName}</p>
				<p className="muted">Advanced: keys and enrollment tokens for manual setups and support.</p>

				{approved ? null : (
					<div className="notice">
						<div className="muted small">Workspace access</div>
						<div className="mono">{accessStatus}</div>
						<div className="muted small" style={{ marginTop: 8 }}>
							Activate workspace access before creating keys or enrolling devices. Use the
							Onboarding flow to check availability.
						</div>
					</div>
				)}

				<label className="label">
					Key type
					<select
						className="input"
						value={keyType}
						onChange={(e) => setKeyType(e.target.value as KeyType)}
					>
						<option value="tenant">Tenant key (CLI, IDE and agent connectors)</option>
						<option value={BROWSER_GUARD_KEY_SCOPE}>Browser Guard ingest-only key</option>
					</select>
				</label>
				{browserKey ? (
					<IngestKeyOptions
						value={installLimitInput}
						valid={installLimit !== null}
						canIssue={canIssueIngestKey}
						onChange={setInstallLimitInput}
					/>
				) : null}

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
						disabled={busy || !approved || !createAllowed || createdKey !== null}
						onClick={async () => {
							setBusy(true);
							setError(null);
							setCreatedKey(null);
							setCreatedKeyNotice(null);
							setShowCreatedKey(false);
							setCopiedKey(false);
							try {
								const res = await supabase.functions.invoke("api-keys", {
									method: "POST",
									headers: { "X-AIDR-Tenant-ID": tenantId },
									body: createKeyBody(keyType, trimmedLabel, installLimit),
								});
								if (res.error || res.data?.ok !== true) {
									setError(readErrorMessage(res.error, "API key creation was not confirmed."));
									return;
								}
								const data = (res.data ?? {}) as { api_key?: string };
								if (!data.api_key) {
									setError("Failed to create API key.");
									return;
								}
								setCreatedKey(data.api_key);
								setCreatedKeyNotice(CREATED_KEY_NOTICE[keyType]);
								setLabel("");
								await load();
							} catch (cause) {
								setError(readErrorMessage(cause, "API key creation is unavailable. Please retry."));
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
						disabled={busy}
						onClick={async () => {
							await load();
						}}
					>
						Refresh
					</button>
				</div>

				{createdKey ? (
					<div className="notice">
						<div className="muted small">
							{createdKeyNotice ?? "Copy this key now (shown once):"}
						</div>
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
						disabled={busy || !approved || !canWrite || createdEnrollToken !== null}
						onClick={async () => {
							setBusy(true);
							setError(null);
							setCreatedEnrollToken(null);
							setShowCreatedEnrollToken(false);
							setCopiedEnrollToken(false);
							try {
								const res = await supabase.functions.invoke("enrollment-tokens", {
									method: "POST",
									headers: { "X-AIDR-Tenant-ID": tenantId },
									body: { action: "create", label: trimmedEnrollLabel || null },
								});
								if (res.error || res.data?.ok !== true) {
									setError(
										readErrorMessage(res.error, "Enrollment token creation was not confirmed."),
									);
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
									readErrorMessage(
										cause,
										"Enrollment token creation is unavailable. Please retry.",
									),
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
								<th>Type</th>
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
									<td className="small">{keyTypeLabel(k)}</td>
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
											disabled={k.revoked || busy || !canWrite || createdKey !== null}
											onClick={() => rotateKey(k.id)}
										>
											Rotate
										</button>
										<button
											className="button button-secondary button-sm"
											type="button"
											disabled={k.revoked || busy || !canWrite}
											onClick={async () => {
												setBusy(true);
												setError(null);
												try {
													const res = await supabase.functions.invoke("api-keys", {
														method: "POST",
														headers: { "X-AIDR-Tenant-ID": tenantId },
														body: { action: "revoke", id: k.id },
													});
													if (res.error || res.data?.ok !== true) {
														throw new Error(
															readErrorMessage(res.error, "API key revocation was not confirmed."),
														);
													}
													await load();
												} catch (cause) {
													setError(readErrorMessage(cause, "API key revocation is unavailable."));
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
									<td colSpan={5} className="muted">
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
											disabled={busy || !canWrite}
											onClick={async () => {
												setBusy(true);
												setError(null);
												try {
													const { data, error: delErr } = await supabase.functions.invoke(
														"enrollment-tokens",
														{
															method: "POST",
															headers: { "X-AIDR-Tenant-ID": tenantId },
															body: { action: "delete", id: t.id },
														},
													);
													if (delErr || data?.ok !== true) {
														throw new Error(
															readErrorMessage(
																delErr,
																"Enrollment token deletion was not confirmed.",
															),
														);
													}
													await load();
												} catch (cause) {
													setError(
														readErrorMessage(cause, "Enrollment token deletion is unavailable."),
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

/** Options shown for an ingest-only Browser Guard key. */
function IngestKeyOptions({
	value,
	valid,
	canIssue,
	onChange,
}: {
	value: string;
	valid: boolean;
	canIssue: boolean;
	onChange: (value: string) => void;
}) {
	return (
		<div className="notice">
			<div className="muted small">
				For Browser Guard managed policy. Users of a managed browser can read this key, so it can
				only report counts-only privacy scans from Browser Guard, for at most the number of browser
				installations below. It cannot read policy, packs or reputation data. Only owners and admins
				can create one.
			</div>
			<label className="label" style={{ marginTop: 8 }}>
				Installation limit
				<input
					className="input"
					inputMode="numeric"
					value={value}
					onChange={(e) => onChange(e.target.value)}
					aria-invalid={!valid}
					style={{ maxWidth: 160 }}
				/>
			</label>
			{valid ? null : (
				<div className="muted small" role="status">
					Enter a whole number from 1 to {MAX_INSTALL_LIMIT.toLocaleString()}.
				</div>
			)}
			{canIssue ? null : (
				<div className="muted small" role="status">
					Ask a workspace owner or admin to create this key.
				</div>
			)}
		</div>
	);
}
