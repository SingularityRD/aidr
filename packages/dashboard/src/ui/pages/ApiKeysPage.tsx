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
	expires_at?: string | null;
	rotated_at?: string | null;
};

/**
 * Key lifetimes offered at issuance (/v1/api-keys `expires_in_days`; `null` is
 * an explicit non-expiring key). Matches the edge function's 1..730 day bound.
 */
const KEY_LIFETIMES: ReadonlyArray<{ value: string; label: string; days: number | null }> = [
	{ value: "30", label: "30 days", days: 30 },
	{ value: "90", label: "90 days", days: 90 },
	{ value: "365", label: "1 year (recommended)", days: 365 },
	{ value: "730", label: "2 years", days: 730 },
	{ value: "never", label: "Never expires (not recommended)", days: null },
];
const DEFAULT_KEY_LIFETIME = "365";
/** Same bounds as the api_keys_label_check constraint. */
export const MAX_KEY_LABEL_LENGTH = 100;
const DAY_MS = 86_400_000;
/** Keys this close to expiry are flagged in the list. */
export const KEY_EXPIRY_WARNING_DAYS = 30;

function lifetimeDays(value: string): number | null {
	return KEY_LIFETIMES.find((option) => option.value === value)?.days ?? null;
}

// Control characters are refused by the API; mirror the rule before submitting.
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;

export function labelProblem(label: string): string | null {
	if ([...label].length > MAX_KEY_LABEL_LENGTH)
		return `Use at most ${MAX_KEY_LABEL_LENGTH} characters.`;
	if (CONTROL_CHARACTERS.test(label)) return "Remove line breaks and other control characters.";
	return null;
}

/**
 * Rotation keeps the key's lifetime: a non-expiring key stays non-expiring and
 * an expiring key gets the same number of days from now (bounded 1..730).
 */
export function rotationLifetimeDays(key: ApiKeyRow): number | null {
	if (!key.expires_at) return null;
	const end = Date.parse(key.expires_at);
	const start = Date.parse(key.rotated_at ?? key.created_at);
	if (!Number.isFinite(end) || !Number.isFinite(start)) return 365;
	return Math.min(730, Math.max(1, Math.round((end - start) / DAY_MS)));
}

export type KeyExpiryState =
	| { kind: "none" }
	| { kind: "expired" }
	| { kind: "expiring"; days: number }
	| { kind: "valid"; days: number };

export function keyExpiryState(
	expiresAt: string | null | undefined,
	now = Date.now(),
): KeyExpiryState {
	if (!expiresAt) return { kind: "none" };
	const end = Date.parse(expiresAt);
	if (!Number.isFinite(end) || end <= now) return { kind: "expired" };
	const days = Math.ceil((end - now) / DAY_MS);
	return days <= KEY_EXPIRY_WARNING_DAYS ? { kind: "expiring", days } : { kind: "valid", days };
}

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
	expiresInDays: number | null,
): Record<string, unknown> {
	const body = { action: "create", label: label || null, expires_in_days: expiresInDays };
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
	const [lifetime, setLifetime] = useState(DEFAULT_KEY_LIFETIME);
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
	const invalidLabel = labelProblem(trimmedLabel);
	const browserKey = keyType === BROWSER_GUARD_KEY_SCOPE;
	const installLimit = useMemo(() => parseInstallLimit(installLimitInput), [installLimitInput]);
	const createAllowed =
		invalidLabel === null && (browserKey ? canIssueIngestKey && installLimit !== null : canWrite);
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

	const rotateKey = async (key: ApiKeyRow) => {
		setBusy(true);
		setError(null);
		try {
			const res = await supabase.functions.invoke("api-keys", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": tenantId },
				body: { action: "renew", id: key.id, expires_in_days: rotationLifetimeDays(key) },
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
						maxLength={MAX_KEY_LABEL_LENGTH}
						aria-invalid={invalidLabel !== null}
					/>
				</label>
				{invalidLabel ? (
					<div className="muted small" role="status">
						{invalidLabel}
					</div>
				) : null}

				<label className="label">
					Expires after
					<select className="input" value={lifetime} onChange={(e) => setLifetime(e.target.value)}>
						{KEY_LIFETIMES.map((option) => (
							<option key={option.value} value={option.value}>
								{option.label}
							</option>
						))}
					</select>
				</label>
				{lifetimeDays(lifetime) === null ? (
					<div className="muted small" role="status">
						A key that never expires stays valid until someone revokes it, even if it leaks. Prefer
						an expiry and rotate the key before it ends.
					</div>
				) : null}

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
									body: createKeyBody(keyType, trimmedLabel, installLimit, lifetimeDays(lifetime)),
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
								<th>Expires</th>
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
									<td className="mono">
										{k.expires_at ? (
											new Date(k.expires_at).toLocaleString()
										) : (
											<span className="muted">never</span>
										)}
									</td>
									<td>
										<KeyStatusBadge keyRow={k} />
									</td>
									<td className="right">
										<button
											className="button button-secondary button-sm"
											type="button"
											disabled={
												k.revoked ||
												keyExpiryState(k.expires_at).kind === "expired" ||
												busy ||
												!canWrite ||
												createdKey !== null
											}
											onClick={() => rotateKey(k)}
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
									<td colSpan={6} className="muted">
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

/** Status of an issued key, with an expiry warning before it stops working. */
function KeyStatusBadge({ keyRow }: { keyRow: ApiKeyRow }) {
	if (keyRow.revoked) return <span className="badge badge-error">revoked</span>;
	const expiry = keyExpiryState(keyRow.expires_at);
	if (expiry.kind === "expired") return <span className="badge badge-error">expired</span>;
	if (expiry.kind === "expiring") {
		return (
			<span className="badge badge-warning" title="Rotate this key before it expires.">
				expires in {expiry.days} {expiry.days === 1 ? "day" : "days"}
			</span>
		);
	}
	return <span className="badge badge-success">active</span>;
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
