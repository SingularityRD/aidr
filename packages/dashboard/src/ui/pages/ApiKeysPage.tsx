import { useCallback, useEffect, useMemo, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { englishT, type Translate, useT } from "../../i18n/I18nProvider";
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
const KEY_LIFETIMES: ReadonlyArray<{
	value: string;
	label: DashboardMessageKey;
	days: number | null;
}> = [
	{ value: "30", label: "keys.life.30", days: 30 },
	{ value: "90", label: "keys.life.90", days: 90 },
	{ value: "365", label: "keys.life.365", days: 365 },
	{ value: "730", label: "keys.life.730", days: 730 },
	{ value: "never", label: "keys.life.never", days: null },
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

export function labelProblem(label: string, t: Translate = englishT): string | null {
	if ([...label].length > MAX_KEY_LABEL_LENGTH)
		return t("keys.label.tooLong", { max: MAX_KEY_LABEL_LENGTH });
	if (CONTROL_CHARACTERS.test(label)) return t("keys.label.control");
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

const CREATED_KEY_NOTICE: Record<KeyType, DashboardMessageKey | null> = {
	tenant: null,
	[BROWSER_GUARD_KEY_SCOPE]: "keys.bgNotice",
};

function keyTypeLabel(key: ApiKeyRow, t: Translate): string {
	if (key.scope === BROWSER_GUARD_KEY_SCOPE) {
		return typeof key.install_limit === "number"
			? t("keys.type.bgLimit", { count: key.install_limit.toLocaleString() })
			: t("keys.type.bg");
	}
	return t("keys.type.tenant");
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
	const t = useT();
	if (!currentTeam) return <div className="card">{t("keys.noTeam")}</div>;
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
	const t = useT();
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
	const invalidLabel = labelProblem(trimmedLabel, t);
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
					error: cause instanceof Error ? cause : new Error(t("keys.serviceUnavailable")),
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
			setError(readErrorMessage(pilotRes.error, t("keys.accessInvalid")));
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
			setError(readErrorMessage(keysRes.error, t("keys.listInvalid")));
			return;
		}
		setKeys(keysRes.data.keys as ApiKeyRow[]);

		if (enrollRes.error || enrollRes.data?.ok !== true || !Array.isArray(enrollRes.data?.tokens)) {
			setEnrollTokens([]);
			setError(readErrorMessage(enrollRes.error, t("keys.tokenListInvalid")));
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
				throw new Error(readErrorMessage(res.error, t("keys.rotateUnconfirmed")));
			}
			const data = (res.data ?? {}) as {
				api_key?: string;
				previous_secret_valid_until?: string | null;
			};
			if (!data.api_key) throw new Error(t("keys.rotateUnconfirmed"));
			setCreatedKey(data.api_key);
			setShowCreatedKey(false);
			setCopiedKey(false);
			const overlapEnd = data.previous_secret_valid_until
				? Date.parse(data.previous_secret_valid_until)
				: Number.NaN;
			setCreatedKeyNotice(
				Number.isFinite(overlapEnd)
					? t("keys.rotatedOverlap", { time: new Date(overlapEnd).toLocaleString() })
					: t("keys.rotatedNow"),
			);
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, t("keys.rotateUnavailable")));
		} finally {
			setBusy(false);
		}
	};

	const approved = admission?.status === "active";

	return (
		<div className="stack">
			<div className="card">
				<h1>{t("nav.apiKeys")}</h1>
				<p>{t("keys.team", { name: teamName })}</p>
				<p className="muted">{t("keys.intro")}</p>

				{approved ? null : (
					<div className="notice">
						<div className="muted small">{t("keys.access")}</div>
						<div className="mono">{accessStatus}</div>
						<div className="muted small" style={{ marginTop: 8 }}>
							{t("keys.activateFirst")}
						</div>
					</div>
				)}

				<label className="label">
					{t("keys.keyType")}
					<select
						className="input"
						value={keyType}
						onChange={(e) => setKeyType(e.target.value as KeyType)}
					>
						<option value="tenant">{t("keys.option.tenant")}</option>
						<option value={BROWSER_GUARD_KEY_SCOPE}>{t("keys.option.bg")}</option>
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
					{t("keys.labelOptional")}
					<input
						className="input"
						value={label}
						onChange={(e) => setLabel(e.target.value)}
						placeholder={t("keys.labelPlaceholder")}
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
					{t("keys.expiresAfter")}
					<select className="input" value={lifetime} onChange={(e) => setLifetime(e.target.value)}>
						{KEY_LIFETIMES.map((option) => (
							<option key={option.value} value={option.value}>
								{t(option.label)}
							</option>
						))}
					</select>
				</label>
				{lifetimeDays(lifetime) === null ? (
					<div className="muted small" role="status">
						{t("keys.neverWarning")}
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
									setError(readErrorMessage(res.error, t("keys.createUnconfirmed")));
									return;
								}
								const data = (res.data ?? {}) as { api_key?: string };
								if (!data.api_key) {
									setError(t("keys.createFailed"));
									return;
								}
								setCreatedKey(data.api_key);
								const notice = CREATED_KEY_NOTICE[keyType];
								setCreatedKeyNotice(notice ? t(notice) : null);
								setLabel("");
								await load();
							} catch (cause) {
								setError(readErrorMessage(cause, t("keys.createUnavailable")));
							} finally {
								setBusy(false);
							}
						}}
					>
						{t("keys.generate")}
					</button>
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={async () => {
							await load();
						}}
					>
						{t("common.refresh")}
					</button>
				</div>

				{createdKey ? (
					<div className="notice">
						<div className="muted small">{createdKeyNotice ?? t("keys.copyOnce")}</div>
						<div className="row" style={{ marginTop: 6 }}>
							<input
								className="input mono"
								style={{ flex: "1 1 260px" }}
								readOnly
								type={showCreatedKey ? "text" : "password"}
								value={showCreatedKey ? createdKey : maskSecret(createdKey)}
								aria-label={t("keys.newKey")}
								autoComplete="off"
							/>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => setShowCreatedKey((visible) => !visible)}
							>
								{showCreatedKey ? t("onb.token.hide") : t("onb.token.reveal")}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={async () => {
									try {
										await navigator.clipboard.writeText(createdKey);
										setCopiedKey(true);
									} catch {
										setError(t("keys.copyBlocked"));
									}
								}}
							>
								{copiedKey ? t("onb.token.copied") : t("onb.token.copy")}
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
								{t("onb.token.clear")}
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
				<h2>{t("keys.tokens.title")}</h2>
				<p className="muted">{t("keys.tokens.intro")}</p>

				<label className="label">
					{t("keys.labelOptional")}
					<input
						className="input"
						value={enrollLabel}
						onChange={(e) => setEnrollLabel(e.target.value)}
						placeholder={t("keys.tokens.placeholder")}
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
									setError(readErrorMessage(res.error, t("keys.tokens.createUnconfirmed")));
									return;
								}
								const data = (res.data ?? {}) as { enrollment_token?: string };
								if (!data.enrollment_token) {
									setError(t("keys.tokens.createFailed"));
									return;
								}

								setCreatedEnrollToken(data.enrollment_token);
								setEnrollLabel("");
								await load();
							} catch (cause) {
								setError(readErrorMessage(cause, t("keys.tokens.createUnavailable")));
							} finally {
								setBusy(false);
							}
						}}
					>
						{t("keys.tokens.generate")}
					</button>
				</div>

				{createdEnrollToken ? (
					<div className="notice">
						<div className="muted small">{t("keys.tokens.copyOnce")}</div>
						<div className="row" style={{ marginTop: 6 }}>
							<input
								className="input mono"
								style={{ flex: "1 1 260px" }}
								readOnly
								type={showCreatedEnrollToken ? "text" : "password"}
								value={showCreatedEnrollToken ? createdEnrollToken : maskSecret(createdEnrollToken)}
								aria-label={t("keys.tokens.new")}
								autoComplete="off"
							/>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => setShowCreatedEnrollToken((visible) => !visible)}
							>
								{showCreatedEnrollToken ? t("onb.token.hide") : t("onb.token.reveal")}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={async () => {
									try {
										await navigator.clipboard.writeText(createdEnrollToken);
										setCopiedEnrollToken(true);
									} catch {
										setError(t("onb.token.copyBlocked"));
									}
								}}
							>
								{copiedEnrollToken ? t("onb.token.copied") : t("onb.token.copy")}
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
								{t("onb.token.clear")}
							</button>
						</div>
					</div>
				) : null}
			</div>

			<div className="card">
				<h2>{t("keys.issued")}</h2>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("keys.col.label")}</th>
								<th>{t("notify.table.type")}</th>
								<th>{t("keys.col.created")}</th>
								<th>{t("keys.col.expires")}</th>
								<th>{t("common.status")}</th>
								<th className="right">
									<span className="sr-only">{t("notify.table.actions")}</span>
								</th>
							</tr>
						</thead>
						<tbody>
							{keys.map((k) => (
								<tr key={k.id}>
									<td>{k.label ?? <span className="muted">{t("keys.noLabel")}</span>}</td>
									<td className="small">{keyTypeLabel(k, t)}</td>
									<td className="mono">{new Date(k.created_at).toLocaleString()}</td>
									<td className="mono">
										{k.expires_at ? (
											new Date(k.expires_at).toLocaleString()
										) : (
											<span className="muted">{t("keys.never")}</span>
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
											{t("keys.rotate")}
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
															readErrorMessage(res.error, t("keys.revokeUnconfirmed")),
														);
													}
													await load();
												} catch (cause) {
													setError(readErrorMessage(cause, t("keys.revokeUnavailable")));
												} finally {
													setBusy(false);
												}
											}}
										>
											{t("keys.revoke")}
										</button>
									</td>
								</tr>
							))}
							{keys.length === 0 ? (
								<tr>
									<td colSpan={6} className="muted">
										{t("keys.empty")}
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
			</div>

			<div className="card">
				<h2>{t("keys.tokens.issued")}</h2>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("keys.col.label")}</th>
								<th>{t("keys.col.created")}</th>
								<th>{t("keys.col.expires")}</th>
								<th>{t("common.status")}</th>
								<th className="right">
									<span className="sr-only">{t("notify.table.actions")}</span>
								</th>
							</tr>
						</thead>
						<tbody>
							{enrollTokens.map((token) => (
								<tr key={token.id}>
									<td>{token.label ?? <span className="muted">{t("keys.noLabel")}</span>}</td>
									<td className="mono">{new Date(token.created_at).toLocaleString()}</td>
									<td className="mono">{new Date(token.expires_at).toLocaleString()}</td>
									<td>
										{token.consumed_at ? (
											<span className="badge badge-neutral">{t("keys.status.consumed")}</span>
										) : Date.now() > Date.parse(token.expires_at) ? (
											<span className="badge badge-warning">{t("keys.status.expired")}</span>
										) : (
											<span className="badge badge-success">{t("keys.status.active")}</span>
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
															body: { action: "delete", id: token.id },
														},
													);
													if (delErr || data?.ok !== true) {
														throw new Error(
															readErrorMessage(delErr, t("keys.tokens.deleteUnconfirmed")),
														);
													}
													await load();
												} catch (cause) {
													setError(readErrorMessage(cause, t("keys.tokens.deleteUnavailable")));
												} finally {
													setBusy(false);
												}
											}}
										>
											{t("notify.row.delete")}
										</button>
									</td>
								</tr>
							))}
							{enrollTokens.length === 0 ? (
								<tr>
									<td colSpan={5} className="muted">
										{t("keys.tokens.empty")}
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
	const t = useT();
	if (keyRow.revoked) return <span className="badge badge-error">{t("keys.status.revoked")}</span>;
	const expiry = keyExpiryState(keyRow.expires_at);
	if (expiry.kind === "expired")
		return <span className="badge badge-error">{t("keys.status.expired")}</span>;
	if (expiry.kind === "expiring") {
		return (
			<span className="badge badge-warning" title={t("keys.rotateHint")}>
				{expiry.days === 1
					? t("keys.expiresInDay")
					: t("keys.expiresInDays", { days: expiry.days })}
			</span>
		);
	}
	return <span className="badge badge-success">{t("keys.status.active")}</span>;
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
	const t = useT();
	return (
		<div className="notice">
			<div className="muted small">{t("keys.bg.body")}</div>
			<label className="label" style={{ marginTop: 8 }}>
				{t("keys.bg.limit")}
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
					{t("keys.bg.limitInvalid", { max: MAX_INSTALL_LIMIT.toLocaleString() })}
				</div>
			)}
			{canIssue ? null : (
				<div className="muted small" role="status">
					{t("keys.bg.askAdmin")}
				</div>
			)}
		</div>
	);
}
