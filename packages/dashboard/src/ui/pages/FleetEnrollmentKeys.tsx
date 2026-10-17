import { useCallback, useEffect, useState } from "react";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";

/** Row returned by GET /v1/fleet-keys (never the secret or its hash). */
type FleetKeyRow = {
	id: string;
	label: string | null;
	key_hint: string;
	seat_cap: number;
	enrolled_count: number;
	use_count: number;
	expires_at: string;
	created_at: string;
	last_used_at: string | null;
	revoked_at: string | null;
};

/** Same bounds as the fleet_enrollment_keys constraints and the Edge Function. */
const MAX_SEAT_CAP = 100_000;
const DEFAULT_SEAT_CAP = "500";
const LIFETIMES: ReadonlyArray<{ days: number; label: DashboardMessageKey }> = [
	{ days: 30, label: "fleet.life.30" },
	{ days: 90, label: "fleet.life.90" },
	{ days: 180, label: "fleet.life.180" },
	{ days: 365, label: "fleet.life.365" },
];
const DEFAULT_LIFETIME = 90;

export function parseSeatCap(value: string): number | null {
	if (!/^\d{1,6}$/.test(value.trim())) return null;
	const cap = Number(value.trim());
	return cap >= 1 && cap <= MAX_SEAT_CAP ? cap : null;
}

type FleetKeyState = "revoked" | "expired" | "exhausted" | "active";

export function fleetKeyState(key: FleetKeyRow, now = Date.now()): FleetKeyState {
	if (key.revoked_at) return "revoked";
	const end = Date.parse(key.expires_at);
	if (!Number.isFinite(end) || end <= now) return "expired";
	if (key.enrolled_count >= key.seat_cap) return "exhausted";
	return "active";
}

const STATE_BADGE: Record<FleetKeyState, { tone: string; label: DashboardMessageKey }> = {
	active: { tone: "badge-success", label: "fleet.status.active" },
	exhausted: { tone: "badge-warning", label: "fleet.status.exhausted" },
	expired: { tone: "badge-error", label: "fleet.status.expired" },
	revoked: { tone: "badge-error", label: "fleet.status.revoked" },
};

function StateBadge({ state, t }: { state: FleetKeyState; t: Translate }) {
	return <span className={`badge ${STATE_BADGE[state].tone}`}>{t(STATE_BADGE[state].label)}</span>;
}

function maskSecret(secret: string): string {
	return `${"•".repeat(Math.max(8, secret.length - 4))}${secret.slice(-4)}`;
}

/**
 * Fleet enrollment keys: one multi-use secret for the machine policy of a
 * whole fleet (MSI, Intune, GPO, Ansible). Owners and admins only; the secret
 * is shown once.
 */
export function FleetEnrollmentKeys({ tenantId }: { tenantId: string }) {
	const t = useT();
	const [keys, setKeys] = useState<FleetKeyRow[]>([]);
	const [label, setLabel] = useState("");
	const [seatCapInput, setSeatCapInput] = useState(DEFAULT_SEAT_CAP);
	const [lifetime, setLifetime] = useState(DEFAULT_LIFETIME);
	const [created, setCreated] = useState<string | null>(null);
	const [revealed, setRevealed] = useState(false);
	const [copied, setCopied] = useState(false);
	const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const seatCap = parseSeatCap(seatCapInput);
	const headers = { "X-AIDR-Tenant-ID": tenantId };

	const load = useCallback(async () => {
		try {
			const res = await supabase.functions.invoke("fleet-keys", {
				method: "GET",
				headers: { "X-AIDR-Tenant-ID": tenantId },
			});
			if (res.error || res.data?.ok !== true || !Array.isArray(res.data?.keys)) {
				setKeys([]);
				setError(readErrorMessage(res.error, t("fleet.listInvalid")));
				return;
			}
			setKeys(res.data.keys as FleetKeyRow[]);
		} catch (cause) {
			setKeys([]);
			setError(readErrorMessage(cause, t("fleet.listInvalid")));
		}
	}, [tenantId]);

	useEffect(() => {
		load();
	}, [load]);

	const create = async () => {
		if (seatCap === null) return;
		setBusy(true);
		setError(null);
		setCreated(null);
		setRevealed(false);
		setCopied(false);
		try {
			const res = await supabase.functions.invoke("fleet-keys", {
				method: "POST",
				headers,
				body: {
					action: "create",
					label: label.trim() || null,
					seat_cap: seatCap,
					ttl_days: lifetime,
				},
			});
			const secret = (res.data ?? {}) as { fleet_key?: unknown };
			if (res.error || res.data?.ok !== true || typeof secret.fleet_key !== "string") {
				setError(readErrorMessage(res.error, t("fleet.createUnconfirmed")));
				return;
			}
			setCreated(secret.fleet_key);
			setLabel("");
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, t("fleet.createUnavailable")));
		} finally {
			setBusy(false);
		}
	};

	const revoke = async (id: string) => {
		setBusy(true);
		setError(null);
		try {
			const res = await supabase.functions.invoke("fleet-keys", {
				method: "POST",
				headers,
				body: { action: "revoke", id },
			});
			if (res.error || res.data?.ok !== true) {
				throw new Error(readErrorMessage(res.error, t("fleet.revokeUnconfirmed")));
			}
			setConfirmRevoke(null);
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, t("fleet.revokeUnavailable")));
		} finally {
			setBusy(false);
		}
	};

	return (
		<div className="card">
			<h2>{t("fleet.title")}</h2>
			<p className="muted">{t("fleet.intro")}</p>
			<p className="muted small">{t("fleet.policyHint")}</p>

			<label className="label">
				{t("fleet.label")}
				<input
					className="input"
					value={label}
					maxLength={100}
					onChange={(e) => setLabel(e.target.value)}
					placeholder={t("fleet.labelPlaceholder")}
				/>
			</label>
			<label className="label">
				{t("fleet.seatCap")}
				<input
					className="input"
					inputMode="numeric"
					value={seatCapInput}
					onChange={(e) => setSeatCapInput(e.target.value)}
					aria-invalid={seatCap === null}
					style={{ maxWidth: 160 }}
				/>
			</label>
			{seatCap === null ? (
				<div className="muted small" role="status">
					{t("fleet.seatCapInvalid", { max: MAX_SEAT_CAP.toLocaleString() })}
				</div>
			) : null}
			<label className="label">
				{t("fleet.lifetime")}
				<select
					className="input"
					value={lifetime}
					onChange={(e) => setLifetime(Number(e.target.value))}
				>
					{LIFETIMES.map((option) => (
						<option key={option.days} value={option.days}>
							{t(option.label)}
						</option>
					))}
				</select>
			</label>
			<div className="row">
				<button
					className="button"
					type="button"
					disabled={busy || seatCap === null || created !== null}
					onClick={create}
				>
					{t("fleet.generate")}
				</button>
			</div>

			{created ? (
				<div className="notice">
					<div className="muted small">{t("fleet.copyOnce")}</div>
					<div className="row" style={{ marginTop: 6 }}>
						<input
							className="input mono"
							style={{ flex: "1 1 260px" }}
							readOnly
							type={revealed ? "text" : "password"}
							value={revealed ? created : maskSecret(created)}
							aria-label={t("fleet.newKey")}
							autoComplete="off"
						/>
						<button
							className="button button-secondary"
							type="button"
							onClick={() => setRevealed((v) => !v)}
						>
							{revealed ? t("onb.token.hide") : t("onb.token.reveal")}
						</button>
						<button
							className="button button-secondary"
							type="button"
							onClick={async () => {
								try {
									await navigator.clipboard.writeText(created);
									setCopied(true);
								} catch {
									setError(t("keys.copyBlocked"));
								}
							}}
						>
							{copied ? t("onb.token.copied") : t("onb.token.copy")}
						</button>
						<button
							className="button button-secondary"
							type="button"
							onClick={() => {
								setCreated(null);
								setRevealed(false);
								setCopied(false);
							}}
						>
							{t("onb.token.clear")}
						</button>
					</div>
				</div>
			) : null}
			{error ? (
				<div className="notice notice-danger" role="alert">
					{error}
				</div>
			) : null}

			<div className="table-wrap">
				<table className="table">
					<thead>
						<tr>
							<th>{t("keys.col.label")}</th>
							<th>{t("fleet.col.hint")}</th>
							<th>{t("fleet.col.owner")}</th>
							<th>{t("fleet.col.machines")}</th>
							<th>{t("fleet.col.uses")}</th>
							<th>{t("keys.col.expires")}</th>
							<th>{t("common.status")}</th>
							<th className="right">
								<span className="sr-only">{t("notify.table.actions")}</span>
							</th>
						</tr>
					</thead>
					<tbody>
						{keys.map((key) => {
							const state = fleetKeyState(key);
							return (
								<tr key={key.id}>
									<td>{key.label ?? <span className="muted">{t("keys.noLabel")}</span>}</td>
									<td className="mono">…{key.key_hint}</td>
									<td className="small">{t("fleet.owner.tenant")}</td>
									<td className="mono">
										{key.enrolled_count.toLocaleString()} / {key.seat_cap.toLocaleString()}
									</td>
									<td className="mono">{key.use_count.toLocaleString()}</td>
									<td className="mono">{new Date(key.expires_at).toLocaleString()}</td>
									<td>
										<StateBadge state={state} t={t} />
									</td>
									<td className="right">
										{state === "revoked" ? null : confirmRevoke === key.id ? (
											<button
												className="button button-secondary button-sm"
												type="button"
												disabled={busy}
												onClick={() => revoke(key.id)}
											>
												{t("fleet.confirmRevoke")}
											</button>
										) : (
											<button
												className="button button-secondary button-sm"
												type="button"
												disabled={busy}
												onClick={() => setConfirmRevoke(key.id)}
											>
												{t("keys.revoke")}
											</button>
										)}
									</td>
								</tr>
							);
						})}
						{keys.length === 0 ? (
							<tr>
								<td colSpan={8} className="muted">
									{t("fleet.empty")}
								</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
		</div>
	);
}
