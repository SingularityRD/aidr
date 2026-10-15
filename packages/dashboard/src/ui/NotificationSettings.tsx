import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { DashboardMessageKey } from "../i18n/en";
import { englishT, type Translate, useRichT, useT } from "../i18n/I18nProvider";
import {
	AGENT_OFFLINE_BOUNDS,
	anyEventSelected,
	type ChannelTarget,
	type ChannelType,
	createNotificationChannel,
	DEFAULT_FILTERS,
	deleteNotificationChannel,
	EXCEPTION_DAYS_BOUNDS,
	generateWebhookSecret,
	loadNotificationSettings,
	type NotificationChannel,
	type NotificationDelivery,
	type NotificationFilters,
	parseRecipients,
	SEVERITIES,
	type NotificationSettings as Settings,
	type Severity,
	SPIKE_BOUNDS,
	type TestResult,
	testNotificationChannel,
	updateNotificationChannel,
} from "../lib/notification-channels";

/** Channel types; Slack and Microsoft Teams are product names in every language. */
const TYPE_LABELS: Record<ChannelType, (t: Translate) => string> = {
	slack: () => "Slack",
	teams: () => "Microsoft Teams",
	webhook: (t) => t("notify.type.webhook"),
	email: (t) => t("notify.type.email"),
};

function typeLabel(type: ChannelType, t: Translate): string {
	return TYPE_LABELS[type](t);
}

const EVENT_LABELS: Record<string, DashboardMessageKey> = {
	"incident.created": "notify.event.incidentCreated",
	"runtime.deny_critical": "notify.event.denyCritical",
	"approval.requested": "notify.event.approvalRequested",
	"privacy.blocked_spike": "notify.event.privacySpike",
	"notification.test": "notify.event.test",
	"agent.offline": "notify.event.agentOffline",
	"agent.recovered": "notify.event.agentRecovered",
	"agent.unprotected": "notify.event.agentUnprotected",
	"governance.review_overdue": "notify.event.reviewOverdue",
	"governance.intake_requested": "notify.event.intakeRequested",
	"governance.change_pending": "notify.event.changePending",
	"governance.exception_expiring": "notify.event.exceptionExpiring",
	"governance.digest": "notify.event.digest",
};

const SEVERITY_LABELS: Record<Severity, DashboardMessageKey> = {
	info: "common.severity.info",
	warning: "common.severity.warning",
	high: "common.severity.high",
	critical: "common.severity.critical",
};

/** Operator copy for the service's machine-readable errors. */
function notificationErrorMessage(code: string, t: Translate = englishT): string {
	switch (code) {
		case "mfa_required":
			return t("notify.error.mfaRequired");
		case "notification_channels_forbidden":
			return t("notify.error.forbidden");
		case "notifications_not_configured":
			return t("notify.error.notConfigured");
		case "notification_channel_limit":
			return t("notify.error.limit");
		case "notification_channel_name_conflict":
			return t("notify.error.nameConflict");
		case "notification_channel_not_found":
			return t("notify.error.notFound");
		case "invalid_channel_name":
			return t("notify.error.invalidName");
		case "invalid_filters":
			return t("notify.error.invalidFilters");
		case "url_not_https":
			return t("notify.error.notHttps");
		case "url_credentials_forbidden":
			return t("notify.error.credentials");
		case "url_port_forbidden":
			return t("notify.error.port");
		case "url_host_forbidden":
			return t("notify.error.host");
		case "url_host_not_allowed":
			return t("notify.error.hostNotAllowed");
		case "invalid_url":
			return t("notify.error.invalidUrl");
		case "invalid_webhook_secret":
			return t("notify.error.secret");
		case "invalid_recipients":
			return t("notify.error.recipients");
		case "workspace_not_active":
			return t("notify.error.notActive");
		case "rate_limited":
			return t("notify.error.rateLimited");
		case "session_revoked":
		case "invalid_access_token":
			return t("common.sessionInvalid");
		default:
			return t("notify.error.generic");
	}
}

function testMessage(result: TestResult, t: Translate): string {
	if (result.status === "delivered") {
		return result.statusCode
			? t("notify.test.deliveredHttp", { code: result.statusCode })
			: t("notify.test.delivered");
	}
	const detail = `${result.error ?? t("common.unknown")}${result.statusCode ? `, HTTP ${result.statusCode}` : ""}`;
	return result.status === "pending"
		? t("notify.test.pending", { detail })
		: t("notify.test.failed", { detail });
}

function eventSummary(filters: NotificationFilters, t: Translate): string {
	const events: string[] = [];
	if (filters.incidentCreated) {
		events.push(
			t("notify.summary.incidents", {
				severity: t(SEVERITY_LABELS[filters.incidentMinSeverity]),
			}),
		);
	}
	if (filters.runtimeDenyCritical) events.push(t("notify.summary.denies"));
	if (filters.approvalRequested) events.push(t("notify.summary.approvals"));
	if (filters.privacyBlockedSpike) {
		events.push(
			t("notify.summary.privacy", {
				threshold: filters.privacySpikeThreshold,
				minutes: filters.privacySpikeWindowMinutes,
			}),
		);
	}
	if (filters.agentOffline) {
		events.push(t("notify.summary.offline", { minutes: filters.agentOfflineMinutes }));
	}
	if (filters.governanceReviewOverdue) events.push(t("notify.summary.overdue"));
	if (filters.governanceIntakeRequested) events.push(t("notify.summary.intake"));
	if (filters.governanceChangePending) events.push(t("notify.summary.changes"));
	if (filters.governanceExceptionExpiring) {
		events.push(t("notify.summary.expiring", { days: filters.governanceExceptionDays }));
	}
	if (filters.governanceDigest) events.push(t("notify.event.digest"));
	return events.join(" · ");
}

function stepUpPath(tenantId: string): string {
	return `/auth/dlp-step-up?tenant=${encodeURIComponent(tenantId)}&return=settings`;
}

function within(value: number, bounds: { min: number; max: number }): boolean {
	return Number.isInteger(value) && value >= bounds.min && value <= bounds.max;
}

function filtersValid(filters: NotificationFilters): boolean {
	return (
		anyEventSelected(filters) &&
		within(filters.agentOfflineMinutes, AGENT_OFFLINE_BOUNDS) &&
		within(filters.governanceExceptionDays, EXCEPTION_DAYS_BOUNDS) &&
		within(filters.privacySpikeThreshold, SPIKE_BOUNDS.threshold) &&
		within(filters.privacySpikeWindowMinutes, SPIKE_BOUNDS.windowMinutes)
	);
}

function FilterFields({
	value,
	onChange,
	idPrefix,
}: {
	value: NotificationFilters;
	onChange: (next: NotificationFilters) => void;
	idPrefix: string;
}) {
	const t = useT();
	const set = (patch: Partial<NotificationFilters>) => onChange({ ...value, ...patch });
	return (
		<fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 8 }}>
			<legend className="label">{t("notify.filters.legend")}</legend>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.incidentCreated}
					onChange={(event) => set({ incidentCreated: event.target.checked })}
				/>
				<span>{t("notify.filters.incidents")}</span>
				<select
					className="input"
					aria-label={t("notify.filters.minSeverity")}
					style={{ width: "auto" }}
					value={value.incidentMinSeverity}
					disabled={!value.incidentCreated}
					onChange={(event) => set({ incidentMinSeverity: event.target.value as Severity })}
				>
					{SEVERITIES.map((severity) => (
						<option key={severity} value={severity}>
							{t(SEVERITY_LABELS[severity])}
						</option>
					))}
				</select>
			</label>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.runtimeDenyCritical}
					onChange={(event) => set({ runtimeDenyCritical: event.target.checked })}
				/>
				<span>{t("notify.filters.denies")}</span>
			</label>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.approvalRequested}
					onChange={(event) => set({ approvalRequested: event.target.checked })}
				/>
				<span>{t("notify.filters.approvals")}</span>
			</label>
			<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
				<label className="row" style={{ gap: 8 }}>
					<input
						type="checkbox"
						checked={value.privacyBlockedSpike}
						onChange={(event) => set({ privacyBlockedSpike: event.target.checked })}
					/>
					<span>{t("notify.filters.spikes")}</span>
				</label>
				<input
					id={`${idPrefix}-threshold`}
					className="input"
					aria-label={t("notify.filters.threshold")}
					type="number"
					min={SPIKE_BOUNDS.threshold.min}
					max={SPIKE_BOUNDS.threshold.max}
					style={{ width: 90 }}
					value={value.privacySpikeThreshold}
					disabled={!value.privacyBlockedSpike}
					onChange={(event) => set({ privacySpikeThreshold: Number(event.target.value) })}
				/>
				<span>{t("notify.filters.blockedWithin")}</span>
				<input
					className="input"
					aria-label={t("notify.filters.window")}
					type="number"
					min={SPIKE_BOUNDS.windowMinutes.min}
					max={SPIKE_BOUNDS.windowMinutes.max}
					style={{ width: 90 }}
					value={value.privacySpikeWindowMinutes}
					disabled={!value.privacyBlockedSpike}
					onChange={(event) => set({ privacySpikeWindowMinutes: Number(event.target.value) })}
				/>
				<span>{t("notify.filters.minutes")}</span>
			</div>
			<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
				<label className="row" style={{ gap: 8 }}>
					<input
						type="checkbox"
						checked={value.agentOffline}
						onChange={(event) => set({ agentOffline: event.target.checked })}
					/>
					<span>{t("notify.filters.offline")}</span>
				</label>
				<input
					id={`${idPrefix}-offline-minutes`}
					className="input"
					aria-label={t("notify.filters.offlineMinutes")}
					type="number"
					min={AGENT_OFFLINE_BOUNDS.min}
					max={AGENT_OFFLINE_BOUNDS.max}
					style={{ width: 100 }}
					value={value.agentOfflineMinutes}
					disabled={!value.agentOffline}
					onChange={(event) => set({ agentOfflineMinutes: Number(event.target.value) })}
				/>
				<span>{t("notify.filters.offlineNote")}</span>
			</div>
			<span className="label" style={{ marginTop: 4 }}>
				{t("notify.filters.governance")}
			</span>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.governanceReviewOverdue}
					onChange={(event) => set({ governanceReviewOverdue: event.target.checked })}
				/>
				<span>{t("notify.filters.overdue")}</span>
			</label>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.governanceIntakeRequested}
					onChange={(event) => set({ governanceIntakeRequested: event.target.checked })}
				/>
				<span>{t("notify.filters.intake")}</span>
			</label>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.governanceChangePending}
					onChange={(event) => set({ governanceChangePending: event.target.checked })}
				/>
				<span>{t("notify.filters.changes")}</span>
			</label>
			<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
				<label className="row" style={{ gap: 8 }}>
					<input
						type="checkbox"
						checked={value.governanceExceptionExpiring}
						onChange={(event) => set({ governanceExceptionExpiring: event.target.checked })}
					/>
					<span>{t("notify.filters.expiring")}</span>
				</label>
				<input
					className="input"
					aria-label={t("notify.filters.expiryWindow")}
					type="number"
					min={EXCEPTION_DAYS_BOUNDS.min}
					max={EXCEPTION_DAYS_BOUNDS.max}
					style={{ width: 80 }}
					value={value.governanceExceptionDays}
					disabled={!value.governanceExceptionExpiring}
					onChange={(event) => set({ governanceExceptionDays: Number(event.target.value) })}
				/>
				<span>{t("notify.filters.daysDaily")}</span>
			</div>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.governanceDigest}
					onChange={(event) => set({ governanceDigest: event.target.checked })}
				/>
				<span>{t("notify.filters.digest")}</span>
			</label>
		</fieldset>
	);
}

const URL_FIELDS: Record<
	Exclude<ChannelType, "email">,
	{ label: DashboardMessageKey; placeholder: string }
> = {
	slack: { label: "notify.url.slack", placeholder: "https://hooks.slack.com/services/…" },
	teams: {
		label: "notify.url.teams",
		placeholder: "https://….logic.azure.com/workflows/…",
	},
	webhook: { label: "notify.url.webhook", placeholder: "https://alerts.example.com/aidr" },
};

/** The destination the form would submit, or null while it is incomplete. */
function draftTarget(
	type: ChannelType,
	url: string,
	secret: string,
	recipients: string,
): ChannelTarget | null {
	if (type === "email") {
		const list = parseRecipients(recipients);
		return list.length > 0 ? { recipients: list } : null;
	}
	if (url.trim() === "") return null;
	if (type !== "webhook") return { url: url.trim() };
	return secret.trim() === "" ? null : { url: url.trim(), secret: secret.trim() };
}

function AddChannelForm({
	tenantId,
	mailConfigured,
	onCreated,
	onError,
}: {
	tenantId: string;
	mailConfigured: boolean;
	onCreated: (channel: NotificationChannel) => void;
	onError: (code: string) => void;
}) {
	const t = useT();
	const richT = useRichT();
	const [type, setType] = useState<ChannelType>("slack");
	const [name, setName] = useState("");
	const [url, setUrl] = useState("");
	const [secret, setSecret] = useState("");
	const [recipients, setRecipients] = useState("");
	const [filters, setFilters] = useState<NotificationFilters>({ ...DEFAULT_FILTERS });
	const [busy, setBusy] = useState(false);

	const target = draftTarget(type, url, secret, recipients);
	const canSave = !busy && name.trim() !== "" && target !== null && filtersValid(filters);

	async function submit(event: React.FormEvent) {
		event.preventDefault();
		if (!canSave || !target) return;
		setBusy(true);
		const result = await createNotificationChannel(tenantId, {
			type,
			name: name.trim(),
			target,
			filters,
		});
		setBusy(false);
		if (!result.ok) {
			onError(result.error);
			return;
		}
		// Destinations are write-only: clear them from the page once stored.
		setName("");
		setUrl("");
		setSecret("");
		setRecipients("");
		setFilters({ ...DEFAULT_FILTERS });
		onCreated(result.value);
	}

	return (
		<form
			onSubmit={submit}
			className="stack"
			aria-label={t("notify.add.label")}
			style={{ marginTop: 16, maxWidth: 560 }}
		>
			<h3>{t("notify.add.title")}</h3>
			<label className="label">
				{t("notify.add.type")}
				<select
					className="input"
					value={type}
					onChange={(event) => setType(event.target.value as ChannelType)}
				>
					{(Object.keys(TYPE_LABELS) as ChannelType[]).map((key) => (
						<option key={key} value={key}>
							{typeLabel(key, t)}
						</option>
					))}
				</select>
			</label>
			<label className="label">
				{t("notify.add.name")}
				<input
					className="input"
					value={name}
					maxLength={80}
					onChange={(event) => setName(event.target.value)}
					placeholder={t("notify.add.namePlaceholder")}
				/>
			</label>
			{type === "email" ? (
				<label className="label">
					{t("notify.add.recipients")}
					<textarea
						className="input"
						rows={2}
						value={recipients}
						onChange={(event) => setRecipients(event.target.value)}
						placeholder="soc@example.com, ir@example.com"
					/>
					{!mailConfigured ? (
						<span className="muted small">{t("notify.add.mailMissing")}</span>
					) : null}
				</label>
			) : (
				<label className="label">
					{t(URL_FIELDS[type].label)}
					<input
						className="input mono"
						type="url"
						autoComplete="off"
						value={url}
						onChange={(event) => setUrl(event.target.value)}
						placeholder={URL_FIELDS[type].placeholder}
					/>
				</label>
			)}
			{type === "webhook" ? (
				<div className="stack" style={{ gap: 4 }}>
					<label className="label" htmlFor="notification-webhook-secret">
						{t("notify.add.secret")}
					</label>
					<div className="row" style={{ gap: 8 }}>
						<input
							id="notification-webhook-secret"
							className="input mono"
							autoComplete="off"
							value={secret}
							onChange={(event) => setSecret(event.target.value)}
						/>
						<button
							type="button"
							className="button button-secondary button-sm"
							onClick={() => setSecret(generateWebhookSecret())}
						>
							{t("notify.add.generate")}
						</button>
					</div>
					<span className="muted small">
						{richT("notify.add.secretNote", {
							header: <span className="mono">X-AIDR-Signature: t=…,v1=…</span>,
						})}
					</span>
				</div>
			) : null}
			<FilterFields value={filters} onChange={setFilters} idPrefix="new-channel" />
			<div className="row">
				<button className="button" type="submit" disabled={!canSave}>
					{busy ? t("common.saving") : t("notify.add.submit")}
				</button>
			</div>
			<p className="muted small">{t("notify.add.note")}</p>
		</form>
	);
}

interface Notice {
	tone: "success" | "error";
	message: string;
	code?: string;
}

function ChannelStatus({ channel }: { channel: NotificationChannel }) {
	const t = useT();
	const last = channel.lastDeliveryStatus
		? t("notify.channel.last", {
				status: `${channel.lastDeliveryStatus}${channel.lastError ? ` (${channel.lastError})` : ""}`,
			})
		: null;
	return (
		<>
			<span className={channel.enabled ? "badge badge-success" : "badge badge-neutral"}>
				{channel.enabled ? t("common.enabled") : t("common.disabled")}
			</span>
			{last ? (
				<div className="muted" style={{ marginTop: 4 }}>
					{last}
				</div>
			) : null}
		</>
	);
}

function deliveryStatus(delivery: NotificationDelivery, t: Translate): string {
	return [
		delivery.status,
		delivery.lastError,
		delivery.lastStatusCode ? `HTTP ${delivery.lastStatusCode}` : null,
		delivery.attempts > 1 ? t("notify.channel.attempts", { count: delivery.attempts }) : null,
	]
		.filter(Boolean)
		.join(" · ");
}

function RecentDeliveries({
	deliveries,
	channels,
}: {
	deliveries: NotificationDelivery[];
	channels: NotificationChannel[];
}) {
	const t = useT();
	if (deliveries.length === 0) return null;
	const names = new Map(channels.map((channel) => [channel.id, channel.name]));
	return (
		<details style={{ marginTop: 16 }}>
			<summary>{t("notify.deliveries.title")}</summary>
			<div className="table-wrap">
				<table className="table">
					<thead>
						<tr>
							<th>{t("notify.deliveries.queued")}</th>
							<th>{t("notify.deliveries.channel")}</th>
							<th>{t("notify.deliveries.event")}</th>
							<th>{t("common.status")}</th>
						</tr>
					</thead>
					<tbody>
						{deliveries.map((delivery) => {
							const event = EVENT_LABELS[delivery.eventType];
							return (
								<tr key={delivery.id}>
									<td className="mono small">{new Date(delivery.createdAt).toLocaleString()}</td>
									<td className="small">
										{names.get(delivery.channelId) ?? t("notify.deliveries.deleted")}
									</td>
									<td className="small">{event ? t(event) : delivery.eventType}</td>
									<td className="small">{deliveryStatus(delivery, t)}</td>
								</tr>
							);
						})}
					</tbody>
				</table>
			</div>
		</details>
	);
}

function NoticeBanner({ notice, tenantId }: { notice: Notice; tenantId: string }) {
	const t = useT();
	const error = notice.tone === "error";
	return (
		<div
			className={`notice ${error ? "notice-danger" : "notice-success"}`}
			role={error ? "alert" : "status"}
			style={{ marginTop: 12 }}
		>
			{notice.message}
			{notice.code === "mfa_required" ? (
				<div style={{ marginTop: 8 }}>
					<Link className="button button-sm" to={stepUpPath(tenantId)}>
						{t("common.verifyMfa")}
					</Link>
				</div>
			) : null}
		</div>
	);
}

function ChannelRow({
	tenantId,
	channel,
	canManage,
	onChanged,
	onDeleted,
	onNotice,
}: {
	tenantId: string;
	channel: NotificationChannel;
	canManage: boolean;
	onChanged: (channel: NotificationChannel) => void;
	onDeleted: (id: string) => void;
	onNotice: (tone: "success" | "error", message: string, code?: string) => void;
}) {
	const t = useT();
	const [busy, setBusy] = useState(false);
	const [editing, setEditing] = useState(false);
	const [filters, setFilters] = useState(channel.filters);
	const [confirmDelete, setConfirmDelete] = useState(false);

	async function run<T>(
		action: () => Promise<{ ok: true; value: T } | { ok: false; error: string }>,
		done: (value: T) => void,
	) {
		setBusy(true);
		const result = await action();
		setBusy(false);
		if (!result.ok) onNotice("error", notificationErrorMessage(result.error, t), result.error);
		else done(result.value);
	}

	return (
		<tr>
			<td>
				<div>{channel.name}</div>
				<div className="muted small mono">{channel.targetHint}</div>
			</td>
			<td className="small">{typeLabel(channel.type, t)}</td>
			<td className="small">
				{editing ? (
					<div className="stack" style={{ gap: 8 }}>
						<FilterFields value={filters} onChange={setFilters} idPrefix={channel.id} />
						<div className="row" style={{ gap: 8 }}>
							<button
								type="button"
								className="button button-sm"
								disabled={busy || !filtersValid(filters)}
								onClick={() =>
									void run(
										() => updateNotificationChannel(tenantId, channel.id, { filters }),
										(updated) => {
											setEditing(false);
											onChanged(updated);
											onNotice("success", t("notify.row.updated", { name: updated.name }));
										},
									)
								}
							>
								{t("notify.row.saveEvents")}
							</button>
							<button
								type="button"
								className="button button-secondary button-sm"
								onClick={() => {
									setFilters(channel.filters);
									setEditing(false);
								}}
							>
								{t("common.cancel")}
							</button>
						</div>
					</div>
				) : (
					eventSummary(channel.filters, t)
				)}
			</td>
			<td className="small">
				<ChannelStatus channel={channel} />
			</td>
			<td className="right">
				{canManage ? (
					<div className="row" style={{ gap: 6, justifyContent: "flex-end", flexWrap: "wrap" }}>
						<button
							type="button"
							className="button button-secondary button-sm"
							disabled={busy}
							aria-label={t("notify.row.testLabel", { name: channel.name })}
							onClick={() =>
								void run(
									() => testNotificationChannel(tenantId, channel.id),
									(result) =>
										onNotice(
											result.status === "delivered" ? "success" : "error",
											testMessage(result, t),
										),
								)
							}
						>
							{t("notify.row.test")}
						</button>
						<button
							type="button"
							className="button button-secondary button-sm"
							disabled={busy}
							aria-label={t(
								channel.enabled ? "notify.row.disableLabel" : "notify.row.enableLabel",
								{
									name: channel.name,
								},
							)}
							onClick={() =>
								void run(
									() =>
										updateNotificationChannel(tenantId, channel.id, { enabled: !channel.enabled }),
									(updated) => onChanged(updated),
								)
							}
						>
							{channel.enabled ? t("notify.row.disable") : t("notify.row.enable")}
						</button>
						{!editing ? (
							<button
								type="button"
								className="button button-secondary button-sm"
								disabled={busy}
								aria-label={t("notify.row.editLabel", { name: channel.name })}
								onClick={() => {
									setFilters(channel.filters);
									setEditing(true);
								}}
							>
								{t("notify.row.edit")}
							</button>
						) : null}
						{confirmDelete ? (
							<button
								type="button"
								className="button button-danger button-sm"
								disabled={busy}
								aria-label={t("notify.row.confirmDeleteLabel", { name: channel.name })}
								onClick={() =>
									void run(
										() => deleteNotificationChannel(tenantId, channel.id),
										(id) => {
											onDeleted(id);
											onNotice("success", t("notify.row.deleted", { name: channel.name }));
										},
									)
								}
							>
								{t("notify.row.confirmDelete")}
							</button>
						) : (
							<button
								type="button"
								className="button button-ghost button-sm"
								disabled={busy}
								aria-label={t("notify.row.deleteLabel", { name: channel.name })}
								onClick={() => setConfirmDelete(true)}
							>
								{t("notify.row.delete")}
							</button>
						)}
					</div>
				) : null}
			</td>
		</tr>
	);
}

/** Settings → Notifications: tenant alert channels (owners and administrators). */
export function NotificationSettings({ tenantId }: { tenantId: string }) {
	const t = useT();
	const [settings, setSettings] = useState<Settings | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [notice, setNotice] = useState<Notice | null>(null);
	const request = useRef(0);

	const load = useCallback(async () => {
		const id = ++request.current;
		setLoadError(null);
		const result = await loadNotificationSettings(tenantId);
		if (id !== request.current) return;
		setSettings(result.ok ? result.value : null);
		setLoadError(result.ok ? null : result.error);
	}, [tenantId]);

	useEffect(() => {
		void load();
		return () => {
			request.current++;
		};
	}, [load]);

	const showNotice = (tone: Notice["tone"], message: string, code?: string) =>
		setNotice({ tone, message, code });

	if (loadError === "notification_channels_forbidden") {
		return (
			<div className="card">
				<h2>{t("notify.title")}</h2>
				<p className="muted">{notificationErrorMessage(loadError, t)}</p>
			</div>
		);
	}
	if (loadError || !settings) {
		return (
			<div className="card">
				<h2>{t("notify.title")}</h2>
				{loadError ? (
					<>
						<div className="notice notice-danger" role="alert">
							{notificationErrorMessage(loadError, t)}
						</div>
						<button className="button button-secondary" type="button" onClick={() => void load()}>
							{t("common.retry")}
						</button>
					</>
				) : (
					<p className="muted">{t("notify.loading")}</p>
				)}
			</div>
		);
	}

	const replace = (channel: NotificationChannel) =>
		setSettings((prev) =>
			prev
				? {
						...prev,
						channels: prev.channels.map((item) => (item.id === channel.id ? channel : item)),
					}
				: prev,
		);
	const canAdd =
		settings.canManage && settings.configured && settings.channels.length < settings.maxChannels;

	return (
		<div className="card">
			<h2>{t("notify.title")}</h2>
			<p className="muted">{t("notify.intro")}</p>
			{!settings.configured ? (
				<div className="notice notice-warning" role="status" style={{ marginTop: 12 }}>
					{notificationErrorMessage("notifications_not_configured", t)}
				</div>
			) : null}
			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}

			{settings.channels.length === 0 ? (
				<p className="muted" style={{ marginTop: 12 }}>
					{t("notify.empty")}
				</p>
			) : (
				<div className="table-wrap" style={{ marginTop: 12 }}>
					<table className="table">
						<thead>
							<tr>
								<th>{t("notify.deliveries.channel")}</th>
								<th>{t("notify.table.type")}</th>
								<th>{t("notify.table.events")}</th>
								<th>{t("common.status")}</th>
								<th className="right">
									<span className="sr-only">{t("notify.table.actions")}</span>
								</th>
							</tr>
						</thead>
						<tbody>
							{settings.channels.map((channel) => (
								<ChannelRow
									key={channel.id}
									tenantId={tenantId}
									channel={channel}
									canManage={settings.canManage}
									onChanged={replace}
									onDeleted={(id) =>
										setSettings((prev) =>
											prev
												? { ...prev, channels: prev.channels.filter((item) => item.id !== id) }
												: prev,
										)
									}
									onNotice={showNotice}
								/>
							))}
						</tbody>
					</table>
				</div>
			)}

			{canAdd ? (
				<AddChannelForm
					tenantId={tenantId}
					mailConfigured={settings.mailConfigured}
					onCreated={(channel) => {
						setSettings((prev) =>
							prev ? { ...prev, channels: [...prev.channels, channel] } : prev,
						);
						showNotice("success", t("notify.added", { name: channel.name }));
					}}
					onError={(code) => showNotice("error", notificationErrorMessage(code, t), code)}
				/>
			) : settings.canManage && settings.configured ? (
				<p className="muted small" style={{ marginTop: 12 }}>
					{t("notify.limit", { max: settings.maxChannels })}
				</p>
			) : null}

			<RecentDeliveries deliveries={settings.recentDeliveries} channels={settings.channels} />
			<p className="muted small" style={{ marginTop: 12 }}>
				{t("notify.mfaNote")}
			</p>
		</div>
	);
}
