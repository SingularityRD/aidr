import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
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

const TYPE_LABELS: Record<ChannelType, string> = {
	slack: "Slack",
	teams: "Microsoft Teams",
	webhook: "Signed webhook",
	email: "E-mail",
};

const EVENT_LABELS: Record<string, string> = {
	"incident.created": "Incident created",
	"runtime.deny_critical": "Critical runtime deny",
	"approval.requested": "Approval requested",
	"privacy.blocked_spike": "Privacy block spike",
	"notification.test": "Test",
	"agent.offline": "Agent offline",
	"agent.recovered": "Agent back online",
	"governance.review_overdue": "AI reviews overdue",
	"governance.intake_requested": "AI intake request",
	"governance.change_pending": "Policy change awaiting approval",
	"governance.exception_expiring": "Exceptions expiring",
	"governance.digest": "Governance digest",
};

/** Operator copy for the service's machine-readable errors. */
export function notificationErrorMessage(code: string): string {
	switch (code) {
		case "mfa_required":
			return "Multi-factor verification is required to change alert channels. Verify with your authenticator, then try again.";
		case "notification_channels_forbidden":
			return "Only workspace owners and administrators can manage alert notifications.";
		case "notifications_not_configured":
			return "Alert delivery is not configured on this deployment. Ask your operator to set AIDR_NOTIFICATION_ENCRYPTION_KEYS.";
		case "notification_channel_limit":
			return "This workspace already has the maximum number of alert channels.";
		case "notification_channel_name_conflict":
			return "Another channel already uses that name.";
		case "notification_channel_not_found":
			return "That channel no longer exists. Reload the list.";
		case "invalid_channel_name":
			return "Enter a channel name of 1 to 80 characters.";
		case "invalid_filters":
			return "Select at least one event, with spike, offline and expiry settings inside the allowed ranges.";
		case "url_not_https":
			return "The destination must be an https:// URL.";
		case "url_credentials_forbidden":
			return "The destination URL must not contain a user name or password.";
		case "url_port_forbidden":
			return "The destination must use the standard HTTPS port (443; 8443 is also allowed for webhooks).";
		case "url_host_forbidden":
			return "Private, local and IP-address destinations are not allowed.";
		case "url_host_not_allowed":
			return "Use the incoming-webhook URL issued by Slack (hooks.slack.com/services/…) or by a Teams workflow.";
		case "invalid_url":
			return "Enter a valid destination URL.";
		case "invalid_webhook_secret":
			return "The signing secret must be 32 to 256 printable characters. Use Generate for a strong one.";
		case "invalid_recipients":
			return "Enter 1 to 10 valid e-mail addresses.";
		case "workspace_not_active":
			return "This workspace is not active, so alert channels can no longer be changed.";
		case "rate_limited":
			return "Too many changes or test sends. Wait a minute and try again.";
		case "session_revoked":
		case "invalid_access_token":
			return "Your session is no longer valid. Sign in again.";
		default:
			return "The notification service did not confirm the request.";
	}
}

function testMessage(result: TestResult): string {
	if (result.status === "delivered") {
		return `Test notification delivered${result.statusCode ? ` (HTTP ${result.statusCode})` : ""}.`;
	}
	const detail = result.error ?? "unknown";
	const code = result.statusCode ? `, HTTP ${result.statusCode}` : "";
	return result.status === "pending"
		? `The test could not be delivered yet (${detail}${code}).`
		: `The test was not delivered (${detail}${code}).`;
}

function eventSummary(filters: NotificationFilters): string {
	const events: string[] = [];
	if (filters.incidentCreated) events.push(`Incidents ≥ ${filters.incidentMinSeverity}`);
	if (filters.runtimeDenyCritical) events.push("Critical denies");
	if (filters.approvalRequested) events.push("Approval requests");
	if (filters.privacyBlockedSpike) {
		events.push(
			`Privacy blocks ≥ ${filters.privacySpikeThreshold}/${filters.privacySpikeWindowMinutes} min`,
		);
	}
	if (filters.agentOffline) events.push(`Agents offline ≥ ${filters.agentOfflineMinutes} min`);
	if (filters.governanceReviewOverdue) events.push("Overdue AI reviews");
	if (filters.governanceIntakeRequested) events.push("AI intake requests");
	if (filters.governanceChangePending) events.push("Policy changes awaiting approval");
	if (filters.governanceExceptionExpiring) {
		events.push(`Exceptions expiring ≤ ${filters.governanceExceptionDays} d`);
	}
	if (filters.governanceDigest) events.push("Governance digest");
	return events.join(" · ");
}

function stepUpPath(tenantId: string): string {
	return `/auth/dlp-step-up?tenant=${encodeURIComponent(tenantId)}&return=settings`;
}

function within(value: number, bounds: { min: number; max: number }): boolean {
	return Number.isInteger(value) && value >= bounds.min && value <= bounds.max;
}

export function filtersValid(filters: NotificationFilters): boolean {
	const { threshold, windowMinutes } = SPIKE_BOUNDS;
	return (
		anyEventSelected(filters) &&
		within(filters.agentOfflineMinutes, AGENT_OFFLINE_BOUNDS) &&
		within(filters.governanceExceptionDays, EXCEPTION_DAYS_BOUNDS) &&
		Number.isInteger(filters.privacySpikeThreshold) &&
		filters.privacySpikeThreshold >= threshold.min &&
		filters.privacySpikeThreshold <= threshold.max &&
		Number.isInteger(filters.privacySpikeWindowMinutes) &&
		filters.privacySpikeWindowMinutes >= windowMinutes.min &&
		filters.privacySpikeWindowMinutes <= windowMinutes.max
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
	const set = (patch: Partial<NotificationFilters>) => onChange({ ...value, ...patch });
	return (
		<fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 8 }}>
			<legend className="label">Send alerts for</legend>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.incidentCreated}
					onChange={(event) => set({ incidentCreated: event.target.checked })}
				/>
				<span>New incidents with severity at least</span>
				<select
					className="input"
					aria-label="Minimum incident severity"
					style={{ width: "auto" }}
					value={value.incidentMinSeverity}
					disabled={!value.incidentCreated}
					onChange={(event) => set({ incidentMinSeverity: event.target.value as Severity })}
				>
					{SEVERITIES.map((severity) => (
						<option key={severity} value={severity}>
							{severity}
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
				<span>Critical runtime denies</span>
			</label>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.approvalRequested}
					onChange={(event) => set({ approvalRequested: event.target.checked })}
				/>
				<span>Actions awaiting out-of-band approval</span>
			</label>
			<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
				<label className="row" style={{ gap: 8 }}>
					<input
						type="checkbox"
						checked={value.privacyBlockedSpike}
						onChange={(event) => set({ privacyBlockedSpike: event.target.checked })}
					/>
					<span>Spikes in blocked AI prompts:</span>
				</label>
				<input
					id={`${idPrefix}-threshold`}
					className="input"
					aria-label="Blocked prompts threshold"
					type="number"
					min={SPIKE_BOUNDS.threshold.min}
					max={SPIKE_BOUNDS.threshold.max}
					style={{ width: 90 }}
					value={value.privacySpikeThreshold}
					disabled={!value.privacyBlockedSpike}
					onChange={(event) => set({ privacySpikeThreshold: Number(event.target.value) })}
				/>
				<span>blocked within</span>
				<input
					className="input"
					aria-label="Spike window in minutes"
					type="number"
					min={SPIKE_BOUNDS.windowMinutes.min}
					max={SPIKE_BOUNDS.windowMinutes.max}
					style={{ width: 90 }}
					value={value.privacySpikeWindowMinutes}
					disabled={!value.privacyBlockedSpike}
					onChange={(event) => set({ privacySpikeWindowMinutes: Number(event.target.value) })}
				/>
				<span>minutes</span>
			</div>
			<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
				<label className="row" style={{ gap: 8 }}>
					<input
						type="checkbox"
						checked={value.agentOffline}
						onChange={(event) => set({ agentOffline: event.target.checked })}
					/>
					<span>Enrolled agent not seen for</span>
				</label>
				<input
					id={`${idPrefix}-offline-minutes`}
					className="input"
					aria-label="Agent offline threshold in minutes"
					type="number"
					min={AGENT_OFFLINE_BOUNDS.min}
					max={AGENT_OFFLINE_BOUNDS.max}
					style={{ width: 100 }}
					value={value.agentOfflineMinutes}
					disabled={!value.agentOffline}
					onChange={(event) => set({ agentOfflineMinutes: Number(event.target.value) })}
				/>
				<span>minutes (one alert per outage, plus a notice when it reports again)</span>
			</div>
			<span className="label" style={{ marginTop: 4 }}>
				AI governance
			</span>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.governanceReviewOverdue}
					onChange={(event) => set({ governanceReviewOverdue: event.target.checked })}
				/>
				<span>AI register items past their review date (daily count)</span>
			</label>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.governanceIntakeRequested}
					onChange={(event) => set({ governanceIntakeRequested: event.target.checked })}
				/>
				<span>New AI intake requests</span>
			</label>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.governanceChangePending}
					onChange={(event) => set({ governanceChangePending: event.target.checked })}
				/>
				<span>Four-eyes policy changes awaiting approval</span>
			</label>
			<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
				<label className="row" style={{ gap: 8 }}>
					<input
						type="checkbox"
						checked={value.governanceExceptionExpiring}
						onChange={(event) => set({ governanceExceptionExpiring: event.target.checked })}
					/>
					<span>Approved exceptions expiring within</span>
				</label>
				<input
					className="input"
					aria-label="Exception expiry window in days"
					type="number"
					min={EXCEPTION_DAYS_BOUNDS.min}
					max={EXCEPTION_DAYS_BOUNDS.max}
					style={{ width: 80 }}
					value={value.governanceExceptionDays}
					disabled={!value.governanceExceptionExpiring}
					onChange={(event) => set({ governanceExceptionDays: Number(event.target.value) })}
				/>
				<span>days (daily count)</span>
			</div>
			<label className="row" style={{ gap: 8 }}>
				<input
					type="checkbox"
					checked={value.governanceDigest}
					onChange={(event) => set({ governanceDigest: event.target.checked })}
				/>
				<span>Scheduled governance digest (counts only; sent when the digest schedule runs)</span>
			</label>
		</fieldset>
	);
}

const URL_FIELDS: Record<Exclude<ChannelType, "email">, { label: string; placeholder: string }> = {
	slack: { label: "Slack incoming-webhook URL", placeholder: "https://hooks.slack.com/services/…" },
	teams: {
		label: "Teams workflow webhook URL",
		placeholder: "https://….logic.azure.com/workflows/…",
	},
	webhook: { label: "Webhook URL (https)", placeholder: "https://alerts.example.com/aidr" },
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
			aria-label="Add alert channel"
			style={{ marginTop: 16, maxWidth: 560 }}
		>
			<h3>Add a channel</h3>
			<label className="label">
				Channel type
				<select
					className="input"
					value={type}
					onChange={(event) => setType(event.target.value as ChannelType)}
				>
					{(Object.keys(TYPE_LABELS) as ChannelType[]).map((key) => (
						<option key={key} value={key}>
							{TYPE_LABELS[key]}
						</option>
					))}
				</select>
			</label>
			<label className="label">
				Channel name
				<input
					className="input"
					value={name}
					maxLength={80}
					onChange={(event) => setName(event.target.value)}
					placeholder="SOC on-call"
				/>
			</label>
			{type === "email" ? (
				<label className="label">
					Recipients
					<textarea
						className="input"
						rows={2}
						value={recipients}
						onChange={(event) => setRecipients(event.target.value)}
						placeholder="soc@example.com, ir@example.com"
					/>
					{!mailConfigured ? (
						<span className="muted small">
							E-mail delivery is not configured on this deployment; e-mail alerts will fail until
							your operator configures a mail provider.
						</span>
					) : null}
				</label>
			) : (
				<label className="label">
					{URL_FIELDS[type].label}
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
						Signing secret
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
							Generate
						</button>
					</div>
					<span className="muted small">
						Copy this into your receiver now: it is stored encrypted and never shown again. Requests
						carry <span className="mono">X-AIDR-Signature: t=…,v1=…</span> (HMAC-SHA256).
					</span>
				</div>
			) : null}
			<FilterFields value={filters} onChange={setFilters} idPrefix="new-channel" />
			<div className="row">
				<button className="button" type="submit" disabled={!canSave}>
					{busy ? "Saving…" : "Add channel"}
				</button>
			</div>
			<p className="muted small">
				Destinations are validated (https only, no private or internal addresses), stored encrypted,
				and never displayed again. Alerts carry identifiers, severities, categories and counts only
				— never prompts, commands or file contents.
			</p>
		</form>
	);
}

interface Notice {
	tone: "success" | "error";
	message: string;
	code?: string;
}

function ChannelStatus({ channel }: { channel: NotificationChannel }) {
	const last = channel.lastDeliveryStatus
		? `Last: ${channel.lastDeliveryStatus}${channel.lastError ? ` (${channel.lastError})` : ""}`
		: null;
	return (
		<>
			<span className={channel.enabled ? "badge badge-success" : "badge badge-neutral"}>
				{channel.enabled ? "enabled" : "disabled"}
			</span>
			{last ? (
				<div className="muted" style={{ marginTop: 4 }}>
					{last}
				</div>
			) : null}
		</>
	);
}

function deliveryStatus(delivery: NotificationDelivery): string {
	return [
		delivery.status,
		delivery.lastError,
		delivery.lastStatusCode ? `HTTP ${delivery.lastStatusCode}` : null,
		delivery.attempts > 1 ? `${delivery.attempts} attempts` : null,
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
	if (deliveries.length === 0) return null;
	const names = new Map(channels.map((channel) => [channel.id, channel.name]));
	return (
		<details style={{ marginTop: 16 }}>
			<summary>Recent deliveries</summary>
			<div className="table-wrap">
				<table className="table">
					<thead>
						<tr>
							<th>Queued</th>
							<th>Channel</th>
							<th>Event</th>
							<th>Status</th>
						</tr>
					</thead>
					<tbody>
						{deliveries.map((delivery) => (
							<tr key={delivery.id}>
								<td className="mono small">{new Date(delivery.createdAt).toLocaleString()}</td>
								<td className="small">{names.get(delivery.channelId) ?? "(deleted)"}</td>
								<td className="small">{EVENT_LABELS[delivery.eventType] ?? delivery.eventType}</td>
								<td className="small">{deliveryStatus(delivery)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</details>
	);
}

function NoticeBanner({ notice, tenantId }: { notice: Notice; tenantId: string }) {
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
						Verify with authenticator
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
		if (!result.ok) onNotice("error", notificationErrorMessage(result.error), result.error);
		else done(result.value);
	}

	return (
		<tr>
			<td>
				<div>{channel.name}</div>
				<div className="muted small mono">{channel.targetHint}</div>
			</td>
			<td className="small">{TYPE_LABELS[channel.type]}</td>
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
											onNotice("success", `Events updated for ${updated.name}.`);
										},
									)
								}
							>
								Save events
							</button>
							<button
								type="button"
								className="button button-secondary button-sm"
								onClick={() => {
									setFilters(channel.filters);
									setEditing(false);
								}}
							>
								Cancel
							</button>
						</div>
					</div>
				) : (
					eventSummary(channel.filters)
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
							aria-label={`Send test to ${channel.name}`}
							onClick={() =>
								void run(
									() => testNotificationChannel(tenantId, channel.id),
									(result) =>
										onNotice(
											result.status === "delivered" ? "success" : "error",
											testMessage(result),
										),
								)
							}
						>
							Send test
						</button>
						<button
							type="button"
							className="button button-secondary button-sm"
							disabled={busy}
							aria-label={`${channel.enabled ? "Disable" : "Enable"} ${channel.name}`}
							onClick={() =>
								void run(
									() =>
										updateNotificationChannel(tenantId, channel.id, { enabled: !channel.enabled }),
									(updated) => onChanged(updated),
								)
							}
						>
							{channel.enabled ? "Disable" : "Enable"}
						</button>
						{!editing ? (
							<button
								type="button"
								className="button button-secondary button-sm"
								disabled={busy}
								aria-label={`Edit events for ${channel.name}`}
								onClick={() => {
									setFilters(channel.filters);
									setEditing(true);
								}}
							>
								Edit events
							</button>
						) : null}
						{confirmDelete ? (
							<button
								type="button"
								className="button button-danger button-sm"
								disabled={busy}
								aria-label={`Confirm delete ${channel.name}`}
								onClick={() =>
									void run(
										() => deleteNotificationChannel(tenantId, channel.id),
										(id) => {
											onDeleted(id);
											onNotice("success", `Deleted ${channel.name}.`);
										},
									)
								}
							>
								Confirm delete
							</button>
						) : (
							<button
								type="button"
								className="button button-ghost button-sm"
								disabled={busy}
								aria-label={`Delete ${channel.name}`}
								onClick={() => setConfirmDelete(true)}
							>
								Delete
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
				<h2>Notifications</h2>
				<p className="muted">{notificationErrorMessage(loadError)}</p>
			</div>
		);
	}
	if (loadError || !settings) {
		return (
			<div className="card">
				<h2>Notifications</h2>
				{loadError ? (
					<>
						<div className="notice notice-danger" role="alert">
							{notificationErrorMessage(loadError)}
						</div>
						<button className="button button-secondary" type="button" onClick={() => void load()}>
							Retry
						</button>
					</>
				) : (
					<p className="muted">Loading alert channels…</p>
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
			<h2>Notifications</h2>
			<p className="muted">
				Real-time alerts to Slack, Microsoft Teams, signed webhooks or e-mail when incidents open,
				critical actions are blocked, approvals are requested or blocked AI prompts spike.
			</p>
			{!settings.configured ? (
				<div className="notice notice-warning" role="status" style={{ marginTop: 12 }}>
					{notificationErrorMessage("notifications_not_configured")}
				</div>
			) : null}
			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}

			{settings.channels.length === 0 ? (
				<p className="muted" style={{ marginTop: 12 }}>
					No alert channels yet.
				</p>
			) : (
				<div className="table-wrap" style={{ marginTop: 12 }}>
					<table className="table">
						<thead>
							<tr>
								<th>Channel</th>
								<th>Type</th>
								<th>Events</th>
								<th>Status</th>
								<th className="right">
									<span className="sr-only">Actions</span>
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
						showNotice("success", `Added ${channel.name}. Send a test to confirm delivery.`);
					}}
					onError={(code) => showNotice("error", notificationErrorMessage(code), code)}
				/>
			) : settings.canManage && settings.configured ? (
				<p className="muted small" style={{ marginTop: 12 }}>
					This workspace has reached the limit of {settings.maxChannels} alert channels.
				</p>
			) : null}

			<RecentDeliveries deliveries={settings.recentDeliveries} channels={settings.channels} />
			<p className="muted small" style={{ marginTop: 12 }}>
				Changes and test sends require multi-factor verification (AAL2) and are recorded in the
				audit log.
			</p>
		</div>
	);
}
