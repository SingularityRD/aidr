// Alert delivery: message formats, webhook signatures, backoff and the
// dispatcher loop shared by `notification-dispatch` and the console test send.
//
// Contract: docs/contracts/notifications.md.
//
// Payloads never carry event content. The outbox row holds identifiers,
// severities, categories and counts (see migration 20260926000021), and
// `buildNotification` re-validates every one of those fields against a fixed
// allow-list before it is rendered, so an unexpected key in the database can
// never reach a receiver.

import { escapeHtml, type Mailer } from "./mailer.ts";
import {
	type ChannelTarget,
	type ChannelType,
	CHANNEL_TYPES,
	checkTargetUrl,
	decryptTarget,
	type DnsResolver,
	type NotificationKeyring,
	resolvePublicAddresses,
} from "./notification-targets.ts";

const NOTIFICATION_SCHEMA = "aidr.notification.v1";
const NOTIFICATION_EVENT_TYPES = [
	"incident.created",
	"runtime.deny_critical",
	"approval.requested",
	"privacy.blocked_spike",
	"notification.test",
	"agent.offline",
	"agent.recovered",
	"governance.review_overdue",
	"governance.intake_requested",
	"governance.change_pending",
	"governance.exception_expiring",
	"governance.digest",
] as const;
type NotificationEventType = (typeof NOTIFICATION_EVENT_TYPES)[number];
const SEVERITIES = ["info", "warning", "high", "critical"] as const;
type Severity = (typeof SEVERITIES)[number];

const SIGNATURE_HEADER = "X-AIDR-Signature";
const SIGNATURE_TOLERANCE_SECONDS = 300;
const USER_AGENT = "Singularity-AIDR-Notifications/1.0";
const DELIVERY_TIMEOUT_MS = 10_000;
const BACKOFF_BASE_SECONDS = 30;
const BACKOFF_CAP_SECONDS = 3600;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** Counts a governance digest may carry (migration 20260928000001); anything else is dropped. */
const DIGEST_COUNT_KEYS = [
	"agents_enrolled",
	"agents_active",
	"decisions_allow",
	"decisions_ask",
	"decisions_deny",
	"approvals_requested",
	"approvals_pending",
	"incidents_reported",
	"incidents_open",
	"incidents_open_critical",
	"browser_blocked",
	"browser_masked",
	"mcp_not_approved",
	"reviews_overdue",
	"intake_pending",
	"policy_changes_pending",
] as const;
type DigestCountKey = (typeof DIGEST_COUNT_KEYS)[number];

const DIGEST_LABELS: Record<DigestCountKey, string> = {
	agents_enrolled: "Agents enrolled",
	agents_active: "Agents active",
	decisions_allow: "Allowed actions",
	decisions_ask: "Held for approval",
	decisions_deny: "Blocked actions",
	approvals_requested: "Approvals requested",
	approvals_pending: "Approvals pending",
	incidents_reported: "Incidents reported",
	incidents_open: "Incidents open",
	incidents_open_critical: "Critical incidents open",
	browser_blocked: "Browser prompts blocked",
	browser_masked: "Browser prompts masked",
	mcp_not_approved: "Unapproved MCP servers",
	reviews_overdue: "AI reviews overdue",
	intake_pending: "AI intake requests pending",
	policy_changes_pending: "Policy changes awaiting approval",
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedInt(value: unknown, max: number): number | null {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max ? value : null;
}

// ── Message model ────────────────────────────────────────────────────────

/** The generic JSON body (schema aidr.notification.v1). */
export interface NotificationMessage {
	schema: typeof NOTIFICATION_SCHEMA;
	id: string;
	event: NotificationEventType;
	test: boolean;
	occurred_at: string;
	tenant_id: string;
	severity: Severity | null;
	category: string | null;
	// The keys marked optional are present (possibly null) on agent.* and
	// governance.* events only, so the body of every original event is
	// unchanged for receivers that validate the published v1 schema strictly.
	subject: { event_id: string | null; agent_id: string | null; incident_id: string | null; request_id?: string | null };
	counts: {
		findings: number | null;
		blocked: number | null;
		window_minutes: number | null;
		/** Items in a governance count (overdue reviews, expiring exceptions). */
		items?: number | null;
		window_days?: number | null;
		/** Offline threshold (agent.offline) or outage length (agent.recovered). */
		offline_minutes?: number | null;
	};
	/** Covered period of a governance digest. */
	period?: { from: string; to: string } | null;
	/** Counts-only governance digest (governance.digest), allow-listed keys. */
	digest?: Partial<Record<DigestCountKey, number>> | null;
	links: { dashboard: string | null };
}

/** Event types that carry the extended subject/counts/period/digest fields. */
function isExtendedEvent(event: NotificationEventType): boolean {
	return event.startsWith("agent.") || event.startsWith("governance.");
}

export interface DeliveryRecord {
	deliveryId: string;
	tenantId: string;
	eventType: NotificationEventType;
	payload: Record<string, unknown>;
	createdAt: string;
}

const DEEP_LINK_PATHS: Record<NotificationEventType, string> = {
	"incident.created": "/incidents",
	"runtime.deny_critical": "/incidents",
	"approval.requested": "/incidents",
	"privacy.blocked_spike": "/privacy-guard",
	"notification.test": "/settings",
	"agent.offline": "/agents",
	"agent.recovered": "/agents",
	"governance.review_overdue": "/governance/register",
	"governance.intake_requested": "/governance/requests",
	"governance.change_pending": "/governance/change-control",
	"governance.exception_expiring": "/governance/requests",
	"governance.digest": "/governance",
};

/** The dashboard origin for deep links, or null when not a usable URL. */
function dashboardOrigin(value: string | null | undefined): string | null {
	if (typeof value !== "string" || value.trim() === "") return null;
	try {
		const url = new URL(value.trim());
		const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
		if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) return null;
		if (url.username || url.password) return null;
		return url.origin;
	} catch {
		return null;
	}
}

function isoTime(value: unknown, fallback: string): string {
	const parsed = typeof value === "string" && value.length <= 64 ? Date.parse(value) : Number.NaN;
	if (Number.isFinite(parsed)) return new Date(parsed).toISOString();
	const fallbackParsed = Date.parse(fallback);
	return Number.isFinite(fallbackParsed) ? new Date(fallbackParsed).toISOString() : new Date(0).toISOString();
}

function optionalIso(value: unknown): string | null {
	if (typeof value !== "string" || value.length > 64) return null;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function digestCounts(value: unknown): NotificationMessage["digest"] {
	if (!isRecord(value)) return null;
	const counts: Partial<Record<DigestCountKey, number>> = {};
	for (const key of DIGEST_COUNT_KEYS) {
		const count = boundedInt(value[key], 10_000_000);
		if (count !== null) counts[key] = count;
	}
	return Object.keys(counts).length > 0 ? counts : null;
}

/** Allow-list projection of an outbox row into the public message. */
export function buildNotification(delivery: DeliveryRecord, dashboardUrl: string | null): NotificationMessage {
	const p = delivery.payload;
	const origin = dashboardOrigin(dashboardUrl);
	const severity = SEVERITIES.includes(p.severity as Severity) ? (p.severity as Severity) : null;
	const periodFrom = optionalIso(p.period_from);
	const periodTo = optionalIso(p.period_to);
	const extended = isExtendedEvent(delivery.eventType);
	const message: NotificationMessage = {
		schema: NOTIFICATION_SCHEMA,
		id: delivery.deliveryId,
		event: delivery.eventType,
		test: delivery.eventType === "notification.test",
		occurred_at: isoTime(p.occurred_at, delivery.createdAt),
		tenant_id: delivery.tenantId,
		severity,
		category: typeof p.category === "string" && IDENTIFIER.test(p.category) ? p.category : null,
		subject: {
			event_id: typeof p.event_row_id === "string" && /^[0-9]{1,19}$/.test(p.event_row_id) ? p.event_row_id : null,
			agent_id: typeof p.agent_id === "string" && UUID.test(p.agent_id) ? p.agent_id.toLowerCase() : null,
			incident_id: typeof p.incident_id === "string" && IDENTIFIER.test(p.incident_id) ? p.incident_id : null,
		},
		counts: {
			findings: boundedInt(p.findings_count, 10_000_000),
			blocked: boundedInt(p.blocked_count, 10_000_000),
			window_minutes: boundedInt(p.window_minutes, 1440),
		},
		links: { dashboard: origin ? `${origin}${DEEP_LINK_PATHS[delivery.eventType]}` : null },
	};
	if (!extended) return message;
	message.subject.request_id = typeof p.request_id === "string" && UUID.test(p.request_id) ? p.request_id.toLowerCase() : null;
	message.counts.items = boundedInt(p.items_count, 10_000_000);
	message.counts.window_days = boundedInt(p.window_days, 90);
	message.counts.offline_minutes = boundedInt(p.offline_minutes, 10_000_000);
	message.period = delivery.eventType === "governance.digest" && periodFrom && periodTo ? { from: periodFrom, to: periodTo } : null;
	message.digest = delivery.eventType === "governance.digest" ? digestCounts(p.digest) : null;
	// Keep the key order stable: links last, as in the original events.
	const { links, ...rest } = message;
	return { ...rest, links };
}

export function notificationTitle(message: NotificationMessage): string {
	switch (message.event) {
		case "incident.created":
			return `New ${message.severity ?? "unrated"} incident`;
		case "runtime.deny_critical":
			return "Critical agent action blocked";
		case "approval.requested":
			return "Agent action awaiting out-of-band approval";
		case "privacy.blocked_spike":
			return message.counts.blocked !== null && message.counts.window_minutes !== null
				? `Spike in blocked AI prompts: ${message.counts.blocked} in ${message.counts.window_minutes} min`
				: "Spike in blocked AI prompts";
		case "notification.test":
			return "Test notification from Singularity AIDR";
		case "agent.offline":
			return message.counts.offline_minutes != null
				? `Agent not seen for ${message.counts.offline_minutes} min`
				: "Agent offline";
		case "agent.recovered":
			return message.counts.offline_minutes != null
				? `Agent back online after ${message.counts.offline_minutes} min`
				: "Agent back online";
		case "governance.review_overdue":
			return message.counts.items != null
				? `${message.counts.items} AI register ${message.counts.items === 1 ? "item is" : "items are"} past the review date`
				: "AI register items past the review date";
		case "governance.intake_requested":
			return "New AI intake request awaiting review";
		case "governance.change_pending":
			return "Policy change awaiting four-eyes approval";
		case "governance.exception_expiring":
			return message.counts.items != null && message.counts.window_days != null
				? `${message.counts.items} AI governance ${message.counts.items === 1 ? "exception expires" : "exceptions expire"} within ${message.counts.window_days} days`
				: "AI governance exceptions expiring soon";
		case "governance.digest":
			return message.category === "monthly" ? "Monthly AI governance summary" : "Weekly AI governance summary";
	}
}

/** Label/value facts shared by every human-readable format. */
function notificationFacts(message: NotificationMessage): Array<[string, string]> {
	const facts: Array<[string, string]> = [["Event", message.event]];
	if (message.severity) facts.push(["Severity", message.severity]);
	if (message.category) facts.push(["Category", message.category]);
	if (message.subject.incident_id) facts.push(["Incident", message.subject.incident_id]);
	if (message.subject.agent_id) facts.push(["Agent", message.subject.agent_id]);
	if (message.subject.request_id) facts.push(["Request", message.subject.request_id]);
	if (message.subject.event_id) facts.push(["Event ID", message.subject.event_id]);
	if (message.counts.findings !== null) facts.push(["Findings", String(message.counts.findings)]);
	if (message.counts.blocked !== null) facts.push(["Blocked sends", String(message.counts.blocked)]);
	if (message.counts.window_minutes !== null) facts.push(["Window", `${message.counts.window_minutes} min`]);
	if (message.counts.items != null) facts.push(["Items", String(message.counts.items)]);
	if (message.counts.window_days != null) facts.push(["Within", `${message.counts.window_days} days`]);
	if (message.counts.offline_minutes != null) {
		facts.push([message.event === "agent.recovered" ? "Offline for" : "Threshold", `${message.counts.offline_minutes} min`]);
	}
	if (message.period) facts.push(["Period", `${message.period.from} – ${message.period.to}`]);
	if (message.digest) {
		for (const key of DIGEST_COUNT_KEYS) {
			const value = message.digest[key];
			if (value !== undefined) facts.push([DIGEST_LABELS[key], String(value)]);
		}
	}
	facts.push([message.event === "agent.offline" ? "Last seen" : "Occurred", message.occurred_at]);
	return facts;
}

function slackEscape(value: string): string {
	return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

/** Slack Block Kit message for an incoming webhook. */
export function slackPayload(message: NotificationMessage): Record<string, unknown> {
	const title = notificationTitle(message);
	const blocks: Array<Record<string, unknown>> = [
		{ type: "header", text: { type: "plain_text", text: title.slice(0, 150), emoji: false } },
	];
	// A section holds at most 10 fields; a digest spills into further sections.
	const facts = notificationFacts(message).slice(0, 30);
	for (let start = 0; start < facts.length; start += 10) {
		blocks.push({
			type: "section",
			fields: facts.slice(start, start + 10).map(([label, value]) => ({
				type: "mrkdwn",
				text: `*${label}*\n${slackEscape(value)}`,
			})),
		});
	}
	if (message.links.dashboard) {
		blocks.push({
			type: "actions",
			elements: [{
				type: "button",
				text: { type: "plain_text", text: "Open in AIDR", emoji: false },
				url: message.links.dashboard,
			}],
		});
	}
	blocks.push({
		type: "context",
		elements: [{ type: "mrkdwn", text: `Singularity AIDR · delivery ${slackEscape(message.id)}` }],
	});
	return { text: title, blocks };
}

/** Microsoft Teams message wrapping an Adaptive Card (Workflows webhook). */
export function teamsPayload(message: NotificationMessage): Record<string, unknown> {
	const card: Record<string, unknown> = {
		$schema: "http://adaptivecards.io/schemas/adaptive-card.json",
		type: "AdaptiveCard",
		version: "1.4",
		body: [
			{ type: "TextBlock", text: notificationTitle(message), weight: "Bolder", size: "Medium", wrap: true },
			{
				type: "FactSet",
				facts: notificationFacts(message).map(([title, value]) => ({ title, value })),
			},
			{
				type: "TextBlock",
				text: `Singularity AIDR · delivery ${message.id}`,
				isSubtle: true,
				size: "Small",
				wrap: true,
			},
		],
	};
	if (message.links.dashboard) {
		card.actions = [{ type: "Action.OpenUrl", title: "Open in AIDR", url: message.links.dashboard }];
	}
	return {
		type: "message",
		attachments: [{ contentType: "application/vnd.microsoft.card.adaptive", contentUrl: null, content: card }],
	};
}

export function emailContent(message: NotificationMessage): { subject: string; text: string; html: string } {
	const title = notificationTitle(message);
	const facts = notificationFacts(message);
	const link = message.links.dashboard;
	const text = [
		title,
		"",
		...facts.map(([label, value]) => `${label}: ${value}`),
		"",
		...(link ? [`Open in AIDR: ${link}`, ""] : []),
		`Delivery ${message.id}. This alert carries identifiers and counts only; review details in the AIDR console.`,
	].join("\n");
	const rows = facts
		.map(([label, value]) => `<tr><th align="left">${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`)
		.join("");
	const html = `<h2>${escapeHtml(title)}</h2><table>${rows}</table>${
		link ? `<p><a href="${escapeHtml(link)}">Open in AIDR</a></p>` : ""
	}<p>Delivery ${escapeHtml(message.id)}. This alert carries identifiers and counts only; review details in the AIDR console.</p>`;
	return { subject: `[AIDR] ${title}`.slice(0, 200), text, html };
}

// ── Signatures ─────────────────────────────────────────────────────────────

function hex(bytes: ArrayBuffer): string {
	return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(secret: string, input: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input)));
}

/** `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>` */
export async function signatureHeader(secret: string, timestampSeconds: number, body: string): Promise<string> {
	return `t=${timestampSeconds},v1=${await hmacHex(secret, `${timestampSeconds}.${body}`)}`;
}

/** Reference verifier (receivers: see docs/contracts/notifications.md). */
export async function verifySignature(
	secret: string,
	header: string | null,
	body: string,
	nowSeconds: number,
	toleranceSeconds = SIGNATURE_TOLERANCE_SECONDS,
): Promise<boolean> {
	if (typeof header !== "string") return false;
	const parts = new Map<string, string[]>();
	for (const item of header.split(",")) {
		const index = item.indexOf("=");
		if (index < 1) continue;
		const key = item.slice(0, index).trim();
		parts.set(key, [...(parts.get(key) ?? []), item.slice(index + 1).trim()]);
	}
	const timestamp = Number(parts.get("t")?.[0]);
	if (!Number.isSafeInteger(timestamp) || Math.abs(nowSeconds - timestamp) > toleranceSeconds) return false;
	const expected = await hmacHex(secret, `${timestamp}.${body}`);
	return (parts.get("v1") ?? []).some((candidate) => {
		if (candidate.length !== expected.length) return false;
		let diff = 0;
		for (let i = 0; i < expected.length; i += 1) diff |= candidate.charCodeAt(i) ^ expected.charCodeAt(i);
		return diff === 0;
	});
}

// ── Retry policy ───────────────────────────────────────────────────────────

/**
 * Exponential backoff with ±20% jitter: 30s, 60s, 120s … capped at one hour.
 * A receiver's Retry-After is honoured when it asks for longer (still capped).
 */
export function backoffSeconds(attempt: number, random: () => number, retryAfterSeconds?: number | null): number {
	const step = Math.max(1, Math.min(attempt, 20));
	const base = Math.min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * 2 ** (step - 1));
	const jitter = 0.8 + 0.4 * Math.min(Math.max(random(), 0), 1);
	const delay = Math.round(base * jitter);
	const hinted = typeof retryAfterSeconds === "number" && Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : 0;
	return Math.min(BACKOFF_CAP_SECONDS, Math.max(1, delay, Math.ceil(hinted)));
}

function parseRetryAfter(value: string | null, nowMs: number): number | null {
	if (!value) return null;
	if (/^[0-9]{1,6}$/.test(value.trim())) return Number(value.trim());
	const date = Date.parse(value);
	return Number.isFinite(date) ? Math.max(0, Math.ceil((date - nowMs) / 1000)) : null;
}

export type DeliveryOutcome = {
	outcome: "delivered" | "retry" | "failed";
	error: string | null;
	statusCode: number | null;
	retryAfterSeconds: number | null;
};

const delivered = (statusCode: number | null): DeliveryOutcome => ({
	outcome: "delivered",
	error: null,
	statusCode,
	retryAfterSeconds: null,
});
const retry = (error: string, statusCode: number | null = null, retryAfterSeconds: number | null = null): DeliveryOutcome => ({
	outcome: "retry",
	error,
	statusCode,
	retryAfterSeconds,
});
const failed = (error: string, statusCode: number | null = null): DeliveryOutcome => ({
	outcome: "failed",
	error,
	statusCode,
	retryAfterSeconds: null,
});

// ── Transport ──────────────────────────────────────────────────────────────

export interface DeliveryDeps {
	fetch: typeof fetch;
	resolveDns: DnsResolver;
	mailer: Mailer;
	now: () => number;
	timeoutMs?: number;
}

async function discard(response: Response): Promise<void> {
	try {
		await response.body?.cancel();
	} catch {
		// The status is all a delivery needs; a body that cannot be cancelled is ignored.
	}
}

async function postJson(
	type: Exclude<ChannelType, "email">,
	url: string,
	body: string,
	headers: Record<string, string>,
	deps: DeliveryDeps,
): Promise<DeliveryOutcome> {
	// Re-validate the stored URL: an allow-list change must apply to old rows too.
	const checked = checkTargetUrl(type, url);
	if (!checked.ok) return failed("target_invalid");
	const addresses = await resolvePublicAddresses(checked.url.hostname, deps.resolveDns);
	if (!addresses.ok) {
		return addresses.error === "ssrf_blocked" ? failed("ssrf_blocked") : retry(addresses.error);
	}
	let response: Response;
	try {
		response = await deps.fetch(checked.url.href, {
			method: "POST",
			headers: { "Content-Type": "application/json", "User-Agent": USER_AGENT, ...headers },
			body,
			redirect: "manual",
			signal: AbortSignal.timeout(deps.timeoutMs ?? DELIVERY_TIMEOUT_MS),
		});
	} catch (error) {
		const name = error instanceof Error ? error.name : "";
		return retry(name === "TimeoutError" || name === "AbortError" ? "timeout" : "network_error");
	}
	await discard(response);
	const status = response.status;
	if (status >= 200 && status < 300) return delivered(status);
	// Following a redirect would bypass the address check on the new host.
	if (status >= 300 && status < 400) return failed("redirect_refused", status);
	if (status === 429) {
		return retry("receiver_rate_limited", status, parseRetryAfter(response.headers.get("Retry-After"), deps.now()));
	}
	if (status === 408 || status >= 500) {
		return retry("receiver_unavailable", status, parseRetryAfter(response.headers.get("Retry-After"), deps.now()));
	}
	return failed("receiver_rejected", status);
}

/** Send one message to one decrypted destination. Never throws. */
export async function deliverMessage(
	target: ChannelTarget,
	message: NotificationMessage,
	deps: DeliveryDeps,
): Promise<DeliveryOutcome> {
	try {
		if (target.type === "slack") return await postJson("slack", target.url, JSON.stringify(slackPayload(message)), {}, deps);
		if (target.type === "teams") return await postJson("teams", target.url, JSON.stringify(teamsPayload(message)), {}, deps);
		if (target.type === "webhook") {
			const body = JSON.stringify(message);
			const timestamp = Math.floor(deps.now() / 1000);
			return await postJson("webhook", target.url, body, {
				"X-AIDR-Event": message.event,
				"X-AIDR-Delivery-ID": message.id,
				"Idempotency-Key": message.id,
				[SIGNATURE_HEADER]: await signatureHeader(target.secret, timestamp, body),
			}, deps);
		}
		const content = emailContent(message);
		const results = [];
		for (const [index, to] of target.recipients.entries()) {
			results.push(await deps.mailer.send({ to, ...content, idempotencyKey: `aidr-notification:${message.id}:${index}` }));
		}
		if (results.every((result) => result.ok)) return delivered(null);
		const reasons = results.flatMap((result) => (result.ok ? [] : [result.reason]));
		if (reasons.includes("not_configured")) return failed("mail_not_configured");
		if (reasons.includes("unavailable")) return retry("mail_unavailable");
		return failed("mail_rejected");
	} catch {
		return retry("delivery_error");
	}
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

export interface ClaimedDelivery extends DeliveryRecord {
	leaseToken: string;
	channelId: string;
	channelType: ChannelType;
	targetCiphertext: string;
	attempts: number;
	maxAttempts: number;
}

/** Validate the claim RPC's rows; null when the shape is not the contract. */
export function parseClaimedDeliveries(value: unknown): ClaimedDelivery[] | null {
	if (!Array.isArray(value)) return null;
	const rows: ClaimedDelivery[] = [];
	for (const row of value) {
		if (
			!isRecord(row) ||
			typeof row.delivery_id !== "string" || !UUID.test(row.delivery_id) ||
			typeof row.lease_token !== "string" || !UUID.test(row.lease_token) ||
			typeof row.tenant_id !== "string" || !UUID.test(row.tenant_id) ||
			typeof row.channel_id !== "string" || !UUID.test(row.channel_id) ||
			!CHANNEL_TYPES.includes(row.channel_type as ChannelType) ||
			typeof row.target_ciphertext !== "string" ||
			!NOTIFICATION_EVENT_TYPES.includes(row.event_type as NotificationEventType) ||
			!isRecord(row.payload) ||
			!Number.isSafeInteger(row.attempts) || !Number.isSafeInteger(row.max_attempts) ||
			typeof row.created_at !== "string"
		) {
			return null;
		}
		rows.push({
			deliveryId: row.delivery_id,
			leaseToken: row.lease_token,
			tenantId: row.tenant_id,
			channelId: row.channel_id,
			channelType: row.channel_type as ChannelType,
			targetCiphertext: row.target_ciphertext,
			eventType: row.event_type as NotificationEventType,
			payload: row.payload,
			attempts: row.attempts as number,
			maxAttempts: row.max_attempts as number,
			createdAt: row.created_at,
		});
	}
	return rows;
}

interface RpcClient {
	rpc(name: string, args: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }>;
}

export interface DispatchOptions extends DeliveryDeps {
	keyring: NotificationKeyring;
	dashboardUrl: string | null;
	random: () => number;
	batchSize?: number;
	maxBatches?: number;
	concurrency?: number;
	leaseSeconds?: number;
	/** Wall-clock budget; no new batch is claimed after it. */
	deadlineMs?: number;
	/** Claim exactly this delivery (the console test send). */
	deliveryId?: string;
}

interface DeliveryResult {
	deliveryId: string;
	status: "delivered" | "pending" | "dead" | "lease_lost";
	error: string | null;
	statusCode: number | null;
}

export interface DispatchSummary {
	claimed: number;
	delivered: number;
	retrying: number;
	dead: number;
	leaseLost: number;
	results: DeliveryResult[];
}

export class DispatchError extends Error {
	constructor(readonly code: "claim_failed" | "complete_failed") {
		super(code);
	}
}

async function processDelivery(db: RpcClient, row: ClaimedDelivery, options: DispatchOptions): Promise<DeliveryResult> {
	const target = await decryptTarget(
		options.keyring,
		{ tenantId: row.tenantId, channelId: row.channelId, type: row.channelType },
		row.targetCiphertext,
	);
	const outcome = target
		? await deliverMessage(target, buildNotification(row, options.dashboardUrl), options)
		: failed("decrypt_failed");
	const { data, error } = await db.rpc("complete_notification_delivery", {
		p_delivery_id: row.deliveryId,
		p_lease_token: row.leaseToken,
		p_outcome: outcome.outcome,
		p_error: outcome.error,
		p_status_code: outcome.statusCode,
		p_retry_in_seconds:
			outcome.outcome === "retry" ? backoffSeconds(row.attempts, options.random, outcome.retryAfterSeconds) : null,
	});
	const status = isRecord(data) ? data.status : null;
	if (error || !["delivered", "pending", "dead", "lease_lost"].includes(String(status))) {
		throw new DispatchError("complete_failed");
	}
	return {
		deliveryId: row.deliveryId,
		status: status as DeliveryResult["status"],
		error: outcome.error,
		statusCode: outcome.statusCode,
	};
}

/**
 * Claim due deliveries in bounded batches and deliver them with limited
 * concurrency. A claim or completion failure stops the run (the leased rows are
 * reclaimed after their lease expires); a receiver failure never does.
 */
export async function runNotificationDispatch(db: RpcClient, options: DispatchOptions): Promise<DispatchSummary> {
	const batchSize = options.batchSize ?? 25;
	const maxBatches = options.deliveryId ? 1 : (options.maxBatches ?? 8);
	const concurrency = Math.max(1, options.concurrency ?? 5);
	const deadline = options.now() + (options.deadlineMs ?? 40_000);
	const summary: DispatchSummary = { claimed: 0, delivered: 0, retrying: 0, dead: 0, leaseLost: 0, results: [] };

	for (let batch = 0; batch < maxBatches && options.now() < deadline; batch += 1) {
		const { data, error } = await db.rpc("claim_notification_deliveries", {
			p_limit: options.deliveryId ? 1 : batchSize,
			p_lease_seconds: options.leaseSeconds ?? 120,
			p_delivery_id: options.deliveryId ?? null,
		});
		const rows = error ? null : parseClaimedDeliveries(data);
		if (!rows) throw new DispatchError("claim_failed");
		if (rows.length === 0) break;
		summary.claimed += rows.length;

		let next = 0;
		let failure: unknown = null;
		const worker = async () => {
			while (next < rows.length && failure === null) {
				const row = rows[next++];
				try {
					const result = await processDelivery(db, row, options);
					summary.results.push(result);
					if (result.status === "delivered") summary.delivered += 1;
					else if (result.status === "pending") summary.retrying += 1;
					else if (result.status === "dead") summary.dead += 1;
					else summary.leaseLost += 1;
				} catch (cause) {
					failure = cause;
				}
			}
		};
		await Promise.all(Array.from({ length: Math.min(concurrency, rows.length) }, worker));
		if (failure) throw failure instanceof DispatchError ? failure : new DispatchError("complete_failed");
		if (rows.length < batchSize) break;
	}
	return summary;
}
