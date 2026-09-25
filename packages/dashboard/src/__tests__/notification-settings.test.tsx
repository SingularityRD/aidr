// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateWebhookSecret, parseRecipients } from "../lib/notification-channels";
import { NotificationSettings } from "../ui/NotificationSettings";

const TENANT = "11111111-1111-4111-8111-111111111111";
const CHANNEL = "44444444-4444-4444-8444-444444444444";
const SLACK_URL = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnopqrstuvwx";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke } }, supabaseEnvError: null }));

interface InvokeOptions {
	method?: string;
	headers?: Record<string, string>;
	body?: Record<string, unknown>;
}

const FILTERS = {
	incident_created: true,
	incident_min_severity: "high",
	runtime_deny_critical: true,
	approval_requested: false,
	privacy_blocked_spike: false,
	privacy_spike_threshold: 10,
	privacy_spike_window_minutes: 15,
};

function channel(overrides: Record<string, unknown> = {}) {
	return {
		id: CHANNEL,
		type: "slack",
		name: "SOC Slack",
		target_hint: "hooks.slack.com · #a1b2c3",
		enabled: true,
		filters: FILTERS,
		created_by: "u",
		created_at: "2026-09-25T10:00:00.000Z",
		updated_at: "2026-09-25T10:00:00.000Z",
		last_delivery_at: null,
		last_delivery_status: null,
		last_error: null,
		consecutive_failures: 0,
		...overrides,
	};
}

function httpError(status: number, error: string) {
	return {
		data: null,
		error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
			context: new Response(JSON.stringify({ error }), { status }),
		}),
	};
}

interface Fixture {
	channels?: ReturnType<typeof channel>[];
	configured?: boolean;
	loadError?: string;
	mutationError?: string;
	testResult?: Record<string, unknown>;
}

function listResponse(fixture: Fixture, channels: ReturnType<typeof channel>[]) {
	if (fixture.loadError) return httpError(403, fixture.loadError);
	return {
		data: {
			ok: true,
			configured: fixture.configured ?? true,
			mail_configured: true,
			permissions: { can_manage: true, requires_aal2: true },
			limits: { max_channels: 20 },
			channels,
			recent_deliveries: [
				{
					id: "d1",
					channel_id: CHANNEL,
					event_type: "incident.created",
					status: "dead",
					attempts: 8,
					last_error: "receiver_unavailable",
					last_status_code: 503,
					created_at: "2026-09-25T09:00:00.000Z",
					delivered_at: null,
				},
			],
		},
		error: null,
	};
}

function mutationResponse(
	fixture: Fixture,
	channels: ReturnType<typeof channel>[],
	body: Record<string, unknown>,
) {
	if (body.action === "create") {
		const created = channel({
			id: "55555555-5555-4555-8555-555555555555",
			name: body.name,
			type: body.type,
			filters: body.filters,
		});
		channels.push(created);
		return { data: { ok: true, channel: created }, error: null };
	}
	if (body.action === "update") {
		const patch = {
			...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
			...(body.filters ? { filters: body.filters } : {}),
		};
		return { data: { ok: true, channel: channel(patch), changed: [] }, error: null };
	}
	if (body.action === "delete")
		return { data: { ok: true, deleted: body.channel_id }, error: null };
	if (body.action === "test") {
		const delivery = fixture.testResult ?? {
			id: "t1",
			status: "delivered",
			error: null,
			status_code: 200,
		};
		return { data: { ok: true, delivery }, error: null };
	}
	throw new Error("unexpected action");
}

function install(fixture: Fixture = {}) {
	const channels = [...(fixture.channels ?? [])];
	invoke.mockImplementation(async (fn: string, options: InvokeOptions) => {
		if (fn !== "notification-channels") throw new Error(`unexpected function ${fn}`);
		if (options.method === "GET") {
			expect(options.headers).toEqual({ "X-AIDR-Tenant-ID": TENANT });
			return listResponse(fixture, channels);
		}
		if (fixture.mutationError) return httpError(403, fixture.mutationError);
		const body = options.body ?? {};
		expect(body.tenant_id).toBe(TENANT);
		return mutationResponse(fixture, channels, body);
	});
}

function posts() {
	return invoke.mock.calls
		.filter(([, options]) => options?.method === "POST")
		.map(([, options]) => options.body);
}

function renderSection() {
	return render(
		<MemoryRouter>
			<NotificationSettings tenantId={TENANT} />
		</MemoryRouter>,
	);
}

beforeEach(() => {
	vi.clearAllMocks();
});
afterEach(cleanup);

describe("Settings → Notifications", () => {
	it("lists channels with only their non-secret hint and recent deliveries", async () => {
		install({ channels: [channel()] });
		renderSection();
		// Once in the channel table and once in the recent-deliveries table.
		expect(await screen.findAllByText("SOC Slack")).toHaveLength(2);
		expect(screen.getByText("hooks.slack.com · #a1b2c3")).toBeInTheDocument();
		expect(screen.getByText("Incidents ≥ high · Critical denies")).toBeInTheDocument();
		expect(screen.getByText(/receiver_unavailable · HTTP 503 · 8 attempts/)).toBeInTheDocument();
	});

	it("adds a Slack channel with the selected events and clears the destination afterwards", async () => {
		install();
		renderSection();
		const form = await screen.findByRole("form", { name: "Add alert channel" });
		const add = within(form).getByRole("button", { name: "Add channel" });
		expect(add).toBeDisabled();
		fireEvent.change(within(form).getByLabelText("Channel name"), {
			target: { value: "SOC on-call" },
		});
		fireEvent.change(within(form).getByLabelText("Slack incoming-webhook URL"), {
			target: { value: SLACK_URL },
		});
		fireEvent.click(within(form).getByLabelText("Actions awaiting out-of-band approval"));
		fireEvent.change(within(form).getByLabelText("Minimum incident severity"), {
			target: { value: "critical" },
		});
		fireEvent.click(add);
		expect(
			await screen.findByText("Added SOC on-call. Send a test to confirm delivery."),
		).toBeInTheDocument();
		expect(posts()).toEqual([
			{
				tenant_id: TENANT,
				action: "create",
				type: "slack",
				name: "SOC on-call",
				target: { url: SLACK_URL },
				filters: { ...FILTERS, incident_min_severity: "critical", approval_requested: true },
			},
		]);
		expect(within(form).getByLabelText("Slack incoming-webhook URL")).toHaveValue("");
		expect(document.body.textContent).not.toContain("abcdefghijklmnop");
	});

	it("generates a webhook signing secret and requires one before saving", async () => {
		install();
		renderSection();
		const form = await screen.findByRole("form", { name: "Add alert channel" });
		fireEvent.change(within(form).getByLabelText("Channel type"), { target: { value: "webhook" } });
		fireEvent.change(within(form).getByLabelText("Channel name"), { target: { value: "SIEM" } });
		fireEvent.change(within(form).getByLabelText("Webhook URL (https)"), {
			target: { value: "https://siem.example.com/aidr" },
		});
		expect(within(form).getByRole("button", { name: "Add channel" })).toBeDisabled();
		fireEvent.click(within(form).getByRole("button", { name: "Generate" }));
		const secret = (within(form).getByLabelText("Signing secret") as HTMLInputElement).value;
		expect(secret).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
		fireEvent.click(within(form).getByRole("button", { name: "Add channel" }));
		await waitFor(() => expect(posts()).toHaveLength(1));
		expect(posts()[0]).toMatchObject({
			type: "webhook",
			target: { url: "https://siem.example.com/aidr", secret },
		});
	});

	it("sends a test and reports the receiver's answer", async () => {
		install({
			channels: [channel()],
			testResult: { id: "t1", status: "dead", error: "receiver_rejected", status_code: 404 },
		});
		renderSection();
		fireEvent.click(await screen.findByRole("button", { name: "Send test to SOC Slack" }));
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"The test was not delivered (receiver_rejected, HTTP 404).",
		);
		expect(posts()).toEqual([{ tenant_id: TENANT, action: "test", channel_id: CHANNEL }]);
	});

	it("disables, edits events and deletes (with confirmation) a channel", async () => {
		install({ channels: [channel()] });
		renderSection();
		fireEvent.click(await screen.findByRole("button", { name: "Disable SOC Slack" }));
		expect(await screen.findByText("disabled")).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Edit events for SOC Slack" }));
		const row = screen.getByRole("button", { name: "Save events" }).closest("tr") as HTMLElement;
		fireEvent.click(within(row).getByLabelText("Critical runtime denies"));
		fireEvent.click(within(row).getByRole("button", { name: "Save events" }));
		expect(await screen.findByText("Events updated for SOC Slack.")).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Delete SOC Slack" }));
		fireEvent.click(screen.getByRole("button", { name: "Confirm delete SOC Slack" }));
		expect(await screen.findByText("Deleted SOC Slack.")).toBeInTheDocument();
		expect(screen.getByText("No alert channels yet.")).toBeInTheDocument();
		expect(posts()).toEqual([
			{ tenant_id: TENANT, action: "update", channel_id: CHANNEL, enabled: false },
			{
				tenant_id: TENANT,
				action: "update",
				channel_id: CHANNEL,
				filters: { ...FILTERS, runtime_deny_critical: false },
			},
			{ tenant_id: TENANT, action: "delete", channel_id: CHANNEL },
		]);
	});

	it("routes an AAL1 session to step-up verification", async () => {
		install({ channels: [channel()], mutationError: "mfa_required" });
		renderSection();
		fireEvent.click(await screen.findByRole("button", { name: "Disable SOC Slack" }));
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Multi-factor verification is required",
		);
		expect(screen.getByRole("link", { name: "Verify with authenticator" })).toHaveAttribute(
			"href",
			`/auth/dlp-step-up?tenant=${TENANT}&return=settings`,
		);
	});

	it("explains role restrictions and an unconfigured deployment", async () => {
		install({ loadError: "notification_channels_forbidden" });
		const { unmount } = renderSection();
		expect(
			await screen.findByText(
				"Only workspace owners and administrators can manage alert notifications.",
			),
		).toBeInTheDocument();
		expect(screen.queryByRole("form", { name: "Add alert channel" })).not.toBeInTheDocument();
		unmount();
		install({ configured: false });
		renderSection();
		expect(await screen.findByText(/AIDR_NOTIFICATION_ENCRYPTION_KEYS/)).toBeInTheDocument();
		expect(screen.queryByRole("form", { name: "Add alert channel" })).not.toBeInTheDocument();
	});

	it("parses recipient lists and generates distinct secrets", () => {
		expect(
			parseRecipients("SOC@example.com, ir@example.com;soc@example.com\nops@example.com"),
		).toEqual(["soc@example.com", "ir@example.com", "ops@example.com"]);
		expect(generateWebhookSecret()).not.toBe(generateWebhookSecret());
	});
});
