import { describe, expect, it, vi } from "vitest";
import { GuardStorage, STORAGE_KEYS } from "../background/storage.js";
import {
	AGENT_RUNTIME,
	backoffDelay,
	browserRuntimeVersion,
	buildEvent,
	type IngestEnvelope,
	ingestUrl,
	sanitizeCounts,
	sanitizeEvent,
	TELEMETRY_LIMITS,
	TelemetryClient,
} from "../background/telemetry.js";
import type { TelemetryConfig } from "../types.js";
import { createChromeFake } from "./helpers/chrome-fake.js";

const CONFIG: TelemetryConfig = {
	controlPlaneUrl: "https://cp.example.com/base",
	apiKey: "aidr_test_key_123456",
};
const CHROME_UA =
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

interface Call {
	url: string;
	init: RequestInit;
	body: IngestEnvelope;
}

function setup(options: { statuses?: number[]; throwNetwork?: boolean } = {}) {
	const fake = createChromeFake({ version: "1.2.3" });
	const storage = new GuardStorage(fake.chrome);
	const calls: Call[] = [];
	const statuses = [...(options.statuses ?? [])];
	let clock = Date.parse("2026-09-24T10:00:00.000Z");
	const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
		calls.push({ url: String(url), init: init ?? {}, body: JSON.parse(String(init?.body)) });
		if (options.throwNetwork) throw new TypeError("Failed to fetch");
		return new Response('{"accepted":1}', { status: statuses.shift() ?? 202 });
	});
	const logs: string[] = [];
	const client = new TelemetryClient({
		storage,
		fetch: fetchMock as unknown as typeof fetch,
		now: () => clock,
		random: () => 0.5,
		navigator: { userAgent: CHROME_UA },
		aidrVersion: "1.2.3",
		log: (m) => logs.push(m),
	});
	return {
		fake,
		storage,
		client,
		calls,
		fetchMock,
		logs,
		advance: (ms: number) => {
			clock += ms;
		},
		now: () => clock,
	};
}

const record = (client: TelemetryClient, counts: unknown = { EMAIL: 2, TC_KIMLIK: 1 }) =>
	client.record({
		site: "chatgpt",
		action: "masked",
		channel: "prompt",
		counts,
		policyId: "acme-2026",
	});

describe("sanitizeCounts", () => {
	it("keeps known entity types with integer counts 1..100000", () => {
		expect(
			sanitizeCounts({
				EMAIL: 2,
				PHONE: 0,
				IBAN: -1,
				PERSON: 1.5,
				SECRET: "3",
				NOT_A_TYPE: 4,
				CREDIT_CARD: 1e9,
				["__proto__"]: 1,
			}),
		).toEqual({ EMAIL: 2, CREDIT_CARD: TELEMETRY_LIMITS.countMax });
		expect(sanitizeCounts(null)).toEqual({});
		expect(sanitizeCounts([1, 2])).toEqual({});
		expect(sanitizeCounts("EMAIL")).toEqual({});
	});
});

describe("buildEvent / sanitizeEvent", () => {
	it("builds a contract-exact event with counts only", () => {
		const event = buildEvent(
			{
				site: "gemini",
				action: "warned",
				channel: "paste",
				counts: { EMAIL: 2, PHONE: 1, bogus: 7 },
				policyId: "acme-2026",
			},
			Date.parse("2026-09-24T10:00:00Z"),
		);
		expect(event).not.toBeNull();
		expect(Object.keys(event ?? {}).sort()).toEqual(
			[
				"action",
				"channel",
				"entity_counts",
				"event_id",
				"event_type",
				"findings_count",
				"policy_id",
				"site",
				"timestamp",
			].sort(),
		);
		expect(event).toMatchObject({
			event_type: "privacy_scan",
			timestamp: "2026-09-24T10:00:00.000Z",
			site: "gemini",
			action: "warned",
			channel: "paste",
			entity_counts: { EMAIL: 2, PHONE: 1 },
			findings_count: 3,
			policy_id: "acme-2026",
		});
		expect(event?.event_id).toMatch(/^bg:[0-9a-f-]{36}$/);
	});

	it("omits an invalid policy id rather than sending it", () => {
		const event = buildEvent(
			{ site: "claude", action: "allowed", channel: "file", counts: {}, policyId: "-bad id" },
			0,
		);
		expect(event).not.toHaveProperty("policy_id");
		expect(event?.findings_count).toBe(0);
	});

	it("rejects events with extra fields (e.g. text) or bad enums", () => {
		const good = buildEvent({ site: "grok", action: "blocked", channel: "prompt", counts: {} }, 0);
		expect(sanitizeEvent(good)).toEqual(good);
		expect(sanitizeEvent({ ...good, text: "alice@example.com" })).toBeNull();
		expect(sanitizeEvent({ ...good, site: "example.com" })).toBeNull();
		expect(sanitizeEvent({ ...good, action: "leaked" })).toBeNull();
		expect(sanitizeEvent({ ...good, event_id: "x" })).toBeNull();
		expect(sanitizeEvent({ ...good, findings_count: -1 })).toBeNull();
	});
});

describe("browserRuntimeVersion", () => {
	it("reports family and major version", () => {
		expect(browserRuntimeVersion({ userAgent: CHROME_UA })).toBe("chrome-126");
		expect(browserRuntimeVersion({ userAgent: `${CHROME_UA} Edg/127.0.2651.74` })).toBe("edge-127");
		expect(
			browserRuntimeVersion({
				userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			}),
		).toBe("firefox-128");
		expect(
			browserRuntimeVersion({
				userAgentData: {
					brands: [
						{ brand: "Not)A;Brand", version: "99" },
						{ brand: "Microsoft Edge", version: "126" },
						{ brand: "Chromium", version: "126" },
					],
				},
			}),
		).toBe("edge-126");
		expect(browserRuntimeVersion(undefined)).toBe("unknown");
	});
});

describe("backoffDelay", () => {
	it("grows exponentially with jitter and caps at one hour", () => {
		const base = TELEMETRY_LIMITS.backoffBaseMs;
		expect(backoffDelay(1, () => 0)).toBe(base / 2);
		expect(backoffDelay(1, () => 1)).toBe(base);
		expect(backoffDelay(3, () => 0.5)).toBe(Math.round(base * 4 * 0.75));
		expect(backoffDelay(50, () => 1)).toBe(TELEMETRY_LIMITS.backoffMaxMs);
		expect(backoffDelay(50, () => 0)).toBe(TELEMETRY_LIMITS.backoffMaxMs / 2);
	});
});

describe("TelemetryClient", () => {
	it("does nothing unless telemetry is configured", async () => {
		const t = setup();
		await record(t.client);
		expect(await t.client.pending()).toEqual([]);
		expect(await t.client.flush()).toBe("disabled");
		expect(t.fetchMock).not.toHaveBeenCalled();
	});

	it("posts the exact envelope to /functions/v1/ingest with bearer auth", async () => {
		const t = setup();
		await t.client.configure(CONFIG);
		await record(t.client);
		expect(await t.client.flush()).toBe("sent");
		expect(t.calls).toHaveLength(1);
		const [call] = t.calls;
		expect(call?.url).toBe("https://cp.example.com/base/functions/v1/ingest");
		expect(ingestUrl(CONFIG)).toBe(call?.url);
		expect(call?.init.method).toBe("POST");
		expect(call?.init.headers).toEqual({
			Authorization: `Bearer ${CONFIG.apiKey}`,
			"Content-Type": "application/json",
		});
		expect(call?.init.credentials).toBe("omit");
		const body = call?.body as IngestEnvelope;
		expect(Object.keys(body).sort()).toEqual(
			["agent_runtime", "agent_runtime_version", "aidr_version", "events", "iid"].sort(),
		);
		expect(body.agent_runtime).toBe(AGENT_RUNTIME);
		expect(body.agent_runtime).toBe("browser_guard");
		expect(body.agent_runtime_version).toBe("chrome-126");
		expect(body.aidr_version).toBe("1.2.3");
		expect(body.iid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
		expect(body.iid).toBe(t.fake.local.data.get(STORAGE_KEYS.installationId));
		expect(body.events).toHaveLength(1);
		expect(body.events[0]).toMatchObject({
			event_type: "privacy_scan",
			site: "chatgpt",
			action: "masked",
			channel: "prompt",
			entity_counts: { EMAIL: 2, TC_KIMLIK: 1 },
			findings_count: 3,
			policy_id: "acme-2026",
		});
		expect(await t.client.pending()).toEqual([]);
	});

	it("never sends text: hostile counts and extra fields are stripped", async () => {
		const t = setup();
		await t.client.configure(CONFIG);
		await record(t.client, { EMAIL: 1, "alice@example.com": 5, text: "secret prompt" });
		await t.client.flush();
		const raw = JSON.stringify(t.calls[0]?.body);
		expect(raw).not.toContain("alice@example.com");
		expect(raw).not.toContain("secret prompt");
		expect(t.calls[0]?.body.events[0]?.entity_counts).toEqual({ EMAIL: 1 });
	});

	it("keeps the installation id stable across flushes", async () => {
		const t = setup();
		await t.client.configure(CONFIG);
		await record(t.client);
		await t.client.flush();
		await record(t.client);
		await t.client.flush();
		expect(t.calls[0]?.body.iid).toBe(t.calls[1]?.body.iid);
	});

	it("flushes automatically once 50 events are pending", async () => {
		const t = setup();
		await t.client.configure(CONFIG);
		for (let i = 0; i < TELEMETRY_LIMITS.flushThreshold - 1; i++) await record(t.client);
		expect(t.fetchMock).not.toHaveBeenCalled();
		await record(t.client);
		await vi.waitFor(() => expect(t.fetchMock).toHaveBeenCalledTimes(1));
		await vi.waitFor(async () => expect(await t.client.pending()).toHaveLength(0));
		expect(t.calls[0]?.body.events).toHaveLength(TELEMETRY_LIMITS.flushThreshold);
	});

	it("bounds the queue at 500 events, dropping the oldest, and sends at most 200 per batch", async () => {
		const t = setup({ throwNetwork: true });
		await t.client.configure(CONFIG);
		// Put the client in backoff so threshold flushes do not drain the queue.
		await record(t.client);
		expect(await t.client.flush()).toBe("failed");
		const first = (await t.client.pending())[0]?.event_id;
		for (let i = 0; i < TELEMETRY_LIMITS.queueMax + 20; i++) await record(t.client);
		const queue = await t.client.pending();
		expect(queue).toHaveLength(TELEMETRY_LIMITS.queueMax);
		expect(queue.some((e) => e.event_id === first)).toBe(false);
		t.fetchMock.mockImplementation(async (_url, init) => {
			t.calls.push({ url: "", init: init ?? {}, body: JSON.parse(String(init?.body)) });
			return new Response("{}", { status: 200 });
		});
		t.advance(TELEMETRY_LIMITS.backoffMaxMs);
		expect(await t.client.flush()).toBe("sent");
		expect(t.calls.at(-1)?.body.events).toHaveLength(TELEMETRY_LIMITS.batchMax);
		expect(await t.client.pending()).toHaveLength(
			TELEMETRY_LIMITS.queueMax - TELEMETRY_LIMITS.batchMax,
		);
	});

	it("backs off exponentially after failures and resets after a success", async () => {
		const t = setup({ statuses: [503, 500] });
		await t.client.configure(CONFIG);
		await record(t.client);
		expect(await t.client.flush()).toBe("failed");
		const state1 = t.fake.local.data.get(STORAGE_KEYS.telemetryState) as {
			failures: number;
			nextAttemptAt: number;
		};
		expect(state1.failures).toBe(1);
		expect(state1.nextAttemptAt - t.now()).toBe(backoffDelay(1, () => 0.5));

		expect(await t.client.flush()).toBe("backoff");
		expect(t.fetchMock).toHaveBeenCalledTimes(1);

		t.advance(backoffDelay(1, () => 0.5));
		expect(await t.client.flush()).toBe("failed");
		const state2 = t.fake.local.data.get(STORAGE_KEYS.telemetryState) as {
			failures: number;
			nextAttemptAt: number;
		};
		expect(state2.failures).toBe(2);
		expect(state2.nextAttemptAt - t.now()).toBe(backoffDelay(2, () => 0.5));
		expect(await t.client.pending()).toHaveLength(1);

		t.advance(backoffDelay(2, () => 0.5));
		expect(await t.client.flush()).toBe("sent");
		expect(t.fake.local.data.get(STORAGE_KEYS.telemetryState)).toMatchObject({
			failures: 0,
			nextAttemptAt: 0,
		});
		expect(await t.client.pending()).toHaveLength(0);
		expect(t.logs.join("\n")).not.toContain(CONFIG.apiKey);
	});

	it("drops a batch the server permanently rejects instead of wedging the queue", async () => {
		const t = setup({ statuses: [422] });
		await t.client.configure(CONFIG);
		await record(t.client);
		expect(await t.client.flush()).toBe("dropped");
		expect(await t.client.pending()).toHaveLength(0);
	});

	it("discards queued events when the destination changes", async () => {
		const t = setup({ throwNetwork: true });
		await t.client.configure(CONFIG);
		await record(t.client);
		expect(await t.client.pending()).toHaveLength(1);
		await t.client.configure(CONFIG);
		expect(await t.client.pending()).toHaveLength(1);
		await t.client.configure({ ...CONFIG, apiKey: "aidr_other_key_987654" });
		expect(await t.client.pending()).toHaveLength(0);
		await record(t.client);
		await t.client.configure(null);
		expect(await t.client.pending()).toHaveLength(0);
		expect(t.client.enabled).toBe(false);
	});

	it("ignores corrupted queue entries read back from storage", async () => {
		const t = setup();
		await t.client.configure(CONFIG);
		await record(t.client);
		const queue = t.fake.local.data.get(STORAGE_KEYS.telemetryQueue) as unknown[];
		t.fake.local.data.set(STORAGE_KEYS.telemetryQueue, [
			...queue,
			{ event_type: "privacy_scan", text: "leak" },
			"junk",
		]);
		expect(await t.client.pending()).toHaveLength(1);
	});
});
