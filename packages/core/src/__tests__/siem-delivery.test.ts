import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { Incident } from "../incidents/types.js";
import {
	createSiemEvent,
	DurableSiemDelivery,
	SIEM_EVENT_JSON_SCHEMA,
	SIEM_EVENT_SCHEMA_VERSION,
	SiemQueueCapacityError,
	SiemStateIntegrityError,
} from "../siem-delivery.js";

const tempDirectories: string[] = [];

async function statePath(): Promise<string> {
	const directory = await mkdtemp(join(tmpdir(), "aidr-siem-delivery-"));
	tempDirectories.push(directory);
	return join(directory, "delivery-state.json");
}

afterEach(async () => {
	vi.restoreAllMocks();
	await Promise.all(
		tempDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
	);
});

const incident: Incident = {
	incident_id: "inc-delivery-1",
	opened_at_ms: 1_700_000_000_000,
	last_seen_ms: 1_700_000_000_500,
	severity: "critical",
	status: "open",
	agent_iid: "agent-7",
	connector: "claude",
	domain: "blocked.example",
	events: [
		{
			signal_id: "sig-1",
			timestamp_ms: 1_700_000_000_000,
			signal_type: "runtime_verdict",
			severity: "critical",
			summary:
				"blocked request Authorization: Bearer secret-bearer-value and api_key=sk-abcdefghijklmnop",
		},
	],
};

function webhookOptions(
	stateFile: string,
	fetcher: typeof fetch,
	overrides: Partial<Parameters<typeof DurableSiemDelivery.open>[0]> = {},
) {
	return {
		stateFile,
		adapter: {
			provider: "webhook" as const,
			endpoint: "https://events.example.test/v1/ingest",
			bearerToken: "delivery-secret-token",
			headers: { "x-customer-secret": "custom-secret-value" },
		},
		fetch: fetcher,
		...overrides,
	};
}

describe("SIEM event schema and redaction", () => {
	it("publishes a stable open schema and deterministic event id", () => {
		const first = createSiemEvent(incident, 1_700_000_001_000);
		const second = createSiemEvent(incident, 1_700_000_002_000);

		expect(SIEM_EVENT_JSON_SCHEMA.$id).toContain("siem-event-v1.json");
		expect(first.schema_version).toBe(SIEM_EVENT_SCHEMA_VERSION);
		expect(first.event_id).toMatch(/^aidr_[a-f0-9]{40}$/);
		expect(second.event_id).toBe(first.event_id);
		expect(second.observed_at_ms).not.toBe(first.observed_at_ms);
	});

	it("redacts credentials from free-form incident content before buffering", () => {
		const envelope = createSiemEvent(incident, 1_700_000_001_000);
		const encoded = JSON.stringify(envelope);

		expect(encoded).not.toContain("secret-bearer-value");
		expect(encoded).not.toContain("sk-abcdefghijklmnop");
		expect(encoded).toContain("[Redacted]");
	});
});

describe("durable webhook delivery", () => {
	it("persists a redacted receipt and sends stable idempotency headers", async () => {
		const path = await statePath();
		let capturedUrl = "";
		let capturedInit: RequestInit | undefined;
		const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			capturedUrl = String(input);
			capturedInit = init;
			return new Response(null, { status: 202 });
		}) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open(webhookOptions(path, fetcher));

		const queued = await delivery.enqueue(incident);
		expect(queued.deduplicated).toBe(false);
		expect((await delivery.enqueue(incident)).deduplicated).toBe(true);
		const result = await delivery.flush();

		expect(result).toMatchObject({ attempted: 1, delivered: 1, pending: 0 });
		expect(capturedUrl).toBe("https://events.example.test/v1/ingest");
		const headers = new Headers(capturedInit?.headers);
		expect(headers.get("idempotency-key")).toBe(queued.receipt.eventId);
		expect(headers.get("x-aidr-event-id")).toBe(queued.receipt.eventId);
		expect(headers.get("authorization")).toBe("Bearer delivery-secret-token");
		expect(capturedInit?.redirect).toBe("error");

		const stored = await readFile(path, "utf8");
		expect(stored).not.toContain("delivery-secret-token");
		expect(stored).not.toContain("custom-secret-value");
		expect(stored).not.toContain("secret-bearer-value");
		expect(stored).not.toContain("/v1/ingest");
		expect(stored).toContain("https://events.example.test");
	});

	it("recovers queued work after restart and deduplicates delivered events", async () => {
		const path = await statePath();
		const neverCalled = vi.fn(
			async () => new Response(null, { status: 500 }),
		) as unknown as typeof fetch;
		const first = await DurableSiemDelivery.open(webhookOptions(path, neverCalled));
		const queued = await first.enqueue(incident);

		const successful = vi.fn(
			async () => new Response(null, { status: 204 }),
		) as unknown as typeof fetch;
		const restarted = await DurableSiemDelivery.open(webhookOptions(path, successful));
		expect((await restarted.flush()).delivered).toBe(1);
		const receipt = await restarted.getReceipt(queued.receipt.receiptId);
		expect(receipt).toMatchObject({ status: "delivered", attemptCount: 1 });

		const duplicate = await restarted.enqueue(incident);
		expect(duplicate.deduplicated).toBe(true);
		expect(duplicate.receipt.receiptId).toBe(queued.receipt.receiptId);
		expect(successful).toHaveBeenCalledTimes(1);
	});

	it("binds receipts to the SIEM destination while allowing bearer rotation", async () => {
		const path = await statePath();
		const fetcher = vi.fn(
			async () => new Response(null, { status: 202 }),
		) as unknown as typeof fetch;
		const first = await DurableSiemDelivery.open(webhookOptions(path, fetcher));
		await first.enqueue(incident);
		await first.flush();

		const rotated = await DurableSiemDelivery.open({
			...webhookOptions(path, fetcher),
			adapter: {
				provider: "webhook",
				endpoint: "https://events.example.test/v1/ingest",
				bearerToken: "rotated-secret",
				headers: { "x-customer-secret": "custom-secret-value" },
			},
		});
		expect((await rotated.enqueue(incident)).deduplicated).toBe(true);
		await expect(
			DurableSiemDelivery.open({
				...webhookOptions(path, fetcher),
				adapter: { provider: "webhook", endpoint: "https://events.example.test/v2/ingest" },
			}),
		).rejects.toThrow("different destination");
		expect(fetcher).toHaveBeenCalledTimes(1);
	});

	it("rejects queued Elastic events when the configured index changes", async () => {
		const path = await statePath();
		const fetcher = vi.fn() as unknown as typeof fetch;
		const options = (index: string) => ({
			stateFile: path,
			adapter: {
				provider: "elastic" as const,
				endpoint: "https://elastic.example.test",
				index,
				apiKey: "elastic-secret",
			},
			fetch: fetcher,
		});
		const first = await DurableSiemDelivery.open(options("aidr-incidents"));
		await first.enqueue(incident);
		await expect(DurableSiemDelivery.open(options("other-index"))).rejects.toThrow(
			"different destination",
		);
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("fails closed on populated legacy state without a destination binding", async () => {
		const path = await statePath();
		const fetcher = vi.fn() as unknown as typeof fetch;
		const first = await DurableSiemDelivery.open(webhookOptions(path, fetcher));
		await first.enqueue(incident);
		const legacy = JSON.parse(await readFile(path, "utf8"));
		delete legacy.payload.destinationFingerprint;
		legacy.sha256 = createHash("sha256").update(JSON.stringify(legacy.payload)).digest("hex");
		await writeFile(path, JSON.stringify(legacy));

		await expect(DurableSiemDelivery.open(webhookOptions(path, fetcher))).rejects.toThrow(
			"no destination binding",
		);
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("fails closed when the bounded queue is full", async () => {
		const path = await statePath();
		const fetcher = vi.fn() as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open(
			webhookOptions(path, fetcher, { maxQueueEntries: 1 }),
		);
		await delivery.enqueue(incident);
		const second = { ...incident, incident_id: "inc-delivery-2" };

		await expect(delivery.enqueue(second)).rejects.toBeInstanceOf(SiemQueueCapacityError);
		expect((await delivery.health()).queueDepth).toBe(1);
	});

	it("dead-letters 401 without retrying and exposes credential-safe health", async () => {
		const path = await statePath();
		const fetcher = vi.fn(
			async () => new Response("token delivery-secret-token invalid", { status: 401 }),
		) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open(webhookOptions(path, fetcher));
		await delivery.enqueue(incident);

		expect(await delivery.flush()).toMatchObject({ attempted: 1, deadLettered: 1, pending: 0 });
		expect(await delivery.flush()).toMatchObject({ attempted: 0, pending: 0 });
		const health = await delivery.health();
		expect(health).toMatchObject({ status: "unhealthy", lastErrorCode: "authorization_rejected" });
		expect(JSON.stringify(health)).not.toContain("delivery-secret-token");
		expect(fetcher).toHaveBeenCalledTimes(1);
	});

	it("honors Retry-After on 429 and retries with the same event id", async () => {
		const path = await statePath();
		let nowMs = 10_000;
		const requestIds: string[] = [];
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			requestIds.push(new Headers(init?.headers).get("idempotency-key") ?? "");
			return requestIds.length === 1
				? new Response(null, { status: 429, headers: { "retry-after": "2" } })
				: new Response(null, { status: 202 });
		}) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open(
			webhookOptions(path, fetcher, {
				now: () => nowMs,
				random: () => 0,
				minBackoffMs: 100,
				maxBackoffMs: 10_000,
			}),
		);
		const queued = await delivery.enqueue(incident);

		expect(await delivery.flush()).toMatchObject({ retrying: 1, pending: 1 });
		const retryReceipt = await delivery.getReceipt(queued.receipt.receiptId);
		expect(retryReceipt).toMatchObject({
			status: "retrying",
			nextAttemptAtMs: 12_000,
			lastStatusCode: 429,
		});
		nowMs = 11_999;
		expect((await delivery.flush()).attempted).toBe(0);
		nowMs = 12_000;
		expect(await delivery.flush()).toMatchObject({ delivered: 1, pending: 0 });
		expect(requestIds).toEqual([queued.receipt.eventId, queued.receipt.eventId]);
	});

	it("retries 5xx with bounded backoff and dead-letters at max attempts", async () => {
		const path = await statePath();
		let nowMs = 1_000;
		const fetcher = vi.fn(
			async () => new Response(null, { status: 503 }),
		) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open(
			webhookOptions(path, fetcher, {
				now: () => nowMs,
				random: () => 0,
				maxAttempts: 2,
				minBackoffMs: 100,
				maxBackoffMs: 200,
			}),
		);
		await delivery.enqueue(incident);

		expect((await delivery.flush()).retrying).toBe(1);
		nowMs = 1_100;
		expect((await delivery.flush()).deadLettered).toBe(1);
		expect((await delivery.health()).lastErrorCode).toBe("upstream_unavailable");
	});

	it("rejects a state file whose checksummed payload was edited", async () => {
		const path = await statePath();
		const delivery = await DurableSiemDelivery.open(
			webhookOptions(path, vi.fn() as unknown as typeof fetch),
		);
		await delivery.enqueue(incident);
		const state = JSON.parse(await readFile(path, "utf8")) as {
			payload: { receipts: Array<{ status: string }> };
		};
		const firstReceipt = state.payload.receipts[0];
		if (!firstReceipt) throw new Error("expected a stored receipt");
		firstReceipt.status = "delivered";
		await writeFile(path, JSON.stringify(state), "utf8");

		await expect(
			DurableSiemDelivery.open(webhookOptions(path, vi.fn() as unknown as typeof fetch)),
		).rejects.toBeInstanceOf(SiemStateIntegrityError);
	});
});

describe("provider adapters", () => {
	it("formats and validates a Splunk HEC event response", async () => {
		const path = await statePath();
		let body = "";
		let headers = new Headers();
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			body = String(init?.body);
			headers = new Headers(init?.headers);
			return new Response(JSON.stringify({ text: "Success", code: 0 }), { status: 200 });
		}) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open({
			stateFile: path,
			adapter: {
				provider: "splunk_hec",
				endpoint: "https://splunk.example.test:8088",
				token: "hec-secret",
				index: "security",
			},
			fetch: fetcher,
		});
		await delivery.enqueue(incident);

		expect((await delivery.flush()).delivered).toBe(1);
		expect(headers.get("authorization")).toBe("Splunk hec-secret");
		expect(JSON.parse(body)).toMatchObject({
			source: "aidr",
			sourcetype: "aidr:incident",
			index: "security",
		});
		expect(String(fetcher.mock.calls[0]?.[0])).toContain("/services/collector/event");
		expect(await readFile(path, "utf8")).not.toContain("hec-secret");
	});

	it("formats a Microsoft Sentinel Logs Ingestion request", async () => {
		const path = await statePath();
		let body = "";
		let url = "";
		const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			url = String(input);
			body = String(init?.body);
			return new Response(null, { status: 204 });
		}) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open({
			stateFile: path,
			adapter: {
				provider: "sentinel",
				endpoint: "https://customer.ingest.monitor.azure.com",
				bearerToken: "azure-secret",
				dcrImmutableId: "dcr-1234567890abcdef",
				streamName: "Custom-AIDRIncident_CL",
			},
			fetch: fetcher,
		});
		await delivery.enqueue(incident);

		expect((await delivery.flush()).delivered).toBe(1);
		expect(url).toContain(
			"/dataCollectionRules/dcr-1234567890abcdef/streams/Custom-AIDRIncident_CL",
		);
		expect(url).toContain("api-version=2023-01-01");
		expect(JSON.parse(body)).toHaveLength(1);
		expect(await readFile(path, "utf8")).not.toContain("azure-secret");
	});

	it("uses Elastic bulk create ids and accepts an existing document as deduplicated delivery", async () => {
		const path = await statePath();
		let body = "";
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			body = String(init?.body);
			return new Response(JSON.stringify({ errors: true, items: [{ create: { status: 409 } }] }), {
				status: 200,
			});
		}) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open({
			stateFile: path,
			adapter: {
				provider: "elastic",
				endpoint: "https://elastic.example.test",
				index: "aidr-incidents",
				apiKey: "elastic-secret",
			},
			fetch: fetcher,
		});
		const queued = await delivery.enqueue(incident);

		expect((await delivery.flush()).delivered).toBe(1);
		const lines = body.trimEnd().split("\n");
		expect(lines).toHaveLength(2);
		const actionLine = lines[0];
		const eventLine = lines[1];
		if (!actionLine || !eventLine) throw new Error("expected a two-line Elastic bulk request");
		expect(JSON.parse(actionLine)).toEqual({
			create: { _index: "aidr-incidents", _id: queued.receipt.eventId },
		});
		expect(JSON.parse(eventLine).event_id).toBe(queued.receipt.eventId);
		expect(await readFile(path, "utf8")).not.toContain("elastic-secret");
	});

	it("rejects insecure, credential-bearing and query-bearing endpoints", async () => {
		const options = (endpoint: string) => ({
			stateFile: join(tmpdir(), `unused-${Math.random()}.json`),
			adapter: { provider: "webhook" as const, endpoint },
			fetch: vi.fn() as unknown as typeof fetch,
		});

		await expect(DurableSiemDelivery.open(options("http://events.example.test"))).rejects.toThrow(
			"HTTPS",
		);
		await expect(
			DurableSiemDelivery.open(options("https://user:pass@events.example.test")),
		).rejects.toThrow("credentials");
		await expect(
			DurableSiemDelivery.open(options("https://events.example.test/?token=secret")),
		).rejects.toThrow("query");
	});
});
