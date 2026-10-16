import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

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

const VERIFY_WINDOWS_ACL = `
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('AIDR_TEST_ACL_PATH')
$item = if ([System.IO.Directory]::Exists($path)) { [System.IO.DirectoryInfo]::new($path) } else { [System.IO.FileInfo]::new($path) }
$acl = $item.GetAccessControl()
if (-not $acl.AreAccessRulesProtected) { throw 'Inherited ACL remains' }
$allowed = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
foreach ($entry in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin $allowed) { throw "Unexpected ACL grant: $($entry.IdentityReference.Value)" }
}
`;

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

function acknowledgedWebhookResponse(init: RequestInit | undefined, status = 202): Response {
	const eventId = new Headers(init?.headers).get("x-aidr-event-id");
	return new Response(null, {
		status,
		headers: eventId ? { "x-aidr-event-id": eventId } : undefined,
	});
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
	// AIDR-SKIP: AIDR-063 qa-owner - POSIX mode-bit permission rejection is not meaningful on NTFS; Windows DACLs are tested below
	it.skipIf(process.platform === "win32")(
		"rejects state paths readable by other local users",
		async () => {
			const path = await statePath();
			const directory = dirname(path);
			await chmod(directory, 0o755);
			await expect(
				DurableSiemDelivery.open(webhookOptions(path, vi.fn() as unknown as typeof fetch)),
			).rejects.toThrow("directory permissions are insecure");

			await chmod(directory, 0o700);
			await DurableSiemDelivery.open(webhookOptions(path, vi.fn() as unknown as typeof fetch));
			await chmod(path, 0o644);
			await expect(
				DurableSiemDelivery.open(webhookOptions(path, vi.fn() as unknown as typeof fetch)),
			).rejects.toThrow("file permissions are insecure");
		},
	);

	// AIDR-SKIP: AIDR-063 qa-owner - POSIX file symlink creation needs a Unix host; Windows DACLs are tested below
	it.skipIf(process.platform === "win32")(
		"rejects a symlinked queue file instead of reading or replacing its target",
		async () => {
			const path = await statePath();
			const target = join(dirname(path), "real-state.json");
			await DurableSiemDelivery.open(webhookOptions(target, vi.fn() as unknown as typeof fetch));
			await symlink(target, path, "file");

			await expect(
				DurableSiemDelivery.open(webhookOptions(path, vi.fn() as unknown as typeof fetch)),
			).rejects.toThrow("not a regular file");
		},
	);

	// AIDR-SKIP: AIDR-063 qa-owner - NTFS DACL inspection requires a Windows host
	it.skipIf(process.platform !== "win32")(
		"secures the state directory and replacement file before exposing SIEM receipts",
		async () => {
			const path = await statePath();
			const delivery = await DurableSiemDelivery.open(
				webhookOptions(path, vi.fn() as unknown as typeof fetch),
			);
			await delivery.enqueue(incident);
			for (const target of [dirname(path), path]) {
				const result = spawnSync(
					"powershell.exe",
					[
						"-NoProfile",
						"-NonInteractive",
						"-EncodedCommand",
						Buffer.from(VERIFY_WINDOWS_ACL, "utf16le").toString("base64"),
					],
					{
						env: { ...process.env, AIDR_TEST_ACL_PATH: target },
						encoding: "utf8",
						timeout: 30_000,
						windowsHide: true,
					},
				);
				expect(result.error).toBeUndefined();
				expect(result.status, result.stderr).toBe(0);
			}
		},
	);

	it("persists a redacted receipt and sends stable idempotency headers", async () => {
		const path = await statePath();
		let capturedUrl = "";
		let capturedInit: RequestInit | undefined;
		const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			capturedUrl = String(input);
			capturedInit = init;
			return acknowledgedWebhookResponse(init);
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

	it("keeps a generic 2xx queued until the receiver returns a correlated receipt", async () => {
		const path = await statePath();
		let nowMs = 1_000;
		const requestIds: string[] = [];
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			requestIds.push(new Headers(init?.headers).get("x-aidr-event-id") ?? "");
			return requestIds.length === 1
				? new Response(null, { status: 202 })
				: acknowledgedWebhookResponse(init);
		}) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open(
			webhookOptions(path, fetcher, {
				now: () => nowMs,
				random: () => 0,
				minBackoffMs: 100,
			}),
		);
		const queued = await delivery.enqueue(incident);

		expect(await delivery.flush()).toMatchObject({ delivered: 0, retrying: 1, pending: 1 });
		expect(await delivery.getReceipt(queued.receipt.receiptId)).toMatchObject({
			status: "retrying",
			lastErrorCode: "invalid_webhook_receipt",
		});
		nowMs = 1_100;
		expect(await delivery.flush()).toMatchObject({ delivered: 1, pending: 0 });
		expect(requestIds).toEqual([queued.receipt.eventId, queued.receipt.eventId]);
	});

	it("cancels unneeded webhook response bodies before retrying", async () => {
		const path = await statePath();
		let cancelled = false;
		const fetcher = vi.fn(
			async () =>
				new Response(
					new ReadableStream({
						cancel() {
							cancelled = true;
						},
					}),
					{ status: 503 },
				),
		) as unknown as typeof fetch;
		const delivery = await DurableSiemDelivery.open(webhookOptions(path, fetcher));
		await delivery.enqueue(incident);

		await delivery.flush();

		expect(cancelled).toBe(true);
	});

	it("recovers queued work after restart and deduplicates delivered events", async () => {
		const path = await statePath();
		const neverCalled = vi.fn(
			async () => new Response(null, { status: 500 }),
		) as unknown as typeof fetch;
		const first = await DurableSiemDelivery.open(webhookOptions(path, neverCalled));
		const queued = await first.enqueue(incident);

		const successful = vi.fn(async (_input: string | URL | Request, init?: RequestInit) =>
			acknowledgedWebhookResponse(init, 204),
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

	it("rejects completion from an expired claim after a replacement claim is persisted", async () => {
		const path = await statePath();
		let now = 1_700_000_000_000;
		const fetcher = vi.fn() as unknown as typeof fetch;
		const first = await DurableSiemDelivery.open(
			webhookOptions(path, fetcher, { now: () => now, requestTimeoutMs: 100 }),
		);
		await first.enqueue(incident);
		const oldClaim = (await first.claimNext()).claim;
		expect(oldClaim).toBeDefined();

		now += 5_101;
		const restarted = await DurableSiemDelivery.open(
			webhookOptions(path, fetcher, { now: () => now, requestTimeoutMs: 100 }),
		);
		const replacement = (await restarted.claimNext()).claim;
		expect(replacement).toBeDefined();
		expect(replacement?.token).not.toBe(oldClaim?.token);
		if (!oldClaim || !replacement) throw new Error("expected_claims");
		expect(
			await restarted.completeClaim(oldClaim, {
				outcome: "delivered",
				code: "accepted",
				statusCode: 202,
			}),
		).toMatchObject({ applied: false, pending: 1 });
		expect(
			await restarted.completeClaim(replacement, {
				outcome: "delivered",
				code: "accepted",
				statusCode: 202,
			}),
		).toMatchObject({ applied: true, delivered: 1, pending: 0 });
	});

	it("binds receipts to the SIEM destination while allowing bearer rotation", async () => {
		const path = await statePath();
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) =>
			acknowledgedWebhookResponse(init),
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

	it("keeps delivery-loss health unhealthy after bounded receipts are trimmed and reopened", async () => {
		const path = await statePath();
		let attempts = 0;
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) =>
			++attempts === 1 ? new Response(null, { status: 401 }) : acknowledgedWebhookResponse(init),
		) as unknown as typeof fetch;
		const options = webhookOptions(path, fetcher, { maxReceipts: 1 });
		const delivery = await DurableSiemDelivery.open(options);
		await delivery.enqueue(incident);
		expect((await delivery.flush()).deadLettered).toBe(1);
		await delivery.enqueue({ ...incident, incident_id: "inc-delivery-2" });
		expect((await delivery.flush()).delivered).toBe(1);

		const reopened = await DurableSiemDelivery.open(options);
		expect(await reopened.health()).toMatchObject({
			status: "unhealthy",
			deadLettered: 0,
			deadLetteredTotal: 1,
			queueDepth: 0,
		});
	});

	it("honors Retry-After on 429 and retries with the same event id", async () => {
		const path = await statePath();
		let nowMs = 10_000;
		const requestIds: string[] = [];
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			requestIds.push(new Headers(init?.headers).get("idempotency-key") ?? "");
			return requestIds.length === 1
				? new Response(null, { status: 429, headers: { "retry-after": "2" } })
				: acknowledgedWebhookResponse(init);
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
		const fetcherMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			body = String(init?.body);
			headers = new Headers(init?.headers);
			return new Response(JSON.stringify({ text: "Success", code: 0 }), { status: 200 });
		});
		const fetcher = fetcherMock as unknown as typeof fetch;
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
		expect(String(fetcherMock.mock.calls[0]?.[0])).toContain("/services/collector/event");
		expect(await readFile(path, "utf8")).not.toContain("hec-secret");
	});

	it("accepts only Sentinel's explicit 204 response contract", async () => {
		const path = await statePath();
		let nowMs = 1_000;
		let attempts = 0;
		let body = "";
		let url = "";
		const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			attempts += 1;
			url = String(input);
			body = String(init?.body);
			return new Response(null, { status: attempts === 1 ? 200 : 204 });
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
			now: () => nowMs,
			random: () => 0,
			minBackoffMs: 100,
		});
		const queued = await delivery.enqueue(incident);

		expect(await delivery.flush()).toMatchObject({ delivered: 0, retrying: 1, pending: 1 });
		expect(await delivery.getReceipt(queued.receipt.receiptId)).toMatchObject({
			status: "retrying",
			lastErrorCode: "unexpected_sentinel_response",
		});
		nowMs = 1_100;
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

	it("records Elastic item-level status instead of a misleading HTTP 200", async () => {
		for (const itemStatus of [401, 429]) {
			const path = await statePath();
			const fetcher = vi.fn(
				async () =>
					new Response(
						JSON.stringify({ errors: true, items: [{ create: { status: itemStatus } }] }),
						{
							status: 200,
						},
					),
			) as unknown as typeof fetch;
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

			await delivery.flush();
			expect(await delivery.getReceipt(queued.receipt.receiptId)).toMatchObject({
				lastStatusCode: itemStatus,
				lastErrorCode: itemStatus === 401 ? "authorization_rejected" : "rate_limited",
			});
		}
	});

	it("rejects insecure, credential-bearing and query-bearing endpoints", async () => {
		const options = (endpoint: string, stateFile: string) => ({
			stateFile,
			adapter: { provider: "webhook" as const, endpoint },
			fetch: vi.fn() as unknown as typeof fetch,
		});

		await expect(
			DurableSiemDelivery.open(options("http://events.example.test", await statePath())),
		).rejects.toThrow("HTTPS");
		await expect(
			DurableSiemDelivery.open(options("https://user:pass@events.example.test", await statePath())),
		).rejects.toThrow("credentials");
		await expect(
			DurableSiemDelivery.open(
				options("https://events.example.test/?token=secret", await statePath()),
			),
		).rejects.toThrow("query");
	});
});
