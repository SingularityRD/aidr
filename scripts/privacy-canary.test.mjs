import { strict as assert } from "node:assert";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ControlPlaneClient } from "../packages/core/src/clients/control-plane.ts";
import { redactRemoteEvent } from "../packages/core/src/managed.ts";
import {
	redactTelemetryData,
	sanitizeTelemetryEndpoint,
} from "../packages/core/src/telemetry-redaction.ts";
import { redactSentryEvent } from "../packages/dashboard/src/sentry.ts";
import { normalizeIngestEvents } from "../supabase/functions/ingest/events.ts";
import { parseDiscoveryIngest } from "../supabase/functions/discovery/logic.ts";

const RAW_PROMPT = "PRIVACY_CANARY_PROMPT_6f2190e4";
const CREDENTIAL = ["ghp_1234", "567890AB", "CDEFGHIJ", "KLMNOPQR", "ST"].join("");
const DISCOVERY_TENANT = "11111111-1111-4111-8111-111111111111";
const DISCOVERY_CYCLE = "22222222-2222-4222-8222-222222222222";

function assertAbsent(value, markers) {
	const serialized = JSON.stringify(value);
	for (const marker of markers) {
		expect(serialized, `Raw canary leaked: ${marker}`).not.toContain(marker);
	}
}

async function readTree(root) {
	const chunks = [];
	for (const entry of await readdir(root, { withFileTypes: true })) {
		const path = join(root, entry.name);
		if (entry.isDirectory()) chunks.push(await readTree(path));
		else if (entry.isFile()) chunks.push(await readFile(path, "utf8"));
	}
	return chunks.join("\n");
}

describe("privacy boundary canaries", () => {
	const originalFetch = globalThis.fetch;
	let queueRoot;

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		if (queueRoot) await rm(queueRoot, { recursive: true, force: true });
		queueRoot = undefined;
	});

	it("scrubs a synthetic credential before managed wire delivery and durable queue storage", async () => {
		queueRoot = await mkdtemp(join(tmpdir(), "aidr-privacy-canary-"));
		const captured = [];
		globalThis.fetch = async (_url, init) => {
			const body = JSON.parse(String(init.body));
			captured.push(body);
			if (captured.length === 1) throw new Error("synthetic offline interval");
			return {
				ok: true,
				status: 200,
				json: async () => ({
					ok: true,
					acknowledged_event_ids: body.events.map((event) => event.event_id),
				}),
			};
		};
		const client = new ControlPlaneClient(
			{ endpoint: "https://control.example.test", timeout_seconds: 1 },
			"synthetic-api-key",
			undefined,
			{ telemetryQueueRoot: queueRoot, telemetryQueue: { initialRetryMs: 1 } },
		);
		const offline = await client.ingest({
			iid: "privacy-canary-agent",
			events: [{
				type: "runtime_verdict",
				tool_input_summary: `curl 'https://example.test/?token=${CREDENTIAL}'`,
				prompt: `Authorization: Bearer ${CREDENTIAL}`,
				metadata: { api_key: CREDENTIAL },
			}],
		});
		expect(offline.ok).toBe(false);
		expect(captured[0].events).toHaveLength(1);
		assertAbsent(captured[0].events, [CREDENTIAL]);
		assertAbsent(await readTree(queueRoot), [CREDENTIAL]);
		await new Promise((resolve) => setTimeout(resolve, 5));
		const retried = await client.ingest({ iid: "privacy-canary-agent", events: [] });
		expect(retried.ok).toBe(true);
		expect(captured).toHaveLength(2);
		assertAbsent(captured[1].events, [CREDENTIAL]);
	});

	it("does not export raw prompt text in default hash or full mode", () => {
		const event = {
			type: "runtime_verdict",
			tool_input_summary: RAW_PROMPT,
			artifacts: [RAW_PROMPT],
			reasons: [RAW_PROMPT],
			prompt: RAW_PROMPT,
			nested: { content: RAW_PROMPT },
		};
		const hash = redactRemoteEvent(event, undefined);
		const full = redactRemoteEvent(event, "full");
		assertAbsent(hash, [RAW_PROMPT]);
		assertAbsent(full, [RAW_PROMPT]);
		expect(hash.tool_input_summary).toMatch(/^sha256:[0-9a-f]{64}$/);
		expect(full.tool_input_summary).toBe("");
	});

	it("does not persist raw credential or prompt from a direct authenticated ingest payload", () => {
		const normalized = normalizeIngestEvents([{
			event_id: "privacy-canary-event",
			type: "runtime_verdict",
			prompt: RAW_PROMPT,
			tool_input_summary: RAW_PROMPT,
			artifacts: [RAW_PROMPT],
			reasons: [RAW_PROMPT],
			nested: { content: RAW_PROMPT },
			api_key: CREDENTIAL,
		}]);
		expect(normalized.ok).toBe(true);
		if (!normalized.ok) throw new Error("Synthetic direct ingest event was rejected");
		assertAbsent(normalized.events, [RAW_PROMPT, CREDENTIAL]);
		expect(normalized.events).toEqual([{
			event_id: "privacy-canary-event",
			type: "runtime_verdict",
			tool_input_summary: "[Redacted]",
			artifacts: ["[Redacted]"],
			reasons: [],
		}]);
	});

	it("scrubs diagnostics and drops credential-bearing OTLP endpoint components", () => {
		const source = {
			message: `Authorization: Bearer ${CREDENTIAL}`,
			request: { url: `https://example.test/path?token=${CREDENTIAL}` },
			contexts: { values: { api_key: CREDENTIAL } },
		};
		assertAbsent(redactTelemetryData(source), [CREDENTIAL]);
		assertAbsent(redactSentryEvent(source), [CREDENTIAL]);
		expect(sanitizeTelemetryEndpoint(`https://user:${CREDENTIAL}@trace.example.test/v1/traces?token=${CREDENTIAL}#fragment`))
			.toBe("https://trace.example.test/v1/traces");
	});

	it("removes structured raw prompt fields from runtime and browser diagnostics", () => {
		const diagnostic = {
			message: "synthetic diagnostic",
			contexts: { request: { prompt: RAW_PROMPT, tool_input: RAW_PROMPT } },
			request: { data: { prompt: RAW_PROMPT } },
		};
		assertAbsent(redactTelemetryData(diagnostic), [RAW_PROMPT]);
		assertAbsent(redactSentryEvent(diagnostic), [RAW_PROMPT]);
	});

	it("drops browser identity and arbitrary request payload fields", () => {
		const event = redactSentryEvent({
			user: { email: "canary@example.test" },
			request: {
				method: "POST",
				url: `https://example.test/incident?case=${RAW_PROMPT}`,
				data: { note: RAW_PROMPT },
				headers: { "x-internal": RAW_PROMPT },
			},
		});
		assertAbsent(event, ["canary@example.test", RAW_PROMPT]);
		expect(event.request).toEqual({ method: "POST", url: "https://example.test/incident" });
	});

	it("does not return arbitrary upstream ingest error details", async () => {
		globalThis.fetch = async () => ({
			ok: false,
			status: 503,
			json: async () => ({ error: "private_customer_secret", debug: RAW_PROMPT }),
		});
		const client = new ControlPlaneClient(
			{ endpoint: "https://control.example.test", timeout_seconds: 1 },
			"synthetic-api-key",
		);
		const result = await client.ingest({ events: [] });
		expect(result.error).toBe("http_error");
		assertAbsent(result, ["private_customer_secret", RAW_PROMPT]);
	});

	it("rejects secret-bearing central discovery targets", () => {
		const base = {
			action: "ingest",
			tenant_id: DISCOVERY_TENANT,
			collector_id: "privacy-canary",
			cycle_id: DISCOVERY_CYCLE,
			sequence: 1,
			stale_after_ms: 60_000,
			complete: true,
			expected_targets: 1,
			items: [{ target: "https://example.test/", reachable: true, attempts: 1, error_code: null }],
		};
		assert.equal(parseDiscoveryIngest(base)?.items[0]?.target, "https://example.test/");
		for (const target of [
			`https://example.test/private/${RAW_PROMPT}`,
			`https://example.test/?token=${CREDENTIAL}`,
			`https://user:${CREDENTIAL}@example.test/`,
		]) {
			expect(parseDiscoveryIngest({ ...base, items: [{ ...base.items[0], target }] })).toBeNull();
		}
	});
});
