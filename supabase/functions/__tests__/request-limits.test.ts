import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
	consumeTenantRateLimit,
	rateLimitHeaders,
	readBoundedJson,
	readBoundedText,
} from "../_shared/request-limits.ts";

describe("bounded request JSON", () => {
	it("counts encoded bytes and parses a bounded object", async () => {
		const request = new Request("https://aidr.test/ingest", {
			method: "POST",
			body: JSON.stringify({ value: "ş" }),
		});
		await expect(readBoundedJson(request, 32)).resolves.toEqual({
			ok: true,
			value: { value: "ş" },
			bytes: 14,
		});
	});

	it("rejects declared and streamed oversize bodies with 413", async () => {
		const declared = new Request("https://aidr.test/file-check", {
			method: "POST",
			headers: { "content-length": "100" },
			body: "{}",
		});
		await expect(readBoundedJson(declared, 10)).resolves.toMatchObject({
			ok: false,
			status: 413,
		});

		const streamed = new Request("https://aidr.test/url-check", {
			method: "POST",
			body: "şşşşşş",
		});
		await expect(readBoundedJson(streamed, 10)).resolves.toMatchObject({
			ok: false,
			status: 413,
		});
	});

	it("returns 413 even when an oversized stream never finishes cancellation", async () => {
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new Uint8Array(11));
			},
			cancel() {
				return new Promise<void>(() => undefined);
			},
		});
		const request = new Request("https://aidr.test/ingest", {
			method: "POST",
			body,
			duplex: "half",
		} as RequestInit);
		await expect(readBoundedJson(request, 10)).resolves.toEqual({
			ok: false,
			status: 413,
			error: "request_too_large",
		});
	});

	it("rejects malformed JSON and malformed UTF-8", async () => {
		await expect(
			readBoundedJson(
				new Request("https://aidr.test", { method: "POST", body: "{" }),
				10,
			),
		).resolves.toMatchObject({ ok: false, status: 400, error: "invalid_json" });
		await expect(
			readBoundedJson(
				new Request("https://aidr.test", {
					method: "POST",
					body: new Uint8Array([0xc3, 0x28]),
				}),
				10,
			),
		).resolves.toMatchObject({ ok: false, status: 400, error: "invalid_json" });
	});
});

describe("bounded request text", () => {
	it("preserves raw text and rejects a chunked body that understates Content-Length", async () => {
		await expect(
			readBoundedText(
				new Request("https://aidr.test/webhook", { method: "POST", body: "ş\r\n" }),
				8,
			),
		).resolves.toEqual({ ok: true, value: "ş\r\n", bytes: 4 });

		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("123"));
				controller.enqueue(new TextEncoder().encode("456"));
				controller.close();
			},
		});
		const request = new Request("https://aidr.test/webhook", {
			method: "POST",
			headers: { "content-length": "2" },
			body,
			duplex: "half",
		} as RequestInit);
		await expect(readBoundedText(request, 5)).resolves.toEqual({
			ok: false,
			status: 413,
			error: "request_too_large",
		});
	});
});

describe("tenant rate limit boundary", () => {
	const request = {
		tenantId: "00000000-0000-4000-8000-000000000001",
		subject: "user-1",
		endpoint: "ingest",
		perSubject: 120,
		perTenant: 5_000,
		now: 120_500,
	};

	it("passes tenant and subject limits to one atomic RPC", async () => {
		const rpc = vi.fn().mockResolvedValue({
			data: [{ allowed: true, remaining: 119 }],
			error: null,
		});
		await expect(consumeTenantRateLimit({ rpc }, request)).resolves.toEqual({
			ok: true,
			remaining: 119,
			retryAfterSeconds: 60,
		});
		expect(rpc).toHaveBeenCalledWith("consume_tenant_rate_limit", {
			p_tenant_id: request.tenantId,
			p_subject: "user-1",
			p_endpoint: "ingest",
			p_window_start: 2,
			p_subject_limit: 120,
			p_tenant_limit: 5_000,
			p_cost: 1,
		});
	});

	it("returns 429 only for an authoritative quota rejection", async () => {
		const rpc = vi.fn().mockResolvedValue({
			data: [{ allowed: false, remaining: 0 }],
			error: null,
		});
		const result = await consumeTenantRateLimit({ rpc }, request);
		expect(result).toMatchObject({
			ok: false,
			status: 429,
			error: "rate_limited",
		});
		expect(rateLimitHeaders(result)).toEqual({
			"RateLimit-Remaining": "0",
			"Retry-After": "60",
		});
	});

	it.each([
		[{ data: null, error: { message: "offline" } }],
		[{ data: [{ allowed: "yes", remaining: 1 }], error: null }],
		[{ data: [{ allowed: true, remaining: 1 }, { allowed: false, remaining: 0 }], error: null }],
		[undefined],
	])("fails closed when the limiter is unavailable or malformed", async (result) => {
		const rpc = vi.fn().mockResolvedValue(result);
		await expect(consumeTenantRateLimit({ rpc }, request)).resolves.toMatchObject({
			ok: false,
			status: 503,
			error: "rate_limit_unavailable",
		});
	});
});

describe("SQL concurrency contract", () => {
	it("locks aggregate then subject and exposes the RPC only to service_role", () => {
		const migration = readFileSync(
			resolve(
				dirname(fileURLToPath(import.meta.url)),
				"../../migrations/20260912000014_tenant_resource_limits.sql",
			),
			"utf8",
		);
		expect(migration.match(/for update;/g)).toHaveLength(2);
		expect(migration.indexOf("select rl.count into strict v_tenant_count")).toBeLessThan(
			migration.indexOf("select rl.count into strict v_subject_count"),
		);
		expect(migration).toContain("revoke all on function public.consume_tenant_rate_limit");
		expect(migration).toContain("to service_role");
		expect(migration).toContain("t.status = 'active'");
	});
});

describe("resource-limit endpoint wiring", () => {
	const functionsDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

	it.each([
		"ingest",
		"url-check",
		"file-check",
		"policy",
		"policy-ack",
		"policy-management",
		"packs-manifest",
		"packs-download",
	])("enforces a tenant rate limit in %s", (name) => {
		const source = readFileSync(join(functionsDir, name, "index.ts"), "utf8");
		expect(source).toContain('from "../_shared/request-limits.ts"');
		expect(source).toContain("await consumeTenantRateLimit(");
		expect(source).toContain("if (!rate.ok)");
	});

	it.each([
		"ingest",
		"url-check",
		"file-check",
		"policy-ack",
		"policy-management",
		"waitlist-signup",
		"billing-portal",
		"invoice-entitlement",
	])(
		"bounds the JSON body in %s",
		(name) => {
			const source = readFileSync(join(functionsDir, name, "index.ts"), "utf8");
			expect(source).toContain("await readBoundedJson(");
		},
	);

	it.each(["delegated-credentials", "paddle-webhook", "stripe-webhook"])(
		"bounds raw request text in %s",
		(name) => {
			const source = readFileSync(join(functionsDir, name, "index.ts"), "utf8");
			expect(source).toContain("await readBoundedText(");
		},
	);

	it("fails Paddle billing closed on ambiguous replay, event, price, and claim inputs", () => {
		const source = readFileSync(join(functionsDir, "paddle-webhook", "index.ts"), "utf8");
		expect(source).toContain("resolvePaddleToleranceSeconds(PADDLE_TOLERANCE_RAW)");
		expect(source).toContain("Number.isSafeInteger(parsed) && parsed > 0 && parsed <= 3600");
		expect(source).toContain("if (!EVENT_ID.test(eventId))");
		expect(source).toContain("AIDR_PADDLE_EXTRA_AGENT_PRICE_ID.trim()");
		expect(source).toContain('supabase.rpc("finish_billing_webhook_event"');
		expect(source).toContain('"apply_billing_subscription_event"');
		expect(source).not.toContain('from("billing_webhook_events").delete()');
	});

	it("bounds identity and device-code JSON through the shared reader", () => {
		for (const path of [
			join(functionsDir, "identity-security", "index.ts"),
			join(functionsDir, "_shared", "auth.ts"),
		]) {
			expect(readFileSync(path, "utf8")).toContain("await readBoundedJson(");
		}
	});
});
