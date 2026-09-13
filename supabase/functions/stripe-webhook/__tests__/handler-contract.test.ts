// Static contract tests for the Stripe Edge Function handler.
//
// ./index.ts calls Deno.serve and imports `npm:@supabase/supabase-js@2`, so it
// cannot be imported into vitest. The pure decision logic lives in ./verify.ts,
// ./events.ts and ./dedup.ts and is unit-tested directly; what remains here is
// the wiring contract that only exists in the handler file - ordering of the
// raw-body read, signature verification, dedup claim and writes, plus the
// fail-closed response and CORS posture.
//
// COVERAGE BOUNDARY: nothing in this suite executes the deployed Deno runtime,
// talks to Supabase, or talks to Stripe.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const FUNCTION_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(FUNCTION_DIR, "..", "..", "..");
const HANDLER = join(FUNCTION_DIR, "index.ts");

const source = readFileSync(HANDLER, "utf8");

function indexOfOrFail(needle: string): number {
	const index = source.indexOf(needle);
	expect(index, `expected ${needle} in the Stripe handler`).toBeGreaterThanOrEqual(0);
	return index;
}

describe("stripe webhook handler contract", () => {
	it("reads the raw body before parsing it", () => {
		const rawBodyRead = indexOfOrFail("await req.text()");
		const firstParse = indexOfOrFail("JSON.parse(rawBody)");

		expect(rawBodyRead).toBeLessThan(firstParse);
	});

	it("verifies the Stripe-Signature header over the raw body", () => {
		expect(source).toContain('"Stripe-Signature"');
		expect(source).toContain("verifyStripeWebhookSignature({");
		expect(source).toContain("signatureHeader: req.headers.get(STRIPE_SIGNATURE_HEADER)");
		expect(source).toContain("rawBody,");
		expect(source).toContain("STRIPE_WEBHOOK_SECRET");
	});

	it("returns 400 and writes nothing when verification fails", () => {
		const verify = indexOfOrFail("await verifyStripeWebhookSignature({");
		const firstWrite = indexOfOrFail("await claimStripeEvent(recorder");
		const firstOk = indexOfOrFail("json(200");

		// Two 400 invalid_signature paths: a missing endpoint secret (checked
		// before any body is read) and a failed verification.
		const rejections = [...source.matchAll(/json\(400, \{ error: "invalid_signature" \}/g)].map(
			(match) => match.index ?? -1,
		);
		expect(rejections).toHaveLength(2);

		for (const index of rejections) {
			expect(index).toBeLessThan(firstWrite);
			expect(index).toBeLessThan(firstOk);
		}

		// The signature-failure 400 comes after the verification call.
		expect(rejections[1]).toBeGreaterThan(verify);
	});

	it("verifies before parsing, and claims the event id before any state write", () => {
		const verify = indexOfOrFail("await verifyStripeWebhookSignature({");
		const parse = indexOfOrFail("JSON.parse(rawBody)");
		const claim = indexOfOrFail("await claimStripeEvent(recorder");
		// Call sites, not the hoisted function declarations.
		const subscriptionWrite = indexOfOrFail("await upsertSubscription(supabase");
		const customerWrite = indexOfOrFail("await upsertBillingCustomer(supabase");
		const entitlementWrite = indexOfOrFail("await writeExtraAgents(");

		expect(verify).toBeLessThan(parse);
		expect(parse).toBeLessThan(claim);
		expect(claim).toBeLessThan(subscriptionWrite);
		expect(claim).toBeLessThan(entitlementWrite);
		expect(claim).toBeLessThan(customerWrite);
	});

	it("deduplicates through the same service-role RPC the Paddle handler uses", () => {
		expect(source).toContain('supabase.rpc("record_billing_webhook_event"');
		expect(source).toContain('p_provider: provider');
		expect(source).not.toContain("p_provider: \"paddle\"");
	});

	it("keeps every caller-visible response body to a static error code", () => {
		const allowed = new Set([
			"method_not_allowed",
			"disabled_for_direct_ga",
			"invalid_signature",
			"invalid_json",
			"invalid_event",
			"misconfigured_supabase_env",
			"webhook_dedup_unavailable",
			"webhook_processing_failed",
			"origin_not_allowed",
		]);

		const calls = [...source.matchAll(/json\(\s*(\d{3})\s*,\s*\{([^}]*)\}/g)];
		expect(calls.length).toBeGreaterThan(0);

		// Every response body is a literal: `ok`-style flags and/or a static
		// snake_case error code. An interpolated `error.message` would not match.
		const literalBody = /^\s*(?:(?:ok|dedup|ignored|recorded|unlinked):\s*true|error:\s*"[a-z_]+")\s*,?\s*$/;
		for (const [, , body] of calls) {
			for (const field of (body as string).split(",")) {
				expect(field.trim(), `unexpected response body: {${body}}`).toMatch(literalBody);
			}
			const code = /error:\s*"([a-z_]+)"/.exec(body as string)?.[1];
			if (code) expect(allowed.has(code), `unexpected error code ${code}`).toBe(true);
		}

		// The removed Lemon Squeezy handler leaked `details: error.message`; make
		// sure that pattern cannot come back.
		expect(source).not.toContain("details:");
	});

	it("validates required Supabase configuration through the shared guard, before any work", () => {
		// AIDR-011: the misconfiguration path no longer builds a literal body in
		// this file - it delegates to `_shared/config.ts`, so the literal-body
		// check above cannot see it. Pin the delegation AND the ordering here, and
		// keep the response body free of internal error text.
		expect(source).toContain('from "../_shared/config.ts"');

		const guard = indexOfOrFail("loadConfig(runtimeEnv, REQUIRED_ENV)");
		expect(source).toContain(
			'const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;',
		);

		// No empty-credential fallback may come back for either variable.
		expect(source).not.toContain('Deno.env.get("SUPABASE_URL")');
		expect(source).not.toContain('Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")');

		// Validated before the raw body is read and before a client is built.
		expect(guard).toBeLessThan(indexOfOrFail("await req.text()"));
		expect(guard).toBeLessThan(indexOfOrFail("createClient(SUPABASE_URL"));

		// The only projection of a configuration error is the shared helper; no
		// exception message and no configuration value is ever returned.
		expect(indexOfOrFail("configFailure(")).toBeGreaterThan(guard);
		expect(source).not.toMatch(/error:\s*error\.message/);
	});

	it("does not grant a CORS allowance to browsers", () => {
		// No ACAO/ACAM/ACAH header is ever emitted. (The file mentions CORS only
		// in comments explaining why there is none.)
		expect(source).not.toMatch(/["']Access-Control-Allow-[A-Za-z-]+["']\s*:/);
		expect(source).not.toMatch(/Access-Control-Allow-Origin["']?\s*[:,]\s*["']?\*/);
		expect(source).not.toContain('"*"');
	});

	it("gates the endpoint behind the direct-GA self-service flag", () => {
		expect(source).toContain("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING");
		expect(source).toContain('json(410, { error: "disabled_for_direct_ga" }');
	});

	it("rejects non-POST methods including preflight", () => {
		expect(source).toContain('json(405, { error: "method_not_allowed" }');
	});

	it("keeps the replay window and price id configurable", () => {
		expect(source).toContain("AIDR_STRIPE_WEBHOOK_TOLERANCE_SECONDS");
		expect(source).toContain("AIDR_STRIPE_EXTRA_AGENT_PRICE_ID");
	});
});

describe("stripe webhook module hygiene", () => {
	it("has no always-true verifier and no CORS wildcard in the function directory", () => {
		const files: string[] = [];
		const walk = (dir: string) => {
			for (const entry of readdirSync(dir)) {
				// Skip this test directory: it asserts on these strings itself.
				if (entry === "__tests__") continue;
				const full = join(dir, entry);
				if (statSync(full).isDirectory()) walk(full);
				else files.push(full);
			}
		};
		walk(FUNCTION_DIR);

		expect(files.length).toBeGreaterThan(0);
		for (const file of files) {
			const contents = readFileSync(file, "utf8");
			expect(contents, file).not.toContain("Access-Control-Allow-Origin");
			expect(contents, file).not.toMatch(/verifyWebhookSignature[\s\S]{0,200}return true/);
		}
	});

	it("removed the Lemon Squeezy edge function", () => {
		const lemonDir = join(REPO_ROOT, "packages", "dashboard", "supabase", "functions", "lemon-webhook");
		expect(() => statSync(lemonDir)).toThrow();
	});
});
