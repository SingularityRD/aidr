/**
 * Regression guards for the removal of the SDK's Lemon Squeezy payment path.
 *
 * The removed client shipped two defects: `processWebhook` skipped signature
 * verification entirely when no secret was configured (so an unauthenticated
 * payload was dispatched), and its signature compare was not constant-time over
 * the received bytes. A client-side payment webhook verifier cannot be made safe
 * — it either holds a secret in an unsafe place or omits verification — so the
 * SDK intentionally offers none, and billing/entitlement issuance is a
 * server-side concern handled by the signature-verified Stripe webhook.
 *
 * These tests fail if that path is reintroduced.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const SDK_SRC = resolve(__dirname, "..");

function collectSourceFiles(dir: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(dir)) {
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) {
			if (entry === "__tests__") continue;
			out.push(...collectSourceFiles(full));
			continue;
		}
		if (entry.endsWith(".ts") || entry.endsWith(".tsx")) out.push(full);
	}
	return out;
}

describe("SDK payment-provider removal", () => {
	it("ships no Lemon Squeezy client module", () => {
		expect(() => statSync(join(SDK_SRC, "billing.ts"))).toThrow();
	});

	it("contains no Lemon Squeezy API calls or credential fields in source", () => {
		const offenders: string[] = [];
		for (const file of collectSourceFiles(SDK_SRC)) {
			const content = readFileSync(file, "utf8");
			// Comments explaining the removal are fine; executable references are not.
			for (const line of content.split("\n")) {
				const trimmed = line.trim();
				if (trimmed.startsWith("*") || trimmed.startsWith("//")) continue;
				if (/lemonsqueezy|lemonSqueezyApiKey|api\.lemonsqueezy\.com/i.test(line)) {
					offenders.push(`${file}: ${trimmed}`);
				}
			}
		}
		expect(offenders).toEqual([]);
	});

	it("exposes no webhook signature verifier", () => {
		const offenders: string[] = [];
		for (const file of collectSourceFiles(SDK_SRC)) {
			const content = readFileSync(file, "utf8");
			if (/verifyWebhookSignature|processWebhook/.test(content)) offenders.push(file);
		}
		expect(offenders).toEqual([]);
	});

	it("keeps the provider-agnostic licence types available", async () => {
		const mod = (await import("../license.js")) as Record<string, unknown>;
		expect(mod).toBeDefined();
		const types = readFileSync(join(SDK_SRC, "license.ts"), "utf8");
		expect(types).toContain("LicenseValidationResult");
		expect(types).toContain("UsageInfo");
	});
});

describe("SDK product-surface removal", () => {
	it.each(["cli.ts", "freemium.ts", "referral.ts", "team-dashboard.ts"])(
		"does not ship the unused %s subsystem",
		(file) => {
			expect(() => statSync(join(SDK_SRC, file))).toThrow();
		},
	);

	it("keeps product and framework-specific surfaces out of the public entry point", () => {
		const entry = readFileSync(join(SDK_SRC, "index.ts"), "utf8");
		expect(entry).not.toMatch(
			/\b(?:FreemiumManager|ReferralSystem|TeamDashboard|AIDRSpeaker|AIDRCrewTool|AIDRTool|AIDRQueryEngine)\b/,
		);
	});
});
