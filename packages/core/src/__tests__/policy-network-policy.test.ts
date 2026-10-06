import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";

describe("network policy enforcement", () => {
	const config = ConfigSchema.parse({
		policy: {
			enabled: true,
			network: { enabled: true, deny_private_ips: true, deny_action: "block" },
		},
	});

	it.each([
		"http://127.0.0.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/",
		"http://[fd00::1]/",
		"http://[fe80::1]/",
		"http://[::ffff:127.0.0.1]/",
		"http://[::ffff:169.254.169.254]/",
	])("denies private and metadata address %s", async (url) => {
		expect(await evaluatePolicy("WebFetch", [{ type: "url", value: url }], config)).toMatchObject({
			decision: "deny",
			matchedThreatId: "POL-NET-001",
		});
	});

	it.each(["https://8.8.8.8/", "https://[2606:4700:4700::1111]/"])(
		"allows public literal address %s",
		async (url) => {
			expect(await evaluatePolicy("WebFetch", [{ type: "url", value: url }], config)).toBeNull();
		},
	);

	it("matches a denied DNS name with its equivalent trailing-dot spelling", async () => {
		const denied = ConfigSchema.parse({
			policy: {
				enabled: true,
				network: { enabled: true, deny_domains: ["blocked.example"], deny_action: "block" },
			},
		});
		expect(
			await evaluatePolicy(
				"WebFetch",
				[{ type: "url", value: "https://blocked.example./" }],
				denied,
			),
		).toMatchObject({
			decision: "deny",
			matchedThreatId: "POL-NET-002",
		});
	});
});
