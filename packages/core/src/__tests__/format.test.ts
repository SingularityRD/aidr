import { describe, expect, it } from "vitest";
import {
	formatSessionStartMessage,
	formatStartupClean,
	formatStartupDisabled,
	formatThreatBanner,
	formatUpdateNotice,
	kv,
	separatorLine,
	severityEmoji,
} from "../format.js";
import type { SessionStartResult } from "../session-start.js";
import type { PluginScanResult } from "../types.js";

const update = {
	currentVersion: "1.0.0",
	latestVersion: "1.2.0",
	updateAvailable: true,
};

function scanResult(findings: PluginScanResult["findings"]): PluginScanResult {
	return {
		plugin: {
			key: "test-plugin",
			installPath: "/tmp/test-plugin",
			version: "1.0.0",
			lastUpdated: "2026-05-06T00:00:00.000Z",
		},
		findings,
	};
}

describe("core format helpers", () => {
	it("formats severity labels, key/value rows, separators, and update notices", () => {
		expect(severityEmoji("critical")).toBe("🚨");
		expect(severityEmoji("high")).toBe("🚨");
		expect(severityEmoji("medium")).toBe("⚠️");
		expect(severityEmoji("warning")).toBe("⚠️");
		expect(severityEmoji("low")).toBe("ℹ️");
		expect(kv("Policy", "cached")).toContain("Policy");
		expect(kv("Policy", "cached")).toContain("cached");
		expect(separatorLine(4)).toBe("━━━━");
		expect(formatUpdateNotice(update)).toContain("v1.2.0");
	});

	it("formats clean startup with update and remote policy freshness", () => {
		const message = formatStartupClean("1.0.0", update, {
			enabled: true,
			path: "/tmp/runtime-policy-cache.json",
			source: "valid",
			usable: true,
			present: true,
			policyVersion: "pol_123",
			ttlSeconds: 42,
		});

		expect(message).toContain("No threats found");
		expect(message).toContain("pol_123 cached, 42s left");
		expect(message).toContain("Update available");
	});

	it("formats expired, invalid, and missing remote policy cache states", () => {
		expect(
			formatStartupClean("1.0.0", null, {
				enabled: true,
				path: "/tmp/cache.json",
				source: "expired",
				usable: false,
				present: true,
				policyVersion: "pol_old",
				ageSeconds: 3600,
			}),
		).toContain("pol_old cache expired, 3600s old");
		expect(
			formatStartupClean("1.0.0", null, {
				enabled: true,
				path: "/tmp/cache.json",
				source: "invalid",
				usable: false,
				present: true,
			}),
		).toContain("cache invalid");
		expect(
			formatStartupClean("1.0.0", null, {
				enabled: true,
				path: "/tmp/cache.json",
				source: "missing",
				usable: false,
				present: false,
			}),
		).not.toContain("Policy");
	});

	it("formats disabled startup with and without device bootstrap instructions", () => {
		expect(formatStartupDisabled("1.0.0", "managed_disabled")).toContain("Disabled");

		const message = formatSessionStartMessage("1.0.0", {
			enabled: false,
			disabled_reason: "activation_required",
			bootstrap: {
				verification_url: "https://aidr.example/verify",
				user_code: "ABCD-EFGH",
				expires_at: "2026-05-06T01:00:00.000Z",
			},
			scanResults: [],
			versionCheck: null,
		});

		expect(message).toContain("activation_required");
		expect(message).toContain("https://aidr.example/verify");
		expect(message).toContain("ABCD-EFGH");
		expect(message).toContain("Expires");
	});

	it("does not claim the product is off when local detection is still running", () => {
		// `enabled: false` historically meant "the product does nothing", but an
		// un-enrolled install still blocks threats locally. The banner must say so
		// rather than reporting a dead end.
		for (const reason of [
			"auth_required",
			"enrollment_repair_required",
			"missing_or_invalid_signed_entitlement",
			"activation_required",
		]) {
			const message = formatSessionStartMessage("1.0.0", {
				enabled: false,
				disabled_reason: reason,
				scanResults: [],
				versionCheck: null,
			});
			expect(message).toContain("Local protection ACTIVE");
			expect(message).not.toContain("Disabled");
		}

		// Reasons that really do stop enforcement must still say Disabled.
		for (const reason of [
			"degraded_safe_mode:integrity",
			"commercial_build_requires_managed_mode",
		]) {
			const message = formatSessionStartMessage("1.0.0", {
				enabled: false,
				disabled_reason: reason,
				scanResults: [],
				versionCheck: null,
			});
			expect(message).toContain("Disabled");
			expect(message).not.toContain("ACTIVE");
		}

		// An unrecognised reason must not be assumed safe: over-claiming protection
		// is the failure mode being guarded against.
		const unknown = formatSessionStartMessage("1.0.0", {
			enabled: false,
			disabled_reason: "some_future_reason",
			scanResults: [],
			versionCheck: null,
		});
		expect(unknown).toContain("Disabled");
		expect(unknown).not.toContain("ACTIVE");
	});

	it("shows operator repair guidance and suppresses a stale device bootstrap", () => {
		const message = formatSessionStartMessage("1.0.0", {
			enabled: false,
			disabled_reason: "enrollment_repair_required",
			bootstrap: { verification_url: "https://aidr.example/stale", user_code: "CONSUMED-CODE" },
			scanResults: [],
			versionCheck: null,
		});
		expect(message).toContain("Local protection ACTIVE");
		expect(message).toContain("Enrollment could not be confirmed locally");
		expect(message).toContain("revoke any affected key in the control plane");
		expect(message).toContain("approve it in the browser");
		expect(message).toContain("Preserve the installation ID and tenant");
		expect(message).not.toContain("https://aidr.example/stale");
		expect(message).not.toContain("CONSUMED-CODE");
	});

	it("formats threat banners with high/critical findings, overflow, and footer notices", () => {
		const findings = Array.from({ length: 6 }, (_, index) => ({
			threatId: `TST-${index}`,
			title: `Threat ${index}`,
			severity: index % 2 === 0 ? "critical" : "high",
			confidence: 0.9,
			action: index === 0 ? "block" : "flag",
			artifact: index === 0 ? "/etc/shadow" : "",
			sourceFile: `plugin-${index}.ts`,
		}));
		findings.push({
			threatId: "LOW-1",
			title: "Low finding",
			severity: "low",
			confidence: 0.1,
			action: "flag",
			artifact: "ignored",
			sourceFile: "low.ts",
		});

		const message = formatThreatBanner("1.0.0", [scanResult(findings)], update, {
			enabled: true,
			path: "/tmp/cache.json",
			source: "expired",
			usable: false,
			present: true,
			policyVersion: "pol_old",
		});

		expect(message).toContain("Threat Detected");
		expect(message).toContain("Threat 0");
		expect(message).toContain("Artifact");
		expect(message).toContain("... and 1 more findings");
		expect(message).not.toContain("Low finding");
		expect(message).toContain("Update available");
		expect(message).toContain("pol_old cache expired");
	});

	it("routes session-start messages between disabled, threat, and clean states", () => {
		const threatResult: SessionStartResult = {
			enabled: true,
			scanResults: [
				scanResult([
					{
						threatId: "TST-1",
						title: "Critical plugin finding",
						severity: "critical",
						confidence: 1,
						action: "block",
						artifact: "payload",
						sourceFile: "plugin.ts",
					},
				]),
			],
			versionCheck: null,
		};
		const cleanResult: SessionStartResult = {
			enabled: true,
			scanResults: [],
			versionCheck: null,
		};

		expect(formatSessionStartMessage("1.0.0", threatResult)).toContain("Critical plugin finding");
		expect(formatSessionStartMessage("1.0.0", cleanResult)).toContain("No threats found");
		expect(
			formatSessionStartMessage("1.0.0", {
				enabled: false,
				disabled_reason: "disabled",
				scanResults: [],
				versionCheck: null,
			}),
		).toBe("Singularity AIDR v1.0.0 - Disabled (disabled)");
	});

	it("labels withheld reputation as review required, not clean", () => {
		const result = scanResult([]);
		result.unavailableChecks = [
			{
				check: "url_reputation",
				reason: "disabled to avoid sending plugin URLs to an external reputation provider",
				uncheckedCount: 2,
			},
		];
		const message = formatSessionStartMessage("1.0.0", {
			enabled: true,
			scanResults: [result],
			versionCheck: null,
		});

		expect(message).toContain("Review Required");
		expect(message).toContain("URL reputation was not verified for 2 item(s)");
		expect(message).not.toContain("No threats found");
	});

	it("reports an MCP inventory coverage gap instead of a complete inventory", () => {
		const gapped = formatSessionStartMessage("1.0.0", {
			enabled: true,
			scanResults: [],
			versionCheck: null,
			posture: {
				mcpServers: 0,
				riskyMcpServers: 0,
				unverifiedMcpServers: 0,
				invalidSources: 1,
				mcpCoverage: "invalid",
				mcpServersNotEnumerated: 0,
				mcpSourcesNotEnumerated: 1,
				infrastructure: "inactive",
			},
		});
		expect(gapped).toContain("Inventory coverage is invalid, not complete");
		expect(gapped).toContain("1 source(s) could not be read at all");

		// A fully readable inventory must not be presented as a gap.
		const complete = formatSessionStartMessage("1.0.0", {
			enabled: true,
			scanResults: [],
			versionCheck: null,
			posture: {
				mcpServers: 2,
				riskyMcpServers: 0,
				unverifiedMcpServers: 0,
				invalidSources: 0,
				mcpCoverage: "read",
				mcpServersNotEnumerated: 0,
				mcpSourcesNotEnumerated: 0,
				infrastructure: "inactive",
			},
		});
		expect(complete).toContain("MCP inventory: 2 configured");
		expect(complete).not.toContain("not complete");
	});
});
