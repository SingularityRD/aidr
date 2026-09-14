import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	detectorPolicyPath,
	loadProvisionedDetectorContext,
} from "../detector-provisioning.js";
import type { AgentRuntime } from "../types.js";
import {
	detectorPolicyPayload,
	detectorPolicyPathFor,
	entitlementSnapshot,
	provisionTenantDetectorPolicy,
	syntheticDlpPolicy,
	TEST_DLP_MARKER,
	TEST_TENANT_ID,
} from "./detector-provisioning-fixtures.js";

let home: string;

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-detector-provisioning-"));
	vi.stubEnv("HOME", home);
});

afterEach(async () => {
	vi.unstubAllEnvs();
	await rm(home, { recursive: true, force: true });
});

describe("shared tenant detector provisioning", () => {
	it("provisions a signed, tenant-bound DLP policy for a connector runtime", async () => {
		await provisionTenantDetectorPolicy({ homeDir: home, agentRuntime: "opencode" });

		// The read is pinned to a fixed, non-tool-selectable location named after
		// the agent runtime.
		expect(detectorPolicyPath("opencode")).toBe(detectorPolicyPathFor(home, "opencode"));
		expect(detectorPolicyPath("opencode")).toBe(
			join(home, ".singularity-aidr", "detectors", "opencode.json"),
		);

		const context = await loadProvisionedDetectorContext("opencode");
		expect(context.runtimeDetectors?.tenantId).toBe(TEST_TENANT_ID);
		expect(context.runtimeDetectors?.dlp?.enabled).toBe(true);
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.id).toBe("tenant-restricted-rule");
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.matchers[0]).toMatchObject({
			values: [TEST_DLP_MARKER],
		});
	});

	it("keeps one runtime's provisioned policy away from another runtime", async () => {
		// Without the `runtime_detectors` premium module the bundle is optional, so
		// a runtime that was never provisioned stays unprovisioned.
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "codex",
			entitlement: entitlementSnapshot({ premiumModules: [] }),
		});

		const provisioned = await loadProvisionedDetectorContext("codex");
		expect(provisioned.runtimeDetectors?.tenantId).toBe(TEST_TENANT_ID);
		await expect(loadProvisionedDetectorContext("opencode")).resolves.toEqual({});
	});

	it("returns an empty context when no policy was issued", async () => {
		// Nothing on disk at all: an unenrolled installation is not provisioned.
		await expect(loadProvisionedDetectorContext("openclaw")).resolves.toEqual({});

		// A verified entitlement that does not require the runtime_detectors
		// module, with no bundle installed, is also simply unprovisioned.
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "openclaw",
			skipPolicy: true,
			entitlement: entitlementSnapshot({ premiumModules: [] }),
		});
		await expect(loadProvisionedDetectorContext("openclaw")).resolves.toEqual({});
	});

	it("rejects a tampered detector policy", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "claude-code",
			tamperPolicy: "signature",
		});
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"trust or tenant binding failed",
		);

		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "claude-code",
			tamperPolicy: "payload",
		});
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects a policy bound to a different tenant than the signed entitlement", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			entitlement: entitlementSnapshot({ tenantId: "tenant-b" }),
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects an expired entitlement and an expired policy", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			entitlement: entitlementSnapshot({ expired: true }),
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
			"trust or tenant binding failed",
		);

		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			payload: detectorPolicyPayload(TEST_TENANT_ID, {
				issued_at: new Date(Date.now() - 120_000).toISOString(),
				expires_at: new Date(Date.now() - 60_000).toISOString(),
			}),
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects a DLP policy whose tenant differs from the signed bundle", async () => {
		// The policy is internally consistent for `tenant-b`, so only the binding
		// to the signed bundle's tenant can reject it.
		const payload = detectorPolicyPayload(TEST_TENANT_ID, {
			dlp: { enabled: true, policy: syntheticDlpPolicy("tenant-b") },
		});
		await provisionTenantDetectorPolicy({ homeDir: home, agentRuntime: "opencode", payload });

		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow(
			"belongs to a different tenant",
		);
	});

	it("refuses signed behavioral learning in a one-shot hook contract", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			payload: detectorPolicyPayload(TEST_TENANT_ID, {
				behavioral: { enabled: true, learning_allowed: true },
			}),
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow("invalid");
	});

	it("fails closed when the signed entitlement requires a missing bundle", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "opencode",
			skipPolicy: true,
		});
		await expect(loadProvisionedDetectorContext("opencode")).rejects.toThrow("unavailable");
	});

	it("refuses an unknown runtime instead of following it out of the detector directory", async () => {
		expect(() => detectorPolicyPath("../../evil" as AgentRuntime)).toThrow(
			"agent runtime is not supported",
		);
		await expect(
			loadProvisionedDetectorContext("../../evil" as AgentRuntime),
		).rejects.toThrow("agent runtime is not supported");
	});
});
