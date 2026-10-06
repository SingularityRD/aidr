import { sign } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nullLogger, scanProvisionedOutput } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	detectorPolicyPayload,
	provisionTenantDetectorPolicy,
	syntheticDlpPolicy,
	TEST_DLP_MARKER,
} from "../../../core/src/__tests__/detector-provisioning-fixtures.js";
import { canonicalDetectorPolicyPayload } from "../../../core/src/detector-provisioning.js";
import { OpenClawOutputProtection } from "../output-protection.js";

let home: string;

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-openclaw-output-"));
	vi.stubEnv("HOME", home);
});

afterEach(async () => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	await rm(home, { recursive: true, force: true });
});

function outputPolicy(marker: string) {
	const policy = syntheticDlpPolicy(undefined, marker);
	return {
		...policy,
		supportedFormats: ["text/plain", "application/json"],
		rules: (policy.rules as Record<string, unknown>[]).map((rule) => ({
			...rule,
			directions: ["output"],
		})),
	};
}

describe("OpenClaw signed tenant output contract", () => {
	it("withholds changed, expired and revoked trust synchronously without after_tool_call", async () => {
		const payload = detectorPolicyPayload(undefined, {
			dlp: { enabled: true, policy: outputPolicy("UNRELATED-SYNTHETIC-MARKER") },
		});
		const provisioned = await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "openclaw",
			payload,
		});
		const protection = new OpenClawOutputProtection(nullLogger);
		const event = {
			toolName: "read",
			toolCallId: "no-observation",
			message: {
				content: [{ type: "text", text: TEST_DLP_MARKER }],
				metadata: { original: TEST_DLP_MARKER },
			},
		};
		const assertWithheld = (ruleId: string) => {
			const result = protection.toolResultPersist(event);
			expect(result).not.toBeInstanceOf(Promise);
			expect(result).toBeDefined();
			expect(JSON.stringify(result)).toContain(ruleId);
			expect(JSON.stringify(result)).not.toContain(TEST_DLP_MARKER);
			expect(result).not.toHaveProperty("message.metadata");
		};

		expect(await scanProvisionedOutput([], "openclaw")).toEqual([]);
		expect(protection.toolResultPersist(event)).toBeUndefined();
		const updatedPayload = {
			...payload,
			dlp: { enabled: true, policy: outputPolicy(TEST_DLP_MARKER) },
		};
		await writeFile(
			provisioned.policyPath,
			JSON.stringify({
				alg: "ed25519",
				payload: updatedPayload,
				sig_b64: sign(
					null,
					Buffer.from(canonicalDetectorPolicyPayload(updatedPayload)),
					provisioned.keys.privateKey,
				).toString("base64"),
			}),
		);
		assertWithheld("OUT-DLP-UNAVAILABLE");
		const delivery = await protection.messageSending({ to: "customer", content: TEST_DLP_MARKER });
		expect(JSON.stringify(delivery)).toContain("OUT-DLP-tenant-restricted-rule");
		expect(JSON.stringify(delivery)).not.toContain(TEST_DLP_MARKER);
		assertWithheld("OUT-DLP-tenant-restricted-rule");

		const now = vi.spyOn(Date, "now").mockReturnValue(Date.parse(payload.expires_at as string));
		assertWithheld("OUT-DLP-UNAVAILABLE");
		now.mockRestore();
		expect(await scanProvisionedOutput([], "openclaw")).toEqual([]);
		const state = JSON.parse(await readFile(provisioned.managedPath, "utf8"));
		delete state.entitlement;
		delete state.entitlement_sig;
		await writeFile(provisioned.managedPath, JSON.stringify(state));
		assertWithheld("OUT-DLP-UNAVAILABLE");
		expect(
			await protection.messageSending({ to: "customer", content: "Ordinary response" }),
		).toBeDefined();
		assertWithheld("OUT-DLP-UNAVAILABLE");
	});
});
