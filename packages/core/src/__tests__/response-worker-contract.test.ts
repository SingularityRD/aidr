import { describe, expect, it } from "vitest";
import { ResponseProviderRegistry } from "../response-provider-registry.js";
import {
	executeResponseStep,
	MemoryResponseJournal,
	planResponseRollback,
	planResponseStep,
	type ResponseAdapter,
	type ResponseCapability,
	type ResponseStep,
	type ResponseStepOutcome,
	reportWorkerCapabilities,
	RESPONSE_CAPABILITIES,
} from "../response-worker-contract.js";

const DIGEST = "a".repeat(64);

interface AdapterOptions {
	capabilities?: readonly ResponseCapability[];
	outcome?: ResponseStepOutcome | ((step: ResponseStep) => ResponseStepOutcome);
	throws?: boolean;
}

function adapter(options: AdapterOptions = {}) {
	const calls: ResponseStep[] = [];
	const instance: ResponseAdapter = {
		adapterId: "test-adapter",
		platform: process.platform,
		capabilities: () => options.capabilities ?? ["quarantine_file", "restore_file", "terminate_process"],
		async execute(step) {
			calls.push(step);
			if (options.throws) throw new Error("host exploded");
			if (typeof options.outcome === "function") return options.outcome(step);
			return (
				options.outcome ?? {
					status: "applied",
					observed: `moved ${step.binding.target}`,
					rollbackToken: `/vault/${step.binding.target}`,
				}
			);
		},
	};
	return { adapter: instance, calls };
}

function plan(overrides: Partial<Parameters<typeof planResponseStep>[0]> = {}) {
	const { adapter: instance } = adapter();
	return planResponseStep({
		adapter: instance,
		capability: "quarantine_file",
		binding: {
			target: "/workspace/evil.sh",
			expectedSha256: DIGEST,
			incidentId: "incident-1",
			authorizedBy: "operator:on-call",
		},
		vaultPath: "/vault/evil.sh",
		ttlMs: 60_000,
		idempotencyKey: "command_0000000000000001",
		liveSha256: DIGEST,
		liveExists: true,
		hasPrivilege: true,
		...overrides,
	});
}

function step(overrides: Partial<ResponseStep> = {}): ResponseStep {
	const planned = plan();
	if (planned.ok === false) throw new Error(`fixture plan failed: ${planned.code}`);
	return { ...planned.step, ...overrides };
}

describe("response step planning (preconditions, fail-closed)", () => {
	it("plans a well-formed quarantine step", () => {
		const planned = plan();
		expect(planned.ok).toBe(true);
		if (!planned.ok) return;
		expect(planned.step).toMatchObject({
			capability: "quarantine_file",
			vaultPath: "/vault/evil.sh",
			ttlMs: 60_000,
			reversible: true,
		});
	});

	it("refuses an action the adapter does not declare, without touching the host", async () => {
		const { adapter: instance, calls } = adapter({ capabilities: ["terminate_process"] });
		const planned = planResponseStep({
			adapter: instance,
			capability: "quarantine_file",
			binding: { target: "/workspace/evil.sh", expectedSha256: null, incidentId: "i", authorizedBy: "operator:x" },
			vaultPath: "/vault/evil.sh",
			idempotencyKey: "command_0000000000000002",
			liveExists: true,
		});
		expect(planned).toMatchObject({ ok: false, code: "unsupported_action" });
		expect(calls).toEqual([]);
	});

	it("refuses an unknown capability string", () => {
		const planned = plan({ capability: "format_disk" as ResponseCapability });
		expect(planned).toMatchObject({ ok: false, code: "unknown_capability" });
	});

	it("refuses a target that is missing, changed, unreadable or escaping the workspace", () => {
		expect(plan({ liveExists: false })).toMatchObject({ ok: false, code: "target_missing" });
		expect(plan({ liveSha256: "b".repeat(64) })).toMatchObject({ ok: false, code: "target_changed" });
		expect(plan({ liveSha256: null })).toMatchObject({ ok: false, code: "target_unreadable" });
		expect(plan({ escapesWorkspace: true })).toMatchObject({ ok: false, code: "target_escapes_workspace" });
	});

	it("requires a rollback destination and a bounded TTL", () => {
		expect(plan({ vaultPath: "  " })).toMatchObject({ ok: false, code: "missing_vault_path" });
		expect(plan({ ttlMs: 500 })).toMatchObject({ ok: false, code: "invalid_ttl" });
		expect(plan({ ttlMs: 25 * 60 * 60 * 1000 })).toMatchObject({ ok: false, code: "invalid_ttl" });
		expect(plan({ idempotencyKey: "short" })).toMatchObject({ ok: false, code: "invalid_idempotency_key" });
		expect(plan({ binding: { target: " ", expectedSha256: null, incidentId: "i", authorizedBy: "op" } })).toMatchObject(
			{ ok: false, code: "missing_target" },
		);
		expect(
			plan({ binding: { target: "/x", expectedSha256: null, incidentId: "", authorizedBy: "operator:x" } }),
		).toMatchObject({ ok: false, code: "missing_incident" });
		expect(
			plan({ binding: { target: "/x", expectedSha256: null, incidentId: "i", authorizedBy: "x" } }),
		).toMatchObject({ ok: false, code: "missing_authorization" });
		expect(
			plan({ binding: { target: "/x", expectedSha256: "nope", incidentId: "i", authorizedBy: "operator:x" } }),
		).toMatchObject({ ok: false, code: "invalid_expected_digest" });
	});

	it("refuses provider-backed actions without a registered provider", () => {
		const { adapter: instance } = adapter({ capabilities: ["revoke_credential"] });
		expect(
			planResponseStep({
				adapter: instance,
				capability: "revoke_credential",
				binding: {
					target: "credential-1",
					providerId: "example-idp",
					expectedSha256: null,
					incidentId: "incident-1",
					authorizedBy: "operator:on-call",
				},
				idempotencyKey: "command_0000000000000004",
				hasPrivilege: true,
			}),
		).toMatchObject({ ok: false, code: "unsupported_action" });
	});

	it("requires the documented privilege for privilege-dependent actions", () => {
		for (const capability of ["isolate_host", "terminate_process", "revoke_credential"] as const) {
			const { adapter: instance } = adapter({ capabilities: RESPONSE_CAPABILITIES });
			const planned = planResponseStep({
				adapter: instance,
				capability,
				binding: { target: "1234", expectedSha256: null, incidentId: "i", authorizedBy: "operator:x" },
				idempotencyKey: "command_0000000000000003",
				hasPrivilege: false,
			});
			expect(planned, capability).toMatchObject({ ok: false, code: "insufficient_privilege" });
		}
	});
});

describe("response step execution (idempotency, TTL, receipts)", () => {
	it("journals an unsupported provider result without invoking the adapter", async () => {
		const { adapter: instance, calls } = adapter({ capabilities: ["contain"] });
		const journal = new MemoryResponseJournal();
		const planned = planResponseStep({
			adapter: instance,
			capability: "contain",
			binding: {
				target: "host-1",
				expectedSha256: null,
				incidentId: "incident-1",
				authorizedBy: "operator:on-call",
			},
			idempotencyKey: "command_0000000000000005",
			hasPrivilege: true,
		});
		expect(planned).toMatchObject({ ok: false, code: "unsupported_action" });
		const manuallyReceived = step({
			capability: "contain",
			binding: { ...step().binding, target: "host-1" },
			reversible: false,
		});
		const result = await executeResponseStep(manuallyReceived, {
			adapter: instance,
			journal,
			now: () => 1_000_000,
		});
		expect(result.receipt).toMatchObject({ status: "refused", code: "unsupported_action", fullyReversible: false });
		expect(calls).toEqual([]);
		expect((await journal.get(manuallyReceived.idempotencyKey))?.receipt.code).toBe("unsupported_action");
	});

	it("routes registered provider actions with idempotency and no clean containment claim", async () => {
		const calls: string[] = [];
		const registry = new ResponseProviderRegistry([
			{
				providerId: "example-idp",
				actions: ["contain"],
				execute: async (request) => {
					calls.push(request.idempotencyKey ?? "missing");
					return { status: "applied", observed: "provider accepted", rollbackToken: "provider-token" };
				},
				verify: async () => ({ observed: true, evidence: "provider queried" }),
			},
		]);
		const { adapter: instance } = adapter({ capabilities: ["contain"] });
		const journal = new MemoryResponseJournal();
		const providerStep = step({
			capability: "contain",
			binding: { ...step().binding, providerId: "example-idp", target: "host-1" },
			reversible: false,
		});
		const first = await executeResponseStep(providerStep, {
			adapter: instance,
			providerRegistry: registry,
			journal,
			now: () => 1_000_000,
		});
		const second = await executeResponseStep(providerStep, {
			adapter: instance,
			providerRegistry: registry,
			journal,
			now: () => 1_001_000,
		});
		expect(first.receipt).toMatchObject({
			status: "partial",
			code: "provider_observed",
			providerId: "example-idp",
			rollbackPossible: false,
			fullyReversible: false,
		});
		expect(second.replayed).toBe(true);
		expect(calls).toEqual([providerStep.idempotencyKey]);
	});

	it("applies a step and records a reversible receipt with a rollback token", async () => {
		const { adapter: instance, calls } = adapter();
		const { receipt, replayed } = await executeResponseStep(step(), {
			adapter: instance,
			journal: new MemoryResponseJournal(),
			now: () => 1_000_000,
		});
		expect(replayed).toBe(false);
		expect(calls).toHaveLength(1);
		expect(receipt).toMatchObject({
			status: "applied",
			code: "applied",
			incidentId: "incident-1",
			rollbackPossible: true,
			fullyReversible: true,
		});
	});

	it("replays the original receipt for the same idempotency key inside the TTL", async () => {
		const { adapter: instance, calls } = adapter();
		const journal = new MemoryResponseJournal();
		let nowMs = 1_000_000;
		const first = await executeResponseStep(step(), { adapter: instance, journal, now: () => nowMs });
		nowMs += 30_000;
		const second = await executeResponseStep(step(), { adapter: instance, journal, now: () => nowMs });
		expect(calls).toHaveLength(1);
		expect(second.replayed).toBe(true);
		expect(second.receipt).toEqual(first.receipt);
	});

	it("refuses a repeated command whose TTL expired instead of applying it twice", async () => {
		const { adapter: instance, calls } = adapter();
		const journal = new MemoryResponseJournal();
		let nowMs = 1_000_000;
		await executeResponseStep(step(), { adapter: instance, journal, now: () => nowMs });
		nowMs += 120_000;
		const late = await executeResponseStep(step(), { adapter: instance, journal, now: () => nowMs });
		expect(calls).toHaveLength(1);
		expect(late.receipt).toMatchObject({ status: "refused", code: "stale_command" });
		expect(late.receipt.rollbackPossible).toBe(false);
	});

	it("reports partial, never applied, when an applied step carries no rollback token", async () => {
		const { adapter: instance } = adapter({
			outcome: { status: "applied", observed: "terminated", rollbackToken: null },
		});
		const { receipt } = await executeResponseStep(step(), {
			adapter: instance,
			journal: new MemoryResponseJournal(),
		});
		expect(receipt.status).toBe("partial");
		expect(receipt.code).toBe("applied_without_rollback");
		expect(receipt.fullyReversible).toBe(false);
	});

	it("surfaces adapter failure and adapter throws as failed, never as success", async () => {
		const failed = adapter({
			outcome: { status: "failed", code: "permission_denied", detail: "no", rollbackToken: null },
		});
		const first = await executeResponseStep(step(), { adapter: failed.adapter, journal: new MemoryResponseJournal() });
		expect(first.receipt).toMatchObject({ status: "failed", code: "permission_denied", rollbackPossible: false });

		const throwing = adapter({ throws: true });
		const second = await executeResponseStep(step(), {
			adapter: throwing.adapter,
			journal: new MemoryResponseJournal(),
		});
		expect(second.receipt).toMatchObject({ status: "failed", code: "adapter_threw" });
	});

	it("reports a no-op when the host is already in the desired state", async () => {
		const { adapter: instance } = adapter({
			outcome: { status: "noop", observed: "already quarantined", rollbackToken: null },
		});
		const { receipt } = await executeResponseStep(step(), {
			adapter: instance,
			journal: new MemoryResponseJournal(),
		});
		expect(receipt).toMatchObject({ status: "noop", code: "already_in_desired_state" });
	});

	it("propagates a refusal from the adapter without inventing an observation", async () => {
		const { adapter: instance } = adapter({
			outcome: { status: "refused", code: "target_locked", detail: "held open" },
		});
		const { receipt } = await executeResponseStep(step(), {
			adapter: instance,
			journal: new MemoryResponseJournal(),
		});
		expect(receipt).toMatchObject({ status: "refused", code: "target_locked", observed: null, rollbackToken: null });
	});
});

describe("response rollback planning", () => {
	it("builds the inverse step for a reversible file action", async () => {
		const { adapter: instance } = adapter();
		const { receipt } = await executeResponseStep(step(), {
			adapter: instance,
			journal: new MemoryResponseJournal(),
		});
		const rollback = planResponseRollback({
			adapter: instance,
			receipt,
			idempotencyKey: "rollback_000000000000001",
		});
		expect(rollback.ok).toBe(true);
		if (!rollback.ok) return;
		expect(rollback.step.capability).toBe("restore_file");
		expect(rollback.step.vaultPath).toBe(receipt.rollbackToken);
		expect(rollback.step.reversible).toBe(false);
	});

	it("refuses a rollback with no token so a UI cannot show a restore that never happened", () => {
		const { adapter: instance } = adapter();
		const refusal = planResponseRollback({
			adapter: instance,
			receipt: {
				commandId: "c",
				incidentId: "i",
				adapterId: "test-adapter",
				platform: "test",
				capability: "quarantine_file",
				status: "partial",
				code: "applied_without_rollback",
				target: "/workspace/evil.sh",
				observed: null,
				rollbackToken: null,
				rollbackPossible: false,
				appliedAtUtc: "2026-09-13T00:00:00.000Z",
				fullyReversible: false,
				idempotencyKey: "command_0000000000000001",
			},
			idempotencyKey: "rollback_000000000000001",
		});
		expect(refusal).toMatchObject({ ok: false, code: "no_rollback_token" });
	});

	it("refuses a rollback when the adapter has no inverse action", async () => {
		const { adapter: instance } = adapter({ capabilities: ["terminate_process", "restore_file"] });
		const refusal = planResponseRollback({
			adapter: instance,
			receipt: {
				commandId: "c",
				incidentId: "i",
				adapterId: "test-adapter",
				platform: "test",
				capability: "terminate_process",
				status: "partial",
				code: "applied_without_rollback",
				target: "1234",
				observed: "killed",
				rollbackToken: "token",
				rollbackPossible: true,
				appliedAtUtc: "2026-09-13T00:00:00.000Z",
				fullyReversible: false,
				idempotencyKey: "command_0000000000000001",
			},
			idempotencyKey: "rollback_000000000000001",
		});
		expect(refusal).toMatchObject({ ok: false, code: "no_inverse_action" });
	});
});

describe("installed worker capability report", () => {
	it("reports exactly what the adapter declares and what it cannot do", () => {
		const { adapter: instance } = adapter({ capabilities: ["quarantine_file", "restore_file"] });
		const report = reportWorkerCapabilities(instance, [
			...RESPONSE_CAPABILITIES,
			"not_a_capability",
		]);
		expect(report.declared).toEqual(["quarantine_file", "restore_file"]);
		expect(report.missing).toEqual(["terminate_process", "isolate_host", "revoke_credential", "contain"]);
		expect(report.limitations.join(" ")).toContain("not_a_capability");
		expect(report.limitations.join(" ")).toContain("host network isolation is not provided");
	});

	it("adds no isolation limitation when the adapter does declare host isolation", () => {
		const { adapter: instance } = adapter({ capabilities: ["isolate_host"] });
		const report = reportWorkerCapabilities(instance, ["isolate_host"]);
		expect(report.missing).toEqual([]);
		expect(report.limitations).toEqual([]);
	});
});
