import { describe, expect, it, vi } from "vitest";
import { ResponseProviderRegistry } from "../response-provider-registry.js";

describe("response provider registry", () => {
	it("fails closed for credential revocation and containment without providers", async () => {
		const registry = new ResponseProviderRegistry();
		for (const action of ["revoke_credential", "contain"] as const) {
			expect(await registry.execute({ action, target: "credential-1" })).toEqual({
				status: "unsupported",
				code: "unsupported_action",
				detail: `no registered provider supports ${action}`,
			});
		}
		expect(registry.supports("revoke_credential")).toBe(false);
		expect(registry.supports("contain")).toBe(false);
	});

	it("does not accept ambiguous providers or provider ids", () => {
		const provider = {
			providerId: "example-idp",
			actions: ["revoke_credential"] as const,
			execute: vi.fn(),
		};
		const registry = new ResponseProviderRegistry([provider]);
		expect(registry.supports("revoke_credential", "")).toBe(false);
		expect(registry.supports("revoke_credential", "other-idp")).toBe(false);
		expect(() => new ResponseProviderRegistry([undefined as never])).toThrow("invalid_response_provider");
	});

	it("requires independent provider verification before returning applied", async () => {
		const execute = vi.fn(async () => ({
			status: "applied" as const,
			observed: "provider accepted",
			rollbackToken: null,
		}));
		const registry = new ResponseProviderRegistry([
			{ providerId: "example-idp", actions: ["revoke_credential"], execute },
		]);
		const result = await registry.execute({
			action: "revoke_credential",
			target: "credential-1",
			idempotencyKey: "cmd-1",
		});
		expect(result).toMatchObject({ status: "failed", code: "provider_observation_unavailable" });
		expect(execute).toHaveBeenCalledWith(expect.objectContaining({ idempotencyKey: "cmd-1", providerId: "example-idp" }));
	});

	it("passes the idempotency key and records provider-observed evidence", async () => {
		const execute = vi.fn(async () => ({
			status: "applied" as const,
			observed: "accepted",
			rollbackToken: null,
		}));
		const verify = vi.fn(async () => ({ observed: true as const, evidence: "queried" }));
		const registry = new ResponseProviderRegistry([
			{ providerId: "example-idp", actions: ["revoke_credential"], execute, verify },
		]);
		await expect(
			registry.execute({ action: "revoke_credential", target: "credential-1", idempotencyKey: "cmd-2" }),
		).resolves.toEqual({ status: "applied", observed: "queried", rollbackToken: null });
		expect(verify).toHaveBeenCalledWith(expect.objectContaining({ idempotencyKey: "cmd-2" }));
	});
});
