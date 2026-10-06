import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
	SignedIngressClient,
	SignedIngressError,
	type SignedIngressRequest,
} from "../signed-ingress.js";

const digest = { algorithm: "sha256", value: "a".repeat(64) };
const scope = { tenant_id: "tenant-1", team_id: "team-1" };

function request(): SignedIngressRequest {
	return {
		schema_version: "aidr-signed-http-ingress/v1",
		principal: { id: "principal-1", credential_digest: digest },
		event: {
			event_id: "event-1",
			schema_version: "aidr-runtime-event/v1",
			kind: "tool_call_requested",
			source: "codex",
			scope,
		},
		tool: {
			scope,
			source: "codex",
			connector_version: "0.6.0",
			tool_name: "search_alerts",
			capability: "alerts.read",
			schema_hash: digest,
			arguments: { query: "severity:critical" },
			target: { kind: "tenant", value: "tenant-1" },
			data_class: "internal",
			mutating: false,
			requested_at: "2026-08-10T10:00:00Z",
		},
		connector: "codex",
		title: "Search critical alerts",
	};
}

describe("SignedIngressClient", () => {
	it.each([
		["2026-08-10T10:00:00.000Z", "2026-08-10T10:00:00Z"],
		["2026-08-10T10:00:00.120Z", "2026-08-10T10:00:00.12Z"],
		["2026-08-10T10:00:00.100Z", "2026-08-10T10:00:00.1Z"],
		["2026-08-10T10:00:00.123Z", "2026-08-10T10:00:00.123Z"],
	])("binds exact body and identity with a canonical timestamp %s", async (now, canonicalTimestamp) => {
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
			const body = String(init?.body);
			const headers = init?.headers as Record<string, string>;
			const envelope = JSON.parse(
				Buffer.from(headers["X-AutoSecOps-AIDR-Signed-Caller"], "base64url").toString("utf8"),
			) as Record<string, unknown>;
			const { signature, ...canonical } = envelope;

			expect(_url).toBe("https://autosecops.test/api/v1/aidr/ingress/tool-calls");
			expect(init?.redirect).toBe("error");
			expect(headers.Authorization).toBeUndefined();
			expect(envelope.request_digest).toBe(createHash("sha256").update(body).digest("hex"));
			expect(envelope.sequence).toBe(42);
			expect(envelope.signed_at).toBe(canonicalTimestamp);
			expect(envelope.connector).toBe("codex");
			expect(envelope.tool).toBe("search_alerts");
			expect(
				verify(
					null,
					Buffer.from(JSON.stringify(canonical), "utf8"),
					publicKey,
					Buffer.from(String(signature), "base64"),
				),
			).toBe(true);

			return new Response(
				JSON.stringify({
					schema_version: "aidr-signed-http-ingress/v1",
					route: "read_only",
					receipt_digest: { algorithm: "sha256", value: "b".repeat(64) },
					replayed: false,
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			);
		});
		const client = new SignedIngressClient({
			endpoint: "https://autosecops.test",
			tenantId: "tenant-1",
			teamId: "team-1",
			callerId: "codex-runtime-1",
			keyGeneration: 3,
			privateKey,
			nextSequence: () => 42,
			now: () => new Date(now),
			requestId: () => "request-1",
			fetchImpl: fetchImpl as typeof fetch,
		});

		const payload = request();
		payload.tool.scope = { team_id: "team-1", tenant_id: "tenant-1" };
		await expect(client.submit(payload)).resolves.toMatchObject({ route: "read_only" });
		expect(fetchImpl).toHaveBeenCalledOnce();
	});

	it("fails closed within the configured timeout budget", async () => {
		const { privateKey } = generateKeyPairSync("ed25519");
		const fetchImpl = vi.fn((_url: string | URL | Request, init?: RequestInit) =>
			new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
			}),
		);
		const client = new SignedIngressClient({
			endpoint: "https://autosecops.test/api",
			tenantId: "tenant-1",
			teamId: "team-1",
			callerId: "codex-runtime-1",
			keyGeneration: 3,
			privateKey,
			nextSequence: () => 43,
			timeoutMs: 20,
			fetchImpl: fetchImpl as typeof fetch,
		});

		const started = performance.now();
		await expect(client.submit(request())).rejects.toEqual(
			expect.objectContaining<SignedIngressError>({ message: "signed ingress timed out" }),
		);
		expect(performance.now() - started).toBeLessThan(500);
	});

	it("rejects scope substitution before sending", async () => {
		const { privateKey } = generateKeyPairSync("ed25519");
		const fetchImpl = vi.fn();
		const client = new SignedIngressClient({
			endpoint: "https://autosecops.test",
			tenantId: "tenant-1",
			teamId: "team-1",
			callerId: "codex-runtime-1",
			keyGeneration: 3,
			privateKey,
			nextSequence: () => 44,
			fetchImpl: fetchImpl as typeof fetch,
		});
		const altered = request();
		altered.tool.scope = { tenant_id: "tenant-2", team_id: "team-1" };

		await expect(client.submit(altered)).rejects.toThrow("invalid signed ingress request");
		altered.event.scope = altered.tool.scope;
		await expect(client.submit(altered)).rejects.toThrow("invalid signed ingress request");
		const malformed = request();
		malformed.principal.credential_digest = { algorithm: "sha256", value: "invalid" };
		await expect(client.submit(malformed)).rejects.toThrow("invalid signed ingress request");
		const mismatchedSource = request();
		mismatchedSource.tool.source = "another-connector";
		await expect(client.submit(mismatchedSource)).rejects.toThrow("invalid signed ingress request");
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("bounds stalled sequence allocation and never submits after timeout", async () => {
		const { privateKey } = generateKeyPairSync("ed25519");
		const fetchImpl = vi.fn();
		let finishSequence!: (sequence: number) => void;
		const client = new SignedIngressClient({
			endpoint: "https://autosecops.test",
			tenantId: "tenant-1",
			teamId: "team-1",
			callerId: "codex-runtime-1",
			keyGeneration: 1,
			privateKey,
			nextSequence: () => new Promise<number>((resolve) => { finishSequence = resolve; }),
			timeoutMs: 20,
			fetchImpl: fetchImpl as typeof fetch,
		});
		await expect(client.submit(request())).rejects.toThrow("signed ingress timed out");
		finishSequence(1);
		await Promise.resolve();
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("rejects insecure and credential-bearing endpoints", () => {
		const { privateKey } = generateKeyPairSync("ed25519");
		for (const endpoint of [
			"http://autosecops.test",
			"https://user:secret@autosecops.test",
			"https://autosecops.test?token=secret",
			"https://autosecops.test#fragment",
			"invalid-endpoint",
		]) {
			expect(() => new SignedIngressClient({
				endpoint,
				tenantId: "tenant-1",
				teamId: "team-1",
				callerId: "codex-runtime-1",
				keyGeneration: 1,
				privateKey,
				nextSequence: () => 1,
			})).toThrow("invalid signed ingress endpoint");
		}
	});

	it.each([[200, "wt05"], [202, "read_only"]])("rejects mismatched response status %s and route %s", async (status, route) => {
		const { privateKey } = generateKeyPairSync("ed25519");
		const client = new SignedIngressClient({
			endpoint: "https://autosecops.test",
			tenantId: "tenant-1",
			teamId: "team-1",
			callerId: "codex-runtime-1",
			keyGeneration: 1,
			privateKey,
			nextSequence: () => 1,
			fetchImpl: async () => new Response(JSON.stringify({
				schema_version: "aidr-signed-http-ingress/v1",
				route,
				receipt_digest: { algorithm: "sha256", value: "b".repeat(64) },
				replayed: false,
			}), { status: Number(status) }),
		});
		await expect(client.submit(request())).rejects.toThrow("invalid signed ingress response");
	});
});
