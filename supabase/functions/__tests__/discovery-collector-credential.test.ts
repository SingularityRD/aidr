import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	collectorCredentialHash,
	createCollectorCredential,
	hasCollectorCredentialPrefix,
	validCollectorCredential,
} from "../discovery/credential.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const MIGRATION = readFileSync(resolve(HERE, "..", "..", "migrations", "20260913000001_discovery_collector_credentials.sql"), "utf8");
const HANDLER = readFileSync(resolve(HERE, "..", "discovery", "index.ts"), "utf8");

describe("discovery collector credential", () => {
	it("generates high-entropy, one-time bearer tokens with a stable format", async () => {
		const first = createCollectorCredential();
		const second = createCollectorCredential();
		expect(validCollectorCredential(first)).toBe(true);
		expect(validCollectorCredential(second)).toBe(true);
		expect(first).not.toBe(second);
		expect(first).toHaveLength(51);
		expect(await collectorCredentialHash(first)).toMatch(/^[0-9a-f]{64}$/);
		expect(await collectorCredentialHash(second)).not.toBe(await collectorCredentialHash(first));
	});

	it("rejects malformed and truncated bearer tokens before any digest is accepted", async () => {
		for (const token of ["aidr_dc_", `aidr_dc_${"a".repeat(42)}`, `aidr_dc_${"a".repeat(44)}`, `aidr_dc_${"!".repeat(43)}`, "eyJhbGciOiJIUzI1NiJ9"])
			expect(validCollectorCredential(token)).toBe(false);
		expect(hasCollectorCredentialPrefix("aidr_dc_bad")).toBe(true);
		await expect(collectorCredentialHash("aidr_dc_bad")).rejects.toThrow("invalid_collector_credential");
	});

	it("keeps machine authority at the collector cursor and ingest boundary", () => {
		expect(HANDLER).toContain('action !== "ingest" && action !== "cursor"');
		expect(HANDLER).toContain('error: "collector_scope_forbidden"');
		expect(HANDLER).toContain('read_tenant_discovery_collector_cursor');
		expect(HANDLER).toContain('ingest_tenant_discovery_cycle_machine');
		expect(HANDLER).toContain('assurance.currentLevel !== "aal2"');
		expect(MIGRATION).toContain("token_hash text not null unique");
		expect(MIGRATION).toContain("grant execute on function public.ingest_tenant_discovery_cycle_machine");
		expect(MIGRATION).toContain("grant execute on function public.read_tenant_discovery_collector_cursor");
		expect(MIGRATION).toContain("to service_role;");
		expect(MIGRATION).toContain("c.token_hash = p_token_hash and c.revoked_at is null and c.expires_at > v_now");
		expect(MIGRATION).toContain("p_sequence, p_stale_after_ms, p_complete");
		expect(MIGRATION).toContain("pg_advisory_xact_lock");
	});
});
