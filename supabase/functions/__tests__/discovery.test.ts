import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	canonicalDiscoveryOrigin,
	discoveryAlertState,
	discoveryFreshness,
	parseDiscoveryIngest,
} from "../discovery/logic.ts";

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(FUNCTIONS_DIR, "..", "..");
const TENANT = "123e4567-e89b-42d3-a456-426614174000";
const CYCLE = "123e4567-e89b-42d3-a456-426614174001";

function cycle(): Record<string, unknown> {
	return {
		action: "ingest",
		tenant_id: TENANT,
		collector_id: "collector-1",
		cycle_id: CYCLE,
		sequence: 1,
		stale_after_ms: 900_000,
		complete: true,
		expected_targets: 2,
		items: [
			{ target: "https://example.test/", reachable: true, attempts: 1, error_code: null },
			{ target: "http://127.0.0.1:8080/", reachable: false, attempts: 3, error_code: "timeout" },
		],
	};
}

describe("managed discovery ingest boundary", () => {
	it("accepts only a complete, bounded origin-level cycle", () => {
		const parsed = parseDiscoveryIngest(cycle());
		expect(parsed?.items).toHaveLength(2);
		expect(parsed?.items[0]?.target).toBe("https://example.test/");
		expect(parsed?.complete).toBe(true);
	});

	it("preserves an incomplete cycle explicitly instead of treating it as healthy", () => {
		const input = cycle();
		input.complete = false;
		input.items = (input.items as unknown[]).slice(0, 1);
		expect(parseDiscoveryIngest(input)?.complete).toBe(false);
		input.complete = true;
		expect(parseDiscoveryIngest(input)).toBeNull();
	});

	it("rejects credential-bearing and raw scan payloads", () => {
		for (const target of [
			"https://user:pass@example.test/",
			"https://example.test/secret-token",
			"https://example.test/?api_key=x",
			"https://example.test/#secret",
			"file:///etc/passwd",
		]) expect(canonicalDiscoveryOrigin(target)).toBeNull();
		const withRawScan = cycle();
		(withRawScan.items as Record<string, unknown>[])[0].scan = { banner: "secret" };
		expect(parseDiscoveryIngest(withRawScan)).toBeNull();
	});

	it("rejects duplicate origins, loose status, replay sequence and oversized inventories", () => {
		const duplicate = cycle();
		(duplicate.items as Record<string, unknown>[])[1].target = "https://example.test:443/";
		expect(parseDiscoveryIngest(duplicate)).toBeNull();
		const loose = cycle();
		(loose.items as Record<string, unknown>[])[1].error_code = "timeout: Bearer secret";
		expect(parseDiscoveryIngest(loose)).toBeNull();
		const replay = cycle();
		replay.sequence = 0;
		expect(parseDiscoveryIngest(replay)).toBeNull();
		const oversized = cycle();
		oversized.expected_targets = 101;
		expect(parseDiscoveryIngest(oversized)).toBeNull();
	});
});

describe("managed discovery freshness", () => {
	it("marks missing, expired and future evidence as non-fresh", () => {
		expect(discoveryFreshness(null, 60_000, 100_000)).toBe("never_seen");
		expect(discoveryFreshness(new Date(39_999).toISOString(), 60_000, 100_000)).toBe("stale");
		expect(discoveryFreshness(new Date(40_000).toISOString(), 60_000, 100_000)).toBe("fresh");
		expect(discoveryFreshness(new Date(100_001).toISOString(), 60_000, 100_000)).toBe("stale");
	});

	it("does not mark omitted or partial observations healthy", () => {
		const base = { lastReachableAt: new Date(95_000).toISOString(), lastCycleId: CYCLE, cycleId: CYCLE, reachable: true, complete: true, staleAfterMs: 60_000 };
		expect(discoveryAlertState(base, 100_000)).toBe("healthy");
		expect(discoveryAlertState({ ...base, complete: false }, 100_000)).toBe("collection_partial");
		expect(discoveryAlertState({ ...base, lastCycleId: TENANT }, 100_000)).toBe("not_reported");
		expect(discoveryAlertState({ ...base, reachable: false }, 100_000)).toBe("unreachable");
	});
});

describe("managed discovery server boundary", () => {
	const source = readFileSync(join(FUNCTIONS_DIR, "discovery", "index.ts"), "utf8");
	const migration = readFileSync(join(REPO_ROOT, "supabase", "migrations", "20260912000015_discovery_inventory.sql"), "utf8");
	const offboarding = readFileSync(join(REPO_ROOT, "supabase", "migrations", "20260912140001_discovery_offboarding.sql"), "utf8");

	it("checks JWT membership, revocation/MFA and tenant rate limits before service-role reads", () => {
		const handler = source.slice(source.indexOf("Deno.serve("));
		for (const check of ["auth.getUser(token)", "membershipActive(membership.data)", "checkIdentityBarrier(db, token", "consumeTenantRateLimit(db"])
			expect(handler).toContain(check);
		expect(handler.indexOf("checkIdentityBarrier(db, token")).toBeLessThan(handler.indexOf('db.from("tenant_discovery_collectors")'));
		expect(migration).toContain("from public, anon, authenticated");
		expect(migration).toContain("to service_role");
	});

	it("keeps cycles atomic, replay-ordered and offboarding-bound", () => {
		expect(migration).toContain("pg_advisory_xact_lock");
		expect(migration).toContain("p_sequence <= v_previous_sequence");
		expect(migration).toContain("if v_count > p_expected_targets or (p_complete and v_count <> p_expected_targets)");
		expect(migration).toContain("tenants_purge_discovery_on_close");
		expect(offboarding).toContain("tenant_offboarding_purge_discovery");
		expect(offboarding).toContain("new.phase <> 'agents'");
		expect(offboarding).toContain("tenant_legal_holds");
	});
});
