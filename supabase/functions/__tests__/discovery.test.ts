import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	canonicalDiscoveryOrigin,
	discoveryAlertState,
	discoveryCollectorState,
	discoveryFreshness,
	parseDiscoveryIngest,
	parseProviderScope,
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
	const provider = () => ({ provider: "aws", scope_hash: "a".repeat(64), coverage: "tagged_resources", complete: true,
		observed_at: new Date(Date.now() - 1000).toISOString(), items: [{ resource_id: "arn:aws:s3:::approved-bucket", resource_type: "s3:bucket",
			scope_id: "aws:123456789012:eu-central-1", region: "eu-central-1", observed_at: new Date(Date.now() - 2000).toISOString() }] });
	it("keeps cloud identifiers out of URL probes and marks failed provider coverage partial", () => {
		const input = { ...cycle(), expected_targets: 0, items: [], provider_resources: provider() };
		expect(parseDiscoveryIngest(input)?.provider_resources?.items[0]?.resource_id).toContain("arn:aws:");
		expect(parseDiscoveryIngest({ ...input, provider_resources: { ...provider(), complete: false, items: [] } })?.complete).toBe(false);
		expect(parseDiscoveryIngest({ ...input, provider_resources: undefined })).toBeNull();
		expect(parseDiscoveryIngest({ ...cycle(), expected_targets: 0, items: [] })).toBeNull();
	});
	it("rejects unbounded, duplicate, credential-bearing arbitrary fields and wrong provider coverage", () => {
		const p = provider(); const input = { ...cycle(), provider_resources: p };
		expect(parseDiscoveryIngest({ ...input, provider_resources: { ...p, coverage: "managed_devices" } })).toBeNull();
		expect(parseDiscoveryIngest({ ...input, provider_resources: { ...p, api_key: "synthetic" } })).toBeNull();
		expect(parseDiscoveryIngest({ ...input, provider_resources: { ...p, items: [p.items[0], p.items[0]] } })).toBeNull();
		expect(parseDiscoveryIngest({ ...input, provider_resources: { ...p, items: Array(1001).fill(p.items[0]) } })).toBeNull();
		expect(parseProviderScope({ provider: "aws", scope_hash: "a".repeat(64), token: "synthetic" })).toBeNull();
	});
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

	it("keeps collector coverage partial or stale until a complete fresh report exists", () => {
		const recent = new Date(95_000).toISOString();
		const old = new Date(39_999).toISOString();
		expect(discoveryCollectorState(recent, true, 60_000, 100_000)).toBe("current");
		expect(discoveryCollectorState(recent, false, 60_000, 100_000)).toBe("partial");
		expect(discoveryCollectorState(old, true, 60_000, 100_000)).toBe("stale");
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
	const reconciliation = readFileSync(join(REPO_ROOT, "supabase", "migrations", "20260923000001_discovery_complete_cycle_reconciliation.sql"), "utf8");

	it("checks JWT membership, revocation/MFA and tenant rate limits before service-role reads", () => {
		const handler = source.slice(source.indexOf("Deno.serve("));
		for (const check of ["auth.getUser(token)", "membershipActive(membership.data)", "checkIdentityBarrier(db, token", "consumeTenantRateLimit(db"])
			expect(handler).toContain(check);
		expect(handler.indexOf("checkIdentityBarrier(db, token")).toBeLessThan(handler.indexOf('db.from("tenant_discovery_collectors")'));
		expect(migration).toContain("from public, anon, authenticated");
		expect(migration).toContain("to service_role");
	});

	it("lists only reported collectors through the authenticated tenant-scoped read branch", () => {
		const handler = source.slice(source.indexOf("Deno.serve("));
		const listStart = handler.indexOf('if (action === "list")');
		const listBranch = handler.slice(listStart, handler.indexOf('if (!exactKeys(input, ["action", "tenant_id", "collector_id"]', listStart));
		expect(listStart).toBeGreaterThan(handler.indexOf("checkIdentityBarrier(db, token"));
		expect(listStart).toBeGreaterThan(handler.indexOf("membershipActive(membership.data)"));
		expect(listStart).toBeGreaterThan(handler.indexOf('state.data?.status !== "active"'));
		expect(listBranch).toContain('.from("tenant_discovery_collectors")');
		expect(listBranch).toContain('.eq("tenant_id", tenant)');
		expect(listBranch).toContain('.order("collector_id", { ascending: true })');
		expect(listBranch).toContain('.limit(limit + 1)');
		expect(listBranch).toContain('coverage_scope: "reported_collectors_only"');
		expect(listBranch).toContain("next_collector:");
		expect(listBranch).not.toMatch(/\.insert\(|\.update\(|\.delete\(|\.rpc\(/);
		const machineAuth = handler.slice(handler.indexOf("if (collectorBinding) {"), handler.indexOf("const [membership, state]"));
		expect(machineAuth).toContain('if (action !== "ingest" && action !== "cursor")');
		expect(machineAuth).toContain("collectorBinding.tenant_id !== tenant || collectorBinding.collector_id !== input.collector_id");
		// Both credential kinds are authenticated before the (up to 512 KiB) body is read.
		const bodyRead = handler.indexOf("readBoundedJson(req,");
		expect(handler.indexOf("db.auth.getUser(token)")).toBeLessThan(bodyRead);
		expect(handler.indexOf('.from("tenant_discovery_credentials")')).toBeLessThan(bodyRead);
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

	it("removes omitted targets only after a complete cycle", () => {
		expect(reconciliation).toMatch(/if p_complete then[\s\S]*delete from public\.tenant_discovery_items[\s\S]*not exists/i);
		expect(reconciliation).toContain("grant execute on function public.ingest_tenant_discovery_cycle");
	});
});
