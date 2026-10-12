// Fake answers for the shared fair-share lease RPCs
// (supabase/migrations/20261011000500_tenant_inflight_shared_leases.sql), for
// handler suites whose subject is not admission: every request is admitted.
// tenant-concurrency.test.ts models the rules; the SQL has its own Postgres suite.

/** An admitting answer for a lease RPC, or null for any other RPC name. */
export function admittedLeaseRpc(name: string): { data: unknown; error: null } | null {
	if (name === "acquire_tenant_inflight_lease") {
		return {
			data: {
				admitted: true, slot: 1, lease_id: "00000000-0000-4000-8000-000000000001", reclaimed: false,
				charged_to: "unresolved", held: 1, total: 1, active: 1,
			},
			error: null,
		};
	}
	if (name === "release_tenant_inflight_lease") return { data: true, error: null };
	return null;
}

/** Wraps a fake client's rpc so lease RPCs are admitted before reaching (and being recorded by) `rpc`. */
export function leaseAware<A extends unknown[], R>(rpc: (name: string, ...args: A) => R) {
	return (name: string, ...args: A): R | Promise<{ data: unknown; error: null }> => {
		const lease = admittedLeaseRpc(name);
		return lease ? Promise.resolve(lease) : rpc(name, ...args);
	};
}
