// Per-tenant in-flight admission control with fair share (load-soak drill
// 2026-10-11, finding O1).
//
// Policy (product decision): when the hot path is saturated, the heaviest
// tenant's excess requests are rejected and quiet tenants keep being served.
//
// Every admitted request holds one lease from before authentication until its
// handler settles, so the API-key lookup's own database reads are bounded too.
// For a request charged to tenant t, with n = t's leases, total = all leases and
// active = tenants holding a lease (counting t):
//
//   0. t is "unresolved", the same key already holds a lease
//      and total >= perTenantMax                 -> 429 tenant_overloaded
//   1. total >= capacity                         -> 503 service_overloaded
//   2. n >= perTenantMax                         -> 429 tenant_overloaded
//   3. total >= perTenantMax (under pressure)
//      and n >= max(floor, floor(capacity / active))
//                                                -> 429 tenant_overloaded
//   4. otherwise admit.
//
// perTenantMax < capacity keeps capacity - perTenantMax slots that one tenant
// alone can never take, so a newly arriving quiet tenant is admitted even while
// a noisy tenant holds everything it may. Once the newcomer is active the noisy
// tenant's fair share shrinks and it is shed until it drops below that share.
//
// Shared state. The leases live in the database
// (supabase/migrations/20261016000100_tenant_inflight_shared_leases.sql), in one
// scope shared by ingest and policy, every edge worker and every replica. One
// RPC acquires: it resolves the tenant from the presented key's SHA-256 (the
// lookup authentication makes), applies the rules above and writes a lease that
// expires after LEASE_SECONDS. One RPC releases it when the handler settles. A
// worker the runtime kills before it releases cannot hold the slot past the
// expiry. The first, per-worker version of this limiter lost its counts and its
// key-to-tenant hints every time the runtime replaced a worker, which under
// overload was every few seconds (docs/production-readiness/
// load-soak-drill-2026-10-11.md, fair-share addenda).
//
// The resolved tenant only decides whose share a request counts against.
// Authorization never reads it: the handler still authenticates the key in full.
// A key that resolves to no tenant is charged to one shared "unresolved" party,
// so a flood of unknown or invalid keys is capped at one fair share.
//
// Failure policy: rate limits are a security control, so a request is never
// admitted on a limiter fault. A malformed configuration, a failed acquire RPC
// or an unreadable answer is 503 tenant_limiter_unavailable and is logged. A
// failed release is logged; the lease then frees itself at its expiry.

import type { EnvReader } from "./config.ts";
import { sha256 } from "./runtime-policy.ts";

export const TENANT_OVERLOADED = "tenant_overloaded";
export const SERVICE_OVERLOADED = "service_overloaded";
export const TENANT_LIMITER_UNAVAILABLE = "tenant_limiter_unavailable";
const UNRESOLVED_TENANT = "unresolved";

/** The admission scope ingest and policy share. */
export const ADMISSION_SCOPE = "machine-api";
// The kit's PostgREST pool holds 10 connections and a request uses at most one
// at a time, so the deployment never queues more requests than the pool serves.
const DEFAULT_CAPACITY = 10;
const DEFAULT_FAIR_SHARE_FLOOR = 2;
const DEFAULT_RETRY_AFTER_SECONDS = 1;
// The main router gives each edge worker a 60 s wall clock, so no live request
// outlives its lease; a lease left by a killed worker frees itself after this.
export const LEASE_SECONDS = 60;
const MAX_CAPACITY = 10_000;
const LOG_INTERVAL_MS = 10_000;

export interface TenantConcurrencyConfig {
	capacity: number;
	perTenantMax: number;
	fairShareFloor: number;
	retryAfterSeconds: number;
}

export type TenantSlotRejection = {
	ok: false;
	status: 429 | 503;
	error: typeof TENANT_OVERLOADED | typeof SERVICE_OVERLOADED | typeof TENANT_LIMITER_UNAVAILABLE;
	retryAfterSeconds: number;
};

/** A lease admitted for a credential, before the credential is authenticated. */
export type CredentialSlot = {
	ok: true;
	/** The tenant the lease is charged to, or "unresolved". Never used for authorization. */
	chargedTo: string;
	/** Frees the lease; idempotent, and never throws. */
	release: () => Promise<void>;
};

export type ConfigParse = { ok: true; config: TenantConcurrencyConfig } | { ok: false; problem: string };

/** The part of the service-role client admission needs. */
export type LeaseDatabase = {
	rpc(name: string, args: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }>;
};

/** `db` is the service-role client; typed loosely like api-key-auth.ts, since the SDK's rpc() is generic. */
export type AdmitCredential = (db: unknown, credential: string) => Promise<CredentialSlot | TenantSlotRejection>;

type Logger = Pick<Console, "warn" | "error">;

function boundedInt(raw: string | null | undefined, name: string, fallback: number, min: number, max: number): number | string {
	const value = (raw ?? "").trim();
	if (value === "") return fallback;
	if (!/^\d{1,6}$/.test(value)) return `${name} must be an integer`;
	const parsed = Number(value);
	return parsed >= min && parsed <= max ? parsed : `${name} must be between ${min} and ${max}`;
}

/** Reads the limiter settings; any malformed value is a configuration problem, never a silent default. */
export function parseTenantConcurrencyConfig(env: EnvReader): ConfigParse {
	const capacity = boundedInt(env("AIDR_TENANT_INFLIGHT_CAPACITY"), "AIDR_TENANT_INFLIGHT_CAPACITY", DEFAULT_CAPACITY, 1, MAX_CAPACITY);
	if (typeof capacity === "string") return { ok: false, problem: capacity };
	const perTenantMax = boundedInt(
		env("AIDR_TENANT_INFLIGHT_MAX"), "AIDR_TENANT_INFLIGHT_MAX",
		Math.max(1, Math.floor(capacity * 0.75)), 1, capacity,
	);
	if (typeof perTenantMax === "string") return { ok: false, problem: perTenantMax };
	const fairShareFloor = boundedInt(
		env("AIDR_TENANT_INFLIGHT_FAIR_SHARE_FLOOR"), "AIDR_TENANT_INFLIGHT_FAIR_SHARE_FLOOR",
		Math.min(DEFAULT_FAIR_SHARE_FLOOR, perTenantMax), 1, perTenantMax,
	);
	if (typeof fairShareFloor === "string") return { ok: false, problem: fairShareFloor };
	const retryAfterSeconds = boundedInt(
		env("AIDR_TENANT_INFLIGHT_RETRY_AFTER_SECONDS"), "AIDR_TENANT_INFLIGHT_RETRY_AFTER_SECONDS",
		DEFAULT_RETRY_AFTER_SECONDS, 1, 60,
	);
	if (typeof retryAfterSeconds === "string") return { ok: false, problem: retryAfterSeconds };
	return { ok: true, config: { capacity, perTenantMax, fairShareFloor, retryAfterSeconds } };
}

type AcquireAnswer =
	| { admitted: true; slot: number; leaseId: string; chargedTo: string; reclaimed: boolean; held: number; total: number; active: number }
	| { admitted: false; reason: string; chargedTo: string; held: number; total: number; active: number };

const REJECTION_REASONS = new Set(["unresolved_key_busy", "capacity", "tenant_max", "fair_share"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function count(value: unknown): number | null {
	return Number.isSafeInteger(value) && (value as number) >= 0 ? value as number : null;
}

/** The acquire RPC's answer, or null when it is not one the migration produces. */
function acquireAnswer(data: unknown): AcquireAnswer | null {
	if (!data || typeof data !== "object" || Array.isArray(data)) return null;
	const row = data as Record<string, unknown>;
	const held = count(row.held), total = count(row.total), active = count(row.active);
	if (held === null || total === null || active === null) return null;
	if (typeof row.charged_to !== "string" || row.charged_to === "") return null;
	const base = { chargedTo: row.charged_to, held, total, active };
	if (row.admitted === true) {
		const slot = count(row.slot);
		if (slot === null || slot < 1 || typeof row.lease_id !== "string" || !UUID.test(row.lease_id) || typeof row.reclaimed !== "boolean") return null;
		return { admitted: true, slot, leaseId: row.lease_id, reclaimed: row.reclaimed, ...base };
	}
	if (row.admitted === false && typeof row.reason === "string" && REJECTION_REASONS.has(row.reason)) {
		return { admitted: false, reason: row.reason, ...base };
	}
	return null;
}

/** Writes a log line at most once per key every LOG_INTERVAL_MS in this worker. */
function throttledLog(now: () => number) {
	const last = new Map<string, number>();
	return (key: string, write: () => void) => {
		const at = now();
		const previous = last.get(key);
		if (previous !== undefined && at - previous < LOG_INTERVAL_MS) return;
		if (last.size >= 1_000) last.clear();
		last.set(key, at);
		write();
	};
}

/**
 * Admission against the shared database leases. One acquire RPC per request,
 * and one release RPC when the handler settles.
 */
export function sharedLeaseAdmission(
	config: TenantConcurrencyConfig,
	options: { logger?: Logger; now?: () => number; scope?: string } = {},
): AdmitCredential {
	const log = options.logger ?? console;
	const scope = options.scope ?? ADMISSION_SCOPE;
	const throttle = throttledLog(options.now ?? Date.now);
	const unavailable = (message: string): TenantSlotRejection => {
		throttle(`error:${message}`, () => log.error(JSON.stringify({ event: "tenant_inflight_limiter_error", message })));
		return { ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: config.retryAfterSeconds };
	};
	return async (database, credential) => {
		const db = database as LeaseDatabase;
		let answer: AcquireAnswer | null;
		try {
			const result = await db.rpc("acquire_tenant_inflight_lease", {
				p_scope: scope,
				p_key_hash: await sha256(credential),
				p_capacity: config.capacity,
				p_per_tenant_max: config.perTenantMax,
				p_fair_share_floor: config.fairShareFloor,
				p_lease_seconds: LEASE_SECONDS,
			});
			if (result.error) return unavailable("acquire_failed");
			answer = acquireAnswer(result.data);
		} catch {
			return unavailable("acquire_failed");
		}
		if (!answer) return unavailable("acquire_answer_invalid");
		if (!answer.admitted) {
			const { reason, chargedTo, held, total, active } = answer;
			throttle(`shed:${chargedTo}:${reason}`, () => log.warn(JSON.stringify({
				event: "tenant_inflight_shed", tenant_id: chargedTo, reason,
				tenant_in_flight: held, total_in_flight: total, active_tenants: active, capacity: config.capacity,
			})));
			return reason === "capacity"
				? { ok: false, status: 503, error: SERVICE_OVERLOADED, retryAfterSeconds: config.retryAfterSeconds }
				: { ok: false, status: 429, error: TENANT_OVERLOADED, retryAfterSeconds: config.retryAfterSeconds };
		}
		if (answer.reclaimed) {
			// The slot's previous lease expired without a release: its worker died.
			throttle("lease_expired", () => log.error(JSON.stringify({ event: "tenant_inflight_lease_expired", lease_seconds: LEASE_SECONDS })));
		}
		const { slot, leaseId, chargedTo } = answer;
		let released = false;
		return {
			ok: true,
			chargedTo,
			release: async () => {
				if (released) return;
				released = true;
				try {
					const result = await db.rpc("release_tenant_inflight_lease", { p_scope: scope, p_slot: slot, p_lease_id: leaseId });
					if (result.error) throw new Error("release_failed");
				} catch {
					throttle("release_failed", () => log.error(JSON.stringify({ event: "tenant_inflight_release_failed", lease_seconds: LEASE_SECONDS })));
				}
			},
		};
	};
}

/** The rejection's response body and headers: a stable code, retryable, with Retry-After. */
export function tenantSlotResponse(rejection: TenantSlotRejection): { status: 429 | 503; body: Record<string, unknown>; headers: Record<string, string> } {
	return {
		status: rejection.status,
		body: { error: rejection.error, retryable: true },
		headers: { "Retry-After": String(rejection.retryAfterSeconds) },
	};
}

/**
 * Admission for one function, built on first use from the environment. A
 * malformed configuration refuses admission (fail closed) and is logged once per
 * worker, so it is never silent.
 */
export function tenantSlotGate(env: EnvReader, logger: Logger = console): AdmitCredential {
	let admit: AdmitCredential | null = null;
	let configProblemLogged = false;
	return (db, credential) => {
		if (!admit) {
			const parsed = parseTenantConcurrencyConfig(env);
			if (!parsed.ok) {
				if (!configProblemLogged) {
					configProblemLogged = true;
					logger.error(JSON.stringify({ event: "tenant_inflight_limiter_misconfigured", problem: parsed.problem }));
				}
				return Promise.resolve({ ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: 30 });
			}
			admit = sharedLeaseAdmission(parsed.config, { logger });
		}
		return admit(db, credential);
	};
}

/** Holds a lease for `credential` while `work` runs; the lease is released however `work` settles. */
export async function withTenantSlot(
	admit: AdmitCredential,
	db: unknown,
	credential: string,
	work: (slot: CredentialSlot) => Promise<Response>,
	reject: (rejection: TenantSlotRejection) => Response,
): Promise<Response> {
	const slot = await admit(db, credential);
	if (!slot.ok) return reject(slot);
	try {
		return await work(slot);
	} finally {
		await slot.release();
	}
}
