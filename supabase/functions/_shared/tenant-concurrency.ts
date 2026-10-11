// Per-tenant in-flight admission control with fair share (load-soak drill
// 2026-10-11, finding O1).
//
// Policy (product decision): when the hot path is saturated, the heaviest
// tenant's excess requests are rejected and quiet tenants keep being served.
//
// Every admitted request holds one slot from before authentication until its
// handler settles, so the API-key lookup's own database reads are bounded too.
// For a request charged to tenant t, with n = t's slots, total = all slots and
// active = tenants holding a slot (counting t):
//
//   1. total >= capacity                      -> 503 service_overloaded
//   2. n >= perTenantMax                      -> 429 tenant_overloaded
//   3. total >= perTenantMax (under pressure)
//      and n >= max(floor, floor(capacity / active))
//                                             -> 429 tenant_overloaded
//   4. otherwise admit.
//
// perTenantMax < capacity keeps capacity - perTenantMax slots that one tenant
// alone can never take, so a newly arriving quiet tenant is admitted even while
// a noisy tenant holds everything it may. Once the newcomer is active the noisy
// tenant's fair share shrinks and it is shed until it drops below that share.
//
// The tenant is known only after the API key is authenticated. Admission uses
// the tenant that the same key (by SHA-256) authenticated as before in this
// isolate; a key not seen yet is charged to one shared "unresolved" pseudo
// tenant, so a flood of unknown or invalid keys is capped at one fair share;
// under pressure each such key has at most one request in flight.
// After authentication the slot is moved to the real tenant, and refused there
// (429) if that tenant is already at its cap or share. The hint only
// decides whose share a request counts against; authorization never reads it,
// and a failed authentication forgets it.
//
// Scope: the state lives in this isolate, so the bound is per function isolate.
// It is not shared across functions or replicas, nor between a retiring
// isolate and its replacement. The edge runtime retires an isolate at its
// wall-clock or CPU-time limit; under overload the 2026-10-11 drill saw that
// every few seconds, and each fresh isolate starts with no counts and no
// key-to-tenant hints (docs/production-readiness/load-soak-drill-2026-10-11.md,
// fair-share addendum).
//
// Failure policy: rate limits are a security control, so a request is never
// admitted on a limiter fault. A malformed configuration or an internal error
// answers 503 tenant_limiter_unavailable and is always logged.

import type { EnvReader } from "./config.ts";

export const TENANT_OVERLOADED = "tenant_overloaded";
export const SERVICE_OVERLOADED = "service_overloaded";
export const TENANT_LIMITER_UNAVAILABLE = "tenant_limiter_unavailable";
export const UNRESOLVED_TENANT = "unresolved";

// The kit's PostgREST pool holds 10 connections and a request uses at most one
// at a time, so one function never queues more requests than the pool serves.
export const DEFAULT_CAPACITY = 10;
export const DEFAULT_FAIR_SHARE_FLOOR = 2;
export const DEFAULT_RETRY_AFTER_SECONDS = 1;
// A slot whose handler has not settled after this long is reclaimed and logged.
// Longer than any edge worker wall clock, so it only catches a hung promise.
export const DEFAULT_LEASE_MS = 150_000;
const MAX_CAPACITY = 10_000;
const SHED_LOG_INTERVAL_MS = 10_000;
const HINT_TTL_MS = 300_000;
const MAX_HINTS = 10_000;

export interface TenantConcurrencyConfig {
	capacity: number;
	perTenantMax: number;
	fairShareFloor: number;
	retryAfterSeconds: number;
	leaseMs: number;
}

export type TenantSlotRejection = {
	ok: false;
	status: 429 | 503;
	error: typeof TENANT_OVERLOADED | typeof SERVICE_OVERLOADED | typeof TENANT_LIMITER_UNAVAILABLE;
	retryAfterSeconds: number;
};

export type TenantSlot = {
	ok: true;
	/**
	 * Moves the slot to another tenant if that tenant could be admitted now
	 * (capacity aside: the slot is already counted). Returns the rejection, and
	 * leaves the slot where it was, when that tenant is at its cap or share.
	 */
	rebind: (tenantId: string) => TenantSlotRejection | null;
	release: () => void;
};

/** A slot admitted for a credential, before the credential is authenticated. */
export type CredentialSlot = {
	ok: true;
	/**
	 * Records the authenticated tenant and moves the slot to it. Returns a
	 * rejection when that tenant is already at its cap or fair share: the caller
	 * answers it instead of continuing (the slot is still released by its owner).
	 */
	authenticated: (tenantId: string) => TenantSlotRejection | null;
	/** Authentication failed: later requests with this credential are unresolved again. */
	unauthenticated: () => void;
	release: () => void;
};

export type ConfigParse = { ok: true; config: TenantConcurrencyConfig } | { ok: false; problem: string };

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
	return { ok: true, config: { capacity, perTenantMax, fairShareFloor, retryAfterSeconds, leaseMs: DEFAULT_LEASE_MS } };
}

export class TenantConcurrencyLimiter {
	readonly config: TenantConcurrencyConfig;
	#inFlight = new Map<string, number>();
	#total = 0;
	#lastShedLog = new Map<string, number>();
	#log: Logger;
	#now: () => number;
	#setTimer: (fn: () => void, ms: number) => unknown;
	#clearTimer: (handle: unknown) => void;

	constructor(
		config: TenantConcurrencyConfig,
		options: {
			logger?: Logger;
			now?: () => number;
			setTimer?: (fn: () => void, ms: number) => unknown;
			clearTimer?: (handle: unknown) => void;
		} = {},
	) {
		this.config = config;
		this.#log = options.logger ?? console;
		this.#now = options.now ?? Date.now;
		this.#setTimer = options.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
		this.#clearTimer = options.clearTimer ?? ((handle) => clearTimeout(handle as number));
	}

	/** Current slots: total and per tenant (tenants with no slot are absent). */
	snapshot(): { total: number; tenants: Record<string, number> } {
		return { total: this.#total, tenants: Object.fromEntries(this.#inFlight) };
	}

	/** The share a tenant may hold under pressure when `active` tenants hold slots. */
	fairShare(active: number): number {
		return Math.max(this.config.fairShareFloor, Math.floor(this.config.capacity / Math.max(1, active)));
	}

	tryAcquire(tenantId: string): TenantSlot | TenantSlotRejection {
		try {
			if (typeof tenantId !== "string" || tenantId === "") throw new Error("tenant id is required");
			const held = this.#inFlight.get(tenantId) ?? 0;
			const { capacity } = this.config;
			if (this.#total >= capacity) return this.#shed(tenantId, 503, SERVICE_OVERLOADED, "capacity", held);
			const overShare = this.#overShare(tenantId, held, this.#total, this.#inFlight.size);
			if (overShare) return overShare;
			this.#add(tenantId, 1);
			this.#total += 1;
			let owner = tenantId;
			let released = false;
			const release = () => {
				if (released) return;
				released = true;
				this.#clearTimer(lease);
				this.#add(owner, -1);
				this.#total = Math.max(0, this.#total - 1);
			};
			const lease = this.#setTimer(() => {
				if (released) return;
				this.#log.error(JSON.stringify({ event: "tenant_inflight_lease_expired", tenant_id: owner, lease_ms: this.config.leaseMs }));
				release();
			}, this.config.leaseMs);
			const rebind = (next: string): TenantSlotRejection | null => {
				if (released || next === owner || typeof next !== "string" || next === "") return null;
				// Judge `next` as if this slot were a new request from it.
				const ownerHeld = this.#inFlight.get(owner) ?? 0;
				const activeWithout = this.#inFlight.size - (ownerHeld === 1 ? 1 : 0);
				const overShare = this.#overShare(next, this.#inFlight.get(next) ?? 0, this.#total - 1, activeWithout);
				if (overShare) return overShare;
				this.#add(owner, -1);
				this.#add(next, 1);
				owner = next;
				return null;
			};
			return { ok: true, rebind, release };
		} catch (error) {
			this.#log.error(JSON.stringify({
				event: "tenant_inflight_limiter_error", tenant_id: typeof tenantId === "string" ? tenantId : null,
				message: error instanceof Error ? error.message : String(error),
			}));
			return { ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: this.config.retryAfterSeconds };
		}
	}

	/** Total in-flight has reached the per-tenant cap: fair shares apply. */
	underPressure(): boolean {
		return this.#total >= this.config.perTenantMax;
	}

	/** A 429 tenant_overloaded for `tenantId`, logged like any other shed. */
	shed(tenantId: string, reason: string): TenantSlotRejection {
		return this.#shed(tenantId, 429, TENANT_OVERLOADED, reason, this.#inFlight.get(tenantId) ?? 0);
	}

	/** Rules 2 and 3: the tenant's own cap, then its fair share under pressure. */
	#overShare(tenantId: string, held: number, total: number, active: number): TenantSlotRejection | null {
		const { perTenantMax } = this.config;
		if (held >= perTenantMax) return this.#shed(tenantId, 429, TENANT_OVERLOADED, "tenant_max", held);
		if (total >= perTenantMax && held >= this.fairShare(active + (held === 0 ? 1 : 0))) {
			return this.#shed(tenantId, 429, TENANT_OVERLOADED, "fair_share", held);
		}
		return null;
	}

	#add(tenantId: string, delta: number) {
		const next = (this.#inFlight.get(tenantId) ?? 0) + delta;
		if (next > 0) this.#inFlight.set(tenantId, next);
		else this.#inFlight.delete(tenantId);
	}

	#shed(tenantId: string, status: 429 | 503, error: TenantSlotRejection["error"], reason: string, held: number): TenantSlotRejection {
		const key = `${tenantId}:${reason}`;
		const now = this.#now();
		const last = this.#lastShedLog.get(key);
		if (last === undefined || now - last >= SHED_LOG_INTERVAL_MS) {
			if (this.#lastShedLog.size >= 1_000) this.#lastShedLog.clear();
			this.#lastShedLog.set(key, now);
			this.#log.warn(JSON.stringify({
				event: "tenant_inflight_shed", tenant_id: tenantId, reason,
				tenant_in_flight: held, total_in_flight: this.#total, active_tenants: this.#inFlight.size,
				capacity: this.config.capacity,
			}));
		}
		return { ok: false, status, error, retryAfterSeconds: this.config.retryAfterSeconds };
	}
}

async function credentialDigest(credential: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(credential));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Admits a request by its bearer credential before authentication, charging it
 * to the tenant that credential last authenticated as (or to the unresolved
 * pseudo tenant), and moves the slot to the authenticated tenant afterwards.
 */
export class CredentialAdmission {
	readonly limiter: TenantConcurrencyLimiter;
	#hints = new Map<string, { tenantId: string; expiresAt: number }>();
	// Unresolved requests in flight per credential digest.
	#pending = new Map<string, number>();
	#now: () => number;

	constructor(limiter: TenantConcurrencyLimiter, options: { now?: () => number } = {}) {
		this.limiter = limiter;
		this.#now = options.now ?? Date.now;
	}

	async admit(credential: string): Promise<CredentialSlot | TenantSlotRejection> {
		let digest: string;
		try {
			digest = await credentialDigest(credential);
		} catch (error) {
			// Unreachable with a string credential; still never an unbounded admission.
			console.error(JSON.stringify({ event: "tenant_inflight_limiter_error", message: error instanceof Error ? error.message : String(error) }));
			return { ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: this.limiter.config.retryAfterSeconds };
		}
		const hint = this.#hints.get(digest);
		const now = this.#now();
		if (hint && hint.expiresAt <= now) this.#hints.delete(digest);
		const charged = hint && hint.expiresAt > now ? hint.tenantId : UNRESOLVED_TENANT;
		// Under pressure a credential not yet resolved in this isolate gets one
		// request at a time, so one tenant's many keys cannot fill the shared
		// unresolved bucket ahead of another tenant's first request (this
		// happens every time the runtime starts a fresh worker).
		const unresolved = charged === UNRESOLVED_TENANT;
		if (unresolved && (this.#pending.get(digest) ?? 0) > 0 && this.limiter.underPressure()) {
			return this.limiter.shed(UNRESOLVED_TENANT, "unresolved_key_busy");
		}
		const slot = this.limiter.tryAcquire(charged);
		if (!slot.ok) return slot;
		let pending = unresolved;
		if (pending) this.#pending.set(digest, (this.#pending.get(digest) ?? 0) + 1);
		const settle = () => {
			if (!pending) return;
			pending = false;
			const left = (this.#pending.get(digest) ?? 1) - 1;
			if (left > 0) this.#pending.set(digest, left);
			else this.#pending.delete(digest);
		};
		return {
			ok: true,
			release: () => {
				settle();
				slot.release();
			},
			authenticated: (tenantId: string) => {
				settle();
				if (this.#hints.size >= MAX_HINTS && !this.#hints.has(digest)) this.#hints.clear();
				this.#hints.set(digest, { tenantId, expiresAt: this.#now() + HINT_TTL_MS });
				return slot.rebind(tenantId);
			},
			unauthenticated: () => {
				settle();
				this.#hints.delete(digest);
			},
		};
	}
}

/** The rejection's response body and headers: a stable code, retryable, with Retry-After. */
export function tenantSlotResponse(rejection: TenantSlotRejection): { status: 429 | 503; body: Record<string, unknown>; headers: Record<string, string> } {
	return {
		status: rejection.status,
		body: { error: rejection.error, retryable: true },
		headers: { "Retry-After": String(rejection.retryAfterSeconds) },
	};
}

export type AdmitCredential = (credential: string) => Promise<CredentialSlot | TenantSlotRejection>;

/**
 * Isolate-wide admission for one function, built on first use from the
 * environment. A malformed configuration refuses admission (fail closed) and is
 * logged once per isolate, so it is never silent.
 */
export function tenantSlotGate(env: EnvReader, logger: Logger = console): AdmitCredential {
	let admission: CredentialAdmission | null = null;
	let configProblemLogged = false;
	return (credential) => {
		if (!admission) {
			const parsed = parseTenantConcurrencyConfig(env);
			if (!parsed.ok) {
				if (!configProblemLogged) {
					configProblemLogged = true;
					logger.error(JSON.stringify({ event: "tenant_inflight_limiter_misconfigured", problem: parsed.problem }));
				}
				return Promise.resolve({ ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: 30 });
			}
			admission = new CredentialAdmission(new TenantConcurrencyLimiter(parsed.config, { logger }));
		}
		return admission.admit(credential);
	};
}

/** Holds a slot for `credential` while `work` runs; the slot is released however `work` settles. */
export async function withTenantSlot(
	admit: AdmitCredential,
	credential: string,
	work: (slot: CredentialSlot) => Promise<Response>,
	reject: (rejection: TenantSlotRejection) => Response,
): Promise<Response> {
	const slot = await admit(credential);
	if (!slot.ok) return reject(slot);
	try {
		return await work(slot);
	} finally {
		slot.release();
	}
}
