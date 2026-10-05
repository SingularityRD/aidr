// Per-isolate JWKS cache with rotation handling.
//
//  * Keys are cached per JWKS URI for `ttlMs`.
//  * An unknown `kid` triggers ONE refetch (an IdP rolled its signing key), but
//    refetches for the same URI are rate-limited to `minRefetchMs`, so a client
//    that sends tokens with random kids cannot turn this function into a
//    request amplifier against the IdP.
//  * If the IdP is unreachable a cached set stays usable for known kids up to
//    `maxStaleMs`; an unknown kid never succeeds from stale data.
//  * Bounded: at most `maxEntries` URIs and `maxKeys` keys per document.

import { type Jwk, type KeyLookup, type OidcAlgorithm, selectKey } from "./oidc.ts";

type JwksFetcher = (jwksUri: string) => Promise<Jwk[] | null>;

interface CacheEntry {
	keys: Jwk[];
	fetchedAt: number;
	lastAttemptAt: number;
}

export interface JwksCacheOptions {
	fetchKeys: JwksFetcher;
	now?: () => number;
	ttlMs?: number;
	minRefetchMs?: number;
	maxStaleMs?: number;
	maxEntries?: number;
	maxKeys?: number;
}

export class JwksCache {
	private readonly entries = new Map<string, CacheEntry>();
	private readonly inflight = new Map<string, Promise<void>>();
	private readonly now: () => number;
	private readonly ttlMs: number;
	private readonly minRefetchMs: number;
	private readonly maxStaleMs: number;
	private readonly maxEntries: number;
	private readonly maxKeys: number;

	constructor(private readonly options: JwksCacheOptions) {
		this.now = options.now ?? Date.now;
		this.ttlMs = options.ttlMs ?? 10 * 60_000;
		this.minRefetchMs = options.minRefetchMs ?? 30_000;
		this.maxStaleMs = options.maxStaleMs ?? 60 * 60_000;
		this.maxEntries = options.maxEntries ?? 100;
		this.maxKeys = options.maxKeys ?? 20;
	}

	/** Forget a URI, for example after the operator re-runs discovery with a new jwks_uri. */
	invalidate(jwksUri: string): void {
		this.entries.delete(jwksUri);
	}

	private async refresh(jwksUri: string): Promise<void> {
		const pending = this.inflight.get(jwksUri);
		if (pending) return pending;
		const run = (async () => {
			const attemptAt = this.now();
			const previous = this.entries.get(jwksUri);
			let keys: Jwk[] | null = null;
			try {
				keys = await this.options.fetchKeys(jwksUri);
			} catch {
				keys = null;
			}
			if (keys && keys.length > 0 && keys.length <= this.maxKeys) {
				if (!this.entries.has(jwksUri) && this.entries.size >= this.maxEntries) {
					const oldest = this.entries.keys().next().value;
					if (oldest !== undefined) this.entries.delete(oldest);
				}
				this.entries.set(jwksUri, { keys, fetchedAt: attemptAt, lastAttemptAt: attemptAt });
			} else if (previous) {
				this.entries.set(jwksUri, { ...previous, lastAttemptAt: attemptAt });
			} else {
				this.entries.set(jwksUri, { keys: [], fetchedAt: 0, lastAttemptAt: attemptAt });
			}
		})().finally(() => this.inflight.delete(jwksUri));
		this.inflight.set(jwksUri, run);
		return run;
	}

	async getKey(jwksUri: string, kid: string | undefined, alg: OidcAlgorithm): Promise<KeyLookup> {
		let entry = this.entries.get(jwksUri);
		const nowMs = this.now();
		if (!entry || nowMs - entry.fetchedAt >= this.ttlMs) {
			if (!entry || nowMs - entry.lastAttemptAt >= this.minRefetchMs) {
				await this.refresh(jwksUri);
				entry = this.entries.get(jwksUri);
			}
		}
		const usable = (candidate: CacheEntry | undefined): candidate is CacheEntry =>
			candidate !== undefined && candidate.keys.length > 0 && this.now() - candidate.fetchedAt < this.maxStaleMs;
		if (!usable(entry)) return { status: "unavailable" };

		const hit = selectKey(entry.keys, kid, alg);
		if (hit) return { status: "found", key: hit };

		// Unknown kid: refetch once if the last attempt is old enough (key rotation).
		if (this.now() - entry.lastAttemptAt >= this.minRefetchMs) {
			await this.refresh(jwksUri);
			const refreshed = this.entries.get(jwksUri);
			if (!usable(refreshed)) return { status: "unavailable" };
			const rotated = selectKey(refreshed.keys, kid, alg);
			if (rotated) return { status: "found", key: rotated };
			// Still unknown after a fresh fetch only counts as unknown if that fetch worked.
			return refreshed.lastAttemptAt === refreshed.fetchedAt
				? { status: "unknown_kid" }
				: { status: "unavailable" };
		}
		return { status: "unknown_kid" };
	}
}

/** Parse a JWKS document body into keys, dropping anything that is not an object. */
export function parseJwks(document: unknown): Jwk[] | null {
	if (!document || typeof document !== "object" || Array.isArray(document)) return null;
	const keys = (document as { keys?: unknown }).keys;
	if (!Array.isArray(keys)) return null;
	return keys.filter(
		(key): key is Jwk => Boolean(key) && typeof key === "object" && !Array.isArray(key),
	);
}
