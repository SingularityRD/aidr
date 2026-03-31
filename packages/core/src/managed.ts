import { createHash, createHmac, createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { ControlPlaneIngestResult } from "./clients/control-plane.js";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { AuthConfig } from "./types.js";

export type ManagedSeatStatus = "ok" | "over_limit" | "unknown";

export const FREE_AGENT_SEATS = 1;
export const PRICE_PER_EXTRA_AGENT_USD_MONTH = 2;

export interface EntitlementSnapshotV1 {
	schema_version: 1;
	issued_at: string;
	expires_at: string;
	free_agents: number;
	extra_agents: number;
	allowed_agents: number;
	price_per_extra_agent_usd_month: number;
}

export interface EntitlementSnapshotV2 {
	schema_version: 2;
	tenant_id: string;
	subscription_tier: "free" | "pro" | "enterprise";
	included_agents: number;
	extra_agents: number;
	allowed_agents: number;
	premium_modules: string[];
	pack_keys?: Array<{
		alg: "aes-256-gcm";
		key_id: string;
		key_b64: string;
		expires_at: string;
	}>;
	issued_at: string;
	expires_at: string;
	grace_until: string;
	serial: string;
	revocation_epoch: number;
}

export interface RevocationListV1 {
	schema_version: 1;
	issued_at: string;
	expires_at: string;
	revocation_epoch: number;
	revocations: {
		artifact_ids: string[];
		pack_ids: string[];
		key_ids: string[];
		entitlement_serials: string[];
	};
}

export interface SignedEd25519<T> {
	alg: "ed25519";
	key_id?: string;
	sig_b64: string;
	payload: T;
}

export interface ManagedState {
	last_success_at?: string;
	grace_until?: string;
	seat_status?: ManagedSeatStatus;
	allowed_agents?: number;
	current_agents?: number;
	sync_disabled_until?: string;
	sync_disabled_reason?: string;
	/**
	 * Commercial v1: persisted API key issued by /v1/enroll.
	 * This enables offline grace without requiring users to edit config files.
	 */
	api_key?: string;

	/**
	 * Device-code bootstrap cache (zero-friction onboarding).
	 * Stored so we don't create a new device session on every startup.
	 */
	device_code?: string;
	user_code?: string;
	verification_url?: string;
	device_expires_at?: string;
	device_started_at?: string;
	entitlement?: EntitlementSnapshotV1 | EntitlementSnapshotV2;
	entitlement_alg?: "hmac-sha256" | "ed25519";
	entitlement_key_id?: string;
	entitlement_sig?: string;
}

export interface ManagedSecurityEvent {
	code:
		| "missing_public_keys"
		| "invalid_ed25519_signature"
		| "invalid_hmac_signature"
		| "invalid_hmac_schema";
	message: string;
}

function emitManagedSecurityEvent(
	event: ManagedSecurityEvent,
	callback?: (event: ManagedSecurityEvent) => void,
): void {
	if (callback) {
		callback(event);
		return;
	}
	console.warn(
		JSON.stringify({
			component: "managed_state",
			level: "warning",
			event: "security_verification_failure",
			code: event.code,
			message: event.message,
		}),
	);
}

export function getAuthToken(auth: AuthConfig): string | undefined {
	const apiKey = auth.api_key?.trim();
	if (apiKey) return apiKey;
	const enroll = auth.enrollment_token?.trim();
	return enroll || undefined;
}

export function managedStatePath(): string {
	return resolvePath("~/.singularity-aidr/managed.json");
}

export function revocationsCachePath(): string {
	return resolvePath("~/.singularity-aidr/revocations.json");
}

export function entitlementKeyringPath(): string {
	return resolvePath("~/.singularity-aidr/entitlement.json");
}

export function sha256Hex(input: string): string {
	return createHash("sha256").update(input).digest("hex");
}

function canonicalizeForSigning(value: unknown): unknown {
	if (Array.isArray(value)) return value.map((v) => canonicalizeForSigning(v));
	if (!value || typeof value !== "object") return value;
	const obj = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) {
		out[key] = canonicalizeForSigning(obj[key]);
	}
	return out;
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(canonicalizeForSigning(value));
}

export function signEntitlementSnapshot(
	snapshot: EntitlementSnapshotV1,
	authToken: string,
): string {
	// v1: local HMAC signature to make cached entitlements tamper-evident offline.
	// Future: accept/verify control-plane signatures using embedded/public keys.
	return createHmac("sha256", authToken).update(canonicalJson(snapshot)).digest("hex");
}

export function verifyEntitlementSnapshotSignature(
	snapshot: EntitlementSnapshotV1,
	sig: string,
	authToken: string,
): boolean {
	try {
		const expected = signEntitlementSnapshot(snapshot, authToken);
		return expected === sig;
	} catch {
		return false;
	}
}

function parseSignatureBase64(raw: string): Buffer | null {
	const trimmed = raw.trim();
	if (!trimmed) return null;
	try {
		const buf = Buffer.from(trimmed, "base64");
		// Ed25519 signatures are 64 bytes.
		if (buf.length !== 64) return null;
		return buf;
	} catch {
		return null;
	}
}

function toPublicKey(key: string) {
	const t = key.trim();
	if (!t) return null;
	try {
		if (t.includes("BEGIN PUBLIC KEY")) return createPublicKey(t);
		// Allow base64-encoded SPKI DER for easier env/config distribution.
		return createPublicKey({ key: Buffer.from(t, "base64"), format: "der", type: "spki" });
	} catch {
		return null;
	}
}

function verifyEd25519(message: Buffer, signature: Buffer, publicKeys: string[]): boolean {
	for (const k of publicKeys) {
		const key = toPublicKey(k);
		if (!key) continue;
		try {
			// For Ed25519 the algorithm parameter must be null.
			if (cryptoVerify(null, message, key, signature)) return true;
		} catch {}
	}
	return false;
}

export function verifyEd25519SignedEntitlementSnapshot(params: {
	snapshot: EntitlementSnapshotV1 | EntitlementSnapshotV2;
	sig_b64: string;
	public_keys_pem: string[];
}): boolean {
	const sig = parseSignatureBase64(params.sig_b64);
	if (!sig) return false;
	const msg = Buffer.from(canonicalJson(params.snapshot), "utf8");
	return verifyEd25519(msg, sig, params.public_keys_pem);
}

export function verifyEd25519SignedRevocationList(params: {
	list: RevocationListV1;
	sig_b64: string;
	public_keys_pem: string[];
}): boolean {
	const sig = parseSignatureBase64(params.sig_b64);
	if (!sig) return false;
	const msg = Buffer.from(canonicalJson(params.list), "utf8");
	return verifyEd25519(msg, sig, params.public_keys_pem);
}

export function redactRemoteEvent(
	entry: Record<string, unknown>,
	mode: "none" | "hash" | "full" | undefined,
): Record<string, unknown> {
	if (mode === "none" || !mode) return entry;

	const summary = typeof entry.tool_input_summary === "string" ? entry.tool_input_summary : "";
	const artifacts = Array.isArray(entry.artifacts) ? (entry.artifacts as unknown[]) : [];
	const artifactStrings = artifacts.map((a) => (typeof a === "string" ? a : JSON.stringify(a)));

	if (mode === "full") {
		return { ...entry, tool_input_summary: "", artifacts: [] };
	}

	return {
		...entry,
		tool_input_summary: `sha256:${sha256Hex(summary)}`,
		artifacts: artifactStrings.map((a) => `sha256:${sha256Hex(a)}`),
	};
}

function buildDefaultEntitlementSnapshot(
	now: Date,
	gracePeriodHours: number,
): EntitlementSnapshotV1 {
	const freeAgents = FREE_AGENT_SEATS;
	const extraAgents = 0;
	return {
		schema_version: 1,
		issued_at: now.toISOString(),
		expires_at: addHoursIso(now, gracePeriodHours),
		free_agents: freeAgents,
		extra_agents: extraAgents,
		allowed_agents: freeAgents + extraAgents,
		price_per_extra_agent_usd_month: PRICE_PER_EXTRA_AGENT_USD_MONTH,
	};
}

function sanitizeSeatCount(input: unknown): number | undefined {
	if (typeof input !== "number") return undefined;
	if (!Number.isFinite(input)) return undefined;
	const rounded = Math.floor(input);
	if (rounded < 0) return 0;
	return rounded;
}

function parseNonNegIntStrict(input: unknown): number | undefined {
	if (typeof input !== "number") return undefined;
	if (!Number.isFinite(input)) return undefined;
	if (!Number.isInteger(input)) return undefined;
	if (input < 0) return 0;
	return input;
}

function isIsoDateString(value: unknown): value is string {
	return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function validateEntitlementSnapshotV1Strict(input: unknown): EntitlementSnapshotV1 | null {
	if (!input || typeof input !== "object" || Array.isArray(input)) return null;
	const obj = input as Record<string, unknown>;
	if (obj.schema_version !== 1) return null;

	const issuedAt = obj.issued_at;
	const expiresAt = obj.expires_at;
	if (!isIsoDateString(issuedAt) || !isIsoDateString(expiresAt)) return null;

	const freeAgents = parseNonNegIntStrict(obj.free_agents);
	const extraAgents = parseNonNegIntStrict(obj.extra_agents);
	const allowedAgents = parseNonNegIntStrict(obj.allowed_agents);
	const price = parseNonNegIntStrict(obj.price_per_extra_agent_usd_month);
	if (freeAgents === undefined) return null;
	if (extraAgents === undefined) return null;
	if (allowedAgents === undefined) return null;
	if (price === undefined) return null;

	return {
		schema_version: 1,
		issued_at: issuedAt,
		expires_at: expiresAt,
		free_agents: freeAgents,
		extra_agents: extraAgents,
		allowed_agents: allowedAgents,
		price_per_extra_agent_usd_month: price,
	};
}

function validateEntitlementSnapshotV2Strict(input: unknown): EntitlementSnapshotV2 | null {
	if (!input || typeof input !== "object" || Array.isArray(input)) return null;
	const obj = input as Record<string, unknown>;
	if (obj.schema_version !== 2) return null;

	const tenantId = typeof obj.tenant_id === "string" ? obj.tenant_id.trim() : "";
	if (!tenantId) return null;

	const tier = typeof obj.subscription_tier === "string" ? obj.subscription_tier : "free";
	if (tier !== "free" && tier !== "pro" && tier !== "enterprise") return null;

	const issuedAt = obj.issued_at;
	const expiresAt = obj.expires_at;
	const graceUntil = obj.grace_until;
	if (!isIsoDateString(issuedAt) || !isIsoDateString(expiresAt) || !isIsoDateString(graceUntil)) {
		return null;
	}

	const includedAgents = parseNonNegIntStrict(obj.included_agents);
	const extraAgents = parseNonNegIntStrict(obj.extra_agents);
	const allowedAgents = parseNonNegIntStrict(obj.allowed_agents);
	const revEpoch = parseNonNegIntStrict(obj.revocation_epoch) ?? 1;
	if (includedAgents === undefined) return null;
	if (extraAgents === undefined) return null;
	if (allowedAgents === undefined) return null;

	const serial = typeof obj.serial === "string" ? obj.serial.trim() : "";
	if (!serial) return null;

	if (!Array.isArray(obj.premium_modules)) return null;
	const premiumModules: string[] = [];
	for (const m of obj.premium_modules) {
		if (typeof m !== "string") return null;
		if (m.trim()) premiumModules.push(m.trim());
	}

	let packKeys: EntitlementSnapshotV2["pack_keys"] | undefined;
	if (obj.pack_keys !== undefined) {
		if (!Array.isArray(obj.pack_keys)) return null;
		const out: NonNullable<EntitlementSnapshotV2["pack_keys"]> = [];
		for (const k of obj.pack_keys) {
			if (!k || typeof k !== "object" || Array.isArray(k)) return null;
			const pk = k as Record<string, unknown>;
			const alg = pk.alg;
			const keyId = typeof pk.key_id === "string" ? pk.key_id.trim() : "";
			const keyB64 = typeof pk.key_b64 === "string" ? pk.key_b64.trim() : "";
			const exp = pk.expires_at;
			if (alg !== "aes-256-gcm") return null;
			if (!keyId || !keyB64) return null;
			if (!isIsoDateString(exp)) return null;
			out.push({ alg: "aes-256-gcm", key_id: keyId, key_b64: keyB64, expires_at: exp });
		}
		packKeys = out;
	}

	return {
		schema_version: 2,
		tenant_id: tenantId,
		subscription_tier: tier as EntitlementSnapshotV2["subscription_tier"],
		included_agents: includedAgents,
		extra_agents: extraAgents,
		allowed_agents: allowedAgents,
		premium_modules: premiumModules,
		...(packKeys ? { pack_keys: packKeys } : {}),
		issued_at: issuedAt,
		expires_at: expiresAt,
		grace_until: graceUntil,
		serial,
		revocation_epoch: Math.max(1, revEpoch),
	};
}

function extractEntitlementFromBody(
	body: Record<string, unknown> | undefined,
	now: Date,
	gracePeriodHours: number,
): EntitlementSnapshotV1 | EntitlementSnapshotV2 | null {
	if (!body) return null;
	const candidate = body.entitlement;
	if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
	const ent = candidate as Record<string, unknown>;

	const schemaVersion = Number(ent.schema_version ?? 1);
	if (schemaVersion === 2) {
		const tenantId = typeof ent.tenant_id === "string" ? ent.tenant_id.trim() : "";
		if (!tenantId) return null;
		const tierRaw = typeof ent.subscription_tier === "string" ? ent.subscription_tier : "free";
		const tier =
			tierRaw === "free" || tierRaw === "pro" || tierRaw === "enterprise"
				? (tierRaw as "free" | "pro" | "enterprise")
				: "free";
		const includedAgents = sanitizeSeatCount(ent.included_agents) ?? FREE_AGENT_SEATS;
		const extraAgents = sanitizeSeatCount(ent.extra_agents) ?? 0;
		const allowedAgents =
			sanitizeSeatCount(ent.allowed_agents) ??
			Math.max(FREE_AGENT_SEATS, includedAgents + extraAgents);
		const premiumModules = Array.isArray(ent.premium_modules)
			? (ent.premium_modules as unknown[])
					.filter((x) => typeof x === "string")
					.map((x) => String(x))
			: [];
		const expiresAt = isIsoDateString(ent.expires_at)
			? ent.expires_at
			: addHoursIso(now, gracePeriodHours);
		const graceUntil = isIsoDateString(ent.grace_until)
			? ent.grace_until
			: addHoursIso(now, gracePeriodHours);
		const issuedAt = isIsoDateString(ent.issued_at) ? ent.issued_at : now.toISOString();
		const serial =
			typeof ent.serial === "string" && ent.serial.trim() ? ent.serial.trim() : crypto.randomUUID();
		const revEpoch =
			typeof ent.revocation_epoch === "number" && Number.isFinite(ent.revocation_epoch)
				? Math.floor(ent.revocation_epoch)
				: 1;

		return {
			schema_version: 2,
			tenant_id: tenantId,
			subscription_tier: tier,
			included_agents: includedAgents,
			extra_agents: extraAgents,
			allowed_agents: allowedAgents,
			premium_modules: premiumModules,
			issued_at: issuedAt,
			expires_at: expiresAt,
			grace_until: graceUntil,
			serial,
			revocation_epoch: Math.max(1, revEpoch),
		};
	}

	// v1 legacy (self-host/dev)
	const freeAgents = sanitizeSeatCount(ent.free_agents) ?? FREE_AGENT_SEATS;
	const extraAgents = sanitizeSeatCount(ent.extra_agents) ?? 0;
	const allowedAgents =
		sanitizeSeatCount(ent.allowed_agents) ?? Math.max(FREE_AGENT_SEATS, freeAgents + extraAgents);
	const price =
		sanitizeSeatCount(ent.price_per_extra_agent_usd_month) ?? PRICE_PER_EXTRA_AGENT_USD_MONTH;
	const expiresAt = isIsoDateString(ent.expires_at)
		? ent.expires_at
		: addHoursIso(now, gracePeriodHours);
	const issuedAt = isIsoDateString(ent.issued_at) ? ent.issued_at : now.toISOString();

	return {
		schema_version: 1,
		issued_at: issuedAt,
		expires_at: expiresAt,
		free_agents: freeAgents,
		extra_agents: extraAgents,
		allowed_agents: allowedAgents,
		price_per_extra_agent_usd_month: price,
	};
}

function extractSignedEntitlementFromBody(body: Record<string, unknown> | undefined): {
	snapshot: EntitlementSnapshotV1 | EntitlementSnapshotV2;
	sig_b64: string;
	key_id?: string;
} | null {
	if (!body) return null;
	const signed = body.entitlement_signed;
	if (!signed || typeof signed !== "object" || Array.isArray(signed)) return null;
	const obj = signed as Record<string, unknown>;
	const snapshot = obj.snapshot;
	if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) return null;
	const s = snapshot as Record<string, unknown>;
	const sv = Number(s.schema_version ?? 1);
	if (sv !== 1 && sv !== 2) return null;
	const sig =
		typeof obj.sig_b64 === "string" ? obj.sig_b64 : typeof obj.sig === "string" ? obj.sig : null;
	if (!sig) return null;
	const keyId = typeof obj.key_id === "string" ? obj.key_id : undefined;
	return {
		snapshot: snapshot as EntitlementSnapshotV1 | EntitlementSnapshotV2,
		sig_b64: sig,
		key_id: keyId,
	};
}

export async function loadManagedState(
	path: string,
	opts?: {
		authToken?: string;
		publicKeysPem?: string[];
		onSecurityEvent?: (event: ManagedSecurityEvent) => void;
	},
): Promise<ManagedState> {
	try {
		const raw = await getFileContent(path, "utf-8");
		const parsed = JSON.parse(raw) as ManagedState;
		if (!parsed || typeof parsed !== "object") return {};

		// Best-effort signature check: if invalid, drop entitlement fields (fail-open).
		if (parsed.entitlement && parsed.entitlement_sig) {
			if (parsed.entitlement_alg === "ed25519") {
				const keys = opts?.publicKeysPem ?? [];
				if (
					keys.length === 0 ||
					!verifyEd25519SignedEntitlementSnapshot({
						snapshot: parsed.entitlement,
						sig_b64: parsed.entitlement_sig,
						public_keys_pem: keys,
					})
				) {
					emitManagedSecurityEvent(
						{
							code: keys.length === 0 ? "missing_public_keys" : "invalid_ed25519_signature",
							message: "Dropping cached entitlement due to failed ed25519 verification.",
						},
						opts?.onSecurityEvent,
					);
					return {
						...parsed,
						entitlement: undefined,
						entitlement_alg: undefined,
						entitlement_key_id: undefined,
						entitlement_sig: undefined,
					};
				}
			} else if (parsed.entitlement_alg === "hmac-sha256") {
				const authToken = opts?.authToken;
				// HMAC entitlements are legacy v1 only.
				if (parsed.entitlement.schema_version !== 1) {
					emitManagedSecurityEvent(
						{
							code: "invalid_hmac_schema",
							message: "Dropping cached entitlement due to unexpected HMAC schema version.",
						},
						opts?.onSecurityEvent,
					);
					return {
						...parsed,
						entitlement: undefined,
						entitlement_alg: undefined,
						entitlement_key_id: undefined,
						entitlement_sig: undefined,
					};
				}
				if (
					!authToken ||
					!verifyEntitlementSnapshotSignature(parsed.entitlement, parsed.entitlement_sig, authToken)
				) {
					emitManagedSecurityEvent(
						{
							code: "invalid_hmac_signature",
							message: "Dropping cached entitlement due to failed HMAC verification.",
						},
						opts?.onSecurityEvent,
					);
					return {
						...parsed,
						entitlement: undefined,
						entitlement_alg: undefined,
						entitlement_key_id: undefined,
						entitlement_sig: undefined,
					};
				}
			}
		}

		return parsed;
	} catch {
		return {};
	}
}

export async function saveManagedState(path: string, state: ManagedState): Promise<void> {
	try {
		const cleaned: ManagedState = { ...state };
		for (const key of Object.keys(cleaned) as (keyof ManagedState)[]) {
			if (cleaned[key] === undefined) delete cleaned[key];
		}
		await atomicWriteJson(path, cleaned);
	} catch {
		// Fail open
	}
}

/**
 * Writes a minimal keyring file used by encrypted intel packs.
 * This keeps the intel layer decoupled from managed state schema.
 */
export async function saveEntitlementKeyringFromState(state: ManagedState): Promise<void> {
	try {
		const ent = state.entitlement;
		if (!ent || ent.schema_version !== 2) return;
		if (state.entitlement_alg !== "ed25519") return;
		if (!Array.isArray(ent.pack_keys) || ent.pack_keys.length === 0) return;

		const keys: Record<string, string> = {};
		for (const k of ent.pack_keys) {
			if (!k || typeof k !== "object") continue;
			if (k.alg !== "aes-256-gcm") continue;
			const id = typeof k.key_id === "string" ? k.key_id.trim() : "";
			const b64 = typeof k.key_b64 === "string" ? k.key_b64.trim() : "";
			if (!id || !b64) continue;
			keys[id] = b64;
		}

		if (Object.keys(keys).length === 0) return;

		await atomicWriteJson(entitlementKeyringPath(), {
			intel_keys: keys,
			issued_at: ent.issued_at,
			expires_at: ent.grace_until,
			tenant_id: ent.tenant_id,
			serial: ent.serial,
		});
	} catch {
		// Fail open
	}
}

export function isSyncDisabled(state: ManagedState): boolean {
	const until =
		typeof state.sync_disabled_until === "string" ? Date.parse(state.sync_disabled_until) : NaN;
	if (!Number.isFinite(until)) return false;
	return Date.now() < until;
}

export function addHoursIso(now: Date, hours: number): string {
	const safeHours = Number.isFinite(hours) ? Math.max(0, hours) : 0;
	return new Date(now.getTime() + safeHours * 60 * 60 * 1000).toISOString();
}

export function applyIngestResult(
	state: ManagedState,
	result: ControlPlaneIngestResult,
	gracePeriodHours: number,
	opts?: { authToken?: string; publicKeysPem?: string[] },
): ManagedState {
	const now = new Date();
	if (result.ok) {
		const signed = extractSignedEntitlementFromBody(result.body);
		const publicKeysPem = opts?.publicKeysPem ?? [];
		const authToken = opts?.authToken;

		let entitlement: EntitlementSnapshotV1 | EntitlementSnapshotV2 | undefined;
		let entitlementAlg: ManagedState["entitlement_alg"] | undefined;
		let entitlementSig: string | undefined;
		let entitlementKeyId: string | undefined;

		if (signed && publicKeysPem.length > 0) {
			const validated =
				validateEntitlementSnapshotV2Strict(signed.snapshot) ??
				validateEntitlementSnapshotV1Strict(signed.snapshot);
			if (
				validated &&
				verifyEd25519SignedEntitlementSnapshot({
					snapshot: validated,
					sig_b64: signed.sig_b64,
					public_keys_pem: publicKeysPem,
				})
			) {
				entitlement = validated;
				entitlementAlg = "ed25519";
				entitlementSig = signed.sig_b64;
				entitlementKeyId = signed.key_id;
			}
		}

		// Back-compat: if server-signed entitlements are not available yet, keep local HMAC snapshots
		// as a tamper-evident cache. Premium unlock should rely on ed25519 entitlements.
		if (!entitlement && authToken) {
			const candidate = extractEntitlementFromBody(result.body, now, gracePeriodHours);
			const local =
				(candidate && candidate.schema_version === 1 ? candidate : null) ??
				buildDefaultEntitlementSnapshot(now, gracePeriodHours);
			entitlement = local;
			entitlementAlg = "hmac-sha256";
			entitlementSig = signEntitlementSnapshot(local, authToken);
			entitlementKeyId = undefined;
		}

		const allowedAgents =
			typeof result.body?.allowed_agents === "number"
				? (result.body.allowed_agents as number)
				: undefined;
		const currentAgents =
			typeof result.body?.current_agents === "number"
				? (result.body.current_agents as number)
				: undefined;

		return {
			...state,
			last_success_at: now.toISOString(),
			grace_until: addHoursIso(now, gracePeriodHours),
			seat_status: "ok",
			sync_disabled_until: undefined,
			sync_disabled_reason: undefined,
			allowed_agents: allowedAgents,
			current_agents: currentAgents,
			entitlement,
			entitlement_alg: entitlementAlg,
			entitlement_key_id: entitlementKeyId,
			entitlement_sig: entitlementSig,
		};
	}

	if (
		result.status === 402 &&
		typeof result.body?.error === "string" &&
		result.body.error === "agent_limit_exceeded"
	) {
		const allowedAgents =
			typeof result.body.allowed_agents === "number"
				? (result.body.allowed_agents as number)
				: undefined;
		const currentAgents =
			typeof result.body.current_agents === "number"
				? (result.body.current_agents as number)
				: undefined;
		return {
			...state,
			seat_status: "over_limit",
			allowed_agents: allowedAgents,
			current_agents: currentAgents,
			sync_disabled_reason: "agent_limit_exceeded",
			// Back off remote attempts; local protection always continues.
			sync_disabled_until: addHoursIso(now, 24),
		};
	}

	return state;
}

export function isEntitlementActive(state: ManagedState, now = new Date()): boolean {
	if (!state.entitlement) return false;
	const exp = Date.parse(state.entitlement.expires_at);
	if (Number.isFinite(exp) && now.getTime() < exp) return true;

	// v2: allow grace window beyond expires_at
	if (state.entitlement.schema_version === 2) {
		const grace = Date.parse(state.entitlement.grace_until);
		if (!Number.isFinite(grace)) return false;
		return now.getTime() < grace;
	}

	return false;
}

/**
 * Premium unlock: only server-signed (ed25519) entitlements should grant paid features.
 * (HMAC snapshots are a local tamper-evident cache/back-compat only.)
 */
export function isPremiumUnlocked(state: ManagedState, now = new Date()): boolean {
	if (!isEntitlementActive(state, now)) return false;
	if (state.entitlement_alg !== "ed25519") return false;
	return (state.entitlement?.allowed_agents ?? FREE_AGENT_SEATS) > FREE_AGENT_SEATS;
}

export function isPremiumModuleEnabled(
	state: ManagedState,
	moduleId: string,
	now = new Date(),
): boolean {
	if (!isEntitlementActive(state, now)) return false;
	if (state.entitlement_alg !== "ed25519") return false;
	if (state.entitlement?.schema_version !== 2) return false;
	return Array.isArray(state.entitlement.premium_modules)
		? state.entitlement.premium_modules.includes(moduleId)
		: false;
}

export async function loadRevocationsCache(
	path: string,
	publicKeysPem: string[],
): Promise<SignedEd25519<RevocationListV1> | null> {
	try {
		const raw = await getFileContent(path, "utf-8");
		const parsed = JSON.parse(raw) as SignedEd25519<RevocationListV1>;
		if (!parsed || typeof parsed !== "object") return null;
		if (parsed.alg !== "ed25519") return null;
		if (typeof parsed.sig_b64 !== "string") return null;
		const list = validateRevocationListV1Strict(parsed.payload);
		if (!list) return null;
		if (!isIsoDateString(list.issued_at) || !isIsoDateString(list.expires_at)) return null;

		// Strict expiry for now. (Optional future: small grace window.)
		if (Date.now() > Date.parse(list.expires_at)) return null;

		if (
			publicKeysPem.length === 0 ||
			!verifyEd25519SignedRevocationList({
				list,
				sig_b64: parsed.sig_b64,
				public_keys_pem: publicKeysPem,
			})
		) {
			return null;
		}

		return { ...parsed, payload: list };
	} catch {
		return null;
	}
}

function validateRevocationListV1Strict(input: unknown): RevocationListV1 | null {
	if (!input || typeof input !== "object" || Array.isArray(input)) return null;
	const obj = input as Record<string, unknown>;
	if (obj.schema_version !== 1) return null;
	if (!isIsoDateString(obj.issued_at) || !isIsoDateString(obj.expires_at)) return null;

	const epoch =
		typeof obj.revocation_epoch === "number" && Number.isFinite(obj.revocation_epoch)
			? Math.max(1, Math.floor(obj.revocation_epoch))
			: 1;

	const revRaw = obj.revocations;
	if (!revRaw || typeof revRaw !== "object" || Array.isArray(revRaw)) return null;
	const rev = revRaw as Record<string, unknown>;

	function parseStringArray(v: unknown): string[] | null {
		if (!Array.isArray(v)) return null;
		const out: string[] = [];
		for (const x of v) {
			if (typeof x !== "string") return null;
			if (x.trim()) out.push(x.trim());
		}
		return out;
	}

	const artifactIds = parseStringArray(rev.artifact_ids) ?? [];
	const packIds = parseStringArray(rev.pack_ids) ?? [];
	const keyIds = parseStringArray(rev.key_ids) ?? [];
	const entitlementSerials = parseStringArray(rev.entitlement_serials) ?? [];

	return {
		schema_version: 1,
		issued_at: obj.issued_at,
		expires_at: obj.expires_at,
		revocation_epoch: epoch,
		revocations: {
			artifact_ids: artifactIds,
			pack_ids: packIds,
			key_ids: keyIds,
			entitlement_serials: entitlementSerials,
		},
	};
}

export function parseSignedRevocationsFromControlPlaneBody(
	body: Record<string, unknown> | undefined,
): SignedEd25519<RevocationListV1> | null {
	if (!body) return null;
	const candidate = body.revocations_signed ?? body;
	if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
	const obj = candidate as Record<string, unknown>;

	const alg = obj.alg;
	if (alg !== "ed25519") return null;
	const sigB64 =
		typeof obj.sig_b64 === "string" ? obj.sig_b64 : typeof obj.sig === "string" ? obj.sig : null;
	if (!sigB64) return null;
	const keyId = typeof obj.key_id === "string" ? obj.key_id : undefined;

	const listRaw = obj.payload ?? obj.list ?? obj.revocations;
	const list = validateRevocationListV1Strict(listRaw);
	if (!list) return null;

	return { alg: "ed25519", sig_b64: sigB64, key_id: keyId, payload: list };
}

export async function saveRevocationsCache(
	path: string,
	signed: SignedEd25519<RevocationListV1>,
): Promise<void> {
	try {
		await atomicWriteJson(path, signed);
	} catch {
		// Fail open
	}
}

export function applyRevocationsToManagedState(params: {
	state: ManagedState;
	iid?: string;
	revocations: RevocationListV1 | null;
}): ManagedState {
	const iid = params.iid?.trim();
	const rev = params.revocations;
	if (!iid || !rev) return params.state;

	const entitlementSerial =
		params.state.entitlement?.schema_version === 2 ? params.state.entitlement.serial : null;
	const revokedBySerial =
		Boolean(entitlementSerial) &&
		Array.isArray(rev.revocations.entitlement_serials) &&
		rev.revocations.entitlement_serials.includes(entitlementSerial as string);

	if (!revokedBySerial) return params.state;

	// Enforce revocation by clearing premium entitlements and disabling sync until the list expires.
	return {
		...params.state,
		seat_status: "over_limit",
		sync_disabled_reason: "revoked",
		sync_disabled_until: rev.expires_at,
		entitlement: undefined,
		entitlement_alg: undefined,
		entitlement_key_id: undefined,
		entitlement_sig: undefined,
	};
}
