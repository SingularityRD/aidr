import { createHash, createHmac, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { isCommercialBuild } from "./build-flavor.js";
import type { ControlPlaneIngestResult } from "./clients/control-plane.js";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import {
	createSecretReferenceId,
	type PlatformSecretStoreKind,
	resolveSecretStore,
	type SecretStore,
} from "./secret-store.js";
import { redactTelemetryData } from "./telemetry-redaction.js";
import type { AuthConfig } from "./types.js";

type ManagedSeatStatus = "ok" | "over_limit" | "unknown";

const FREE_AGENT_SEATS = 1;
const PRICE_PER_EXTRA_AGENT_USD_MONTH = 2;

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
	last_sync_attempt_at?: string;
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
	api_key_ref?: { store: PlatformSecretStoreKind; id: string; created_at: string };
	/** Preserve the installation's locked telemetry WAL across authenticated key rotations. */
	telemetry_queue?: { credential_namespace: string; anchor_namespace: string; mac: string };

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
		| "missing_entitlement_signature"
		| "invalid_entitlement_alg"
		| "invalid_ed25519_schema"
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

type AgentTokenClaims = { uid: string; agent_id: string; jti: string; iat: number; exp: number };
const AGENT_TOKEN_MAX_TTL_SECONDS = 7 * 24 * 60 * 60;

// Identity/lifetime consistency only: the HS256 key stays on the control plane.
// Authentication of these credentials is the HTTPS authority's responsibility.
function readAgentTokenClaims(token: string): AgentTokenClaims | null {
	if (token.length > 8192) return null;
	const parts = token.split(".");
	if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) return null;
	try {
		const header = JSON.parse(Buffer.from(parts[0] ?? "", "base64url").toString("utf8"));
		const claims = JSON.parse(Buffer.from(parts[1] ?? "", "base64url").toString("utf8"));
		if (!header || header.alg !== "HS256" || header.typ !== "JWT" || !claims) return null;
		if (
			![claims.uid, claims.agent_id, claims.jti].every(
				(value) => typeof value === "string" && value.trim(),
			)
		)
			return null;
		if (
			!Number.isSafeInteger(claims.iat) ||
			!Number.isSafeInteger(claims.exp) ||
			claims.iat < 0 ||
			claims.exp <= claims.iat ||
			claims.exp - claims.iat > AGENT_TOKEN_MAX_TTL_SECONDS
		)
			return null;
		return claims as AgentTokenClaims;
	} catch {
		return null;
	}
}

function validAgentTokenNow(claims: AgentTokenClaims, nowMs: number): boolean {
	const now = Math.floor(nowMs / 1000);
	return claims.iat <= now + 300 && now < claims.exp;
}

/** Prefer an authenticated managed rotation over the same installation's older configured JWT. */
export function getEffectiveManagedApiKey(
	configuredApiKey: string | undefined,
	state: ManagedState,
	nowMs = Date.now(),
): string {
	const configured = typeof configuredApiKey === "string" ? configuredApiKey.trim() : "";
	const managed = typeof state.api_key === "string" ? state.api_key.trim() : "";
	if (!configured) return managed;
	const previous = readAgentTokenClaims(configured);
	const next = readAgentTokenClaims(managed);
	return previous &&
		next &&
		previous.uid === next.uid &&
		previous.agent_id === next.agent_id &&
		next.exp > previous.exp &&
		validAgentTokenNow(next, nowMs)
		? managed
		: configured;
}

export function managedTelemetryQueueNamespace(
	binding: ManagedState["telemetry_queue"],
	endpoint: string,
	authToken: string,
	iid: string,
): string {
	const namespace = createHash("sha256")
		.update(`${endpoint.replace(/\/+$/, "")}\0${authToken}\0${iid}`)
		.digest("hex");
	// Endpoint, credential or installation changes must retain their own queues.
	if (binding?.credential_namespace !== namespace) return namespace;
	if (
		typeof binding.anchor_namespace !== "string" ||
		!/^[a-f0-9]{64}$/.test(binding.anchor_namespace) ||
		binding.mac !== telemetryQueueBindingMac(binding, authToken)
	) {
		throw new Error("Invalid managed telemetry queue binding");
	}
	return binding.anchor_namespace;
}

function telemetryQueueBindingMac(
	binding: { credential_namespace: string; anchor_namespace: string },
	authToken: string,
): string {
	return createHmac("sha256", authToken)
		.update(`aidr-telemetry-queue-v1\0${binding.credential_namespace}\0${binding.anchor_namespace}`)
		.digest("hex");
}

/** Bounded renewal for sessions whose clean tool calls do not emit telemetry. */
export function shouldRefreshManagedEntitlement(
	state: ManagedState,
	authToken: string,
	nowMs = Date.now(),
): boolean {
	const lastAttempt = Date.parse(state.last_sync_attempt_at ?? "");
	if (Number.isFinite(lastAttempt) && lastAttempt <= nowMs && nowMs - lastAttempt < 5 * 60_000)
		return false;
	if (!isEntitlementActive(state, new Date(nowMs))) return true;
	const lastSuccess = Date.parse(state.last_success_at ?? state.entitlement?.issued_at ?? "");
	const claims = readAgentTokenClaims(authToken);
	return (
		!Number.isFinite(lastSuccess) ||
		lastSuccess > nowMs ||
		nowMs - lastSuccess >= 6 * 3_600_000 ||
		Boolean(claims && claims.exp * 1000 - nowMs <= 48 * 3_600_000)
	);
}

export function managedStatePath(): string {
	return resolvePath("~/.singularity-aidr/managed.json");
}

function entitlementKeyringPath(): string {
	return resolvePath("~/.singularity-aidr/entitlement.json");
}

function sha256Hex(input: string): string {
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

function signEntitlementSnapshot(snapshot: EntitlementSnapshotV1, authToken: string): string {
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

/**
 * Generic detached Ed25519 verification over `canonicalJson(value)`, trying every configured
 * key. Shared by signed policy envelopes so they use the entitlement signing wire format.
 */
export function verifyEd25519CanonicalJson(params: {
	value: unknown;
	sig_b64: string;
	public_keys_pem: string[];
}): boolean {
	const sig = parseSignatureBase64(params.sig_b64);
	if (!sig) return false;
	return verifyEd25519(
		Buffer.from(canonicalJson(params.value), "utf8"),
		sig,
		params.public_keys_pem,
	);
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

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: keep every outbound field check in one auditable privacy boundary
export function redactRemoteEvent(
	entry: Record<string, unknown>,
	mode: "none" | "hash" | "full" | undefined,
): Record<string, unknown> {
	// Always scrub credential material at the network boundary, including when
	// a caller explicitly chooses raw (`none`) mode. Hash/full then provide
	// stronger minimisation for production telemetry.
	const scrubbed = redactTelemetryData(entry);
	// Remote event producers are not a schema boundary. A new field can contain
	// arbitrary prompt or tool content under an innocuous key, so export only
	// the fields the ingest contract actually understands. The server repeats
	// this projection for clients that bypass the managed runtime.
	const safeEntry: Record<string, unknown> = {};
	const identifier = (value: unknown): string | undefined =>
		typeof value === "string" &&
		/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value) &&
		!/(?:^|[._:-])(?:api[_-]?key|access[_-]?token|authorization|bearer|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|client[_-]?secret|refresh[_-]?token|signature)(?:[._:-]|$)|^(?:sk[_-]|ghp_|github_pat_|xox[baprs]-|npm_|pypi-|AKIA)/i.test(
			value,
		) &&
		!/^(?:\d[.:-]?){8,15}$/.test(value)
			? value
			: undefined;
	const copyIdentifier = (key: string) => {
		const value = identifier(scrubbed[key]);
		if (value !== undefined) safeEntry[key] = value;
	};
	for (const key of [
		"event_id",
		"session_id",
		"incident_id",
		"tool_name",
		"source",
		"matched_threat_id",
		"plugin_key",
	])
		copyIdentifier(key);
	const copyEnum = (key: string, allowed: readonly string[]) => {
		if (typeof scrubbed[key] === "string" && allowed.includes(scrubbed[key])) {
			safeEntry[key] = scrubbed[key];
		}
	};
	copyEnum("type", [
		"runtime_verdict",
		"incident",
		"plugin_scan",
		"plugin_scan_finding",
		"runtime_policy_cache",
	]);
	for (const key of ["verdict", "decision"]) copyEnum(key, ["allow", "ask", "deny"]);
	copyEnum("severity", ["info", "warning", "high", "critical"]);
	copyEnum("status", ["open", "acknowledged", "contained", "resolved", "suppressed"]);
	if (typeof scrubbed.timestamp === "string" && scrubbed.timestamp.length <= 40) {
		const timestamp = Date.parse(scrubbed.timestamp);
		if (Number.isFinite(timestamp)) safeEntry.timestamp = new Date(timestamp).toISOString();
	}
	if (
		typeof scrubbed.findings_count === "number" &&
		Number.isInteger(scrubbed.findings_count) &&
		scrubbed.findings_count >= 0 &&
		scrubbed.findings_count <= 1_000_000
	) {
		safeEntry.findings_count = scrubbed.findings_count;
	}
	if (typeof scrubbed.user_override === "boolean") safeEntry.user_override = scrubbed.user_override;
	if (
		typeof scrubbed.duration_ms === "number" &&
		Number.isFinite(scrubbed.duration_ms) &&
		scrubbed.duration_ms >= 0
	) {
		safeEntry.duration_ms = scrubbed.duration_ms;
	}
	if (typeof scrubbed.tool_input_summary === "string")
		safeEntry.tool_input_summary = scrubbed.tool_input_summary;
	if (Array.isArray(scrubbed.artifacts)) safeEntry.artifacts = scrubbed.artifacts;
	if (Array.isArray(scrubbed.reasons)) safeEntry.reasons = scrubbed.reasons;
	if (Array.isArray(scrubbed.recommended_actions)) {
		safeEntry.recommended_actions = scrubbed.recommended_actions
			.slice(0, 16)
			.filter(
				(action): action is string =>
					typeof action === "string" &&
					["review", "investigate", "isolate", "revoke", "rotate_credentials", "notify"].includes(
						action,
					),
			);
	}
	const cache = scrubbed.runtime_policy_cache;
	if (cache && typeof cache === "object" && !Array.isArray(cache)) {
		const source = (cache as Record<string, unknown>).source;
		const version = identifier((cache as Record<string, unknown>).policy_version);
		const usable = (cache as Record<string, unknown>).usable;
		safeEntry.runtime_policy_cache = {
			...(typeof source === "string" &&
			["disabled", "missing", "valid", "expired", "mismatched", "invalid"].includes(source)
				? { source }
				: {}),
			...(version !== undefined ? { policy_version: version } : {}),
			...(typeof usable === "boolean" ? { usable } : {}),
		};
	}
	if (mode === "none") return safeEntry;
	const effectiveMode = mode ?? "hash";

	const summary =
		typeof safeEntry.tool_input_summary === "string" ? safeEntry.tool_input_summary : "";
	const artifacts = Array.isArray(safeEntry.artifacts) ? (safeEntry.artifacts as unknown[]) : [];
	const artifactStrings = artifacts.map((a) => (typeof a === "string" ? a : JSON.stringify(a)));

	if (effectiveMode === "full") {
		return { ...safeEntry, tool_input_summary: "", artifacts: [], reasons: [] };
	}

	return {
		...safeEntry,
		tool_input_summary: `sha256:${sha256Hex(summary)}`,
		artifacts: artifactStrings.map((a) => `sha256:${sha256Hex(a)}`),
		// Reasons may contain package/domain names or prompt snippets. Counts and
		// threat IDs are sufficient for remote triage without exporting content.
		reasons: [],
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
	if (typeof input !== "number" || !Number.isSafeInteger(input) || input < 0) return undefined;
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
	if (
		!Number.isSafeInteger(freeAgents + extraAgents) ||
		allowedAgents !== freeAgents + extraAgents
	) {
		return null;
	}
	if (Date.parse(issuedAt) > Date.parse(expiresAt)) return null;

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
	const issuedMs = Date.parse(issuedAt);
	const expiresMs = Date.parse(expiresAt);
	const graceMs = Date.parse(graceUntil);
	// A zero-hour grace is valid, but it cannot precede the online expiry.
	if (issuedMs > expiresMs || expiresMs > graceMs) return null;

	const includedAgents = parseNonNegIntStrict(obj.included_agents);
	const extraAgents = parseNonNegIntStrict(obj.extra_agents);
	const allowedAgents = parseNonNegIntStrict(obj.allowed_agents);
	const revEpoch = parseNonNegIntStrict(obj.revocation_epoch);
	if (includedAgents === undefined) return null;
	if (extraAgents === undefined) return null;
	if (allowedAgents === undefined) return null;
	if (revEpoch === undefined || revEpoch < 1) return null;
	if (
		!Number.isSafeInteger(includedAgents + extraAgents) ||
		allowedAgents !== includedAgents + extraAgents
	) {
		return null;
	}

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
			if (Date.parse(exp) > graceMs || Date.parse(exp) < issuedMs) return null;
			if (!/^(?:[A-Za-z0-9+/]{4}){10}[A-Za-z0-9+/]{3}=$/.test(keyB64)) return null;
			if (Buffer.from(keyB64, "base64").length !== 32) return null;
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
		revocation_epoch: revEpoch,
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
		secretStore?: SecretStore;
		source?: { raw: string | null };
	},
): Promise<ManagedState> {
	let credentialPresent = false;
	try {
		if (opts?.source?.raw === null) return {};
		const raw = opts?.source ? (opts.source.raw as string) : await getFileContent(path, "utf-8");
		const parsed = JSON.parse(raw) as ManagedState;
		if (!parsed || typeof parsed !== "object") return {};
		if (isCommercialBuild()) {
			credentialPresent = Boolean(parsed.api_key || parsed.api_key_ref);
			if (parsed.api_key && parsed.api_key_ref) {
				throw new Error("Managed credential has conflicting storage locations.");
			}
			if (parsed.api_key) {
				if (opts?.source) throw new Error("Captured credential requires prior vault migration.");
				// Migrate legacy plaintext only after the vault and reference are durable.
				await saveManagedState(path, parsed, opts?.secretStore);
				return loadManagedState(path, { ...opts, source: undefined });
			}
			if (parsed.api_key_ref) {
				const ref = parsed.api_key_ref;
				const store = opts?.secretStore ?? resolveSecretStore({ selection: ref.store });
				if (store.kind !== ref.store || store.location !== "os-vault") {
					throw new Error("Managed credential vault does not match its reference.");
				}
				const key = store.get(ref.id);
				if (!key) throw new Error("Managed credential is missing from its vault.");
				parsed.api_key = key;
			}
		}

		const dropEntitlement = (event: ManagedSecurityEvent): ManagedState => {
			emitManagedSecurityEvent(event, opts?.onSecurityEvent);
			return {
				...parsed,
				entitlement: undefined,
				entitlement_alg: undefined,
				entitlement_key_id: undefined,
				entitlement_sig: undefined,
			};
		};

		// A cached entitlement is usable only with its verified signature and a
		// valid schema. Old signed v2 snapshots with grace before expiry must be
		// refreshed by the control plane; their signed timestamps cannot be repaired locally.
		if (parsed.entitlement !== undefined) {
			if (typeof parsed.entitlement_sig !== "string" || !parsed.entitlement_sig.trim()) {
				return dropEntitlement({
					code: "missing_entitlement_signature",
					message: "Dropping cached entitlement without a signature.",
				});
			}
			if (parsed.entitlement_alg === "ed25519") {
				const validated =
					validateEntitlementSnapshotV2Strict(parsed.entitlement) ??
					validateEntitlementSnapshotV1Strict(parsed.entitlement);
				if (!validated) {
					return dropEntitlement({
						code: "invalid_ed25519_schema",
						message: "Dropping cached entitlement with an invalid signed snapshot schema.",
					});
				}
				const keys = opts?.publicKeysPem ?? [];
				if (
					keys.length === 0 ||
					!verifyEd25519SignedEntitlementSnapshot({
						snapshot: parsed.entitlement,
						sig_b64: parsed.entitlement_sig,
						public_keys_pem: keys,
					})
				) {
					return dropEntitlement({
						code: keys.length === 0 ? "missing_public_keys" : "invalid_ed25519_signature",
						message: "Dropping cached entitlement due to failed ed25519 verification.",
					});
				}
			} else if (parsed.entitlement_alg === "hmac-sha256") {
				const authToken = opts?.authToken;
				// HMAC entitlements are legacy v1 only.
				if (!validateEntitlementSnapshotV1Strict(parsed.entitlement)) {
					return dropEntitlement({
						code: "invalid_hmac_schema",
						message: "Dropping cached entitlement due to unexpected HMAC schema version.",
					});
				}
				if (
					!authToken ||
					!verifyEntitlementSnapshotSignature(
						parsed.entitlement as EntitlementSnapshotV1,
						parsed.entitlement_sig,
						authToken,
					)
				) {
					return dropEntitlement({
						code: "invalid_hmac_signature",
						message: "Dropping cached entitlement due to failed HMAC verification.",
					});
				}
			} else {
				return dropEntitlement({
					code: "invalid_entitlement_alg",
					message: "Dropping cached entitlement without a supported signature algorithm.",
				});
			}
		}

		return parsed;
	} catch (error) {
		if (isCommercialBuild() && credentialPresent) throw error;
		return {};
	}
}

export async function saveManagedState(
	path: string,
	state: ManagedState,
	secretStore?: SecretStore,
	options: { requirePersistence?: boolean } = {},
): Promise<void> {
	let created: { store: SecretStore; id: string } | undefined;
	let committed = false;
	try {
		const cleaned: ManagedState = { ...state };
		let previousRef: ManagedState["api_key_ref"];
		if (isCommercialBuild()) {
			try {
				const previous = JSON.parse(await getFileContent(path, "utf-8")) as ManagedState;
				previousRef = previous.api_key_ref;
			} catch {
				// No prior managed state.
			}
		}
		if (isCommercialBuild() && cleaned.api_key) {
			const existing = cleaned.api_key_ref;
			const store = secretStore ?? resolveSecretStore({ selection: existing?.store });
			if (store.location !== "os-vault" || (existing && existing.store !== store.kind)) {
				throw new Error("Managed credential requires a matching OS vault.");
			}
			const current = existing ? store.get(existing.id) : null;
			const ref =
				existing && current === cleaned.api_key
					? existing
					: {
							store: store.kind as PlatformSecretStoreKind,
							id: createSecretReferenceId(),
							created_at: new Date().toISOString(),
						};
			if (ref !== existing) {
				store.put(ref.id, cleaned.api_key);
				created = { store, id: ref.id };
			}
			cleaned.api_key_ref = ref;
			delete cleaned.api_key;
		}
		for (const key of Object.keys(cleaned) as (keyof ManagedState)[]) {
			if (cleaned[key] === undefined) delete cleaned[key];
		}
		await atomicWriteJson(path, cleaned);
		committed = true;
		if (previousRef && previousRef.id !== cleaned.api_key_ref?.id) {
			try {
				const oldStore =
					secretStore?.kind === previousRef.store
						? secretStore
						: resolveSecretStore({ selection: previousRef.store });
				oldStore.revoke(previousRef.id);
			} catch {
				console.warn(
					"Managed credential was replaced, but its old vault entry could not be removed.",
				);
			}
		}
	} catch (error) {
		if (!committed && created) {
			try {
				created.store.revoke(created.id);
			} catch {
				/* Unreferenced vault entry only. */
			}
		}
		if (isCommercialBuild() || options.requirePersistence) throw error;
		// Fail open
	}
}

/**
 * Writes a minimal keyring file used by encrypted intel packs.
 * This keeps the intel layer decoupled from managed state schema.
 */
async function clearManagedKeyring(path: string, revoked: boolean): Promise<void> {
	let previous: Record<string, unknown> | null = null;
	try {
		previous = JSON.parse(await getFileContent(path, "utf-8")) as Record<string, unknown>;
	} catch {
		// No previously issued keyring.
	}
	if (
		revoked ||
		previous?.managed === true ||
		(typeof previous?.tenant_id === "string" && typeof previous?.serial === "string")
	) {
		await atomicWriteJson(path, { managed: true, intel_keys: {}, revoked });
	}
}

function currentPackKeys(ent: EntitlementSnapshotV2): {
	keys: Record<string, string>;
	expiresAt: Record<string, string>;
} {
	const keys: Record<string, string> = {};
	const expiresAt: Record<string, string> = {};
	for (const key of ent.pack_keys ?? []) {
		const id = key.key_id.trim();
		const b64 = key.key_b64.trim();
		const expiry = Date.parse(key.expires_at);
		if (
			!id ||
			!b64 ||
			!Number.isFinite(expiry) ||
			expiry <= Date.now() ||
			expiry > Date.parse(ent.grace_until)
		)
			continue;
		keys[id] = b64;
		expiresAt[id] = key.expires_at;
	}
	return { keys, expiresAt };
}

export async function saveEntitlementKeyringFromState(state: ManagedState): Promise<void> {
	try {
		const ent = state.entitlement;
		const path = entitlementKeyringPath();
		const active =
			ent?.schema_version === 2 &&
			state.entitlement_alg === "ed25519" &&
			isEntitlementActive(state);
		if (!active) {
			// Revocation clears the in-memory entitlement. Replace any previously
			// issued managed keyring so a stale encrypted pack cannot reload it.
			await clearManagedKeyring(path, state.sync_disabled_reason === "revoked");
			return;
		}

		const packKeys = currentPackKeys(ent);

		await atomicWriteJson(path, {
			managed: true,
			intel_keys: packKeys.keys,
			key_expires_at: packKeys.expiresAt,
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

function addHoursIso(now: Date, hours: number): string {
	const safeHours = Number.isFinite(hours) ? Math.max(0, hours) : 0;
	return new Date(now.getTime() + safeHours * 60 * 60 * 1000).toISOString();
}

export function applyIngestResult(
	state: ManagedState,
	result: ControlPlaneIngestResult,
	gracePeriodHours: number,
	opts?: { authToken?: string; publicKeysPem?: string[]; endpoint?: string; iid?: string },
): ManagedState {
	const now = new Date();
	// An idempotent telemetry replay never contacted the control plane. It is
	// not a fresh entitlement response and must not replace a signed cache.
	if (result.ok && result.status === undefined && result.body?.telemetry_queue) return state;
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
		const rotatedKey = typeof result.body?.api_key === "string" ? result.body.api_key.trim() : "";
		const previousClaims = authToken ? readAgentTokenClaims(authToken) : null;
		const rotatedClaims = rotatedKey ? readAgentTokenClaims(rotatedKey) : null;
		const acceptRotation =
			result.status === 200 &&
			previousClaims &&
			rotatedClaims &&
			validAgentTokenNow(previousClaims, now.getTime()) &&
			validAgentTokenNow(rotatedClaims, now.getTime()) &&
			previousClaims.uid === rotatedClaims.uid &&
			previousClaims.agent_id === rotatedClaims.agent_id &&
			result.body?.agent_id === previousClaims.agent_id &&
			rotatedClaims.exp > previousClaims.exp &&
			entitlementAlg === "ed25519" &&
			entitlement?.schema_version === 2 &&
			entitlement.tenant_id === previousClaims.uid &&
			isEntitlementActive({ entitlement }, now);
		let telemetryQueue = state.telemetry_queue;
		if (acceptRotation && authToken && opts?.endpoint && opts.iid) {
			const binding = {
				credential_namespace: managedTelemetryQueueNamespace(
					undefined,
					opts.endpoint,
					rotatedKey,
					opts.iid,
				),
				anchor_namespace: managedTelemetryQueueNamespace(
					state.telemetry_queue,
					opts.endpoint,
					authToken,
					opts.iid,
				),
			};
			telemetryQueue = { ...binding, mac: telemetryQueueBindingMac(binding, rotatedKey) };
		}

		return {
			...state,
			...(acceptRotation ? { api_key: rotatedKey } : {}),
			telemetry_queue: telemetryQueue,
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
		result.status === 401 &&
		(result.error === "invalid_api_key" || result.body?.error === "invalid_api_key")
	) {
		// A definitive authentication rejection invalidates the local grant.
		// Transport failures retain the signed offline window, but a revoked or
		// malformed key must not continue to use it after the server rejects it.
		return {
			...state,
			api_key: state.api_key === opts?.authToken ? undefined : state.api_key,
			api_key_ref: state.api_key === opts?.authToken ? undefined : state.api_key_ref,
			seat_status: "unknown",
			sync_disabled_until: undefined,
			sync_disabled_reason: "invalid_api_key",
			entitlement: undefined,
			entitlement_alg: undefined,
			entitlement_key_id: undefined,
			entitlement_sig: undefined,
		};
	}

	const denial = typeof result.body?.error === "string" ? result.body.error : result.error;
	if (
		result.status === 403 &&
		[
			"tenant_access_denied",
			"tenant_not_admitted",
			"entitlement_not_provisioned",
			"agent_key_mismatch",
			"agent_not_authorized",
		].includes(denial ?? "")
	) {
		// A reachable authority explicitly denied this installation. Offline
		// grace applies to outages, not to an observed admission revocation.
		return {
			...state,
			seat_status: "unknown",
			sync_disabled_until: undefined,
			sync_disabled_reason: denial,
			entitlement: undefined,
			entitlement_alg: undefined,
			entitlement_key_id: undefined,
			entitlement_sig: undefined,
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
			entitlement: undefined,
			entitlement_alg: undefined,
			entitlement_key_id: undefined,
			entitlement_sig: undefined,
			// Retry within five minutes after a seat purchase or reassignment.
			sync_disabled_until: addHoursIso(now, 5 / 60),
		};
	}

	return state;
}

export function isEntitlementActive(state: ManagedState, now = new Date()): boolean {
	if (!state.entitlement) return false;
	if (state.sync_disabled_reason === "revoked") return false;
	const issued = Date.parse(state.entitlement.issued_at);
	const exp = Date.parse(state.entitlement.expires_at);
	if (!Number.isFinite(issued) || !Number.isFinite(exp) || now.getTime() < issued) return false;

	if (state.entitlement.schema_version === 2) {
		const grace = Date.parse(state.entitlement.grace_until);
		if (!Number.isFinite(grace) || grace < exp) return false;
		return now.getTime() < grace;
	}

	return now.getTime() < exp;
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
	const modules = state.entitlement.premium_modules;
	if (!Array.isArray(modules)) return false;
	// The server publishes premium_intel; intel_packs is the legacy client capability name.
	return (
		modules.includes(moduleId) ||
		(moduleId === "intel_packs" && modules.includes("premium_intel")) ||
		(moduleId === "premium_intel" && modules.includes("intel_packs"))
	);
}

export async function loadRevocationsCache(
	path: string,
	publicKeysPem: string[],
	now = Date.now(),
	source?: { raw: string | null },
): Promise<SignedEd25519<RevocationListV1> | null> {
	try {
		if (source?.raw === null) return null;
		const raw = source ? (source.raw as string) : await getFileContent(path, "utf-8");
		const parsed = JSON.parse(raw) as SignedEd25519<RevocationListV1>;
		if (!parsed || typeof parsed !== "object") return null;
		if (parsed.alg !== "ed25519") return null;
		if (typeof parsed.sig_b64 !== "string") return null;
		const list = validateRevocationListV1Strict(parsed.payload);
		if (!list) return null;
		if (!isRevocationListCurrent(list, now)) return null;

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

function isRevocationListCurrent(list: RevocationListV1, now: number): boolean {
	return Date.parse(list.issued_at) <= now && now < Date.parse(list.expires_at);
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
	now = Date.now(),
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
	if (!list || !isRevocationListCurrent(list, now)) return null;

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
