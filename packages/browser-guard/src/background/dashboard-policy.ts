/**
 * Shadow AI decisions made in the AIDR dashboard, delivered as a signed policy document.
 *
 * Owners and administrators allow (`approved`) or block (`banned`) a detected AI service in
 * the dashboard; the decision is an AI governance register entry. Enrolled installs fetch
 * `GET {controlPlaneUrl}/functions/v1/browser-guard-policy` with their telemetry key on
 * every refresh (startup, managed-policy change, and the DASHBOARD_POLICY_ALARM period):
 *
 *   { policy_version: "browser-guard/v1", policy_sha256,
 *     browser_guard: { shadow_ai: { blocked: [ids], sanctioned: [ids] },
 *                      require_native_ner?: boolean },
 *     policy_signed: { alg: "ed25519", key_id, sig_b64, envelope }, cache_seconds }
 *
 * `require_native_ner` (optional; the control plane sends it only when true) is the
 * tenant's "require native NER" setting. It has the meaning of the managed
 * `requireNativeNer` key and is merged with it the same way: true wins, so the dashboard
 * can switch the requirement on but never off where the enterprise policy set it.
 *
 * The envelope is the connectors' signed runtime-policy envelope
 * (supabase/functions/_shared/policy-signature.ts): an Ed25519 signature over the
 * key-sorted JSON of { schema_version, key_id, policy_version, policy_sha256, sequence,
 * issued_at, expires_at, tenant_id }. A document is applied only when
 *   - the signature verifies against a key in the managed `dashboardPolicy.publicKeysPem`
 *     (an administrator-only setting: a user cannot add a key),
 *   - `policy_sha256` is the SHA-256 of the canonical `browser_guard` object and both it and
 *     `policy_version` match the signed envelope (a tampered list or flag is refused). The
 *     canonical form is the control plane's one canonical JSON
 *     (packages/core/src/policy-canonical-json.ts, pinned by
 *     docs/contracts/policy-canonical-json-vectors.json),
 *   - the tenant matches `dashboardPolicy.tenantId` when one is pinned,
 *   - the validity window holds and the sequence is not lower than the highest one already
 *     accepted (a replayed older document is refused).
 * Anything else is ignored and the last verified document stays in force.
 *
 * Precedence (most restrictive wins): the dashboard can add blocks and sanctions on top of
 * the enterprise policy (`shadowAi` from chrome.storage.managed), never relax it. A
 * dashboard block applies in every mode; a dashboard "allow" only marks a service as
 * sanctioned when the enterprise policy does not block it (an MDM `blocked` id, or an
 * unsanctioned service under an MDM `block-unsanctioned` mode, stays blocked). Once the
 * signed document expires without a successful refresh its blocks stay in force and its
 * sanctions are dropped. `require_native_ner: true` tightens like a block: it applies in every
 * mode, forces the native bridge on (`useNativeHost`) and stays in force after expiry.
 */
import { canonicalPolicyJson } from "../../../core/src/policy-canonical-json.js";
import type { DashboardPolicyTrust, GuardPolicy, ShadowAiPolicy } from "../types.js";
import { ed25519SpkiFromPem } from "./policy.js";
import { blockedServices } from "./shadow-ai.js";
import type { GuardStorage } from "./storage.js";

export const DASHBOARD_POLICY_VERSION = "browser-guard/v1";
export const DASHBOARD_POLICY_ALARM = "aidr-dashboard-policy";
export const DASHBOARD_POLICY_LIMITS = Object.freeze({
	refreshMinutes: 15,
	fetchTimeoutMs: 15_000,
	maxResponseBytes: 64 * 1024,
	maxIds: 500,
	maxClockSkewMs: 5 * 60_000,
	maxValidityMs: 30 * 24 * 3_600_000,
});
/** storage.local keys (see ./storage.ts). */
export const DASHBOARD_STORAGE_KEYS = Object.freeze({
	document: "dashboardPolicy",
	highWater: "dashboardPolicyHighWater",
});

const SERVICE_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const KEY_ID = /^[\x21-\x7e]{1,128}$/;

export interface DashboardShadowAi {
	readonly blocked: readonly string[];
	readonly sanctioned: readonly string[];
}

export interface VerifiedDashboardPolicy {
	readonly shadowAi: DashboardShadowAi;
	/** `browser_guard.require_native_ner`; absent in the document means false. */
	readonly requireNativeNer: boolean;
	readonly sequence: number;
	readonly policySha256: string;
	readonly expiresAt: number;
	readonly tenantId: string;
	readonly keyId: string;
}

type DashboardPolicyFailure =
	| "malformed"
	| "digest_mismatch"
	| "no_trusted_keys"
	| "bad_signature"
	| "binding_mismatch"
	| "tenant_mismatch"
	| "not_yet_valid"
	| "expired"
	| "rollback";

export type DashboardPolicyResult =
	| { readonly ok: true; readonly policy: VerifiedDashboardPolicy }
	| { readonly ok: false; readonly reason: DashboardPolicyFailure };

interface HighWater {
	readonly sequence: number;
	readonly policySha256: string;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
	return raw !== null && typeof raw === "object" && !Array.isArray(raw);
}

const exactKeys = (raw: Record<string, unknown>, keys: readonly string[]) =>
	Object.keys(raw).length === keys.length && keys.every((k) => Object.hasOwn(raw, k));

/** `raw` has every `required` key and nothing outside `required` + `optional`. */
const allowedKeys = (
	raw: Record<string, unknown>,
	required: readonly string[],
	optional: readonly string[],
) =>
	required.every((k) => Object.hasOwn(raw, k)) &&
	Object.keys(raw).every((k) => required.includes(k) || optional.includes(k));

/**
 * The control plane's one canonical JSON (signer: supabase/functions/_shared/canonical-json.ts;
 * this is the connectors' verifier copy, checked against
 * docs/contracts/policy-canonical-json-vectors.json).
 */
export const canonicalJson: (value: unknown) => string = canonicalPolicyJson;

async function sha256Hex(text: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function idList(raw: unknown): string[] | null {
	if (!Array.isArray(raw) || raw.length > DASHBOARD_POLICY_LIMITS.maxIds) return null;
	if (!raw.every((id) => typeof id === "string" && SERVICE_ID.test(id))) return null;
	return [...new Set(raw as string[])];
}

interface DashboardDocument {
	readonly shadowAi: DashboardShadowAi;
	readonly requireNativeNer: boolean;
}

/**
 * The `browser_guard` object: `{ shadow_ai: { blocked, sanctioned }, require_native_ner? }`.
 * Any other key, or a `require_native_ner` that is not a boolean, refuses the document.
 */
function documentOf(raw: unknown): DashboardDocument | null {
	if (!isRecord(raw) || !allowedKeys(raw, ["shadow_ai"], ["require_native_ner"])) return null;
	const requireNativeNer = Object.hasOwn(raw, "require_native_ner")
		? raw.require_native_ner
		: false;
	if (typeof requireNativeNer !== "boolean") return null;
	const shadow = raw.shadow_ai;
	if (!isRecord(shadow) || !exactKeys(shadow, ["blocked", "sanctioned"])) return null;
	const blocked = idList(shadow.blocked);
	const sanctioned = idList(shadow.sanctioned);
	if (!blocked || !sanctioned) return null;
	// Deny wins inside the document too.
	return {
		shadowAi: { blocked, sanctioned: sanctioned.filter((id) => !blocked.includes(id)) },
		requireNativeNer,
	};
}

interface Envelope {
	schema_version: 1;
	key_id: string;
	policy_version: string;
	policy_sha256: string;
	sequence: number;
	issued_at: string;
	expires_at: string;
	tenant_id: string;
}

const ENVELOPE_KEYS = [
	"schema_version",
	"key_id",
	"policy_version",
	"policy_sha256",
	"sequence",
	"issued_at",
	"expires_at",
	"tenant_id",
];

function envelopeOf(raw: unknown): Envelope | null {
	if (!isRecord(raw) || !exactKeys(raw, ENVELOPE_KEYS) || raw.schema_version !== 1) return null;
	const { key_id, policy_version, policy_sha256, sequence, issued_at, expires_at, tenant_id } = raw;
	if (typeof key_id !== "string" || !KEY_ID.test(key_id)) return null;
	if (typeof policy_version !== "string" || typeof tenant_id !== "string") return null;
	if (typeof policy_sha256 !== "string" || !SHA256_HEX.test(policy_sha256)) return null;
	if (!Number.isSafeInteger(sequence) || (sequence as number) < 1) return null;
	for (const stamp of [issued_at, expires_at]) {
		if (typeof stamp !== "string" || !ISO_DATE.test(stamp) || !Number.isFinite(Date.parse(stamp)))
			return null;
	}
	return raw as unknown as Envelope;
}

function base64Bytes(raw: string): Uint8Array<ArrayBuffer> | null {
	if (raw.length === 0 || raw.length > 256 || raw.length % 4 !== 0 || !BASE64.test(raw))
		return null;
	try {
		return Uint8Array.from(atob(raw), (c) => c.charCodeAt(0));
	} catch {
		return null;
	}
}

async function signatureValid(
	envelope: Envelope,
	signature: Uint8Array<ArrayBuffer>,
	publicKeysPem: readonly string[],
): Promise<boolean> {
	const message = new TextEncoder().encode(canonicalJson(envelope));
	for (const pem of publicKeysPem) {
		const der = ed25519SpkiFromPem(pem);
		if (!der) continue;
		try {
			const key = await crypto.subtle.importKey("spki", der, { name: "Ed25519" }, false, [
				"verify",
			]);
			if (await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message)) return true;
		} catch {
			// A browser without Ed25519 WebCrypto cannot verify: the document is refused.
		}
	}
	return false;
}

interface ParsedBody {
	readonly parsed: DashboardDocument;
	readonly document: unknown;
	readonly policySha256: string;
	readonly envelope: Envelope;
	readonly signature: Uint8Array<ArrayBuffer>;
}

/** Shape checks only (nothing here is trusted yet). */
function parseBody(body: unknown): ParsedBody | null {
	if (!isRecord(body) || body.policy_version !== DASHBOARD_POLICY_VERSION) return null;
	const parsed = documentOf(body.browser_guard);
	const signed = body.policy_signed;
	if (!parsed || typeof body.policy_sha256 !== "string" || !isRecord(signed)) return null;
	if (signed.alg !== "ed25519" || typeof signed.sig_b64 !== "string") return null;
	const envelope = envelopeOf(signed.envelope);
	const signature = base64Bytes(signed.sig_b64);
	if (!envelope || !signature || signed.key_id !== envelope.key_id) return null;
	return {
		parsed,
		document: body.browser_guard,
		policySha256: body.policy_sha256,
		envelope,
		signature,
	};
}

interface VerifyOptions {
	readonly trust: DashboardPolicyTrust;
	readonly now: number;
	readonly highWater?: HighWater | null;
	readonly acceptExpired?: boolean;
}

/** Checks on an authentic envelope: binding, tenant, validity window and anti-rollback. */
function envelopeFailure(
	parsed: ParsedBody,
	options: VerifyOptions,
): DashboardPolicyFailure | null {
	const { envelope } = parsed;
	if (
		envelope.policy_sha256 !== parsed.policySha256 ||
		envelope.policy_version !== DASHBOARD_POLICY_VERSION
	)
		return "binding_mismatch";
	if (options.trust.tenantId !== null && envelope.tenant_id !== options.trust.tenantId)
		return "tenant_mismatch";
	const issuedAt = Date.parse(envelope.issued_at);
	const expiresAt = Date.parse(envelope.expires_at);
	if (expiresAt < issuedAt || expiresAt - issuedAt > DASHBOARD_POLICY_LIMITS.maxValidityMs)
		return "malformed";
	if (issuedAt > options.now + DASHBOARD_POLICY_LIMITS.maxClockSkewMs) return "not_yet_valid";
	if (!options.acceptExpired && options.now >= expiresAt) return "expired";
	const high = options.highWater;
	if (!high) return null;
	if (envelope.sequence < high.sequence) return "rollback";
	if (envelope.sequence === high.sequence && envelope.policy_sha256 !== high.policySha256)
		return "rollback";
	return null;
}

/**
 * Verifies one response body. `highWater` is the highest accepted document (omit it when
 * re-checking a stored document); `acceptExpired` lets a stored document past its expiry
 * be re-verified so its blocks can stay in force.
 */
export async function verifyDashboardPolicy(
	body: unknown,
	options: VerifyOptions,
): Promise<DashboardPolicyResult> {
	const fail = (reason: DashboardPolicyFailure) => ({ ok: false as const, reason });
	if (options.trust.publicKeysPem.length === 0) return fail("no_trusted_keys");
	const parsed = parseBody(body);
	if (!parsed) return fail("malformed");
	// The digest covers the document exactly as received (before de-duplication).
	if ((await sha256Hex(canonicalJson(parsed.document))) !== parsed.policySha256)
		return fail("digest_mismatch");
	if (!(await signatureValid(parsed.envelope, parsed.signature, options.trust.publicKeysPem)))
		return fail("bad_signature");
	// Authentic from here on: bind it to what was received.
	const failure = envelopeFailure(parsed, options);
	if (failure) return fail(failure);
	const { envelope } = parsed;
	return {
		ok: true,
		policy: {
			shadowAi: parsed.parsed.shadowAi,
			requireNativeNer: parsed.parsed.requireNativeNer,
			sequence: envelope.sequence,
			policySha256: envelope.policy_sha256,
			expiresAt: Date.parse(envelope.expires_at),
			tenantId: envelope.tenant_id,
			keyId: envelope.key_id,
		},
	};
}

/**
 * Effective Shadow AI policy: the enterprise policy plus the dashboard decisions, most
 * restrictive wins. `expired` drops the dashboard's sanctions and keeps its blocks.
 */
export function mergeDashboardShadowAi(
	local: ShadowAiPolicy,
	dashboard: DashboardShadowAi,
	expired: boolean,
): ShadowAiPolicy {
	const blocked = [...new Set([...local.blocked, ...dashboard.blocked])];
	// What the enterprise policy blocks on its own can never be sanctioned by the dashboard.
	const locallyBlocked = new Set([...local.blocked, ...blockedServices(local).map((s) => s.id)]);
	const added = expired
		? []
		: dashboard.sanctioned.filter((id) => !locallyBlocked.has(id) && !blocked.includes(id));
	const sanctioned = [...new Set([...local.sanctioned, ...added])];
	return Object.freeze({
		mode: local.mode,
		sanctioned: Object.freeze(sanctioned),
		blocked: Object.freeze(blocked),
	});
}

function readHighWater(raw: unknown): HighWater | null {
	if (!isRecord(raw)) return null;
	const { sequence, policySha256 } = raw;
	if (!Number.isSafeInteger(sequence) || (sequence as number) < 1) return null;
	if (typeof policySha256 !== "string" || !SHA256_HEX.test(policySha256)) return null;
	return { sequence: sequence as number, policySha256 };
}

/**
 * Fetches, verifies and stores the dashboard document, and re-verifies the stored one for
 * each policy load. Storage holds the raw signed body (never trusted without re-checking)
 * and the high-water mark (kept even when the document is dropped).
 */
export class DashboardPolicyClient {
	constructor(
		private readonly deps: {
			readonly storage: GuardStorage;
			readonly fetch: typeof fetch;
			readonly now: () => number;
			readonly log: (message: string) => void;
		},
	) {}

	/** The stored document re-verified against `trust`, or null. */
	async stored(
		trust: DashboardPolicyTrust,
	): Promise<{ policy: VerifiedDashboardPolicy; expired: boolean } | null> {
		const body = await this.deps.storage.getLocal(DASHBOARD_STORAGE_KEYS.document);
		if (body === undefined || body === null) return null;
		const now = this.deps.now();
		const result = await verifyDashboardPolicy(body, { trust, now, acceptExpired: true });
		if (!result.ok) {
			this.deps.log(`dashboard policy: stored document ignored (${result.reason})`);
			return null;
		}
		return { policy: result.policy, expired: now >= result.policy.expiresAt };
	}

	/**
	 * One refresh. Returns true when a new verified document was stored (the caller then
	 * reloads the effective policy); false leaves the stored document in force.
	 */
	async refresh(
		trust: DashboardPolicyTrust,
		endpoint: { readonly controlPlaneUrl: string; readonly apiKey: string },
	): Promise<boolean> {
		const body = await this.download(endpoint);
		if (body === null) return false;
		const highWater = readHighWater(
			await this.deps.storage.getLocal(DASHBOARD_STORAGE_KEYS.highWater),
		);
		const result = await verifyDashboardPolicy(body, {
			trust,
			now: this.deps.now(),
			highWater,
		});
		if (!result.ok) {
			this.deps.log(`dashboard policy: document refused (${result.reason})`);
			return false;
		}
		// High-water first: a crash between the writes must never re-admit an older document.
		const stored =
			(await this.deps.storage.setLocal(DASHBOARD_STORAGE_KEYS.highWater, {
				sequence: result.policy.sequence,
				policySha256: result.policy.policySha256,
			})) && (await this.deps.storage.setLocal(DASHBOARD_STORAGE_KEYS.document, body));
		if (!stored) this.deps.log("dashboard policy: could not store the verified document");
		return stored;
	}

	private async download(endpoint: {
		readonly controlPlaneUrl: string;
		readonly apiKey: string;
	}): Promise<unknown> {
		const url = `${endpoint.controlPlaneUrl.replace(/\/+$/, "")}/functions/v1/browser-guard-policy`;
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), DASHBOARD_POLICY_LIMITS.fetchTimeoutMs);
		try {
			const response = await this.deps.fetch(url, {
				method: "GET",
				headers: { Authorization: `Bearer ${endpoint.apiKey}`, Accept: "application/json" },
				cache: "no-store",
				credentials: "omit",
				redirect: "error",
				signal: controller.signal,
			});
			if (!response.ok) {
				this.deps.log(`dashboard policy: refresh failed (HTTP ${response.status})`);
				return null;
			}
			const text = await response.text();
			if (text.length > DASHBOARD_POLICY_LIMITS.maxResponseBytes) {
				this.deps.log("dashboard policy: response too large");
				return null;
			}
			return JSON.parse(text);
		} catch {
			this.deps.log("dashboard policy: refresh failed");
			return null;
		} finally {
			clearTimeout(timer);
		}
	}
}

/**
 * Applies the verified dashboard document to an evaluated policy (frozen copy): its Shadow
 * AI decisions (see mergeDashboardShadowAi) and `require_native_ner`. The stricter
 * `requireNativeNer` wins (true from either side), even after the document expired; like
 * the managed key, it forces `useNativeHost` on and both keys are reported as locked.
 */
export function withDashboardPolicy(
	policy: GuardPolicy,
	dashboard: { policy: VerifiedDashboardPolicy; expired: boolean } | null,
): GuardPolicy {
	if (!dashboard) return policy;
	const requireNativeNer = dashboard.policy.requireNativeNer && policy.requireNativeNer !== true;
	const lockedKeys = requireNativeNer
		? ["requireNativeNer", "useNativeHost"].filter((key) => !policy.managedKeys.includes(key))
		: [];
	return Object.freeze({
		...policy,
		shadowAi: mergeDashboardShadowAi(policy.shadowAi, dashboard.policy.shadowAi, dashboard.expired),
		...(requireNativeNer
			? {
					requireNativeNer: true,
					useNativeHost: true,
					managedKeys: Object.freeze([...policy.managedKeys, ...lockedKeys]),
				}
			: {}),
	});
}
