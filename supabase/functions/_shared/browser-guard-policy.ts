// Signed Browser Guard policy document (docs/ai-governance.md, packages/browser-guard/README.md).
//
// Shadow AI allow/block decisions are AI governance register entries (`ai_assets`,
// asset_type `ai_site`, identifier = Browser Guard catalog id): `banned` blocks the
// service and `approved` sanctions it. The `ai_governance_policy_overlay` RPC already
// resolves bans against approved, unexpired exceptions; it reports the result as
// `browser_guard_shadow_ai`. This module turns that into the document the
// `browser-guard-policy` Edge Function signs with the runtime-policy Ed25519 key.
//
// Wire contract (verified by packages/browser-guard/src/background/dashboard-policy.ts):
//
//   { policy_version: "browser-guard/v1", policy_sha256, browser_guard: { shadow_ai: { blocked, sanctioned } },
//     policy_signed: { alg: "ed25519", key_id, sig_b64, envelope }, cache_seconds }
//
// `policy_sha256` is SHA-256 over `canonicalPolicy(browser_guard)` and is bound, with
// `policy_version`, the tenant and a monotonic sequence, inside the signed envelope.
// The document can only tighten what a browser enforces: Browser Guard merges it under
// its enterprise-managed policy with "most restrictive wins".

/** Fixed version label: domain-separates this envelope from runtime-policy envelopes. */
export const BROWSER_GUARD_POLICY_VERSION = "browser-guard/v1";
/** Same pattern as the Browser Guard catalog id (AI_SERVICE_ID_PATTERN). */
export const SHADOW_AI_SERVICE_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** Upper bound per list; Browser Guard refuses a larger document as a whole. */
const SHADOW_AI_DECISIONS_MAX = 500;

interface BrowserGuardShadowAi {
	blocked: string[];
	sanctioned: string[];
}

export interface BrowserGuardPolicyDocument {
	shadow_ai: BrowserGuardShadowAi;
}

function idList(value: unknown): string[] {
	if (!Array.isArray(value) || value.length > SHADOW_AI_DECISIONS_MAX ||
		!value.every((item) => typeof item === "string" && SHADOW_AI_SERVICE_ID.test(item))) {
		throw new Error("invalid_browser_guard_policy");
	}
	return [...new Set(value as string[])].sort();
}

/**
 * Build the document from the overlay RPC result. Anything malformed is refused, never
 * trimmed: serving a partial block list would silently relax enforcement. A service that
 * is somehow both blocked and sanctioned stays blocked only (most restrictive wins).
 */
export function browserGuardPolicyFromOverlay(overlay: unknown): BrowserGuardPolicyDocument {
	if (!overlay || typeof overlay !== "object" || Array.isArray(overlay)) throw new Error("invalid_browser_guard_policy");
	const shadow = (overlay as Record<string, unknown>).browser_guard_shadow_ai;
	if (!shadow || typeof shadow !== "object" || Array.isArray(shadow)) throw new Error("invalid_browser_guard_policy");
	const record = shadow as Record<string, unknown>;
	const blocked = idList(record.blocked);
	const blockedSet = new Set(blocked);
	const sanctioned = idList(record.sanctioned).filter((id) => !blockedSet.has(id));
	return { shadow_ai: { blocked, sanctioned } };
}
