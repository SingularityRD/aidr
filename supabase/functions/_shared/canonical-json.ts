// The one canonical JSON form of the control-plane signing contract, on the signer side:
// signed entitlements (enroll, ingest), the runtime-policy envelope and every digest it
// binds (`policy_sha256`, `governance_sha256`, `detection_exceptions_sha256`).
//
// Edge Functions are deployed independently of the workspace packages and cannot import
// packages/core, so this is the server copy of `canonicalPolicyJson` in
// packages/core/src/policy-canonical-json.ts (the connector verifier). Both copies are
// checked against docs/contracts/policy-canonical-json-vectors.json, so a drift fails a
// test instead of a signature: keys sorted by UTF-16 code unit, objects rebuilt with
// `Object.fromEntries` (a `"__proto__"` key stays an ordinary key) and serialised by
// `JSON.stringify`, which emits integer-like keys first in numeric order.

function sortKeys(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(sortKeys);
	if (!value || typeof value !== "object") return value;
	const record = value as Record<string, unknown>;
	return Object.fromEntries(Object.keys(record).sort().map((key) => [key, sortKeys(record[key])]));
}

export function canonicalJson(value: unknown): string {
	return JSON.stringify(sortKeys(value)) ?? "null";
}
