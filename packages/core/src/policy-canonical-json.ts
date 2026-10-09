/**
 * The one canonical JSON form of the control-plane signing contract: signed
 * entitlements, revocation lists and runtime-policy envelopes, and the
 * `policy_sha256`, `governance_sha256` and `detection_exceptions_sha256`
 * digests the signed envelope binds.
 *
 * Every object is rebuilt with its keys sorted by UTF-16 code unit and the
 * result is passed to `JSON.stringify`. That is byte for byte what the signer
 * produces (`canonicalJson` in supabase/functions/_shared/policy-signature.ts
 * and `canonicalPolicy` in supabase/functions/_shared/runtime-policy.ts, which
 * cannot import this package), so it inherits two `JSON.stringify` rules that a
 * hand-rolled serializer easily gets wrong:
 *
 *   - integer-like keys (`"9"`, `"10"`) are emitted first in ascending numeric
 *     order, because a rebuilt object enumerates them that way, and only then
 *     the remaining keys in sorted order;
 *   - a key whose value is `undefined`, a function or a symbol is omitted, and
 *     such a value inside an array is written as `null`.
 *
 * Objects are rebuilt with `Object.fromEntries`, so a `"__proto__"` key from
 * parsed JSON stays an ordinary key instead of being dropped by an assignment.
 *
 * Signer and verifier both check docs/contracts/policy-canonical-json-vectors.json,
 * so any drift between the two copies fails a test instead of a signature.
 */
export function canonicalPolicyJson(value: unknown): string {
	return JSON.stringify(sortKeys(value)) ?? "null";
}

function sortKeys(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(sortKeys);
	if (!value || typeof value !== "object") return value;
	const record = value as Record<string, unknown>;
	return Object.fromEntries(
		Object.keys(record)
			.sort()
			.map((key) => [key, sortKeys(record[key])]),
	);
}
