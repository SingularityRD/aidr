/**
 * Which HTTP request headers the SDK inspects, and which it withholds.
 *
 * Header values reach backends (custom command/query headers, `X-Forwarded-*`,
 * `Referer`), so the Express/Next.js helpers inspect them like the body.
 * Credential-bearing headers are the exception: their values are opaque
 * secrets, never commands or URLs, and running the secret-detection rules over
 * them would block every authenticated request. They are therefore neither
 * inspected nor copied into `CheckRequest.context` — so they never reach
 * decision events, `.use()` callbacks or logs.
 */

/** Header names that always carry credentials or session state. */
export const CREDENTIAL_HEADER_NAMES: readonly string[] = Object.freeze([
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"api-key",
	"x-auth-token",
	"x-access-token",
	"x-refresh-token",
	"x-id-token",
	"x-csrf-token",
	"x-xsrf-token",
	"x-amz-security-token",
	"x-goog-api-key",
]);

/**
 * Any header whose name names a credential (`x-myapp-token`,
 * `x-session-id`, `x-hub-signature-256`, …) is withheld too.
 */
const CREDENTIAL_NAME_RE =
	/(?:auth|token|secret|passw(?:or)?d|api[-_]?key|cookie|session|signature|credential|bearer|jwt)/i;

/** Largest serialized header set inspected; a larger one is denied as not fully inspected. */
export const MAX_INSPECTED_HEADER_CHARS = 64 * 1024;

export type IncomingHeaderValue = string | readonly string[] | number | undefined;

/** True when the header's value must be withheld from inspection and from the check context. */
export function isCredentialHeader(name: string, extra: readonly string[] = []): boolean {
	const lower = name.trim().toLowerCase();
	return (
		CREDENTIAL_HEADER_NAMES.includes(lower) ||
		extra.some((item) => item.trim().toLowerCase() === lower) ||
		CREDENTIAL_NAME_RE.test(lower)
	);
}

export interface PartitionedHeaders {
	/** Non-credential headers, lower-cased names, multi-values joined with `, `. */
	inspected: Record<string, string>;
	/** Names (only) of the credential headers that were withheld. */
	withheld: string[];
}

/** Split request headers into the inspected set and the withheld credential names. */
export function partitionHeaders(
	headers: Record<string, IncomingHeaderValue> | undefined,
	extraSensitive: readonly string[] = [],
): PartitionedHeaders {
	const inspected: Record<string, string> = {};
	const withheld: string[] = [];
	for (const [rawName, rawValue] of Object.entries(headers ?? {})) {
		if (rawValue === undefined) continue;
		const name = rawName.toLowerCase();
		if (isCredentialHeader(name, extraSensitive)) {
			withheld.push(name);
			continue;
		}
		inspected[name] = Array.isArray(rawValue) ? rawValue.join(", ") : String(rawValue);
	}
	return { inspected, withheld: withheld.sort() };
}
