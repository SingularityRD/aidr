// Tenant-bound OIDC client secret resolution.
//
// A provider row names its secret only by a short reference (`client_secret_ref`)
// that the tenant owner types. That reference is NOT an authorization: an owner
// could otherwise type another tenant's reference, point the provider at an
// issuer they control and make this server POST the other tenant's secret to
// their token endpoint. A secret is therefore released only when the operator
// has bound that reference to the caller's tenant and issuer (and, optionally,
// client id) in AIDR_OIDC_CLIENT_SECRET_BINDINGS:
//
//   AIDR_OIDC_CLIENT_SECRET_BINDINGS = {
//     "CONTOSO": { "tenant_id": "<tenant uuid>", "issuer": "https://login.microsoftonline.com/<dir>/v2.0",
//                  "client_id": "<optional client id>" }
//   }
//   AIDR_OIDC_CLIENT_SECRET_CONTOSO = <secret value>
//
// Anything unbound, mismatched or malformed resolves to null ("not configured"),
// the same answer as a reference with no secret at all, so the answer reveals
// nothing about other tenants' references. Fail closed: a malformed bindings
// document binds nothing.

import { normalizeIssuer } from "./oidc.ts";

export const CLIENT_SECRET_BINDINGS_ENV = "AIDR_OIDC_CLIENT_SECRET_BINDINGS";
export const CLIENT_SECRET_ENV_PREFIX = "AIDR_OIDC_CLIENT_SECRET_";

const REF = /^[A-Z0-9_]{1,40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_BINDINGS_BYTES = 64 * 1024;

/** What the server knows about the provider asking for its secret (all from the stored row). */
export interface ClientSecretRequest {
	tenantId: string;
	issuer: string;
	clientId: string;
	ref: string;
}

interface Binding {
	tenantId: string;
	issuer: string;
	clientId: string | null;
}

function parseBindings(raw: string | undefined): ReadonlyMap<string, Binding> {
	const bindings = new Map<string, Binding>();
	if (!raw || raw.length > MAX_BINDINGS_BYTES) return bindings;
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return bindings;
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return bindings;
	for (const [ref, value] of Object.entries(parsed as Record<string, unknown>)) {
		if (!REF.test(ref) || ref === "BINDINGS" || !value || typeof value !== "object" || Array.isArray(value)) continue;
		const entry = value as Record<string, unknown>;
		const tenantId = typeof entry.tenant_id === "string" ? entry.tenant_id.toLowerCase() : "";
		const issuer = normalizeIssuer(entry.issuer);
		const clientId = entry.client_id === undefined ? null : entry.client_id;
		if (!UUID.test(tenantId) || !issuer) continue;
		if (clientId !== null && (typeof clientId !== "string" || clientId.length === 0)) continue;
		bindings.set(ref, { tenantId, issuer, clientId: clientId as string | null });
	}
	return bindings;
}

/**
 * The client secret for this provider, or null unless the operator bound `ref`
 * to exactly this tenant and issuer (and client id, when the binding names one).
 */
export function resolveClientSecret(
	readEnv: (name: string) => string | undefined,
	request: ClientSecretRequest,
): string | null {
	// "BINDINGS" would name the bindings document itself, never a secret.
	if (!REF.test(request.ref) || request.ref === "BINDINGS") return null;
	const binding = parseBindings(readEnv(CLIENT_SECRET_BINDINGS_ENV)).get(request.ref);
	if (!binding) return null;
	if (binding.tenantId !== request.tenantId.toLowerCase()) return null;
	if (binding.issuer !== request.issuer) return null;
	if (binding.clientId !== null && binding.clientId !== request.clientId) return null;
	const value = readEnv(`${CLIENT_SECRET_ENV_PREFIX}${request.ref}`);
	return value && value.trim() !== "" ? value : null;
}
