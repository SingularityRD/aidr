import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson as sharedCorsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import {
	matchesDelegatedContext,
	signDelegatedCredential,
	verifyDelegatedCredentialForBroker,
} from "../_shared/delegated-credential.ts";

const REQUIRED_ENV = [
	"SUPABASE_URL",
	"SUPABASE_SERVICE_ROLE_KEY",
	"AIDR_DELEGATION_ISSUER",
	"AIDR_DELEGATION_SIGNING_KEY_ID",
	"AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64",
	"AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64",
] as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const SCOPE = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;

function corsJson(req: Request, status: number, body: Record<string, unknown>): Response {
	const response = sharedCorsJson(req, status, body);
	response.headers.set("Cache-Control", "no-store");
	response.headers.set("Content-Type", "application/json");
	return response;
}

function exactObject(value: unknown, required: string[], optional: string[] = []): value is Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const object = value as Record<string, unknown>;
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(object, key)) && Object.keys(object).every((key) => allowed.has(key));
}

function uuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value);
}

function safeName(value: unknown, max = 256): value is string {
	return typeof value === "string" && value.length >= 1 && value.length <= max && SAFE_NAME.test(value);
}

function scopes(value: unknown): value is string[] {
	return Array.isArray(value) && value.length >= 1 && value.length <= 32 && value.every((scope) => typeof scope === "string" && SCOPE.test(scope)) && new Set(value).size === value.length;
}

function integerIn(value: unknown, min: number, max: number): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

function validGrant(body: Record<string, unknown>): boolean {
	return exactObject(body, ["action", "tenant_id", "subject_user_id", "agent_id", "tool_server_id", "tool_name", "resource_type", "resource_id", "audience", "scopes"], ["max_ttl_seconds", "max_delegation_depth", "grant_expires_in_seconds"]) &&
		uuid(body.tenant_id) && uuid(body.subject_user_id) && uuid(body.agent_id) &&
		safeName(body.tool_server_id) && safeName(body.tool_name) && safeName(body.resource_type, 128) &&
		typeof body.resource_id === "string" && body.resource_id.length >= 1 && body.resource_id.length <= 2048 && !/[\u0000-\u001f\u007f]/.test(body.resource_id) &&
		safeName(body.audience) && scopes(body.scopes) &&
		(body.max_ttl_seconds === undefined || integerIn(body.max_ttl_seconds, 30, 900)) &&
		(body.max_delegation_depth === undefined || integerIn(body.max_delegation_depth, 0, 4)) &&
		(body.grant_expires_in_seconds === undefined || integerIn(body.grant_expires_in_seconds, 60, 7_776_000));
}

function validIssue(body: Record<string, unknown>): boolean {
	return exactObject(body, ["action", "tenant_id", "grant_id", "scopes"], ["ttl_seconds"]) && uuid(body.tenant_id) && uuid(body.grant_id) && scopes(body.scopes) && (body.ttl_seconds === undefined || integerIn(body.ttl_seconds, 1, 900));
}

function validRedelegation(body: Record<string, unknown>): boolean {
	return exactObject(body, ["action", "scopes"], ["ttl_seconds"]) && scopes(body.scopes) && (body.ttl_seconds === undefined || integerIn(body.ttl_seconds, 1, 900));
}

function validRevoke(body: Record<string, unknown>): boolean {
	return exactObject(body, ["action", "tenant_id", "grant_id"]) && uuid(body.tenant_id) && uuid(body.grant_id);
}

function validLineage(body: Record<string, unknown>): boolean {
	return exactObject(body, ["action", "tenant_id", "token_id"]) && uuid(body.tenant_id) && uuid(body.token_id);
}

function dbError(req: Request, error: { code?: string } | null): Response {
	if (error?.code === "42501") return corsJson(req, 403, { error: "delegation_forbidden" });
	if (error?.code === "22023" || error?.code === "22P02" || error?.code === "23514") return corsJson(req, 400, { error: "invalid_delegation_request" });
	return corsJson(req, 503, { error: "delegation_unavailable" });
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("delegated-credentials", config.error, (status, body) => corsJson(req, status, body));
	const raw = await req.text();
	if (raw.length > 32_768) return corsJson(req, 413, { error: "request_too_large" });
	let body: Record<string, unknown>;
	try {
		body = JSON.parse(raw);
	} catch {
		return corsJson(req, 400, { error: "invalid_json" });
	}
	if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.action !== "string") return corsJson(req, 400, { error: "invalid_request" });
	const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
	const bearer = getBearerToken(req.headers.get("Authorization"));

	try {
		if (body.action === "introspect" || body.action === "redelegate") {
			if (!bearer) return corsJson(req, 401, { error: "missing_delegated_credential" });
			const verified = await verifyDelegatedCredentialForBroker({
				token: bearer,
				keyId: config.values.AIDR_DELEGATION_SIGNING_KEY_ID,
				publicKeySpkiBase64: config.values.AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64,
				issuer: config.values.AIDR_DELEGATION_ISSUER,
			});
			if (!verified.ok) return corsJson(req, 401, { error: verified.error });

			if (body.action === "introspect") {
				if (!exactObject(body, ["action", "context"]) || !matchesDelegatedContext(verified.claims, body.context)) return corsJson(req, 403, { error: "delegation_context_mismatch" });
				const { data, error } = await db.rpc("validate_delegated_credential", { p_claims: verified.claims, p_claims_sha256: verified.claimsSha256 });
				if (error) return dbError(req, error);
				if (!data?.active) return corsJson(req, 401, { error: "delegation_inactive" });
				return corsJson(req, 200, { ok: true, active: true, lineage: data });
			}

			if (!validRedelegation(body)) return corsJson(req, 400, { error: "invalid_delegation_request" });
			const reserved = await db.rpc("reserve_child_delegated_credential", {
				p_issuer: config.values.AIDR_DELEGATION_ISSUER,
				p_parent_claims: verified.claims,
				p_parent_sha256: verified.claimsSha256,
				p_request: body,
			});
			if (reserved.error) return dbError(req, reserved.error);
			const signed = await signDelegatedCredential({ claims: reserved.data?.claims, keyId: config.values.AIDR_DELEGATION_SIGNING_KEY_ID, privateKeyPkcs8Base64: config.values.AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64 });
			const finalized = await db.rpc("finalize_delegated_credential", { p_claims: signed.claims, p_claims_sha256: signed.claimsSha256 });
			if (finalized.error || finalized.data !== true) return corsJson(req, 503, { error: "delegation_not_finalized" });
			return corsJson(req, 201, { ok: true, token_type: "AIDR-Delegation", access_token: signed.token, expires_at: new Date(signed.claims.expiresAt * 1000).toISOString(), scopes: signed.claims.scopes, delegation_depth: signed.claims.delegationDepth });
		}

		if (!bearer) return corsJson(req, 401, { error: "missing_access_token" });
		const { data: auth, error: authError } = await db.auth.getUser(bearer);
		if (authError || !auth.user) return corsJson(req, 401, { error: "invalid_access_token" });
		if (!["grant", "revoke_grant", "lineage", "issue"].includes(body.action) || !uuid(body.tenant_id)) {
			return corsJson(req, 400, { error: "invalid_delegation_request" });
		}
		const identity = await checkIdentityBarrier(db, bearer, auth.user.id, body.tenant_id);
		if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });

		if (body.action === "grant") {
			if (!validGrant(body)) return corsJson(req, 400, { error: "invalid_grant" });
			const { data, error } = await db.rpc("create_delegated_credential_grant", { p_actor_user_id: auth.user.id, p_request: body });
			return error ? dbError(req, error) : corsJson(req, 201, { ok: true, ...data });
		}
		if (body.action === "revoke_grant") {
			if (!validRevoke(body)) return corsJson(req, 400, { error: "invalid_revoke_request" });
			const { data, error } = await db.rpc("revoke_delegated_credential_grant", { p_actor_user_id: auth.user.id, p_tenant_id: body.tenant_id, p_grant_id: body.grant_id });
			if (error) return dbError(req, error);
			return data === true ? corsJson(req, 200, { ok: true }) : corsJson(req, 404, { error: "grant_not_found" });
		}
		if (body.action === "lineage") {
			if (!validLineage(body)) return corsJson(req, 400, { error: "invalid_lineage_request" });
			const { data, error } = await db.rpc("read_delegated_credential_lineage", { p_actor_user_id: auth.user.id, p_tenant_id: body.tenant_id, p_token_id: body.token_id });
			if (error) return dbError(req, error);
			return data?.found ? corsJson(req, 200, { ok: true, lineage: data.lineage }) : corsJson(req, 404, { error: "delegation_not_found" });
		}
		if (body.action !== "issue" || !validIssue(body)) return corsJson(req, 400, { error: "invalid_delegation_request" });
		const reserved = await db.rpc("reserve_delegated_credential", { p_actor_user_id: auth.user.id, p_issuer: config.values.AIDR_DELEGATION_ISSUER, p_request: body });
		if (reserved.error) return dbError(req, reserved.error);
		const signed = await signDelegatedCredential({ claims: reserved.data?.claims, keyId: config.values.AIDR_DELEGATION_SIGNING_KEY_ID, privateKeyPkcs8Base64: config.values.AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64 });
		const finalized = await db.rpc("finalize_delegated_credential", { p_claims: signed.claims, p_claims_sha256: signed.claimsSha256 });
		if (finalized.error || finalized.data !== true) return corsJson(req, 503, { error: "delegation_not_finalized" });
		return corsJson(req, 201, { ok: true, token_type: "AIDR-Delegation", access_token: signed.token, expires_at: new Date(signed.claims.expiresAt * 1000).toISOString(), scopes: signed.claims.scopes, delegation_depth: signed.claims.delegationDepth });
	} catch {
		return corsJson(req, 503, { error: "delegation_unavailable" });
	}
});
