// Supabase Edge Function: POST /v1/version-check
//
// Auth: none (public; see scripts/verify-endpoint-auth-matrix.mjs)
//
// Serves the latest published AIDR release to `checkForUpdate()` in
// packages/core/src/version-check.ts. Connectors resolve
// `<gateway>/v1/version-check`, which the AIDR gateway maps onto this function
// exactly like every other `/v1/<operation>` route.
//
// Privacy: the request body (AIDR version, runtime, OS, architecture, random
// installation id) is bounded and parsed only to validate `aidr_version`; it is
// never stored, logged or used as a rate-limit key. An enrolled runtime may also
// send an API-key bearer; it is ignored here — this endpoint is public and
// grants nothing.
//
// Abuse controls, fail closed: a deployment-wide aggregate bucket always
// applies, plus a per-client bucket keyed by the SHA-256 of a proxy-attested
// client IP (never caller-supplied proxy headers) when the shared ingress
// secret is configured. A rate-limit storage failure answers 503.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { configFailure, type EnvReader, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { consumeRateLimit, type RateLimitDb } from "../_shared/rate-limit.ts";
import { isNewerRelease, normalizeReleaseVersion, resolveLatestRelease } from "../_shared/release-version.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { getRequestId } from "../_shared/response.ts";
import { INGRESS_SECRET_ENV, ingressIpBucket, validIngressSecret, verifiedIngressIp } from "../_shared/trusted-ingress.ts";

// Required configuration. Validated per request, before any DB work (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const MAX_BODY_BYTES = 4 * 1024;
export const VERSION_CHECK_INGRESS_CONTEXT = "version-check:v1";
const AGGREGATE_RATE_LIMIT_KEY = "version-check:global:v1";
const CLIENT_RATE_LIMIT_PREFIX = "version-check:v1:client:";
const DEFAULT_AGGREGATE_PER_MINUTE = 6_000;
const DEFAULT_CLIENT_PER_MINUTE = 30;
// Every client asks for the same public answer; a short shared cache keeps
// repeated startups off the function.
const CACHE_CONTROL = "public, max-age=300";

function json(status: number, body: Record<string, unknown>, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			"Cache-Control": status === 200 ? CACHE_CONTROL : "no-store",
			"X-Content-Type-Options": "nosniff",
			...headers,
		},
	});
}

function rateLimitSetting(env: EnvReader, name: string, fallback: number): number | null {
	const raw = env(name);
	const value = raw === undefined || raw === null || raw.trim() === "" ? fallback : Number(raw);
	return Number.isSafeInteger(value) && value > 0 && value <= 1_000_000 ? value : null;
}

async function limited(db: RateLimitDb, key: string, limit: number): Promise<Response | null> {
	const result = await consumeRateLimit(db, key, limit);
	if (result.status === "allowed") return null;
	return result.status === "limited"
		? json(429, { error: "rate_limited" }, { "Retry-After": String(result.retryAfterSeconds) })
		: json(503, { error: "rate_limit_unavailable" }, { "Retry-After": String(result.retryAfterSeconds) });
}

export async function handleVersionCheck(req: Request): Promise<Response> {
	const env = runtimeEnv;
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" }, { Allow: "POST" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("version-check", config.error, json);

	const aggregateLimit = rateLimitSetting(env, "AIDR_VERSION_CHECK_RATE_LIMIT_PER_MINUTE", DEFAULT_AGGREGATE_PER_MINUTE);
	const clientLimit = rateLimitSetting(env, "AIDR_VERSION_CHECK_CLIENT_RATE_LIMIT_PER_MINUTE", DEFAULT_CLIENT_PER_MINUTE);
	if (aggregateLimit === null || clientLimit === null) return json(500, { error: "server_misconfigured" });

	const body = await readBoundedJson(req, MAX_BODY_BYTES);
	if (!body.ok) return json(body.status, { error: body.error });
	const payload = body.value && typeof body.value === "object" && !Array.isArray(body.value)
		? (body.value as Record<string, unknown>)
		: null;
	if (!payload) return json(400, { error: "invalid_body" });
	const currentVersion = payload.aidr_version === undefined ? null : normalizeReleaseVersion(payload.aidr_version);
	if (payload.aidr_version !== undefined && currentVersion === null) return json(400, { error: "invalid_aidr_version" });

	const db = createClient(config.values.SUPABASE_URL!, config.values.SUPABASE_SERVICE_ROLE_KEY!, {
		auth: { persistSession: false, autoRefreshToken: false },
	}) as unknown as RateLimitDb;
	const aggregate = await limited(db, AGGREGATE_RATE_LIMIT_KEY, aggregateLimit);
	if (aggregate) return aggregate;
	const ingressSecret = env(INGRESS_SECRET_ENV);
	if (validIngressSecret(ingressSecret)) {
		const ip = await verifiedIngressIp(req, ingressSecret, VERSION_CHECK_INGRESS_CONTEXT);
		if (ip) {
			const client = await limited(db, `${CLIENT_RATE_LIMIT_PREFIX}${await ingressIpBucket(ip)}`, clientLimit);
			if (client) return client;
		}
	}

	const latest = await resolveLatestRelease(env);
	if (!latest.ok) {
		// Name the operator-side reason; never invent a version.
		console.error("[version-check] latest release unavailable", JSON.stringify({ reason: latest.reason, request_id: getRequestId(req) }));
		return json(503, { error: "latest_version_unavailable", reason: latest.reason });
	}
	return json(200, {
		version: latest.version,
		source: latest.source,
		...(latest.channel ? { channel: latest.channel } : {}),
		...(currentVersion ? { update_available: isNewerRelease(currentVersion, latest.version) } : {}),
	});
}

Deno.serve(handleVersionCheck);
