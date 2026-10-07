// Supabase Edge Function: POST /v1/waitlist/signup
//
// Auth: none
//
// Public waitlist intake. Abuse controls, all fail closed:
// - Cloudflare Turnstile server-side verification whenever TURNSTILE_SECRET_KEY
//   is configured. A missing, rejected or unverifiable token never writes.
// - A per-client bucket keyed by the SHA-256 of a proxy-attested client IP when
//   AIDR_WAITLIST_INGRESS_SECRET is configured (see _shared/trusted-ingress.ts),
//   plus one deployment-wide aggregate bucket that always applies.
// - Bounded body, strict email syntax and bounded optional fields.
// - Insert-only persistence (ON CONFLICT DO NOTHING): a repeated signup cannot
//   overwrite an existing row, and the response is identical either way, so the
//   endpoint does not reveal whether an address is already on the list.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { ConfigurationError, configFailure, type EnvReader, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { buildCorsHeaders, parseAllowedOrigins, resolveAllowedOrigin } from "../_shared/origin.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { getRequestId } from "../_shared/response.ts";
import { validIngressSecret, verifiedIngressIp } from "../_shared/trusted-ingress.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const MAX_WAITLIST_BODY_BYTES = 8 * 1024;
const MAX_TURNSTILE_RESPONSE_BYTES = 16 * 1024;
const MAX_TURNSTILE_TOKEN_LENGTH = 2048;
const TURNSTILE_TIMEOUT_MS = 5_000;
export const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
export const WAITLIST_INGRESS_CONTEXT = "waitlist-signup:v1";
// Proxy IP headers are caller-controlled at this Edge Function boundary, so a
// per-client key is derived only from a signed ingress proof. The aggregate
// bucket bounds total intake whether or not that proof is configured.
const AGGREGATE_RATE_LIMIT_KEY = "waitlist:global:v1";
const CLIENT_RATE_LIMIT_PREFIX = "waitlist:v2:client:";
const OPTIONAL_FIELD_LIMITS = { name: 200, company: 200, message: 2_000 } as const;

type WaitlistClient = ReturnType<typeof createClient<any>>;

export interface WaitlistSignupDeps {
	/** Outbound fetch used for Turnstile verification. */
	fetch?: typeof fetch;
	/** Service-role client factory. */
	createDb?: (url: string, serviceRoleKey: string) => WaitlistClient;
	/** Clock in epoch milliseconds. */
	now?: () => number;
}

const EMAIL_LOCAL_PART = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const DOMAIN_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const TOP_LEVEL_LABEL = /^(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$/;

/**
 * Returns the trimmed address when it is a plausible deliverable mailbox
 * (dot-atom local part, at least two DNS labels, alphabetic or IDNA TLD), or
 * null. Quoted local parts, IP-literal domains and whitespace are refused.
 */
export function normalizeWaitlistEmail(raw: unknown): string | null {
	if (typeof raw !== "string") return null;
	const email = raw.trim();
	if (email.length > 254) return null;
	const at = email.indexOf("@");
	if (at < 1 || at !== email.lastIndexOf("@")) return null;
	const local = email.slice(0, at);
	const domain = email.slice(at + 1);
	if (local.length > 64 || !EMAIL_LOCAL_PART.test(local)) return null;
	if (domain.length > 253) return null;
	const labels = domain.split(".");
	if (labels.length < 2 || !labels.every((label) => DOMAIN_LABEL.test(label))) return null;
	return TOP_LEVEL_LABEL.test(labels[labels.length - 1]!) ? email : null;
}

// C0 controls other than tab/newline/carriage return, DEL, and C1 controls.
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;

function optionalField(value: unknown, maxLength: number, multiline: boolean): { ok: true; value: string | null } | { ok: false } {
	if (value === undefined || value === null) return { ok: true, value: null };
	if (typeof value !== "string") return { ok: false };
	const trimmed = value.trim();
	if (trimmed.length > maxLength || CONTROL_CHARACTERS.test(trimmed)) return { ok: false };
	if (!multiline && /[\r\n\t]/.test(trimmed)) return { ok: false };
	return { ok: true, value: trimmed || null };
}

function rateLimitSetting(env: EnvReader, name: string, fallback: number, max: number): number | null {
	const raw = env(name);
	const value = raw === undefined || raw === null ? fallback : Number(raw);
	return Number.isSafeInteger(value) && value > 0 && value <= max ? value : null;
}

async function sha256Hex(input: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function consumeRateLimit(
	supabase: WaitlistClient,
	key: string,
	windowStart: number,
	limit: number,
): Promise<boolean> {
	try {
		const { error } = await supabase.rpc("increment_rate_limit", {
			p_key: key,
			p_window_start: windowStart,
			p_delta: 1,
		});
		if (error) return false;
		const { data, error: countError } = await supabase
			.from("rate_limits")
			.select("count")
			.eq("key", key)
			.eq("window_start", windowStart)
			.maybeSingle();
		if (countError) return false;
		const count = data && typeof data === "object" && "count" in data ? data.count : null;
		return typeof count === "number" && Number.isSafeInteger(count) && count > 0 && count <= limit;
	} catch {
		return false;
	}
}

type TurnstileOutcome = "verified" | "rejected" | "unavailable";

/**
 * Server-side Turnstile check. Only an explicit `success: true` from Cloudflare
 * verifies; a transport error, timeout, non-200 or malformed answer is
 * `unavailable`, which the caller treats as a refusal.
 */
export async function verifyTurnstileToken(
	fetchImpl: typeof fetch,
	secret: string,
	token: string,
	remoteIp: string | null,
): Promise<TurnstileOutcome> {
	const form = new URLSearchParams({ secret, response: token });
	if (remoteIp) form.set("remoteip", remoteIp);
	let response: Response;
	try {
		response = await fetchImpl(TURNSTILE_VERIFY_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: form,
			redirect: "error",
			signal: AbortSignal.timeout(TURNSTILE_TIMEOUT_MS),
		});
	} catch {
		return "unavailable";
	}
	if (response.status !== 200) {
		void response.body?.cancel().catch(() => undefined);
		return "unavailable";
	}
	const parsed = await readBoundedJson(response, MAX_TURNSTILE_RESPONSE_BYTES);
	if (!parsed.ok || !parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
		return "unavailable";
	}
	const success = (parsed.value as { success?: unknown }).success;
	if (success === true) return "verified";
	return success === false ? "rejected" : "unavailable";
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createWaitlistSignupHandler(deps: WaitlistSignupDeps = {}) {
	const fetchImpl: typeof fetch = deps.fetch ?? ((input, init) => fetch(input, init));
	const now = deps.now ?? Date.now;
	const connect = deps.createDb ?? ((url: string, key: string) =>
		createClient<any>(url, key, { auth: { persistSession: false } }));

	const allowedOrigins = parseAllowedOrigins(
		runtimeEnv("AIDR_ALLOWED_ORIGINS") ?? undefined,
		runtimeEnv("AIDR_DEVELOPMENT_MODE") === "true",
	);
	// Hard aggregate cap; tune upward for legitimate launch traffic.
	const aggregatePerMinute = rateLimitSetting(runtimeEnv, "AIDR_WAITLIST_RL_PER_MIN", 1000, 100_000);
	const clientPerMinute = rateLimitSetting(runtimeEnv, "AIDR_WAITLIST_IP_RL_PER_MIN", 5, 10_000);
	const invalidSettings = [
		...(aggregatePerMinute === null ? ["AIDR_WAITLIST_RL_PER_MIN"] : []),
		...(clientPerMinute === null ? ["AIDR_WAITLIST_IP_RL_PER_MIN"] : []),
	];
	const settingsError = invalidSettings.length > 0 ? new ConfigurationError({ invalid: invalidSettings }) : null;

	function json(status: number, body: Record<string, unknown>, req: Request) {
		return new Response(JSON.stringify(body), {
			status,
			headers: {
				...buildCorsHeaders(req.headers.get("Origin"), allowedOrigins),
				"X-Request-ID": getRequestId(req),
			},
		});
	}

	return async function handleWaitlistSignup(req: Request): Promise<Response> {
		const origin = req.headers.get("Origin");
		const allowedOrigin = resolveAllowedOrigin(origin, allowedOrigins);
		if (origin && !allowedOrigin) return json(403, { error: "origin_not_allowed" }, req);

		if (req.method === "OPTIONS") return json(200, { ok: true }, req);
		if (req.method !== "POST") return json(405, { error: "method_not_allowed" }, req);

		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("waitlist-signup", config.error, (status, body) => json(status, body, req));
		}
		if (settingsError) {
			return configFailure("waitlist-signup", settingsError, (status, body) => json(status, body, req));
		}
		const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;
		const turnstileSecret = runtimeEnv("TURNSTILE_SECRET_KEY")?.trim() || null;
		const ingressSecret = runtimeEnv("AIDR_WAITLIST_INGRESS_SECRET") || null;
		if (ingressSecret !== null && !validIngressSecret(ingressSecret)) {
			return configFailure(
				"waitlist-signup",
				new ConfigurationError({ invalid: ["AIDR_WAITLIST_INGRESS_SECRET"] }),
				(status, body) => json(status, body, req),
			);
		}

		// With a configured ingress secret, the per-client bucket is mandatory: a
		// request that bypasses the signing proxy is refused instead of falling
		// back to the aggregate bucket alone.
		const clientIp = ingressSecret
			? await verifiedIngressIp(req, ingressSecret, WAITLIST_INGRESS_CONTEXT, now())
			: null;
		if (ingressSecret && !clientIp) return json(403, { error: "trusted_ingress_required" }, req);

		const parsed = await readBoundedJson(req, MAX_WAITLIST_BODY_BYTES);
		if (!parsed.ok) return json(parsed.status, { error: parsed.error }, req);
		if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
			return json(400, { error: "invalid_json" }, req);
		}
		const body = parsed.value as Record<string, unknown>;

		const email = normalizeWaitlistEmail(body.email);
		if (!email) return json(400, { error: "invalid_email" }, req);
		const name = optionalField(body.name, OPTIONAL_FIELD_LIMITS.name, false);
		const company = optionalField(body.company, OPTIONAL_FIELD_LIMITS.company, false);
		const message = optionalField(body.message, OPTIONAL_FIELD_LIMITS.message, true);
		if (!name.ok || !company.ok || !message.ok) return json(400, { error: "invalid_field" }, req);

		// Verify the human challenge before touching shared rate-limit storage, so
		// unsolved requests cannot drain the aggregate bucket for real visitors.
		if (turnstileSecret) {
			const token = body.turnstile_token ?? body["cf-turnstile-response"];
			if (typeof token !== "string" || !token.trim() || token.length > MAX_TURNSTILE_TOKEN_LENGTH) {
				return json(403, { error: "captcha_required" }, req);
			}
			const outcome = await verifyTurnstileToken(fetchImpl, turnstileSecret, token.trim(), clientIp);
			if (outcome === "unavailable") return json(503, { error: "captcha_unavailable" }, req);
			if (outcome !== "verified") return json(403, { error: "captcha_failed" }, req);
		}

		const supabase = connect(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
		const windowStart = Math.floor(now() / 60_000);
		// Check the client bucket first so one caller cannot consume the shared
		// aggregate budget after reaching its own quota.
		const withinClient = !clientIp || await consumeRateLimit(
			supabase,
			`${CLIENT_RATE_LIMIT_PREFIX}${await sha256Hex(clientIp)}`,
			windowStart,
			clientPerMinute!,
		);
		const ok = withinClient &&
			await consumeRateLimit(supabase, AGGREGATE_RATE_LIMIT_KEY, windowStart, aggregatePerMinute!);
		if (!ok) return json(429, { error: "rate_limited" }, req);

		const { error } = await supabase
			.from("waitlist_signups")
			.upsert(
				{ email, name: name.value, company: company.value, message: message.value },
				{ onConflict: "email_lower", ignoreDuplicates: true },
			);
		if (error) return json(500, { error: "db_error" }, req);

		return json(200, { ok: true }, req);
	};
}

export const handleWaitlistSignup = createWaitlistSignupHandler();

Deno.serve(handleWaitlistSignup);
