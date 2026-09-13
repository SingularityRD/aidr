// Supabase Edge Function: POST /v1/device/start
//
// Auth: none (device-code bootstrap)
//
// Creates a short-lived device session. The client polls /v1/device/poll until authorized.

import { createClient } from "npm:@supabase/supabase-js@2";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
// The reverse proxy must remove any client-supplied x-aidr-client-* headers and
// add a signed, canonical remote IP. The function must not infer a client IP
// from x-forwarded-for/cf-connecting-ip/x-real-ip: direct callers control them.
const REQUIRED_ENV = [
	"SUPABASE_URL",
	"SUPABASE_SERVICE_ROLE_KEY",
	"AIDR_DEVICE_START_INGRESS_SECRET",
] as const;

const DASHBOARD_VERIFY_URL = (Deno.env.get("AIDR_DASHBOARD_VERIFY_URL") ?? "/verify").trim();

const DEVICE_TTL_MINUTES = Number(Deno.env.get("AIDR_DEVICE_TTL_MINUTES") ?? "10");
const DEVICE_POLL_INTERVAL_SECONDS = Number(Deno.env.get("AIDR_DEVICE_POLL_INTERVAL_SECONDS") ?? "3");
const DEVICE_START_RL_PER_MIN = Number(Deno.env.get("AIDR_DEVICE_START_RL_PER_MIN") ?? "30");
const DEVICE_START_GLOBAL_RL_PER_MIN = Number(Deno.env.get("AIDR_DEVICE_START_GLOBAL_RL_PER_MIN") ?? "300");

const INGRESS_IP_HEADER = "x-aidr-client-ip";
const INGRESS_TIMESTAMP_HEADER = "x-aidr-client-timestamp";
const INGRESS_SIGNATURE_HEADER = "x-aidr-client-signature";
const INGRESS_CONTEXT = "device-start:v1";
const MAX_CLOCK_SKEW_SECONDS = 60;

function canonicalIp(value: string | null): string | null {
	if (!value || value.length > 45 || value !== value.trim()) return null;
	if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) {
		const parts = value.split(".");
		if (parts.some((part) => Number(part) > 255 || (part.length > 1 && part.startsWith("0")))) return null;
		return value;
	}
	if (!value.includes(":") || !/^[0-9a-fA-F:]+$/.test(value)) return null;
	try {
		const hostname = new URL(`http://[${value}]/`).hostname;
		return hostname.slice(1, -1).toLowerCase();
	} catch {
		return null;
	}
}

function constantTimeHexEqual(actual: string, expected: string): boolean {
	if (!/^[a-f0-9]{64}$/.test(actual) || expected.length !== 64) return false;
	let difference = 0;
	for (let i = 0; i < 64; i++) difference |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
	return difference === 0;
}

async function verifiedIngressIp(req: Request, secret: string): Promise<string | null> {
	const ip = canonicalIp(req.headers.get(INGRESS_IP_HEADER));
	const timestamp = req.headers.get(INGRESS_TIMESTAMP_HEADER);
	const signature = req.headers.get(INGRESS_SIGNATURE_HEADER);
	if (!ip || !timestamp || !signature || !/^(0|[1-9]\d{0,15})$/.test(timestamp)) return null;
	const seconds = Number(timestamp);
	if (!Number.isSafeInteger(seconds) || Math.abs(Math.floor(Date.now() / 1000) - seconds) > MAX_CLOCK_SKEW_SECONDS) return null;
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const signed = await crypto.subtle.sign(
		"HMAC",
		key,
		new TextEncoder().encode(`${INGRESS_CONTEXT}\n${timestamp}\n${ip}`),
	);
	const expected = Array.from(new Uint8Array(signed), (byte) => byte.toString(16).padStart(2, "0")).join("");
	return constantTimeHexEqual(signature, expected) ? ip : null;
}

async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest("SHA-256", data);
	const bytes = new Uint8Array(digest);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function bytesToBase64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

function base64Url(bytes: Uint8Array): string {
	const b64 = bytesToBase64(bytes);
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomDeviceCode(): string {
	const raw = new Uint8Array(32);
	crypto.getRandomValues(raw);
	return `aidr_device_${base64Url(raw)}`;
}

function randomUserCode(): string {
	// 8 chars, avoid ambiguous (O/0, I/1, etc.)
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
	const bytes = new Uint8Array(8);
	crypto.getRandomValues(bytes);
	let out = "";
	for (const b of bytes) out += alphabet[b % alphabet.length]!;
	return out;
}

function addMinutesIso(minutes: number): string {
	const safe = Number.isFinite(minutes) ? Math.max(1, Math.min(60, Math.floor(minutes))) : 10;
	return new Date(Date.now() + safe * 60 * 1000).toISOString();
}

async function rateLimitStart(
	supabase: ReturnType<typeof createClient>,
	ip: string,
): Promise<boolean> {
	const nowMin = Math.floor(Date.now() / 60000);
	const ipHash = await sha256Hex(ip);
	// Check the signed client bucket first so a single caller cannot consume the
	// shared deployment budget after reaching its own quota. A bounded aggregate
	// also limits session creation by many real IPs. It is an availability tradeoff:
	// an attacker with enough real IPs can exhaust the public bootstrap budget.
	return await consumeRateLimit(supabase, `device_start:v2:client:${ipHash}`, nowMin, DEVICE_START_RL_PER_MIN)
		&& await consumeRateLimit(supabase, "device_start:v2:aggregate", nowMin, DEVICE_START_GLOBAL_RL_PER_MIN);
}

async function consumeRateLimit(
	supabase: ReturnType<typeof createClient>,
	key: string,
	nowMin: number,
	limit: number,
): Promise<boolean> {
	const { error } = await supabase.rpc("increment_rate_limit", {
		p_key: key,
		p_window_start: nowMin,
		p_delta: 1,
	});
	// Rate limiting is a mandatory abuse control for unauthenticated device
	// bootstrap. If its storage is unavailable, fail closed instead of minting
	// unlimited device sessions.
	if (error) return false;
	const { data, error: countError } = await supabase
		.from("rate_limits")
		.select("count")
		.eq("key", key)
		.eq("window_start", nowMin)
		.maybeSingle();
	if (countError) return false;
	const count = Number((data as any)?.count ?? 0);
	return Number.isSafeInteger(count) && count > 0 && count <= limit;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("device-start", config.error, (status, body) => corsJson(req, status, body));
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, AIDR_DEVICE_START_INGRESS_SECRET } = config.values;
	const invalid: string[] = [];
	if (new TextEncoder().encode(AIDR_DEVICE_START_INGRESS_SECRET).length < 32) invalid.push("AIDR_DEVICE_START_INGRESS_SECRET");
	if (!Number.isSafeInteger(DEVICE_START_RL_PER_MIN) || DEVICE_START_RL_PER_MIN < 1 || DEVICE_START_RL_PER_MIN > 10000) invalid.push("AIDR_DEVICE_START_RL_PER_MIN");
	if (!Number.isSafeInteger(DEVICE_START_GLOBAL_RL_PER_MIN) || DEVICE_START_GLOBAL_RL_PER_MIN < DEVICE_START_RL_PER_MIN || DEVICE_START_GLOBAL_RL_PER_MIN > 100000) invalid.push("AIDR_DEVICE_START_GLOBAL_RL_PER_MIN");
	if (invalid.length > 0) return corsJson(req, 500, { error: "server_misconfigured", invalid });

	const ip = await verifiedIngressIp(req, AIDR_DEVICE_START_INGRESS_SECRET);
	if (!ip) return corsJson(req, 403, { error: "trusted_ingress_required" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const ok = await rateLimitStart(supabase, ip);
	if (!ok) return corsJson(req, 429, { error: "rate_limited" });

	const expiresAt = addMinutesIso(DEVICE_TTL_MINUTES);

	let deviceCode = "";
	let userCode = "";
	let inserted = false;

	for (let i = 0; i < 10; i++) {
		deviceCode = randomDeviceCode();
		userCode = randomUserCode();
		const deviceHash = await sha256Hex(deviceCode);
		const { error } = await supabase.from("device_sessions").insert({
			device_code_hash: deviceHash,
			user_code: userCode,
			expires_at: expiresAt,
		});
		if (!error) {
			inserted = true;
			break;
		}
	}

	if (!inserted) return corsJson(req, 500, { error: "device_session_issue_failed" });

	const verificationUrl =
		DASHBOARD_VERIFY_URL.includes("?")
			? `${DASHBOARD_VERIFY_URL}&code=${encodeURIComponent(userCode)}`
			: `${DASHBOARD_VERIFY_URL}?code=${encodeURIComponent(userCode)}`;

	return corsJson(req, 200, {
		ok: true,
		verification_url: verificationUrl,
		user_code: userCode,
		device_code: deviceCode,
		expires_at: expiresAt,
		interval_seconds: Math.max(1, Math.floor(DEVICE_POLL_INTERVAL_SECONDS || 3)),
	});
});
