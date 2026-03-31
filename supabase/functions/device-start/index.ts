// Supabase Edge Function: POST /v1/device/start
//
// Auth: none (device-code bootstrap)
//
// Creates a short-lived device session. The client polls /v1/device/poll until authorized.

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const DASHBOARD_VERIFY_URL = (Deno.env.get("AIDR_DASHBOARD_VERIFY_URL") ?? "/verify").trim();

const DEVICE_TTL_MINUTES = Number(Deno.env.get("AIDR_DEVICE_TTL_MINUTES") ?? "10");
const DEVICE_POLL_INTERVAL_SECONDS = Number(Deno.env.get("AIDR_DEVICE_POLL_INTERVAL_SECONDS") ?? "3");
const DEVICE_START_RL_PER_MIN = Number(Deno.env.get("AIDR_DEVICE_START_RL_PER_MIN") ?? "30");

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function getClientIp(req: Request): string {
	const h =
		req.headers.get("x-forwarded-for") ??
		req.headers.get("cf-connecting-ip") ??
		req.headers.get("x-real-ip") ??
		"";
	// x-forwarded-for can be a list: client, proxy1, proxy2...
	const first = h.split(",")[0]?.trim() ?? "";
	return first || "unknown";
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
	const key = `device_start:${ipHash.slice(0, 16)}`;
	const { error } = await supabase.rpc("increment_rate_limit", {
		p_key: key,
		p_window_start: nowMin,
		p_delta: 1,
	});
	// Fail open if rate limiting isn't configured yet.
	if (error) return true;
	const { data } = await supabase
		.from("rate_limits")
		.select("count")
		.eq("key", key)
		.eq("window_start", nowMin)
		.maybeSingle();
	const count = Number((data as any)?.count ?? 0);
	return Number.isFinite(DEVICE_START_RL_PER_MIN) && DEVICE_START_RL_PER_MIN > 0
		? count <= DEVICE_START_RL_PER_MIN
		: true;
}

Deno.serve(async (req) => {
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "misconfigured_supabase_env" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const ip = getClientIp(req);
	const ok = await rateLimitStart(supabase, ip);
	if (!ok) return json(429, { error: "rate_limited" });

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

	if (!inserted) return json(500, { error: "device_session_issue_failed" });

	const verificationUrl =
		DASHBOARD_VERIFY_URL.includes("?")
			? `${DASHBOARD_VERIFY_URL}&code=${encodeURIComponent(userCode)}`
			: `${DASHBOARD_VERIFY_URL}?code=${encodeURIComponent(userCode)}`;

	return json(200, {
		ok: true,
		verification_url: verificationUrl,
		user_code: userCode,
		device_code: deviceCode,
		expires_at: expiresAt,
		interval_seconds: Math.max(1, Math.floor(DEVICE_POLL_INTERVAL_SECONDS || 3)),
	});
});

