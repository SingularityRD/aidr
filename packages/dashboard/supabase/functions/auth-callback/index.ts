import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";

const REQUIRED_ENV = [
  "SUPABASE_URL",
  "SUPABASE_ANON_KEY",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "AUTH_CALLBACK_ALLOWED_ORIGINS",
  "AUTH_CALLBACK_STATE_SECRET",
] as const;

const CORS_HEADERS = "authorization, x-client-info, apikey, content-type";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";

export interface CallbackState {
  tenantId: string;
  redirectUri: string;
}

function json(status: number, body: Record<string, unknown>, origin?: string): Response {
  const headers: Record<string, string> = {
    "Access-Control-Allow-Headers": CORS_HEADERS,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Content-Type": "application/json",
    Vary: "Origin",
  };
  if (origin) headers["Access-Control-Allow-Origin"] = origin;
  return new Response(JSON.stringify(body), { status, headers });
}

export function allowedOrigins(value: string): Set<string> {
  return new Set(value.split(",").map((origin) => origin.trim()).filter(Boolean));
}

export function requestOrigin(req: Request, origins: Set<string>): string | null {
  const origin = req.headers.get("Origin");
  return origin && origins.has(origin) ? origin : null;
}

function decodeBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

export function parseState(value: unknown): CallbackState | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) return null;
  try {
    const [encodedPayload, encodedSignature] = value.split(".");
    if (!encodedPayload || !encodedSignature) return null;
    const decoded = JSON.parse(new TextDecoder().decode(decodeBase64Url(encodedPayload)));
    if (
      !decoded || typeof decoded !== "object" ||
      typeof decoded.tenant_id !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decoded.tenant_id) ||
      typeof decoded.redirect_uri !== "string"
    ) return null;
    return { tenantId: decoded.tenant_id, redirectUri: decoded.redirect_uri };
  } catch {
    return null;
  }
}

async function verifyState(value: unknown, secret: string, requestOriginValue: string): Promise<CallbackState | null> {
  if (typeof value !== "string") return null;
  const separator = value.indexOf(".");
  if (separator <= 0) return null;
  const payload = value.slice(0, separator);
  const supplied = value.slice(separator + 1);
  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
    );
    valid = await crypto.subtle.verify("HMAC", key, decodeBase64Url(supplied), new TextEncoder().encode(payload));
  } catch {
    return null;
  }
  if (!valid) return null;
  const parsed = parseState(value);
  if (!parsed) return null;
  try {
    if (new URL(parsed.redirectUri).origin !== requestOriginValue) return null;
  } catch {
    return null;
  }
  return parsed;
}

interface GoogleUserInfo {
  id: string;
  email: string;
  verified_email?: boolean;
  name?: string;
  picture?: string;
}

interface CallbackConfig {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  AUTH_CALLBACK_ALLOWED_ORIGINS: string;
  AUTH_CALLBACK_STATE_SECRET: string;
}

export async function handleRequest(req: Request, env: (name: string) => string | undefined = runtimeEnv): Promise<Response> {
  const config = loadConfig(env, REQUIRED_ENV);
  if (!config.ok) return configFailure("auth-callback", config.error, (status, body) => json(status, body));
  const values = config.values as CallbackConfig;
  const origins = allowedOrigins(values.AUTH_CALLBACK_ALLOWED_ORIGINS);
  const origin = requestOrigin(req, origins);

  // This endpoint is browser-facing. An absent or unconfigured Origin is not
  // treated as a trusted non-browser caller: fail closed before any secret use.
  if (!origin) return json(403, { error: "origin_not_allowed" });
  if (req.method === "OPTIONS") return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers": CORS_HEADERS,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      Vary: "Origin",
    },
  });
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" }, origin);

  let payload: { code?: unknown; state?: unknown };
  try {
    payload = await req.json();
  } catch {
    return json(400, { error: "invalid_request" }, origin);
  }
  if (typeof payload.code !== "string" || payload.code.length < 1 || payload.code.length > 4096) {
    return json(400, { error: "authorization_code_required" }, origin);
  }
  const state = await verifyState(payload.state, values.AUTH_CALLBACK_STATE_SECRET, origin);
  if (!state) return json(400, { error: "invalid_state" }, origin);

  try {
    const tokenResponse = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: payload.code,
        client_id: values.GOOGLE_CLIENT_ID,
        client_secret: values.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${values.SUPABASE_URL}/auth/v1/callback`,
        grant_type: "authorization_code",
      }),
    });
    if (!tokenResponse.ok) return json(401, { error: "authorization_failed" }, origin);
    const tokens = await tokenResponse.json() as { id_token?: string; access_token?: string };
    if (typeof tokens.id_token !== "string" || typeof tokens.access_token !== "string") {
      return json(401, { error: "authorization_failed" }, origin);
    }

    const userInfoResponse = await fetch(GOOGLE_USERINFO_URL, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (!userInfoResponse.ok) return json(401, { error: "authorization_failed" }, origin);
    const googleUser = await userInfoResponse.json() as GoogleUserInfo;
    if (!googleUser.id || !googleUser.email || googleUser.verified_email !== true) {
      return json(401, { error: "email_not_verified" }, origin);
    }

    // The anon client exchanges Google's identity for a normal user session.
    // No service-role key or admin auth API is used on this public endpoint.
    const supabase = createClient(values.SUPABASE_URL, values.SUPABASE_ANON_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: authData, error: authError } = await supabase.auth.signInWithIdToken({
      provider: "google",
      token: tokens.id_token,
    });
    if (authError || !authData.session || !authData.user) {
      console.error("Supabase identity exchange failed", authError?.message);
      return json(401, { error: "authorization_failed" }, origin);
    }

    // Tenant binding is checked using the newly authenticated user's RLS
    // session. A caller cannot select another tenant by changing state.
    const { data: membership, error: membershipError } = await supabase
      .from("tenant_members")
      .select("tenant_id")
      .eq("tenant_id", state.tenantId)
      .eq("user_id", authData.user.id)
      .maybeSingle();
    if (membershipError || !membership || membership.tenant_id !== state.tenantId) {
      return json(403, { error: "tenant_not_allowed" }, origin);
    }

    return json(200, {
      success: true,
      userId: authData.user.id,
      tenantId: state.tenantId,
      session: authData.session,
    }, origin);
  } catch (error) {
    console.error("Auth callback error", error instanceof Error ? error.message : "unknown error");
    return json(500, { error: "internal_server_error" }, origin);
  }
}

if (import.meta.main) serve(handleRequest);
