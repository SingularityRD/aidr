// Browser side of tenant OIDC SSO. The IdP redirects back to /auth/oidc/callback;
// the code and state are handed to the `oidc-sso` Edge function together with a
// per-tab binding secret that never leaves this browser except in that call.
// The secret's hash is registered at start, so a callback URL replayed into a
// different browser (login CSRF) cannot complete the flow.

import { supabase } from "../lib/supabase";

const BINDING_KEY = "aidr.oidc.binding.v1";
const MAX_FLOW_AGE_MS = 15 * 60_000;

export type OidcFlowMode = "login" | "link";
type StoredBinding = { verifier: string; mode: OidcFlowMode; returnTo: string; startedAt: number };

export type OidcStartResult = { ok: true; url: string } | { ok: false; message: string };
export type OidcCallbackResult =
	| { ok: true; mode: OidcFlowMode; returnTo: string }
	| { ok: false; message: string };

const SAFE_MESSAGES: Record<string, string> = {
	sso_not_available:
		"Single sign-on is not available for this address. Check the spelling or contact your administrator.",
	rate_limited: "Too many attempts. Wait a minute and try again.",
	tenant_not_authorized: "Your account is not a member of this workspace.",
	mfa_required: "Complete multi-factor verification, then try again.",
	sso_required: "This workspace requires single sign-on.",
};

const LOGIN_FAILURES: Record<string, string> = {
	request_invalid:
		"This sign-in link has expired or was already used. Start again from the sign-in page.",
	binding_mismatch:
		"This sign-in was started in a different browser. Start again from the sign-in page.",
	token_invalid:
		"The identity provider's response could not be verified. Contact your administrator.",
	token_exchange_failed: "The identity provider rejected the sign-in. Contact your administrator.",
	domain_not_verified:
		"Your email domain is not verified for this workspace. Contact your administrator.",
	email_claim_missing:
		"The identity provider did not return an email address. Contact your administrator.",
	not_provisioned:
		"Your account has not been provisioned for this workspace yet. Contact your administrator.",
	group_not_mapped: "None of your directory groups grants access to this workspace.",
	groups_overage: "Your directory group list is too large to evaluate. Contact your administrator.",
	identity_conflict:
		"This identity is already linked to a different account. Contact your administrator.",
	provider_unavailable: "Single sign-on is temporarily unavailable. Try again later.",
	session_unavailable: "A session could not be created. Try again later.",
};

function randomVerifier(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

async function sha256Hex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function readBinding(): StoredBinding | null {
	try {
		const parsed: unknown = JSON.parse(sessionStorage.getItem(BINDING_KEY) ?? "null");
		if (!parsed || typeof parsed !== "object") return null;
		const value = parsed as Partial<StoredBinding>;
		if (
			typeof value.verifier !== "string" ||
			!/^[A-Za-z0-9_-]{43}$/.test(value.verifier) ||
			(value.mode !== "login" && value.mode !== "link") ||
			typeof value.returnTo !== "string" ||
			typeof value.startedAt !== "number" ||
			Date.now() - value.startedAt > MAX_FLOW_AGE_MS
		)
			return null;
		return value as StoredBinding;
	} catch {
		return null;
	}
}

function clearBinding() {
	try {
		sessionStorage.removeItem(BINDING_KEY);
	} catch {
		// Storage unavailable: nothing to clear.
	}
}

/** Extract the public { error, reason } pair from an Edge response, never raw server text. */
export async function readFunctionError(
	error: unknown,
	data: unknown,
): Promise<{ error?: string; reason?: string }> {
	const pick = (value: unknown) =>
		value && typeof value === "object" && typeof (value as { error?: unknown }).error === "string"
			? {
					error: (value as { error: string }).error,
					reason:
						typeof (value as { reason?: unknown }).reason === "string"
							? (value as { reason: string }).reason
							: undefined,
				}
			: null;
	const direct = pick(data);
	if (direct) return direct;
	const context = (error as { context?: unknown } | null)?.context;
	if (context instanceof Response) {
		try {
			return pick(await context.clone().json()) ?? {};
		} catch {
			return {};
		}
	}
	return {};
}

export function isSafeIdpUrl(value: unknown): value is string {
	if (typeof value !== "string") return false;
	try {
		const url = new URL(value);
		return url.protocol === "https:" && !url.username && !url.password;
	} catch {
		return false;
	}
}

/** Hand the browser to the identity provider (a seam so tests need not navigate). */
export function redirectToIdp(url: string): void {
	window.location.assign(url);
}

/** Begin a sign-in (or, with mode "link", an identity link for the signed-in user). */
export async function startOidcFlow(input: {
	email?: string;
	providerId?: string;
	mode?: OidcFlowMode;
	returnTo: string;
}): Promise<OidcStartResult> {
	const mode = input.mode ?? "login";
	const verifier = randomVerifier();
	try {
		sessionStorage.setItem(
			BINDING_KEY,
			JSON.stringify({
				verifier,
				mode,
				returnTo: input.returnTo,
				startedAt: Date.now(),
			} satisfies StoredBinding),
		);
	} catch {
		return {
			ok: false,
			message: "This browser blocks the storage single sign-on needs. Enable it and try again.",
		};
	}
	const { data, error } = await supabase.functions.invoke("oidc-sso", {
		body: {
			action: "start",
			mode,
			binding_challenge: await sha256Hex(verifier),
			...(input.providerId
				? { provider_id: input.providerId }
				: { email: input.email?.trim().toLowerCase() }),
		},
	});
	const url = (data as { authorization_url?: unknown } | null)?.authorization_url;
	if (error || !isSafeIdpUrl(url)) {
		clearBinding();
		const code = (await readFunctionError(error, data)).error;
		return {
			ok: false,
			message: (code && SAFE_MESSAGES[code]) || "Single sign-on is unavailable. Try again later.",
		};
	}
	return { ok: true, url };
}

/** Finish the flow at /auth/oidc/callback. */
export async function completeOidcFlow(search: string): Promise<OidcCallbackResult> {
	const params = new URLSearchParams(search);
	const binding = readBinding();
	// The binding is single-use whether or not the flow succeeds.
	clearBinding();
	const code = params.get("code");
	const state = params.get("state");
	if (params.get("error") || !code || !state || !binding)
		return { ok: false, message: LOGIN_FAILURES.request_invalid as string };

	const { data, error } = await supabase.functions.invoke("oidc-sso", {
		body: { action: "callback", code, state, binding_verifier: binding.verifier },
	});
	const result = (data ?? {}) as Record<string, unknown>;
	if (error || result.ok !== true) {
		const details = await readFunctionError(error, data);
		return {
			ok: false,
			message:
				LOGIN_FAILURES[details.reason ?? ""] ??
				SAFE_MESSAGES[details.error ?? ""] ??
				"Single sign-on failed. Try again.",
		};
	}
	if (binding.mode === "link") return { ok: true, mode: "link", returnTo: binding.returnTo };

	const tokenHash = typeof result.token_hash === "string" ? result.token_hash : "";
	const ticket = typeof result.login_ticket === "string" ? result.login_ticket : "";
	if (!/^[0-9a-f]{64}$/i.test(tokenHash) || !/^[A-Za-z0-9_-]{32,128}$/.test(ticket))
		return { ok: false, message: LOGIN_FAILURES.session_unavailable as string };

	// Redeem the one-time Auth token, then prove possession of the login ticket so
	// the server binds THIS session to the provider. Until it does, tenant data
	// stays locked for an enforcing workspace.
	const verified = await supabase.auth.verifyOtp({ token_hash: tokenHash, type: "magiclink" });
	if (verified.error || !verified.data.session)
		return { ok: false, message: LOGIN_FAILURES.session_unavailable as string };
	const bound = await supabase.functions.invoke("oidc-sso", {
		body: { action: "bind_session", login_ticket: ticket },
	});
	if (bound.error || (bound.data as { ok?: unknown } | null)?.ok !== true) {
		await supabase.auth.signOut();
		return { ok: false, message: LOGIN_FAILURES.session_unavailable as string };
	}
	return { ok: true, mode: "login", returnTo: binding.returnTo };
}
