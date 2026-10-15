// Browser side of tenant OIDC SSO. The IdP redirects back to /auth/oidc/callback;
// the code and state are handed to the `oidc-sso` Edge function together with a
// per-tab binding secret that never leaves this browser except in that call.
// The secret's hash is registered at start, so a callback URL replayed into a
// different browser (login CSRF) cannot complete the flow.

import type { DashboardMessageKey } from "../i18n/en";
import { englishT, type Translate } from "../i18n/I18nProvider";
import { supabase } from "../lib/supabase";

const BINDING_KEY = "aidr.oidc.binding.v1";
const MAX_FLOW_AGE_MS = 15 * 60_000;

export type OidcFlowMode = "login" | "link";
type StoredBinding = { verifier: string; mode: OidcFlowMode; returnTo: string; startedAt: number };

export type OidcStartResult = { ok: true; url: string } | { ok: false; message: string };
export type OidcCallbackResult =
	| { ok: true; mode: OidcFlowMode; returnTo: string }
	| { ok: false; message: string };

const SAFE_MESSAGES: Record<string, DashboardMessageKey> = {
	sso_not_available: "of.notAvailable",
	rate_limited: "of.rateLimited",
	tenant_not_authorized: "of.notMember",
	mfa_required: "saml.err.mfa",
	sso_required: "of.ssoRequired",
};

const LOGIN_FAILURES: Record<string, DashboardMessageKey> = {
	request_invalid: "of.requestInvalid",
	binding_mismatch: "of.bindingMismatch",
	token_invalid: "of.tokenInvalid",
	token_exchange_failed: "of.exchangeFailed",
	domain_not_verified: "of.domain",
	email_claim_missing: "of.noEmail",
	not_provisioned: "of.notProvisioned",
	group_not_mapped: "of.groupNotMapped",
	groups_overage: "of.groupsOverage",
	identity_conflict: "of.identityConflict",
	provider_unavailable: "of.providerUnavailable",
	session_unavailable: "of.sessionUnavailable",
};

function lookup(map: Record<string, DashboardMessageKey>, code: string | undefined | null) {
	return code && Object.hasOwn(map, code) ? map[code] : undefined;
}

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
	/** Message language; English when omitted. */
	t?: Translate;
}): Promise<OidcStartResult> {
	const t = input.t ?? englishT;
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
			message: t("of.storageBlocked"),
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
			message: t(lookup(SAFE_MESSAGES, code) ?? "of.unavailable"),
		};
	}
	return { ok: true, url };
}

/** Finish the flow at /auth/oidc/callback. */
export async function completeOidcFlow(
	search: string,
	t: Translate = englishT,
): Promise<OidcCallbackResult> {
	const params = new URLSearchParams(search);
	const binding = readBinding();
	// The binding is single-use whether or not the flow succeeds.
	clearBinding();
	const code = params.get("code");
	const state = params.get("state");
	if (params.get("error") || !code || !state || !binding)
		return { ok: false, message: t("of.requestInvalid") };

	const { data, error } = await supabase.functions.invoke("oidc-sso", {
		body: { action: "callback", code, state, binding_verifier: binding.verifier },
	});
	const result = (data ?? {}) as Record<string, unknown>;
	if (error || result.ok !== true) {
		const details = await readFunctionError(error, data);
		return {
			ok: false,
			message: t(
				lookup(LOGIN_FAILURES, details.reason) ??
					lookup(SAFE_MESSAGES, details.error) ??
					"oidc.failed",
			),
		};
	}
	if (binding.mode === "link") return { ok: true, mode: "link", returnTo: binding.returnTo };

	const tokenHash = typeof result.token_hash === "string" ? result.token_hash : "";
	const ticket = typeof result.login_ticket === "string" ? result.login_ticket : "";
	if (!/^[0-9a-f]{64}$/i.test(tokenHash) || !/^[A-Za-z0-9_-]{32,128}$/.test(ticket))
		return { ok: false, message: t("of.sessionUnavailable") };

	// Redeem the one-time Auth token, then prove possession of the login ticket so
	// the server binds THIS session to the provider. Until it does, tenant data
	// stays locked for an enforcing workspace.
	const verified = await supabase.auth.verifyOtp({ token_hash: tokenHash, type: "magiclink" });
	if (verified.error || !verified.data.session)
		return { ok: false, message: t("of.sessionUnavailable") };

	const bound = await supabase.functions.invoke("oidc-sso", {
		body: { action: "bind_session", login_ticket: ticket },
	});
	if (bound.error || (bound.data as { ok?: unknown } | null)?.ok !== true) {
		await supabase.auth.signOut();
		return { ok: false, message: t("of.sessionUnavailable") };
	}
	return { ok: true, mode: "login", returnTo: binding.returnTo };
}

type JitRole = "admin" | "member" | "viewer";
export type JitMappingLine = { group: string; role: JitRole };

/**
 * Parse the just-in-time group mapping textarea: one `value=role` per line.
 * The LAST `=` separates the role, so LDAP-style group DNs such as
 * `cn=aidr-admins,ou=groups,dc=corp,dc=example=admin` keep their own `=`.
 * Blank lines are ignored; the first malformed line is reported (1-based).
 */
export function parseJitMappingLines(
	text: string,
): { ok: true; mappings: JitMappingLine[] } | { ok: false; line: number } {
	const mappings: JitMappingLine[] = [];
	for (const [index, raw] of text.split(/\r?\n/).entries()) {
		const line = raw.trim();
		if (!line) continue;
		const separator = line.lastIndexOf("=");
		const group = separator > 0 ? line.slice(0, separator).trim() : "";
		const role = line
			.slice(separator + 1)
			.trim()
			.toLowerCase();
		if (!group || (role !== "admin" && role !== "member" && role !== "viewer"))
			return { ok: false, line: index + 1 };
		mappings.push({ group, role });
	}
	return { ok: true, mappings };
}

export function formatJitMappingLines(mappings: readonly JitMappingLine[]): string {
	return mappings.map((mapping) => `${mapping.group}=${mapping.role}`).join("\n");
}
