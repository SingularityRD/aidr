const RECOVERY_CODE_BYTES = 20;
const RECOVERY_CODE_COUNT = 8;
const MIN_PASSWORD_LENGTH = 14;
const MAX_PASSWORD_LENGTH = 128;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECOVERY_TOKEN_HASH_RE = /^[0-9a-f]{64}$/i;

export function dashboardRecoveryUrl(base: string): URL {
	const configured = new URL(base);
	const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(configured.hostname);
	if ((configured.protocol !== "https:" && !(configured.protocol === "http:" && loopback)) ||
		configured.username || configured.password) {
		throw new Error("invalid_dashboard_url");
	}
	const url = new URL("/auth/recover", configured.origin);
	return url;
}

export function normalizeEmail(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const email = value.trim().toLowerCase();
	return email.length > 0 && email.length <= 254 && EMAIL_RE.test(email) ? email : null;
}

export function normalizeUuid(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const uuid = value.trim().toLowerCase();
	return UUID_RE.test(uuid) ? uuid : null;
}

export function normalizeRecoveryTokenHash(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const tokenHash = value.trim().toLowerCase();
	return RECOVERY_TOKEN_HASH_RE.test(tokenHash) ? tokenHash : null;
}

export function normalizeRecoveryCode(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const normalized = value.replace(/[^0-9a-f]/gi, "").toLowerCase();
	return /^[0-9a-f]{40}$/.test(normalized) ? normalized : null;
}

export function formatRecoveryCode(value: string): string {
	const normalized = normalizeRecoveryCode(value);
	if (!normalized) throw new Error("invalid_recovery_code");
	return normalized.toUpperCase().match(/.{1,5}/g)?.join("-") ?? "";
}

export function generateRecoveryCodes(
	count = RECOVERY_CODE_COUNT,
	randomValues: (bytes: Uint8Array) => Uint8Array = (bytes) => crypto.getRandomValues(bytes),
): string[] {
	if (!Number.isInteger(count) || count < 4 || count > 16) {
		throw new Error("invalid_recovery_code_count");
	}
	const seen = new Set<string>();
	while (seen.size < count) {
		const bytes = randomValues(new Uint8Array(RECOVERY_CODE_BYTES));
		if (!(bytes instanceof Uint8Array) || bytes.length !== RECOVERY_CODE_BYTES) {
			throw new Error("invalid_random_source");
		}
		const raw = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
		seen.add(formatRecoveryCode(raw));
	}
	return [...seen];
}

export function validateNewPassword(value: unknown): string | null {
	if (typeof value !== "string") return null;
	if (value.length < MIN_PASSWORD_LENGTH || value.length > MAX_PASSWORD_LENGTH) return null;
	if (/^\s|\s$/.test(value)) return null;
	const normalized = value.toLowerCase().replace(/[^a-z0-9]/g, "");
	if (["passwordpassword", "changemepassword", "singularityaidr", "administrator"].includes(normalized)) {
		return null;
	}
	return value;
}

function jwtPayload(token: string): Record<string, unknown> | null {
	const encoded = token.split(".")[1];
	if (!encoded) return null;
	try {
		const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(encoded.length / 4) * 4, "=");
		const payload: unknown = JSON.parse(atob(base64));
		return payload && typeof payload === "object" && !Array.isArray(payload)
			? (payload as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}

export function jwtIssuedAtMs(token: string): number | null {
	const issuedAt = jwtPayload(token)?.iat;
	return typeof issuedAt === "number" && Number.isFinite(issuedAt) && issuedAt > 0
		? issuedAt * 1000
		: null;
}

export function jwtExpiresAtMs(token: string): number | null {
	const expiresAt = jwtPayload(token)?.exp;
	if (typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) return null;
	const milliseconds = expiresAt * 1000;
	return Number.isSafeInteger(milliseconds) && Number.isFinite(new Date(milliseconds).getTime())
		? milliseconds
		: null;
}

export function jwtHasAuthenticationMethod(token: string, requiredMethod: string): boolean {
	const entries = jwtPayload(token)?.amr;
	if (!Array.isArray(entries)) return false;
	return entries.some((entry) => {
		if (entry === requiredMethod) return true;
		return Boolean(
			entry &&
				typeof entry === "object" &&
				!Array.isArray(entry) &&
				(entry as { method?: unknown }).method === requiredMethod,
		);
	});
}

export function jwtHasSamlProvider(token: string, providerId: string): boolean {
	const entries = jwtPayload(token)?.amr;
	if (!Array.isArray(entries)) return false;
	return entries.some((entry) => Boolean(
		entry &&
			typeof entry === "object" &&
			!Array.isArray(entry) &&
			(entry as { method?: unknown }).method === "sso/saml" &&
			(entry as { provider?: unknown }).provider === providerId,
	));
}

export function jwtSamlProviderId(token: string): string | null {
	const entries = jwtPayload(token)?.amr;
	if (!Array.isArray(entries)) return null;
	const providers = entries
		.filter((entry) => entry && typeof entry === "object" && !Array.isArray(entry) &&
			(entry as { method?: unknown }).method === "sso/saml")
		.map((entry) => normalizeUuid((entry as { provider?: unknown }).provider));
	return providers.length === 1 ? providers[0] ?? null : null;
}

export function jwtSessionId(token: string): string | null {
	return normalizeUuid(jwtPayload(token)?.session_id);
}

export function sessionPassesRevocationBarrier(
	token: string,
	revokedBefore: string | null | undefined,
): boolean {
	if (!revokedBefore) return true;
	const issuedAt = jwtIssuedAtMs(token);
	const barrier = Date.parse(revokedBefore);
	return issuedAt !== null && Number.isFinite(barrier) && issuedAt > barrier;
}

export function policyAllowsAssurance(requireMfa: boolean, assurance: string | null): boolean {
	return !requireMfa || assurance === "aal2";
}

export function recoveryCodeIssueError(
	actorUserId: string,
	targetUserId: string,
	): "recovery_code_issue_forbidden" | null {
	if (actorUserId !== targetUserId) return "recovery_code_issue_forbidden";
	return null;
}
