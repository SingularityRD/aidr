const KEY = "aidr.postAuthReturnTo.v1";

const FALLBACK_RETURN_TO = "/onboarding";

/**
 * Only allow an absolute path on this dashboard origin. In particular, do
 * not accept protocol-relative URLs (`//host`) or backslash variants that a
 * browser may normalize into an external navigation.
 */
function isSafeReturnTo(value: unknown): value is string {
	if (typeof value !== "string") return false;
	const candidate = value.trim();
	if (
		!candidate ||
		!candidate.startsWith("/") ||
		candidate.startsWith("//") ||
		candidate.includes("\\") ||
		/[\u0000-\u001f\u007f]/.test(candidate)
	)
		return false;
	try {
		const decoded = decodeURIComponent(candidate);
		if (decoded.startsWith("//") || decoded.includes("\\") || /[\u0000-\u001f\u007f]/.test(decoded))
			return false;
		const parsed = new URL(candidate, "https://aidr.invalid");
		return parsed.origin === "https://aidr.invalid";
	} catch {
		return false;
	}
}

export function sanitizeReturnTo(value: unknown, fallback = FALLBACK_RETURN_TO): string {
	return isSafeReturnTo(value) ? value.trim() : fallback;
}

export function setPostAuthReturnTo(path: unknown) {
	const safePath = sanitizeReturnTo(path);
	try {
		localStorage.setItem(KEY, safePath);
	} catch {
		// ignore
	}
}

export function takePostAuthReturnTo(): string | null {
	try {
		const v = localStorage.getItem(KEY);
		if (!v) return null;
		localStorage.removeItem(KEY);
		return isSafeReturnTo(v) ? v : null;
	} catch {
		return null;
	}
}

export function buildReturnToFromRequest(request: Request): string {
	try {
		const url = new URL(request.url);
		const path = `${url.pathname}${url.search}`;
		return sanitizeReturnTo(path, "/");
	} catch {
		return "/";
	}
}
