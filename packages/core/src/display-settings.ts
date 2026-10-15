/**
 * Display-only settings recorded when the configuration is loaded, so message
 * builders that never see the configuration (block messages on every
 * connector) can still show them. Same pattern as `setConfiguredLocale`.
 * Nothing here changes enforcement.
 */

/**
 * A link an administrator configured, safe to print: http(s) only, no
 * credentials, no whitespace, control or bidi characters. Null otherwise; a
 * bad value is dropped, never "fixed".
 */
export function safeDisplayUrl(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	if (!trimmed || trimmed.length > 2048 || /[\p{Cc}\p{Cf}\s]/u.test(trimmed)) return null;
	try {
		const url = new URL(trimmed);
		if (url.protocol !== "https:" && url.protocol !== "http:") return null;
		if (url.username || url.password) return null;
		return url.toString();
	} catch {
		return null;
	}
}

let supportContactUrl: string | null = null;

/** Record `support_contact_url` from the loaded configuration (loadConfig calls this). */
export function setConfiguredSupportContact(value: unknown): void {
	supportContactUrl = safeDisplayUrl(value);
}

/** Where a developer reports a false positive, when the organisation configured it. */
export function configuredSupportContact(): string | null {
	return supportContactUrl;
}
