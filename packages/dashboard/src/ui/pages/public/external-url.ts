export function safeExternalUrl(value: string | undefined, allowMailto = false): string | null {
	if (!value || /[\u0000-\u001f\u007f]/.test(value)) return null;
	try {
		const parsed = new URL(value);
		if (
			!parsed.username &&
			!parsed.password &&
			(parsed.protocol === "https:" || (allowMailto && parsed.protocol === "mailto:"))
		) {
			return parsed.toString();
		}
	} catch {
		// Invalid deployment configuration is rendered as a visible fail-closed notice.
	}
	return null;
}
