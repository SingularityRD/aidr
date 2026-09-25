/**
 * Commercial controls for the direct-GA release profile.
 *
 * The default is deliberately invoice-only. Self-service checkout is an
 * explicitly opt-in legacy/staging mode and must never be enabled by an
 * unreviewed production build.
 */
const requestedMode = (import.meta.env.VITE_AIDR_COMMERCIAL_MODE ?? "invoice").trim().toLowerCase();

export const selfServiceCheckoutEnabled = requestedMode === "self-service";

export function safeCommercialLink(
	value: string | undefined | null,
	allowMailto = false,
): string | null {
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
		return null;
	}
	return null;
}

export function getSalesContactHref(): string | null {
	const salesUrl = safeCommercialLink(import.meta.env.VITE_SALES_URL, true);
	if (salesUrl) return salesUrl;

	const salesEmail = import.meta.env.VITE_SALES_EMAIL?.trim();
	return salesEmail ? safeCommercialLink(`mailto:${salesEmail}`, true) : null;
}

/**
 * Product-owner decision: prices are not published anywhere customer-facing.
 * Every paid edition is quoted; this address is the fixed quote channel.
 */
export const QUOTE_CONTACT_EMAIL = "anil@singularityrd.com";

/** mailto: link for a quote request, optionally naming the edition. */
export function quoteRequestHref(edition?: string): string {
	const subject = edition
		? `Singularity AIDR ${edition} quote request`
		: "Singularity AIDR quote request";
	return `mailto:${QUOTE_CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}`;
}
