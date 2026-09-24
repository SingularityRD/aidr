/**
 * High-precision post-filters for common-PII matches.
 *
 * The DLP `PiiDetectorImpl` patterns are deliberately broad: its phone pattern
 * accepts any run of 7-15 digits and its SSN pattern any nine digits. That
 * recall is useful when a tenant writes a policy around it, but on ordinary
 * agent traffic it turns epoch timestamps, order ids and IP addresses into
 * "PII". Every enforcing caller (tool-output quarantine, the built-in DLP
 * baseline on tool input) filters matches through these checks first, so a
 * finding means a value that actually looks like the claimed PII type.
 */
import { luhnCheck, PiiDetectorImpl, type PiiMatch } from "./dlp/pii-detector.js";

export interface PiiPrecisionOptions {
	/**
	 * Require an explicit "SSN" / "social security" label shortly before a
	 * formatted SSN. Used for free-form tool output, where a bare 3-2-4 digit
	 * group is too weak to quarantine a whole result.
	 */
	requireSsnContext?: boolean;
}

const CARD_GROUPINGS = new Set(["4-4-4-4", "4-4-4-4-3", "4-6-5", "4-6-4"]);
const SSN_CONTEXT =
	/\b(?:ssn|social[\s_-]+security(?:[\s_-]+(?:number|no\.?|#))?|soc\.?\s*sec\.?)\b/i;

/**
 * Issuer (IIN) ranges and valid lengths of the major card networks:
 * `[prefix digits, lowest prefix, highest prefix, shortest length, longest length]`.
 */
const CARD_NETWORKS: ReadonlyArray<readonly [number, number, number, number, number]> = [
	[1, 4, 4, 13, 13], // Visa
	[1, 4, 4, 16, 16],
	[1, 4, 4, 19, 19],
	[2, 51, 55, 16, 16], // Mastercard
	[4, 2221, 2720, 16, 16],
	[2, 34, 34, 15, 15], // American Express
	[2, 37, 37, 15, 15],
	[4, 6011, 6011, 16, 19], // Discover
	[2, 65, 65, 16, 19],
	[3, 644, 649, 16, 19],
	[4, 3528, 3589, 16, 19], // JCB
	[3, 300, 305, 14, 19], // Diners Club
	[2, 36, 36, 14, 19],
	[2, 38, 38, 14, 19],
	[2, 62, 62, 16, 19], // UnionPay
];

function hasCardBrand(digits: string): boolean {
	return CARD_NETWORKS.some(([prefixLength, low, high, minLength, maxLength]) => {
		const prefix = Number(digits.slice(0, prefixLength));
		return (
			prefix >= low && prefix <= high && digits.length >= minLength && digits.length <= maxLength
		);
	});
}

/** Luhn-valid, issued by a known network, and written the way cards are written. */
export function isPlausibleCardNumber(value: string): boolean {
	if (!/^\d[\d -]*\d$/.test(value)) return false;
	const separators = value.match(/[ -]/g) ?? [];
	if (separators.length > 0) {
		if (new Set(separators).size !== 1) return false;
		const grouping = value
			.split(separators[0] ?? " ")
			.map((group) => group.length)
			.join("-");
		if (!CARD_GROUPINGS.has(grouping)) return false;
	}
	const digits = value.replace(/\D/g, "");
	if (/^(\d)\1+$/.test(digits)) return false;
	return luhnCheck(digits) && hasCardBrand(digits);
}

/**
 * International numbers must carry their `+` country prefix; national numbers
 * must use the NANP 3-3-4 layout with separators. A bare digit run (epoch
 * seconds, order ids) or a dotted quad is never a phone number here.
 */
export function isPlausiblePhoneNumber(match: PiiMatch, text: string): boolean {
	const previous = text[match.start - 1];
	const value = previous === "+" || previous === "(" ? `${previous}${match.value}` : match.value;
	const digits = value.replace(/\D/g, "");
	if (digits.length < 10 || digits.length > 15) return false;
	if (value.startsWith("+"))
		return /^\+\d{1,3}[-\s.]?(?:\(?\d{1,4}\)?[-\s.]?){1,4}\d{2,5}$/.test(value);
	return /^(?:1[-\s.])?(?:\(\d{3}\)\s?|\d{3}[-\s.])\d{3}[-\s.]\d{4}$/.test(value);
}

/** Only the canonical dashed layout; nine bare digits are an id, not an SSN. */
export function isPlausibleSsn(match: PiiMatch, text: string, requireContext: boolean): boolean {
	if (!/^\d{3}-\d{2}-\d{4}$/.test(match.value)) return false;
	if (!requireContext) return true;
	return SSN_CONTEXT.test(text.slice(Math.max(0, match.start - 48), match.start));
}

/** True when a raw `PiiDetectorImpl` match survives the precision checks for its type. */
export function isPrecisePiiMatch(
	match: PiiMatch,
	text: string,
	options: PiiPrecisionOptions = {},
): boolean {
	switch (match.type) {
		case "credit_card":
			return isPlausibleCardNumber(match.value);
		case "phone":
			return isPlausiblePhoneNumber(match, text);
		case "ssn":
			return isPlausibleSsn(match, text, options.requireSsnContext === true);
		case "email":
			return true;
		default:
			// IP addresses and generic key prefixes are not PII verdicts on their own.
			return false;
	}
}

/**
 * Detector for the built-in common-PII baseline: SSN, payment card, email and
 * phone. IP addresses and loose key prefixes are handled by secret detection.
 */
const COMMON_PII_DETECTOR = new PiiDetectorImpl({
	enableIpAddress: false,
	enableAwsKey: false,
	enableApiKey: false,
});

/** Common PII in `text` that passes the precision checks, ordered by position. */
export function detectPreciseCommonPii(
	text: string,
	options: PiiPrecisionOptions & { types?: ReadonlyArray<PiiMatch["type"]> } = {},
): PiiMatch[] {
	return COMMON_PII_DETECTOR.detect(text).filter(
		(match) =>
			(options.types === undefined || options.types.includes(match.type)) &&
			isPrecisePiiMatch(match, text, options),
	);
}
