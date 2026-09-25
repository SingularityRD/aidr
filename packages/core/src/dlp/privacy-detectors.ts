/**
 * Adapter between the vendored AIDR Privacy rule layer (`./privacy-rules/`, generated
 * by scripts/sync-privacy-rules.mjs) and the core DLP vocabulary.
 *
 * The privacy rules are pure and synchronous: no NER, no I/O, no timers. A scan that
 * cannot inspect all of its input reports `incomplete` with static reason codes; callers
 * that enforce policy must treat that as a failed inspection, never as a clean result.
 *
 * @module dlp/privacy-detectors
 */

import type { DlpDetector } from "./policy.js";
import { keyType } from "./privacy-rules/detectors.js";
import { type RuleFinding, scanText } from "./privacy-rules/rules.js";
import type { EntityType } from "./privacy-rules/types.js";

/** Core detector name (snake_case policy data) → privacy entity type. */
export const DLP_DETECTOR_ENTITY_TYPES: Readonly<Record<DlpDetector, EntityType>> = Object.freeze({
	tc_kimlik: "TC_KIMLIK",
	iban: "IBAN",
	phone: "PHONE",
	email: "EMAIL",
	credit_card: "CREDIT_CARD",
	us_ssn: "US_SSN",
	address: "ADDRESS",
	person: "PERSON",
	date_of_birth: "DATE_OF_BIRTH",
	passport: "PASSPORT",
	national_id: "NATIONAL_ID",
	tax_id: "TAX_ID",
	bank_account: "BANK_ACCOUNT",
	ip_address: "IP_ADDRESS",
	mac_address: "MAC_ADDRESS",
	secret: "SECRET",
	private_key: "PRIVATE_KEY",
	classified: "CLASSIFIED",
});

const ENTITY_DETECTORS: ReadonlyMap<EntityType, DlpDetector> = new Map(
	Object.entries(DLP_DETECTOR_ENTITY_TYPES).map(([detector, type]) => [
		type,
		detector as DlpDetector,
	]),
);

function digitCount(value: string): number {
	let count = 0;
	for (const character of value) if (character >= "0" && character <= "9") count++;
	return count;
}

/**
 * Minimum shape for a value the privacy rules attributed to a numeric identifier.
 * The rules deliberately protect a labelled value even when its checksum fails; that
 * stays true here. What this rejects is a label followed by no identifier at all, as
 * in source code and schemas (`phone: string`, `tc = 'x'`, `iban: IbanType`).
 */
const VALUE_SHAPES: Partial<Record<DlpDetector, (value: string) => boolean>> = {
	tc_kimlik: (value) => digitCount(value) >= 6,
	iban: (value) => /^[A-Za-z]{2}[ -]?[0-9]{2}/.test(value.trim()),
	phone: (value) => {
		const digits = digitCount(value);
		return digits >= 7 && digits <= 15;
	},
	credit_card: (value) => digitCount(value) >= 12,
	us_ssn: (value) => digitCount(value) >= 4,
	date_of_birth: (value) => digitCount(value) >= 1,
	passport: (value) => digitCount(value) >= 1,
	national_id: (value) => digitCount(value) >= 1,
	tax_id: (value) => digitCount(value) >= 1,
	bank_account: (value) => digitCount(value) >= 1,
};

/** true when `value` is shaped like the identifier `detector` reports. */
export function isPlausibleDetectorValue(detector: DlpDetector, value: string): boolean {
	return VALUE_SHAPES[detector]?.(value) ?? true;
}

/**
 * The enabled detector implied by a structured-data key such as `tckn`, `iban`,
 * `telefon` or `password` (normalized, Turkish-aware), if any.
 */
export function detectorForKey(
	key: string,
	detectors: readonly DlpDetector[],
): DlpDetector | undefined {
	const type = keyType(key);
	const detector = type === undefined ? undefined : ENTITY_DETECTORS.get(type);
	return detector !== undefined && detectors.includes(detector) ? detector : undefined;
}

/** Upper bound matching the privacy normalizer's own 1 MiB working-text limit. */
export const PRIVACY_DETECTOR_MAX_CHARS = 1024 * 1024;

export interface PrivacyDetectorMatch {
	readonly detector: DlpDetector;
	/** Half-open UTF-16 offsets into the scanned string. */
	readonly start: number;
	readonly end: number;
	/** Heuristic score, not a calibrated probability. */
	readonly score: number;
}

export interface PrivacyDetectorScan {
	readonly matches: readonly PrivacyDetectorMatch[];
	/** true when part of the input was not inspected; matches are then only a lower bound. */
	readonly incomplete: boolean;
	/** Static reason codes; never contain input text. */
	readonly reasons: readonly string[];
}

/** `finding` (found in the text starting at `base`) as a match, if its value is plausible. */
function plausibleMatch(
	text: string,
	base: number,
	finding: RuleFinding,
): PrivacyDetectorMatch | undefined {
	const detector = ENTITY_DETECTORS.get(finding.type);
	const start = base + finding.start;
	const end = base + finding.end;
	if (!detector || !isPlausibleDetectorValue(detector, text.slice(start, end))) return undefined;
	return { detector, start, end, score: finding.score };
}

/**
 * Scan `text` with the vendored TR/EN privacy rules, reporting only `detectors`.
 * Overlapping findings of the enabled types are unioned (never partially exposed).
 *
 * The rules protect a labelled field to the end of its line and give a union the type of its
 * highest-priority member, so `Tel: 0532 123 45 67 IBAN TR33 …` comes back as one IBAN finding
 * that starts with a phone number. The shape check is for a single value; a union that fails it
 * is re-scanned without its label and the plausible values inside it are kept, instead of
 * dropping every value the field ran into.
 */
export function scanPrivacyDetectors(
	text: string,
	detectors: readonly DlpDetector[],
	maxChars: number = PRIVACY_DETECTOR_MAX_CHARS,
): PrivacyDetectorScan {
	const options = {
		enabled: detectors.map((detector) => DLP_DETECTOR_ENTITY_TYPES[detector]),
		maxChars: Math.min(Math.max(1, maxChars), PRIVACY_DETECTOR_MAX_CHARS),
	};
	const result = scanText(text, options);
	const reasons = new Set(result.reasons);
	const matches: PrivacyDetectorMatch[] = [];
	for (const finding of result.findings) {
		const match = plausibleMatch(text, 0, finding);
		if (match) {
			matches.push(match);
			continue;
		}
		// Values inside a union lie within it, so matches stay sorted and disjoint.
		const inner = scanText(text.slice(finding.start, finding.end), options);
		for (const reason of inner.reasons) reasons.add(reason);
		for (const value of inner.findings) {
			const valueMatch = plausibleMatch(text, finding.start, value);
			if (valueMatch) matches.push(valueMatch);
		}
	}
	return { matches, incomplete: reasons.size > 0, reasons: [...reasons].sort() };
}

/** Constant, type-only placeholder for a redacted detector match, e.g. `[TC_KIMLIK]`. */
export function privacyDetectorPlaceholder(detector: DlpDetector): string {
	return `[${DLP_DETECTOR_ENTITY_TYPES[detector]}]`;
}
