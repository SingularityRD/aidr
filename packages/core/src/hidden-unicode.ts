/**
 * Invisible-Unicode inspection shared by output inspection (read time) and the
 * context-poisoning detector (write time).
 *
 * Three smuggling techniques are recognised:
 *   - Unicode tag characters (U+E0000-E007F) mirror printable ASCII but render
 *     as nothing, so a sentence can be hidden inside any text a model reads.
 *     Emoji subdivision flags (U+1F3F4 followed by tag characters, e.g. the
 *     flag of England) are the one legitimate use and are exempted.
 *   - Long runs of zero-width characters, which encode bits (a common
 *     steganographic scheme); real prose never has eight in a row.
 *   - Bidirectional control characters, which make text read differently from
 *     how it displays (Trojan Source).
 *
 * No Node.js APIs are used, so browser-side callers may import it as well.
 */

const BLACK_FLAG = 0x1f3f4;
const TAG_FIRST = 0xe0000;
const TAG_LAST = 0xe007f;
const CANCEL_TAG = 0xe007f;
/** Longest legitimate flag tag sequence: region code plus CANCEL TAG. */
const MAX_FLAG_TAGS = 7;

const ZERO_WIDTH = new Set([
	0x180e, 0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff,
]);
const BIDI_CONTROL = /[\u202A-\u202E\u2066-\u2069]/g;

/** Zero-width runs at least this long are treated as an encoded payload. */
export const ZERO_WIDTH_PAYLOAD_RUN = 8;

export interface HiddenUnicodeReport {
	/** ASCII decoded from tag characters outside emoji flag sequences. */
	tagText: string;
	/** Tag characters outside emoji flag sequences. */
	tagCount: number;
	/** Bidirectional embedding, override and isolate controls. */
	bidiCount: number;
	/** Longest run of consecutive zero-width characters. */
	longestZeroWidthRun: number;
}

function isTag(codePoint: number): boolean {
	return codePoint >= TAG_FIRST && codePoint <= TAG_LAST;
}

export function inspectHiddenUnicode(text: string): HiddenUnicodeReport {
	let tagText = "";
	let tagCount = 0;
	let longestZeroWidthRun = 0;
	let zeroWidthRun = 0;
	// Tag characters still allowed as part of an emoji flag sequence.
	let flagBudget = 0;
	for (const character of text) {
		const codePoint = character.codePointAt(0) ?? 0;
		if (ZERO_WIDTH.has(codePoint)) {
			zeroWidthRun += 1;
			if (zeroWidthRun > longestZeroWidthRun) longestZeroWidthRun = zeroWidthRun;
		} else {
			zeroWidthRun = 0;
		}
		if (codePoint === BLACK_FLAG) {
			flagBudget = MAX_FLAG_TAGS;
			continue;
		}
		if (!isTag(codePoint)) {
			flagBudget = 0;
			continue;
		}
		if (flagBudget > 0) {
			flagBudget = codePoint === CANCEL_TAG ? 0 : flagBudget - 1;
			continue;
		}
		tagCount += 1;
		const ascii = codePoint - TAG_FIRST;
		if (ascii >= 0x20 && ascii <= 0x7e) tagText += String.fromCharCode(ascii);
	}
	const bidiCount = text.match(BIDI_CONTROL)?.length ?? 0;
	return { tagText, tagCount, bidiCount, longestZeroWidthRun };
}

/**
 * Text with every invisible or bidirectional control character rendered as
 * `<U+XXXX>`, so a reviewer sees what a model would read.
 */
export function renderInvisibleCharacters(text: string): string {
	let rendered = "";
	for (const character of text) {
		const codePoint = character.codePointAt(0) ?? 0;
		rendered +=
			isTag(codePoint) ||
			ZERO_WIDTH.has(codePoint) ||
			/[\u202A-\u202E\u2066-\u2069]/.test(character)
				? `<U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}>`
				: character;
	}
	return rendered;
}
