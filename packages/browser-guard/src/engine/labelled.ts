/**
 * Free-text detectors for entity types the shared privacy rule layer only recognises by JSON key
 * name (`username`, `healthId`, `plaka`...) or through the optional native NER host:
 * USERNAME, HEALTH_ID, LICENSE_PLATE and LOCATION.
 *
 * Every detector is deliberately conservative, because a false positive rewrites the user's prompt:
 * - USERNAME, HEALTH_ID and LOCATION fire only after an explicit Turkish or English label followed
 *   by `:` or `=` (`kullanıcı adı:`, `username=`, `SGK sicil no:`, `NHS number:`, `konum:`...).
 * - LICENSE_PLATE fires on a validated Turkish plate (province 01-81, plate alphabet, letter/digit
 *   grouping) written with spaces (`34 ABC 123`), or after a plate label; EU-style plates are
 *   recognised only after a label.
 * - Identifiers with a public check algorithm (NHS number, German KVNR) must pass it.
 *
 * All offsets refer to the `text` passed in; labels are matched on a length-preserving copy with
 * Turkish İ/ı folded to i. Enabled-type gating is the caller's job, except that LOCATION reuses
 * address labels only while ADDRESS itself is disabled (otherwise the ADDRESS rule already masks
 * the same span).
 */
import type { EntityType } from "../types.js";

type LabelledEvidence = "pattern" | "checksum" | "context";
export type LabelledEmit = (
	start: number,
	end: number,
	type: EntityType,
	score: number,
	evidence: LabelledEvidence,
) => void;

/** Length-preserving: JS case-insensitive matching does not fold Turkish dotted/dotless i. */
const foldLabel = (text: string): string => text.replace(/[İı]/g, "i");

const SEP = "[ \\t]*[:=][ \\t]*";
const BEFORE_LABEL = "(?<![\\p{L}\\p{N}_])";
const NO = "(?:no(?:su)?\\.?|numarasi|number|num\\.?|#)";

function labelRegex(labels: readonly string[], value: string, flags = "giu"): RegExp {
	return new RegExp(`${BEFORE_LABEL}(?:${labels.join("|")})${SEP}${value}`, flags);
}

/** Emits capture group 1 of every match that `accept` keeps. */
function each(
	labelText: string,
	re: RegExp,
	accept: (value: string, match: RegExpMatchArray) => boolean,
	emit: (start: number, end: number) => void,
): void {
	for (const m of labelText.matchAll(re)) {
		const value = m[1];
		if (!value || m.index === undefined) continue;
		const start = m.index + m[0].length - value.length;
		if (accept(value, m)) emit(start, start + value.length);
	}
}

// ---------------------------------------------------------------- USERNAME

const USERNAME_LABELS = [
	"kullanici[ \\t]*ad[i]?",
	"kullanici[ \\t]+(?:kodu|kimligi|id)",
	"user[ _-]?name",
	"user[ _-]?id",
	"login(?:[ _-]?(?:name|id))?",
	"giri[sş][ \\t]+ad[i]?",
	"oturum[ \\t]+ad[i]?",
];
const USERNAME_RE = labelRegex(
	USERNAME_LABELS,
	"(@?[\\p{L}\\p{N}][\\p{L}\\p{N}._-]{1,63})(?![\\p{L}\\p{N}._@-])",
);
/** Values that are field types, placeholders or outcomes rather than an account name. */
const USERNAME_STOPWORDS: ReadonlySet<string> = new Set([
	"string",
	"str",
	"number",
	"int",
	"integer",
	"boolean",
	"bool",
	"any",
	"null",
	"nil",
	"none",
	"undefined",
	"true",
	"false",
	"yes",
	"no",
	"evet",
	"hayir",
	"hayır",
	"yok",
	"var",
	"required",
	"optional",
	"function",
	"object",
	"text",
	"varchar",
	"failed",
	"fail",
	"failure",
	"success",
	"successful",
	"ok",
	"error",
	"basarili",
	"başarılı",
	"basarisiz",
	"başarısız",
	"empty",
	"bos",
	"boş",
	"unknown",
	"n/a",
	"na",
	"xxx",
]);

function plausibleUsername(value: string): boolean {
	const lower = value.toLocaleLowerCase("tr");
	if (USERNAME_STOPWORDS.has(lower) || USERNAME_STOPWORDS.has(value.toLowerCase())) return false;
	// `req.body.username`, `user.login`: code reading the field, not a value.
	if (/user_?name|login/i.test(value)) return false;
	return !/[._-]$/.test(value);
}

// ---------------------------------------------------------------- HEALTH_ID

const HEALTH_GENERIC_LABELS = [
	// Turkish: health insurance / SGK registration / patient and MEDULA numbers.
	`sa[gğ]l[i]k[ \\t]+(?:sigortas[i][ \\t]+|sigorta[ \\t]+)?(?:kimlik[ \\t]+)?${NO}`,
	`(?:sgk|ssk|ba[gğ]-?kur|emekli[ \\t]+sand[i][gğ][i])[ \\t]+(?:sicil[ \\t]+|tescil[ \\t]+)?${NO}`,
	`sigorta[ \\t]+(?:sicil|tescil)[ \\t]+${NO}`,
	`hasta[ \\t]+(?:protokol[ \\t]+|dosya[ \\t]+|kay[i]t[ \\t]+)?${NO}`,
	`medula[ \\t]+(?:takip[ \\t]+)?${NO}`,
	// English / EU.
	"health[ \\t]+(?:insurance[ \\t]+)?(?:card[ \\t]+)?(?:id|number|no\\.?|#)",
	"medical[ \\t]+(?:insurance[ \\t]+)?(?:card[ \\t]+)?(?:id|number|no\\.?)",
	"(?:medical|health)[ \\t]+record[ \\t]+(?:number|no\\.?|#)",
	"mrn",
	"patient[ \\t]+(?:id|number|no\\.?|#)",
	"(?:ehic|european[ \\t]+health[ \\t]+insurance[ \\t]+card)(?:[ \\t]+(?:number|no\\.?))?",
];
const NHS_LABELS = ["nhs[ \\t]+(?:number|no\\.?|#)"];
const KVNR_LABELS = ["krankenversichertennummer", "kvnr"];

/** Groups separated by one space or hyphen; every group carries a digit. */
const HEALTH_VALUE =
	"([A-Za-z0-9]*[0-9][A-Za-z0-9]*(?:[ -][A-Za-z0-9]*[0-9][A-Za-z0-9]*)*)(?![\\p{L}\\p{N}])";
const HEALTH_GENERIC_RE = labelRegex(HEALTH_GENERIC_LABELS, HEALTH_VALUE);
const NHS_RE = labelRegex(NHS_LABELS, HEALTH_VALUE);
const KVNR_RE = labelRegex(KVNR_LABELS, HEALTH_VALUE);

function plausibleHealthId(value: string): boolean {
	const alnum = value.replace(/[^A-Za-z0-9]/g, "");
	const digits = alnum.replace(/[^0-9]/g, "").length;
	return digits >= 5 && alnum.length <= 25;
}

/** UK NHS number: 10 digits, weights 10..2, check = 11 - (sum mod 11), 10 is invalid. */
export function validNhsNumber(value: string): boolean {
	const digits = value.replace(/[ -]/g, "");
	if (!/^[0-9]{10}$/.test(digits)) return false;
	let sum = 0;
	for (let i = 0; i < 9; i++) sum += Number(digits[i]) * (10 - i);
	let check = 11 - (sum % 11);
	if (check === 11) check = 0;
	return check !== 10 && check === Number(digits[9]);
}

/**
 * German Krankenversichertennummer: a letter and nine digits. The letter becomes its two-digit
 * alphabet position, then the first ten digits are weighted 1,2,1,2..., products cross-summed,
 * and the total mod 10 is the ninth digit.
 */
export function validKvnr(value: string): boolean {
	const compact = value.replace(/[ -]/g, "").toUpperCase();
	if (!/^[A-Z][0-9]{9}$/.test(compact)) return false;
	const letter = String(compact.charCodeAt(0) - 64).padStart(2, "0");
	const digits = `${letter}${compact.slice(1, 9)}`;
	let sum = 0;
	for (let i = 0; i < digits.length; i++) {
		const product = Number(digits[i]) * (i % 2 === 0 ? 1 : 2);
		sum += product > 9 ? product - 9 : product;
	}
	return sum % 10 === Number(compact[9]);
}

// ---------------------------------------------------------------- LICENSE_PLATE

/** Letters used on Turkish plates (no Ç, Ğ, İ, Ö, Ş, Ü, Q, W, X). */
const TR_PLATE_LETTERS = /^[ABCDEFGHIJKLMNOPRSTUVYZ]{1,3}$/;
/** Unit, currency and other uppercase tokens that make `16 GB 512` look like a plate. */
const PLATE_BLOCKLIST: ReadonlySet<string> = new Set([
	"KB",
	"MB",
	"GB",
	"TB",
	"PB",
	"HZ",
	"KHZ",
	"MHZ",
	"GHZ",
	"MS",
	"NS",
	"KM",
	"CM",
	"MM",
	"KG",
	"MG",
	"ML",
	"TL",
	"TRY",
	"USD",
	"EUR",
	"GBP",
	"AM",
	"PM",
	"UTC",
	"GMT",
	"CPU",
	"GPU",
	"RAM",
	"SSD",
	"HDD",
	"PC",
	"ID",
	"NO",
	"PR",
	"TR",
	"EN",
	"ABD",
	"VS",
	"KW",
	"HP",
]);

/** Validates a Turkish plate: province 01-81, 1-3 plate letters, digit count matching the letters. */
export function validTurkishPlate(province: string, letters: string, digits: string): boolean {
	const code = Number(province);
	if (province.length !== 2 || code < 1 || code > 81) return false;
	if (!TR_PLATE_LETTERS.test(letters) || !/^[0-9]{2,5}$/.test(digits)) return false;
	if (/^0+$/.test(digits)) return false;
	const n = digits.length;
	switch (letters.length) {
		case 1:
			return n === 4 || n === 5;
		case 2:
			return n === 3 || n === 4;
		default:
			return n === 2 || n === 3;
	}
}

/** `34 ABC 123` with single spaces, uppercase, outside a larger token or number. */
const TR_PLATE_RE =
	/(?<![\p{L}\p{N}.,:/#$€£₺+-])([0-9]{2}) ([A-Z]{1,3}) ([0-9]{2,5})(?![\p{L}\p{N}]|[.,:/-][0-9])/gu;

const PLATE_LABELS = [
	"plaka(?:[ \\t]+(?:no(?:su)?|numarasi))?",
	"ara[cç][ \\t]+plakas[i]",
	"(?:license|licence|number|registration|vehicle|car)[ \\t]+plate(?:[ \\t]+(?:number|no\\.?))?",
	"plate[ \\t]+(?:number|no\\.?)",
	"(?:vehicle|car)[ \\t]+registration(?:[ \\t]+(?:number|no\\.?))?",
	"kennzeichen",
	"immatriculation",
];
/** One to four alphanumeric groups of 1-4 characters, separated by a space, hyphen or dot. */
const PLATE_LABELLED_RE = labelRegex(
	PLATE_LABELS,
	"([A-Za-z0-9ÄÖÜäöü]{1,4}(?:[ .·-]?[A-Za-z0-9ÄÖÜäöü]{1,4}){0,3})(?![\\p{L}\\p{N}])",
);

function labelledPlate(value: string): "tr" | "eu" | null {
	const tr = /^([0-9]{2})[ -]?([A-Za-z]{1,3})[ -]?([0-9]{2,5})$/.exec(value);
	if (tr && validTurkishPlate(tr[1] as string, (tr[2] as string).toUpperCase(), tr[3] as string)) {
		return "tr";
	}
	const alnum = value.replace(/[^\p{L}\p{N}]/gu, "");
	if (alnum.length < 4 || alnum.length > 10) return null;
	if (!/[0-9]/.test(alnum) || !/\p{L}/u.test(alnum)) return null;
	return "eu";
}

// ---------------------------------------------------------------- LOCATION

const LOCATION_LABELS = [
	"konum",
	"lokasyon",
	"[sş]ehir",
	"il",
	"il[cç]e",
	"semt",
	"do[gğ]um[ \\t]+yeri",
	"ikamet[ \\t]+(?:yeri|edilen[ \\t]+(?:yer|[sş]ehir|il))",
	"ya[sş]ad[i][gğ][i][ \\t]+(?:yer|[sş]ehir|il)",
	"location",
	"current[ \\t]+location",
	"city",
	"town",
	"hometown",
	"birthplace",
	"place[ \\t]+of[ \\t]+(?:birth|residence)",
	"city[ \\t]+of[ \\t]+(?:birth|residence)",
];
/** Address labels the privacy rule layer maps to ADDRESS; reused for LOCATION when ADDRESS is off. */
const ADDRESS_LABELS = [
	"(?:home|postal|street|mailing|ev|i[sş])[ \\t]+(?:address|adresi)",
	"address",
	"adres(?:i|im)?",
	"ikametg[aâ]h",
];

/** Rest of a place-name token; a dot only inside an abbreviation (`St.Louis`), never at the end. */
const PLACE_TAIL = "(?:[\\p{L}\\p{M}\\p{N}'’-]|\\.(?=[\\p{L}\\p{N}]))*";
/** Lowercase connectors inside place names (`Rio de Janeiro`, `Frankfurt am Main`). */
const PLACE_CONNECTOR = "(?:de|da|del|di|do|dos|la|le|van|von|der|am|upon|on|sur|en)";
/**
 * Capitalised place-name tokens joined by spaces, commas or slashes (`Kadıköy/İstanbul`,
 * `Rio de Janeiro, Brazil`). Case-sensitive (under `i`, `\p{Lu}` would match any letter) and
 * matched on the original, unfolded text, so it is a sticky regex applied right after a label.
 */
const LOCATION_VALUE_RE = new RegExp(
	`\\p{Lu}${PLACE_TAIL}(?:(?:[ \\t]*[,/][ \\t]*|[ \\t]+)(?:${PLACE_CONNECTOR}[ \\t]+)?[\\p{Lu}\\p{N}]${PLACE_TAIL}){0,8}`,
	"uy",
);
const LOCATION_LABEL_RE = new RegExp(
	`${BEFORE_LABEL}(?:${LOCATION_LABELS.join("|")})${SEP}`,
	"giu",
);
const ADDRESS_AS_LOCATION_RE = labelRegex(ADDRESS_LABELS, '([^\\r\\n;|"<>]{4,200})');

/** The capitalised place name starting at `from` (right after a location label), or null. */
function locationAt(text: string, from: number): readonly [number, number] | null {
	LOCATION_VALUE_RE.lastIndex = from;
	const m = LOCATION_VALUE_RE.exec(text);
	if (!m || m[0].length > 120) return null;
	const end = from + m[0].length;
	// `Location: Https://…` / `City: Foo:bar`: a header or key, not a place.
	if (/^(?::|\/\/)/.test(text.slice(end, end + 2))) return null;
	return [from, end];
}

/** Trims a free-form address value to its last letter/digit; rejects URLs and bare numbers. */
function trimAddress(value: string): string | null {
	const trimmed = value.replace(/[\s.,!?]+$/u, "");
	if (trimmed.length < 4 || /:\/\//.test(trimmed) || !/\p{L}{2}/u.test(trimmed)) return null;
	return trimmed;
}

// ---------------------------------------------------------------- driver

function detectPlates(text: string, labelText: string, emit: LabelledEmit): void {
	for (const m of text.matchAll(TR_PLATE_RE)) {
		const [whole, province, letters, digits] = m as unknown as [string, string, string, string];
		if (PLATE_BLOCKLIST.has(letters) || !validTurkishPlate(province, letters, digits)) continue;
		emit(m.index, m.index + whole.length, "LICENSE_PLATE", 0.85, "pattern");
	}
	for (const m of labelText.matchAll(PLATE_LABELLED_RE)) {
		const value = m[1] as string;
		const kind = labelledPlate(value);
		if (!kind) continue;
		const start = m.index + m[0].length - value.length;
		emit(start, start + value.length, "LICENSE_PLATE", kind === "tr" ? 0.95 : 0.9, "context");
	}
}

function detectLocations(
	text: string,
	labelText: string,
	addressEnabled: boolean,
	emit: LabelledEmit,
): void {
	for (const m of labelText.matchAll(LOCATION_LABEL_RE)) {
		const span = locationAt(text, m.index + m[0].length);
		if (span) emit(span[0], span[1], "LOCATION", 0.85, "context");
	}
	if (addressEnabled) return;
	for (const m of labelText.matchAll(ADDRESS_AS_LOCATION_RE)) {
		const raw = m[1] as string;
		const lead = raw.length - raw.trimStart().length;
		const value = trimAddress(raw.trimStart());
		if (!value) continue;
		const start = m.index + m[0].length - raw.length + lead;
		emit(start, start + value.length, "LOCATION", 0.85, "context");
	}
}

/**
 * Runs the labelled free-text detectors over `text`. `enabled` limits the work to enabled types;
 * findings are reported through `emit` in `text` offsets.
 */
export function detectLabelled(
	text: string,
	enabled: ReadonlySet<EntityType>,
	emit: LabelledEmit,
): void {
	const labelText = foldLabel(text);
	if (enabled.has("USERNAME")) {
		each(labelText, USERNAME_RE, plausibleUsername, (s, e) =>
			emit(s, e, "USERNAME", 0.9, "context"),
		);
	}
	if (enabled.has("HEALTH_ID")) {
		each(labelText, HEALTH_GENERIC_RE, plausibleHealthId, (s, e) =>
			emit(s, e, "HEALTH_ID", 0.9, "context"),
		);
		each(labelText, NHS_RE, validNhsNumber, (s, e) => emit(s, e, "HEALTH_ID", 0.95, "checksum"));
		each(labelText, KVNR_RE, validKvnr, (s, e) => emit(s, e, "HEALTH_ID", 0.95, "checksum"));
	}
	if (enabled.has("LICENSE_PLATE")) detectPlates(text, labelText, emit);
	if (enabled.has("LOCATION")) detectLocations(text, labelText, enabled.has("ADDRESS"), emit);
}
