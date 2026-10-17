// Synthetic test data for the Browser Guard E2E suite.
//
// Every value is fake but checksum-valid, so the real detection engine must
// recognise it. The validators below re-verify each value at import time: a
// typo here would otherwise surface as a confusing "not masked" failure.

/** Turkish national ID (TC Kimlik No) checksum. */
function validTckn(value) {
	if (!/^[1-9][0-9]{10}$/.test(value)) return false;
	const d = [...value].map(Number);
	const odd = d[0] + d[2] + d[4] + d[6] + d[8];
	const even = d[1] + d[3] + d[5] + d[7];
	const d10 = (((odd * 7 - even) % 10) + 10) % 10;
	const d11 = d.slice(0, 10).reduce((a, b) => a + b, 0) % 10;
	return d[9] === d10 && d[10] === d11;
}

/** ISO 13616 IBAN mod-97 checksum (compact form, no spaces). */
function validIban(value) {
	const compact = value.replace(/\s+/g, "").toUpperCase();
	if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$/.test(compact)) return false;
	const rearranged = compact.slice(4) + compact.slice(0, 4);
	let remainder = 0;
	for (const ch of rearranged) {
		const code = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
		for (const digit of code) remainder = (remainder * 10 + Number(digit)) % 97;
	}
	return remainder === 1;
}

const EMAIL = "ayse.yilmaz@example.com";
export const EMAIL_2 = "john.doe@example.org";
/** 1,0,0,0,0,0,0,0,1 -> d10 = (2*7 - 0) % 10 = 4, d11 = (1+1+4) % 10 = 6. */
const TCKN = "10000000146";
const IBAN = "TR330006100519786457841326";
const API_KEY = "sk-proj-Q7vX2mN9pL4kR8tW1yB6cD3fG5hJ0sAaZe";

if (!validTckn(TCKN)) throw new Error(`test data: ${TCKN} is not a valid TCKN`);
if (!validIban(IBAN)) throw new Error(`test data: ${IBAN} is not a valid IBAN`);

/**
 * The per-page-life vault tag (src/engine/vault.ts `newVaultTag`, minted by
 * src/content/boot.ts): exactly four lower-case letters or digits.
 */
const VAULT_TAG = "[a-z0-9]{4}";

/**
 * Matches a placeholder the extension mints in a page, e.g. `[EMAIL_1_k3f9]`:
 * `[<PREFIX>_<n>_<tag>]` with n >= 1 and no leading zero (src/engine/vault.ts).
 * Every placeholder minted in a page carries the tag, so an untagged `[EMAIL_1]`
 * does not match.
 */
export function placeholderPattern(prefix) {
	return new RegExp(`\\[${prefix}_[1-9][0-9]{0,8}_${VAULT_TAG}\\]`);
}

/**
 * A sensitive item the suite types into a page: `value` must never reach the
 * network in a masking mode, `placeholder` matches the vault's replacement.
 */
const ITEMS = {
	email: { type: "EMAIL", value: EMAIL, placeholder: placeholderPattern("EMAIL") },
	tckn: { type: "TC_KIMLIK", value: TCKN, placeholder: placeholderPattern("TCKN") },
	iban: { type: "IBAN", value: IBAN, placeholder: placeholderPattern("IBAN") },
	apiKey: { type: "SECRET", value: API_KEY, placeholder: placeholderPattern("SECRET") },
};

/** Data profiles: the real extension gets every entity; the self-test extension only masks one email. */
export const PROFILES = {
	full: {
		items: [ITEMS.email, ITEMS.tckn, ITEMS.iban, ITEMS.apiKey],
		prompt: `Please email ${EMAIL} about the refund. TCKN ${TCKN}, IBAN ${IBAN}, deploy key ${API_KEY}`,
		pasteText: `Customer record: ${EMAIL}, TC ${TCKN}`,
		pasteItems: [ITEMS.email, ITEMS.tckn],
		csv: `name,email,note\nAyse Yilmaz,${EMAIL},vip\nJohn Doe,${EMAIL_2},standard\n`,
		csvItems: [ITEMS.email, { type: "EMAIL", value: EMAIL_2, placeholder: placeholderPattern("EMAIL") }],
	},
	selfTest: {
		items: [{ type: "EMAIL", value: "secret@example.com", placeholder: placeholderPattern("EMAIL") }],
		prompt: "Please write to secret@example.com about the refund",
		pasteText: "Customer record: secret@example.com",
		pasteItems: [{ type: "EMAIL", value: "secret@example.com", placeholder: placeholderPattern("EMAIL") }],
		csv: "name,email\nAyse,secret@example.com\n",
		csvItems: [{ type: "EMAIL", value: "secret@example.com", placeholder: placeholderPattern("EMAIL") }],
	},
};

export const CLEAN_PROMPT = "Summarise the plot of Hamlet in three sentences.";

/** Luhn checksum (payment card numbers), spaces ignored. */
function validLuhn(value) {
	const digits = value.replace(/\s+/g, "");
	if (!/^[0-9]{13,19}$/.test(digits)) return false;
	let sum = 0;
	for (let i = 0; i < digits.length; i++) {
		let d = Number(digits[digits.length - 1 - i]);
		if (i % 2 === 1) {
			d *= 2;
			if (d > 9) d -= 9;
		}
		sum += d;
	}
	return sum % 10 === 0;
}

// The customer-demo data set (scenarios/entities.mjs, docs/demo/browser-guard-demo.tr.md):
// every identifier class the demo shows, in the formats people actually type.
const PHONE = "+90 532 123 45 67";
const CARD = "4539 1488 0343 6467";
const IBAN_SPACED = "TR33 0006 1005 1978 6457 8413 26";
const GITHUB_TOKEN = ["ghp", "R4nd0mF4k3T0k3nF0rDem0Purp0s3s0nly12"].join("_");
const AWS_KEY = "AKIAZ7QX3EXAMPLE4DMO";

if (!validLuhn(CARD)) throw new Error(`test data: ${CARD} fails the Luhn check`);
if (!validIban(IBAN_SPACED)) throw new Error(`test data: ${IBAN_SPACED} is not a valid IBAN`);

/**
 * Items of the demo prompt. `restore: false` marks types the default policy never
 * restores (`neverRestore`: SECRET, PRIVATE_KEY): their placeholders stay in the reply.
 */
export const DEMO_ITEMS = [
	{ ...ITEMS.email, restore: true },
	{ type: "PHONE", value: PHONE, placeholder: placeholderPattern("PHONE"), restore: true },
	{ ...ITEMS.tckn, restore: true },
	{ type: "IBAN", value: IBAN_SPACED, placeholder: placeholderPattern("IBAN"), restore: true },
	{ type: "CREDIT_CARD", value: CARD, placeholder: placeholderPattern("CARD"), restore: true },
	{ ...ITEMS.apiKey, restore: false },
	{ type: "SECRET", value: GITHUB_TOKEN, placeholder: placeholderPattern("SECRET"), restore: false },
	{ type: "SECRET", value: AWS_KEY, placeholder: placeholderPattern("SECRET"), restore: false },
];

/** The prompt the demo types (Turkish, as in the demo guide). */
export const DEMO_PROMPT = [
	`Müşteri Ayşe Yılmaz için iade yazısı hazırla. E-posta ${EMAIL}, telefon ${PHONE},`,
	`TCKN ${TCKN}, IBAN ${IBAN_SPACED}, kart ${CARD}.`,
	`Deploy anahtarları: ${API_KEY} ${GITHUB_TOKEN} ${AWS_KEY}`,
].join(" ");

/** Matches any vault placeholder, e.g. `[EMAIL_1]`, `[NATIONAL_ID_2]`, `[EMAIL_1_k3f9]` (tagged). */
export const ANY_PLACEHOLDER = /\[[A-Z][A-Z_]*_\d+(?:_[a-z0-9]{4,8})?\]/g;
