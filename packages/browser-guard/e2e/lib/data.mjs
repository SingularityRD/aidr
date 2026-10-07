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
 * A sensitive item the suite types into a page: `value` must never reach the
 * network in a masking mode, `placeholder` matches the vault's replacement.
 */
const ITEMS = {
	email: { type: "EMAIL", value: EMAIL, placeholder: /\[EMAIL_\d+\]/ },
	tckn: { type: "TC_KIMLIK", value: TCKN, placeholder: /\[TCKN_\d+\]/ },
	iban: { type: "IBAN", value: IBAN, placeholder: /\[IBAN_\d+\]/ },
	apiKey: { type: "SECRET", value: API_KEY, placeholder: /\[SECRET_\d+\]/ },
};

/** Data profiles: the real extension gets every entity; the self-test extension only masks one email. */
export const PROFILES = {
	full: {
		items: [ITEMS.email, ITEMS.tckn, ITEMS.iban, ITEMS.apiKey],
		prompt: `Please email ${EMAIL} about the refund. TCKN ${TCKN}, IBAN ${IBAN}, deploy key ${API_KEY}`,
		pasteText: `Customer record: ${EMAIL}, TC ${TCKN}`,
		pasteItems: [ITEMS.email, ITEMS.tckn],
		csv: `name,email,note\nAyse Yilmaz,${EMAIL},vip\nJohn Doe,${EMAIL_2},standard\n`,
		csvItems: [ITEMS.email, { type: "EMAIL", value: EMAIL_2, placeholder: /\[EMAIL_\d+\]/ }],
	},
	selfTest: {
		items: [{ type: "EMAIL", value: "secret@example.com", placeholder: /\[EMAIL_\d+\]/ }],
		prompt: "Please write to secret@example.com about the refund",
		pasteText: "Customer record: secret@example.com",
		pasteItems: [{ type: "EMAIL", value: "secret@example.com", placeholder: /\[EMAIL_\d+\]/ }],
		csv: "name,email\nAyse,secret@example.com\n",
		csvItems: [{ type: "EMAIL", value: "secret@example.com", placeholder: /\[EMAIL_\d+\]/ }],
	},
};

export const CLEAN_PROMPT = "Summarise the plot of Hamlet in three sentences.";

/** Matches any vault placeholder, e.g. `[EMAIL_1]`, `[NATIONAL_ID_2]`, `[EMAIL_1_k3f9]` (tagged). */
export const ANY_PLACEHOLDER = /\[[A-Z][A-Z_]*_\d+(?:_[a-z0-9]{4,8})?\]/g;
