/**
 * Sensitive field names (JSON keys, CSV/Markdown column headers) shared by file sanitisation
 * (engine/files.ts) and prompt scanning of pasted tables and JSON (engine/structured.ts).
 */
import { keyType } from "../../../privacy/src/detectors.js";
import type { EntityType } from "../types.js";

/**
 * Sensitive field names beyond the privacy layer's `keyType` dictionary (normalised: lower-case
 * ASCII letters/digits only). Suffix matches catch `db_password`, `github_token`, ...
 */
const EXTRA_SENSITIVE_KEYS: Readonly<Record<string, EntityType>> = {
	token: "SECRET",
	authtoken: "SECRET",
	bearertoken: "SECRET",
	idtoken: "SECRET",
	sessiontoken: "SECRET",
	sessionid: "SECRET",
	csrftoken: "SECRET",
	apisecret: "SECRET",
	secretkey: "SECRET",
	accesskey: "SECRET",
	accesskeyid: "SECRET",
	secretaccesskey: "SECRET",
	passphrase: "SECRET",
	credential: "SECRET",
	credentials: "SECRET",
	connectionstring: "SECRET",
	cvv: "SECRET",
	cvc: "SECRET",
	pin: "SECRET",
	otp: "SECRET",
	surname: "PERSON",
	givenname: "PERSON",
	familyname: "PERSON",
	soyadi: "PERSON",
	musteriadi: "PERSON",
	customername: "PERSON",
	ceptelefonu: "PHONE",
	telno: "PHONE",
	tcno: "TC_KIMLIK",
	tckimliknumarasi: "TC_KIMLIK",
	ibanno: "IBAN",
};
const SENSITIVE_KEY_SUFFIXES: ReadonlyArray<readonly [string, EntityType]> = [
	["password", "SECRET"],
	["passwd", "SECRET"],
	["secret", "SECRET"],
	["secretkey", "SECRET"],
	["token", "SECRET"],
	["apikey", "SECRET"],
	["accesskey", "SECRET"],
	["privatekey", "PRIVATE_KEY"],
];
/** Field names too generic to force-mask in JSON (`"name": "my-package"`); CSV columns still use them. */
const AMBIGUOUS_JSON_KEYS: ReadonlySet<string> = new Set(["name", "ad", "tc"]);

function normaliseKey(key: string): string {
	return key
		.normalize("NFKD")
		.replace(/\p{M}/gu, "")
		.replace(/[ıİ]/g, "i")
		.toLowerCase()
		.replace(/[^a-z0-9]/g, "");
}

/**
 * Entity type implied by a field name (JSON key / CSV header), or undefined.
 * Reuses the AIDR Privacy dictionary and adds credential-style keys and suffixes.
 */
export function sensitiveKeyType(key: string, ambiguousAllowed = true): EntityType | undefined {
	const k = normaliseKey(key);
	if (!k || k.length > 64) return undefined;
	if (!ambiguousAllowed && AMBIGUOUS_JSON_KEYS.has(k)) return undefined;
	const direct = keyType(key) ?? EXTRA_SENSITIVE_KEYS[k];
	if (direct) return direct;
	for (const [suffix, type] of SENSITIVE_KEY_SUFFIXES) if (k.endsWith(suffix)) return type;
	return undefined;
}
