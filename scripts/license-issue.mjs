#!/usr/bin/env node
/**
 * Issue a vendor-signed `aidr-license-v1` on-prem / air-gapped license.
 *
 * This runs only in the vendor's isolated license-signing environment. The Ed25519
 * private key is read from a file (`--private-key-file`, owner-only on POSIX) or
 * from the environment (`AIDR_LICENSE_SIGNING_KEY_FILE` / `AIDR_LICENSE_SIGNING_KEY`
 * holding the PEM) — never from a command argument, where it would land in shell
 * history and process listings.
 *
 * Terms are validated with the verifier's own `validateLicensePayload`, so a
 * license a customer's verifier would refuse is never issued: in particular
 * `--deployment airgap` requires `--plan-id enterprise` (catalog feature
 * `air_gapped_deployment`), refused with `plan_feature_required`.
 *
 * The written license is self-verified against the public half of the signing
 * key and, with `--public-keys`, against the registry customers will ship, so a
 * license signed by an unregistered or retired key is caught before delivery.
 */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import {
	AIRGAP_PLAN_IDS,
	DEPLOYMENTS,
	LICENSE_FORMAT,
	LicenseError,
	licenseSigningMessage,
	loadPublicKeyRegistry,
	PLAN_IDS,
	parsePublicKeyRegistry,
	PUBLIC_KEYS_FORMAT,
	validateLicensePayload,
	verifyLicense,
} from "./license-verify.mjs";

const DAY_MS = 24 * 60 * 60 * 1000;

function isoSeconds(ms) {
	return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

/** Load the signing key from a restricted file or the environment. */
export function loadSigningKey({ privateKeyFile, env = process.env } = {}) {
	const file = privateKeyFile ?? env.AIDR_LICENSE_SIGNING_KEY_FILE;
	let pem;
	if (file) {
		const path = resolve(file);
		const stats = lstatSync(path);
		if (stats.isSymbolicLink() || !stats.isFile()) throw new LicenseError("signing_key", "license signing key must be a regular, non-symlink file");
		if (process.platform !== "win32" && (stats.mode & 0o077) !== 0) {
			throw new LicenseError("signing_key", "license signing key file must be owner-only (mode 0600) on POSIX systems");
		}
		pem = readFileSync(path, "utf8");
	} else if (env.AIDR_LICENSE_SIGNING_KEY) {
		pem = env.AIDR_LICENSE_SIGNING_KEY;
	} else {
		throw new LicenseError("signing_key", "supply the Ed25519 signing key with --private-key-file, AIDR_LICENSE_SIGNING_KEY_FILE or AIDR_LICENSE_SIGNING_KEY");
	}
	let key;
	try {
		key = createPrivateKey(pem);
	} catch {
		throw new LicenseError("signing_key", "license signing key is not a PEM private key");
	}
	if (key.asymmetricKeyType !== "ed25519") throw new LicenseError("signing_key", "license signing key must be Ed25519");
	return key;
}

/** Sign validated terms and return the license document. */
export function signLicense(payload, { privateKey, keyId }) {
	validateLicensePayload(payload);
	const signature = sign(null, licenseSigningMessage(payload), privateKey);
	return { format: LICENSE_FORMAT, key_id: keyId, payload, sig: signature.toString("base64") };
}

/** The registry entry a vendor publishes for the public half of a signing key. */
export function publicKeyEntry(privateKey, { keyId, notBefore, notAfter = null, status = "active", retiredAt = null }) {
	return {
		key_id: keyId,
		algorithm: "ed25519",
		public_key_pem: createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString(),
		not_before: notBefore,
		not_after: notAfter,
		status,
		// A retired key records when it stopped signing; verifiers cap its use by it.
		...(status === "retired" ? { retired_at: retiredAt } : {}),
	};
}

/** Build payload terms from CLI-style options. */
export function buildPayload(options, now = Date.now()) {
	const issuedAt = options.issuedAt ?? isoSeconds(now);
	const features = (options.features ?? "")
		.split(",")
		.map((feature) => feature.trim())
		.filter(Boolean);
	const payload = {
		license_id: options.licenseId,
		customer: options.customer?.trim(),
		plan_id: options.planId,
		seats: Number(options.seats),
		features,
		deployment: options.deployment,
		issued_at: issuedAt,
		not_before: options.notBefore ?? issuedAt,
		expires_at: options.expiresAt,
		grace_days: options.graceDays === undefined ? 14 : Number(options.graceDays),
	};
	validateLicensePayload(payload);
	return payload;
}

const USAGE = `Usage:
  node scripts/license-issue.mjs --key-id <id> --license-id <id> --customer <name> --plan-id <plan>
    --seats <n> --deployment ${DEPLOYMENTS.join("|")} --expires-at <ISO> [--features a,b] [--not-before <ISO>]
    (--plan-id is one of ${PLAN_IDS.join("|")}; --deployment airgap requires --plan-id ${AIRGAP_PLAN_IDS.join("|")})
    [--issued-at <ISO>] [--grace-days <0..90, default 14>] [--public-keys <registry.json>] --out <license.json>
    (signing key: --private-key-file <0600 pem> | AIDR_LICENSE_SIGNING_KEY_FILE | AIDR_LICENSE_SIGNING_KEY)
  node scripts/license-issue.mjs --print-public-key-entry --key-id <id> [--not-before <ISO>]
    (prints the registry entry for deploy/onprem/license-public-keys.json)`;

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	try {
		const { values } = parseArgs({
			strict: true,
			options: {
				help: { type: "boolean", short: "h" },
				"private-key-file": { type: "string" },
				"print-public-key-entry": { type: "boolean" },
				"key-id": { type: "string" },
				"license-id": { type: "string" },
				customer: { type: "string" },
				"plan-id": { type: "string" },
				seats: { type: "string" },
				features: { type: "string" },
				deployment: { type: "string" },
				"issued-at": { type: "string" },
				"not-before": { type: "string" },
				"expires-at": { type: "string" },
				"grace-days": { type: "string" },
				"public-keys": { type: "string" },
				out: { type: "string" },
			},
		});
		if (values.help) {
			console.log(USAGE);
			process.exit(0);
		}
		if (!values["key-id"]) throw new LicenseError("usage", USAGE);
		const privateKey = loadSigningKey({ privateKeyFile: values["private-key-file"] });
		if (values["print-public-key-entry"]) {
			const entry = publicKeyEntry(privateKey, { keyId: values["key-id"], notBefore: values["not-before"] ?? isoSeconds(Date.now()) });
			// Validate the entry exactly as a customer's verifier will parse it.
			parsePublicKeyRegistry({ format: PUBLIC_KEYS_FORMAT, schema_version: 1, keys: [entry] });
			console.log(JSON.stringify(entry, null, 2));
			process.exit(0);
		}
		if (!values.out) throw new LicenseError("usage", USAGE);
		const payload = buildPayload({
			licenseId: values["license-id"],
			customer: values.customer,
			planId: values["plan-id"],
			seats: values.seats,
			features: values.features,
			deployment: values.deployment,
			issuedAt: values["issued-at"],
			notBefore: values["not-before"],
			expiresAt: values["expires-at"],
			graceDays: values["grace-days"],
		});
		const license = signLicense(payload, { privateKey, keyId: values["key-id"] });

		// Self-check: the document must verify against the key that signed it and,
		// when supplied, against the registry that will ship to the customer.
		const selfRegistry = parsePublicKeyRegistry({
			format: PUBLIC_KEYS_FORMAT,
			schema_version: 1,
			keys: [publicKeyEntry(privateKey, { keyId: values["key-id"], notBefore: payload.issued_at })],
		});
		verifyLicense(license, { publicKeys: selfRegistry, now: Date.parse(payload.not_before) });
		if (values["public-keys"]) {
			const registry = loadPublicKeyRegistry(values["public-keys"]);
			const entry = registry.get(values["key-id"]);
			if (!entry || entry.status !== "active") {
				throw new LicenseError("unknown_key", `key ${values["key-id"]} is not an active key in ${values["public-keys"]}; publish it before issuing licenses`);
			}
			verifyLicense(license, { publicKeys: registry, now: Date.parse(payload.not_before) });
		}
		// wx: never overwrite a previously delivered license file.
		writeFileSync(resolve(values.out), `${JSON.stringify(license, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o644 });
		const graceEnds = new Date(Date.parse(payload.expires_at) + payload.grace_days * DAY_MS).toISOString();
		console.log(`Issued license ${payload.license_id} for ${payload.customer}: ${payload.seats} seats, ${payload.deployment}, valid ${payload.not_before} .. ${payload.expires_at} (managed features until ${graceEnds}), key ${values["key-id"]}.`);
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "license issuance failed"}`);
		process.exitCode = 1;
	}
}
