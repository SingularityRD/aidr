#!/usr/bin/env node
/**
 * Issue a vendor-signed `aidr-license-revocations-v1` list: the license ids that
 * must receive no NEW update packs (core `verifyLicenseRevocations` and
 * `acceptPack`, packages/core/src/intel/license-revocations.ts). Installed packs
 * keep enforcing on a revoked license; revocation only stops what comes next.
 *
 * Runs in the vendor's license-signing environment with the same key handling
 * as scripts/license-issue.mjs (`--private-key-file` owner-only, or
 * AIDR_LICENSE_SIGNING_KEY_FILE / AIDR_LICENSE_SIGNING_KEY), and signs with a
 * key from the license public-key registry. The list is complete, not a delta:
 * each issue carries every revoked license id and a `sequence` higher than the
 * previous list, so an endpoint holding a newer list never goes back to an older
 * one.
 *
 *   node scripts/license-revocations-issue.mjs --key-id <id> --sequence <n>
 *     (--license-id <id>... | --license-ids-file <file: one id per line>)
 *     [--issued-at <ISO>] [--public-keys <registry.json>] --out <license-revocations.json>
 */
import { createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { loadSigningKey } from "./license-issue.mjs";
import { canonicalJson, ISO_UTC, LicenseError, loadPublicKeyRegistry, requireRegularFile } from "./license-verify.mjs";

export const LICENSE_REVOCATIONS_FORMAT = "aidr-license-revocations-v1";
const LICENSE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_REVOKED_LICENSES = 1000;

const message = (payload) => Buffer.from(`${LICENSE_REVOCATIONS_FORMAT}\n${canonicalJson(payload)}`, "utf8");

/** Validate and build the payload exactly as the core verifier will read it. */
export function buildRevocationsPayload({ licenseIds, sequence, issuedAt }) {
	const ids = [...new Set(licenseIds.map((id) => String(id).trim()).filter(Boolean))].sort();
	if (ids.length > MAX_REVOKED_LICENSES) throw new LicenseError("invalid_payload", `at most ${MAX_REVOKED_LICENSES} license ids per list`);
	const bad = ids.find((id) => !LICENSE_ID.test(id));
	if (bad !== undefined) throw new LicenseError("invalid_payload", `invalid license id ${JSON.stringify(bad)}`);
	const seq = Number(sequence);
	if (!Number.isSafeInteger(seq) || seq < 1) throw new LicenseError("invalid_payload", "--sequence must be a positive integer, higher than the previous list's");
	if (typeof issuedAt !== "string" || !ISO_UTC.test(issuedAt) || !Number.isFinite(Date.parse(issuedAt))) {
		throw new LicenseError("invalid_payload", "issued_at must be an ISO-8601 UTC timestamp");
	}
	return { issued_at: issuedAt, sequence: seq, license_ids: ids };
}

export function signRevocations(payload, { privateKey, keyId }) {
	return { format: LICENSE_REVOCATIONS_FORMAT, key_id: keyId, payload, sig: sign(null, message(payload), privateKey).toString("base64") };
}

/** Signature check against the signing key's public half and, optionally, the registry that ships. */
export function checkRevocations(document, { publicKey, registry }) {
	const signature = Buffer.from(document.sig, "base64");
	if (!verify(null, message(document.payload), publicKey, signature)) throw new LicenseError("bad_signature", "revocation list does not verify against its signing key");
	if (registry) {
		const entry = registry.get(document.key_id);
		if (!entry || entry.status !== "active") throw new LicenseError("unknown_key", `key ${document.key_id} is not an active key in the license public-key registry; publish it first`);
		if (!verify(null, message(document.payload), entry.publicKey, signature)) throw new LicenseError("bad_signature", `revocation list does not verify against registry key ${document.key_id}`);
	}
}

const USAGE = `Usage:
  node scripts/license-revocations-issue.mjs --key-id <id> --sequence <n>
    (--license-id <id>... | --license-ids-file <file>) [--issued-at <ISO>] [--public-keys <registry.json>] --out <file>
    (signing key: --private-key-file <0600 pem> | AIDR_LICENSE_SIGNING_KEY_FILE | AIDR_LICENSE_SIGNING_KEY)`;

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	try {
		const { values } = parseArgs({
			strict: true,
			options: {
				help: { type: "boolean", short: "h" },
				"private-key-file": { type: "string" },
				"key-id": { type: "string" },
				sequence: { type: "string" },
				"license-id": { type: "string", multiple: true },
				"license-ids-file": { type: "string" },
				"issued-at": { type: "string" },
				"public-keys": { type: "string" },
				out: { type: "string" },
			},
		});
		if (values.help) {
			console.log(USAGE);
			process.exit(0);
		}
		if (!values["key-id"] || !values.out || !values.sequence) throw new LicenseError("usage", USAGE);
		const licenseIds = [...(values["license-id"] ?? [])];
		if (values["license-ids-file"]) {
			const path = resolve(values["license-ids-file"]);
			requireRegularFile(path, "license ids file");
			licenseIds.push(...readFileSync(path, "utf8").split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")));
		}
		const issuedAt = values["issued-at"] ?? new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace(".000Z", "Z");
		const payload = buildRevocationsPayload({ licenseIds, sequence: values.sequence, issuedAt });
		const privateKey = loadSigningKey({ privateKeyFile: values["private-key-file"] });
		const document = signRevocations(payload, { privateKey, keyId: values["key-id"] });
		checkRevocations(document, {
			publicKey: createPublicKey(privateKey),
			registry: values["public-keys"] ? loadPublicKeyRegistry(values["public-keys"]) : undefined,
		});
		writeFileSync(resolve(values.out), `${JSON.stringify(document, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o644 });
		console.log(`Issued license revocation list #${payload.sequence} (${payload.license_ids.length} revoked license(s)), key ${values["key-id"]}.`);
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "revocation list issuance failed"}`);
		process.exitCode = 1;
	}
}
