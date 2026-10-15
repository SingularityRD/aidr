#!/usr/bin/env node
/**
 * Issue a vendor-signed `aidr-customer-packet-v1` for a per-customer installer.
 *
 * Runs only in the vendor's isolated license-signing environment, under the same
 * key custody rules as scripts/license-issue.mjs: the Ed25519 private key comes
 * from a file (`--private-key-file`, owner-only on POSIX) or the environment
 * (`AIDR_LICENSE_SIGNING_KEY_FILE` / `AIDR_LICENSE_SIGNING_KEY`), never from a
 * command argument, and it is never printed.
 *
 * The packet embeds an already-issued license that carries `customer_id`
 * (scripts/license-issue.mjs --customer-id). It must verify against the registry
 * that ships to the customer (`--public-keys`, required), and the packet signing
 * key must be an active key there. The written packet is verified again with the
 * customer's own verifier before it is written, so a packet the endpoint would
 * refuse is never delivered. A packet never carries a secret: the payload has
 * no field for an enrollment code or API key and unknown fields are refused.
 */
import { createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import {
	CUSTOMER_PACKET_FORMAT,
	CustomerPacketError,
	customerPacketSigningMessage,
	SENSITIVITIES,
	validateCustomerPacketPayload,
	verifyCustomerPacket,
} from "./customer-packet-verify.mjs";
import { loadSigningKey } from "./license-issue.mjs";
import { loadPublicKeyRegistry, readLicenseFile } from "./license-verify.mjs";

function isoSeconds(ms) {
	return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

/** Build packet terms from CLI-style options and an issued license document. */
export function buildPacketPayload(options, now = Date.now()) {
	const license = options.license;
	const licenseCustomerId = license?.payload?.customer_id;
	if (typeof licenseCustomerId !== "string") {
		throw new CustomerPacketError("customer_mismatch", "the license has no customer_id; issue it with scripts/license-issue.mjs --customer-id <id>");
	}
	if (options.customerId !== undefined && options.customerId !== licenseCustomerId) {
		throw new CustomerPacketError("customer_mismatch", `--customer-id ${options.customerId} does not match the license customer_id ${licenseCustomerId}`);
	}
	const payload = {
		customer_id: licenseCustomerId,
		packet_id: options.packetId,
		issued_at: options.issuedAt ?? isoSeconds(now),
		license,
		...(options.controlPlaneUrl === undefined ? {} : { control_plane_url: options.controlPlaneUrl }),
		...(options.sensitivity === undefined ? {} : { sensitivity: options.sensitivity }),
		...(options.displayName === undefined ? {} : { display_name: options.displayName }),
		...(options.licensingPublicKeysPem === undefined || options.licensingPublicKeysPem.length === 0
			? {}
			: { licensing_public_keys_pem: options.licensingPublicKeysPem }),
	};
	validateCustomerPacketPayload(payload);
	return payload;
}

/** Sign validated packet terms and return the packet document. */
export function signCustomerPacket(payload, { privateKey, keyId }) {
	validateCustomerPacketPayload(payload);
	const signature = sign(null, customerPacketSigningMessage(payload), privateKey);
	return { format: CUSTOMER_PACKET_FORMAT, key_id: keyId, payload, sig: signature.toString("base64") };
}

/**
 * Self-check before delivery: the signature verifies with the public half of the
 * signing key, the key is active in the customer registry, and the full customer
 * verifier (embedded license included) accepts the packet.
 */
export function selfVerifyCustomerPacket(packet, { privateKey, publicKeys, now = Date.now() }) {
	if (!verify(null, customerPacketSigningMessage(packet.payload), createPublicKey(privateKey), Buffer.from(packet.sig, "base64"))) {
		throw new CustomerPacketError("bad_signature", "the packet does not verify with the key that signed it");
	}
	const entry = publicKeys.get(packet.key_id);
	if (!entry || entry.status !== "active") {
		throw new CustomerPacketError("unknown_key", `key ${packet.key_id} is not an active key in the customer registry; publish it before issuing packets`);
	}
	return verifyCustomerPacket(packet, { publicKeys, now });
}

/** The PEM public keys in the given files (a file may hold several blocks). */
export function readLicensingPublicKeys(files) {
	const keys = [];
	for (const file of files) {
		const blocks = readFileSync(resolve(file), "utf8").match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g) ?? [];
		if (blocks.length === 0) throw new CustomerPacketError("usage", `${file} holds no PEM public key`);
		keys.push(...blocks.map((block) => `${block}\n`));
	}
	return [...new Set(keys)];
}

const USAGE = `Usage:
  node scripts/customer-packet-issue.mjs --key-id <id> --license-file <license.json> --packet-id <id>
    --public-keys <license-public-keys.json shipped to the customer> --out <customer-packet.json>
    [--customer-id <id, must match the license>] [--issued-at <ISO>]
    [--control-plane-url <https://...>] [--sensitivity ${SENSITIVITIES.join("|")}] [--display-name <text>]
    [--licensing-public-key-file <deployment endpoint-policy/licensing-public-keys.pem>]...
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
				"license-file": { type: "string" },
				"customer-id": { type: "string" },
				"packet-id": { type: "string" },
				"issued-at": { type: "string" },
				"control-plane-url": { type: "string" },
				sensitivity: { type: "string" },
				"display-name": { type: "string" },
				"licensing-public-key-file": { type: "string", multiple: true },
				"public-keys": { type: "string" },
				out: { type: "string" },
			},
		});
		if (values.help) {
			console.log(USAGE);
			process.exit(0);
		}
		for (const required of ["key-id", "license-file", "packet-id", "public-keys", "out"]) {
			if (!values[required]) throw new CustomerPacketError("usage", `--${required} is required\n${USAGE}`);
		}
		const privateKey = loadSigningKey({ privateKeyFile: values["private-key-file"] });
		const publicKeys = loadPublicKeyRegistry(values["public-keys"]);
		const { document: license } = readLicenseFile(values["license-file"]);
		const payload = buildPacketPayload({
			license,
			customerId: values["customer-id"],
			packetId: values["packet-id"],
			issuedAt: values["issued-at"],
			controlPlaneUrl: values["control-plane-url"],
			sensitivity: values.sensitivity,
			displayName: values["display-name"],
			licensingPublicKeysPem: readLicensingPublicKeys(values["licensing-public-key-file"] ?? []),
		});
		const packet = signCustomerPacket(payload, { privateKey, keyId: values["key-id"] });
		const result = selfVerifyCustomerPacket(packet, { privateKey, publicKeys });
		// wx: never overwrite a previously delivered packet.
		writeFileSync(resolve(values.out), `${JSON.stringify(packet, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o644 });
		console.log(
			`Issued customer packet ${payload.packet_id} for ${payload.customer_id} (license ${result.license.payload.license_id}, ${result.license_state}, updates until ${result.license.grace_ends_at}), key ${values["key-id"]}.`,
		);
		if (result.license_state !== "active") {
			console.error(`WARNING: the embedded license is ${result.license_state}; the installer still installs local detection, but new update packs follow the license term.`);
		}
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "customer packet issuance failed"}`);
		process.exitCode = 1;
	}
}
