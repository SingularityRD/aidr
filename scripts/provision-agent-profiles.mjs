#!/usr/bin/env node

/**
 * Sign an agent permission profile document into one runtime's tenant detector
 * bundle (`~/.singularity-aidr/detectors/<runtime>.json`) — the same Ed25519,
 * entitlement-bound distribution the tenant DLP policy uses.
 *
 * The bundle is one signed payload per runtime, so publishing profiles must not
 * drop a DLP, behavioural or reputation-feed section that is already installed
 * (and publishing DLP must not drop profiles; see provision-dlp-detector.mjs).
 * Existing sections are carried over only when the installed bundle names the
 * same tenant and verifies against the signing key; anything else is refused
 * rather than re-signed.
 */
import { createPrivateKey, createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	canonicalDetectorPolicyPayload,
	validateAgentProfileSource,
} from "../packages/core/dist/index.js";

const RUNTIMES = new Set(["claude-code", "cursor", "vscode", "openclaw", "opencode", "codex"]);
const TENANT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_BUNDLE_BYTES = 8 * 1024 * 1024;
const MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;
/** Sections another publisher owns; carried over verbatim from a verified bundle. */
const CARRIED_SECTIONS = ["dlp", "behavioral", "reputation_feed", "agent_profiles"];

function assert(condition, message) {
	if (!condition) throw new Error(message);
}

export function validateExpiry(expiresAt, now = new Date()) {
	assert(
		typeof expiresAt === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(expiresAt),
		"Bundle expiry must be an RFC3339 UTC timestamp",
	);
	const expiry = Date.parse(expiresAt);
	assert(Number.isFinite(expiry), "Bundle expiry is not a real UTC timestamp");
	assert(
		expiry > now.getTime() && expiry - now.getTime() <= MAX_LIFETIME_MS,
		"Bundle expiry must be in the next 24 hours",
	);
}

async function readSmallRegularFile(path, maxBytes, label) {
	const info = await lstat(path);
	assert(
		info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= maxBytes,
		`${label} must be a small regular file`,
	);
	return readFile(path);
}

/** The installed bundle for a runtime, or null when none is installed. */
export async function readInstalledBundle(outputDir, runtime) {
	assert(RUNTIMES.has(runtime), "Unsupported agent runtime");
	try {
		const raw = await readSmallRegularFile(join(outputDir, `${runtime}.json`), MAX_BUNDLE_BYTES, "Installed bundle");
		return JSON.parse(raw.toString("utf8"));
	} catch (error) {
		if (error?.code === "ENOENT") return null;
		throw new Error("Installed bundle is unreadable; remove it deliberately before publishing");
	}
}

/**
 * The sections of an installed bundle that may be re-signed: same tenant and a
 * signature that verifies against the publisher's key. `replace` names the
 * section being published, which is never carried over.
 */
export function carriedSections(installed, { tenant, publicKey, replace }) {
	if (!installed) return { schemaVersion: 1, sections: {} };
	const payload = installed.payload;
	if (payload?.tenant_id !== tenant) return { schemaVersion: 1, sections: {} };
	const signature = Buffer.from(String(installed.sig_b64 ?? ""), "base64");
	const verified =
		installed.alg === "ed25519" &&
		signature.length === 64 &&
		verify(null, Buffer.from(canonicalDetectorPolicyPayload(payload)), publicKey, signature);
	assert(verified, "Installed bundle for this tenant does not verify against the signing key; refusing to re-sign its sections");
	const sections = {};
	for (const key of CARRIED_SECTIONS) {
		if (key !== replace && payload[key] !== undefined) sections[key] = payload[key];
	}
	return { schemaVersion: payload.schema_version === 2 ? 2 : 1, sections };
}

/** Build and sign the bundle carrying the validated profile document. */
export function signAgentProfileBundle({ source, tenant, expiresAt, privateKey, carried, now = new Date() }) {
	assert(TENANT.test(tenant ?? ""), "Invalid tenant ID");
	assert(privateKey.asymmetricKeyType === "ed25519", "Signing key must be Ed25519");
	validateExpiry(expiresAt, now);
	const result = validateAgentProfileSource(source);
	assert(result.ok, `Agent profile document is invalid: ${result.ok ? "" : result.errors.join("; ")}`);
	const payload = {
		schema_version: carried?.schemaVersion ?? 1,
		tenant_id: tenant,
		issued_at: now.toISOString(),
		expires_at: expiresAt,
		...(carried?.sections ?? {}),
		agent_profiles: result.document,
	};
	return {
		bundle: {
			alg: "ed25519",
			payload,
			sig_b64: sign(null, Buffer.from(canonicalDetectorPolicyPayload(payload)), privateKey).toString("base64"),
		},
		profiles: result.document.profiles.map((profile) => profile.name),
		diagnostics: result.diagnostics,
	};
}

export async function installBundle(outputDir, runtime, bundle) {
	assert(RUNTIMES.has(runtime), "Unsupported agent runtime");
	const serialized = `${JSON.stringify(bundle)}\n`;
	assert(Buffer.byteLength(serialized) <= MAX_BUNDLE_BYTES, "Signed bundle exceeds runtime size limit");
	await mkdir(outputDir, { recursive: true, mode: 0o700 });
	const directory = await lstat(outputDir);
	assert(
		directory.isDirectory() &&
			!directory.isSymbolicLink() &&
			resolve(await realpath(outputDir)).toLowerCase() === resolve(outputDir).toLowerCase(),
		"Output directory must not redirect to another location",
	);
	const target = join(outputDir, `${runtime}.json`);
	const temporary = join(outputDir, `.${runtime}.${randomUUID()}.tmp`);
	try {
		await writeFile(temporary, serialized, { flag: "wx", mode: 0o600 });
		await rename(temporary, target);
	} catch (error) {
		await rm(temporary, { force: true });
		throw error;
	}
	return target;
}

function parseArgs(argv) {
	const args = {};
	for (let i = 0; i < argv.length; i += 2) {
		const key = argv[i];
		assert(key?.startsWith("--") && argv[i + 1] && args[key] === undefined, "Invalid or duplicate option");
		args[key] = argv[i + 1];
	}
	assert(
		Object.keys(args).every((key) =>
			["--tenant", "--runtime", "--profiles", "--expires-at", "--private-key", "--output-dir"].includes(key),
		),
		"Unknown option",
	);
	return args;
}

export async function main(argv, { now = new Date() } = {}) {
	const args = parseArgs(argv);
	const runtime = args["--runtime"];
	assert(RUNTIMES.has(runtime), "Unsupported agent runtime");
	assert(args["--profiles"] && args["--private-key"] && args["--output-dir"], "Profiles, private key and output directory are required");
	const privateKey = createPrivateKey(await readSmallRegularFile(args["--private-key"], 32768, "Signing key"));
	const source = (await readSmallRegularFile(args["--profiles"], 256 * 1024, "Profile document")).toString("utf8");
	const outputDir = args["--output-dir"];
	const carried = carriedSections(await readInstalledBundle(outputDir, runtime), {
		tenant: args["--tenant"],
		publicKey: createPublicKey(privateKey),
		replace: "agent_profiles",
	});
	const signed = signAgentProfileBundle({
		source,
		tenant: args["--tenant"],
		expiresAt: args["--expires-at"],
		privateKey,
		carried,
		now,
	});
	const output = await installBundle(outputDir, runtime, signed.bundle);
	return {
		output,
		tenant: args["--tenant"],
		runtime,
		profiles: signed.profiles,
		carried_sections: Object.keys(carried.sections),
		status: "signed_bundle_written_not_agent_verified",
	};
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main(process.argv.slice(2)).then(
		(result) => console.log(JSON.stringify(result)),
		(error) => {
			console.error(error instanceof Error ? error.message : "Agent profile provisioning failed");
			process.exitCode = 1;
		},
	);
}
