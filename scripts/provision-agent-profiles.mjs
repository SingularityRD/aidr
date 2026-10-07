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
 *
 * The document comes from one of two places:
 *   --profiles <file>                   a local JSON/YAML document, or
 *   --endpoint URL --token-file F --revision N
 *                                       the revision staged (and, with four-eyes,
 *                                       approved) in the dashboard. It is pulled
 *                                       from policy-management with an owner/admin
 *                                       AAL2 access token, must be the tenant's
 *                                       CURRENT staged revision, and its sha256
 *                                       over the canonical document must match the
 *                                       digest the control plane recorded.
 * The control plane never holds the signing key: connectors verify the bundle
 * against the operator's licensing keys (supabase/migrations/
 * 20260928000002_agent_profile_staging.sql explains why).
 */
import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	canonicalDetectorPolicyPayload,
	validateAgentProfileSource,
} from "../packages/core/dist/index.js";

const RUNTIMES = new Set(["claude-code", "cursor", "vscode", "openclaw", "opencode", "codex"]);
const TENANT = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_RESPONSE_BYTES = 1024 * 1024;
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

/** The staged-revision request must name a clean HTTPS policy-management URL. */
export function validateStagedRequest({ endpoint, tenant, revision }) {
	let url;
	try {
		url = new URL(endpoint);
	} catch {
		throw new Error("Profile endpoint must be a clean HTTPS URL");
	}
	assert(url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash,
		"Profile endpoint must be a clean HTTPS URL");
	assert(url.pathname.endsWith("/functions/v1/policy-management"), "Profile endpoint is not policy-management");
	assert(UUID.test(tenant ?? ""), "Invalid tenant ID");
	assert(Number.isSafeInteger(revision) && revision > 0, "A positive staged revision is required");
	return url;
}

async function boundedJson(response) {
	const declared = Number(response.headers.get("content-length"));
	assert(!Number.isFinite(declared) || declared <= MAX_RESPONSE_BYTES, "Profile response is too large");
	assert(response.body, "Profile response has no body");
	const chunks = [];
	let size = 0;
	for await (const chunk of response.body) {
		size += chunk.byteLength;
		assert(size <= MAX_RESPONSE_BYTES, "Profile response is too large");
		chunks.push(chunk);
	}
	return JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
}

/** sha256 over the canonical document, as recorded by the control plane. */
export function stagedProfileDigest(document) {
	return createHash("sha256").update(canonicalDetectorPolicyPayload(document), "utf8").digest("hex");
}

/**
 * Pull one staged revision. Refuses a superseded revision, another tenant's
 * answer and a document whose digest does not match the recorded one.
 */
export async function readStagedProfileRevision({ endpoint, token, tenant, revision, fetcher = fetch }) {
	const url = validateStagedRequest({ endpoint, tenant, revision });
	const response = await fetcher(url.href, {
		method: "POST",
		redirect: "error",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify({ action: "read_agent_profile_revision", tenant_id: tenant, version: revision }),
		signal: AbortSignal.timeout(10_000),
	});
	assert(response.ok, `Staged profile read failed (HTTP ${response.status})`);
	const body = await boundedJson(response);
	const staged = body?.revision;
	assert(body?.ok === true && typeof body.tenant_id === "string" && body.tenant_id.toLowerCase() === tenant.toLowerCase(),
		"Staged profile answer belongs to another tenant");
	assert(staged && staged.version === revision && staged.policy && typeof staged.policy === "object",
		"Staged profile revision is absent or changed");
	assert(body.current === true,
		`Revision ${revision} is not the current staged revision (current: ${String(body.current_version)}); refusing to publish a superseded document`);
	assert(typeof staged.policy_sha256 === "string" && stagedProfileDigest(staged.policy) === staged.policy_sha256,
		"Staged profile digest does not match the document");
	return { source: JSON.stringify(staged.policy), sha256: staged.policy_sha256, version: staged.version };
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
			[
				"--tenant", "--runtime", "--profiles", "--expires-at", "--private-key", "--output-dir",
				"--endpoint", "--token-file", "--revision",
			].includes(key),
		),
		"Unknown option",
	);
	return args;
}

export async function main(argv, { now = new Date(), fetcher = fetch } = {}) {
	const args = parseArgs(argv);
	const runtime = args["--runtime"];
	assert(RUNTIMES.has(runtime), "Unsupported agent runtime");
	const staged = args["--endpoint"] !== undefined || args["--token-file"] !== undefined || args["--revision"] !== undefined;
	assert(staged !== (args["--profiles"] !== undefined),
		"Give either --profiles <file> or --endpoint, --token-file and --revision for a staged revision");
	assert(args["--private-key"] && args["--output-dir"], "Private key and output directory are required");
	let source;
	let stagedRevision = null;
	if (staged) {
		assert(args["--endpoint"] && args["--token-file"] && args["--revision"],
			"A staged revision needs --endpoint, --token-file and --revision");
		assert(/^[1-9][0-9]{0,15}$/.test(args["--revision"]), "A positive staged revision is required");
		const token = (await readSmallRegularFile(args["--token-file"], 8192, "AAL2 access token")).toString("utf8").trim();
		stagedRevision = await readStagedProfileRevision({
			endpoint: args["--endpoint"], token, tenant: args["--tenant"], revision: Number(args["--revision"]), fetcher,
		});
		source = stagedRevision.source;
	}
	const privateKey = createPrivateKey(await readSmallRegularFile(args["--private-key"], 32768, "Signing key"));
	if (!staged) {
		source = (await readSmallRegularFile(args["--profiles"], 256 * 1024, "Profile document")).toString("utf8");
	}
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
		...(stagedRevision ? { staged_revision: stagedRevision.version, policy_sha256: stagedRevision.sha256 } : {}),
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
