#!/usr/bin/env node

/** Sign one MFA-verified, saved tenant DLP revision for an installed agent. */
import { createPrivateKey, createPublicKey, randomUUID, sign } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DlpPolicySchema, canonicalDetectorPolicyPayload } from "../packages/core/dist/index.js";
import { carriedSections, readInstalledBundle } from "./provision-agent-profiles.mjs";

const RUNTIMES = new Set(["claude-code", "cursor", "vscode", "openclaw", "opencode", "codex"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;

function assert(condition, message) {
	if (!condition) throw new Error(message);
}

function validateExpiry(expiresAt, now) {
	assert(typeof expiresAt === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(expiresAt),
		"DLP bundle expiry must be an RFC3339 UTC timestamp");
	const expiry = Date.parse(expiresAt);
	assert(Number.isFinite(expiry) && [new Date(expiry).toISOString(), new Date(expiry).toISOString().replace(".000Z", "Z")].includes(expiresAt),
		"DLP bundle expiry is not a real UTC timestamp");
	assert(expiry > now.getTime() && expiry - now.getTime() <= MAX_LIFETIME_MS,
		"DLP bundle expiry must be in the next 24 hours");
}

export function validateRequest({ endpoint, tenant, version, runtime, expiresAt }, now = new Date()) {
	const url = new URL(endpoint);
	assert(url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash,
		"DLP policy endpoint must be a clean HTTPS URL");
	assert(url.pathname.endsWith("/functions/v1/policy-management"), "DLP policy endpoint is not policy-management");
	assert(UUID.test(tenant), "Invalid tenant ID");
	assert(Number.isSafeInteger(version) && version > 0, "A positive saved revision is required");
	assert(RUNTIMES.has(runtime), "Unsupported agent runtime");
	validateExpiry(expiresAt, now);
	return url;
}

async function boundedJson(response) {
	const declared = Number(response.headers.get("content-length"));
	assert(!Number.isFinite(declared) || declared <= MAX_RESPONSE_BYTES, "DLP policy response is too large");
	assert(response.body, "DLP policy response has no body");
	const chunks = [];
	let size = 0;
	for await (const chunk of response.body) {
		size += chunk.byteLength;
		assert(size <= MAX_RESPONSE_BYTES, "DLP policy response is too large");
		chunks.push(chunk);
	}
	return JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
}

export async function readSavedDlpRevision({ endpoint, token, tenant, version, fetcher = fetch }) {
	const response = await fetcher(endpoint, {
		method: "POST",
		redirect: "error",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify({ action: "read_dlp_policy", tenant_id: tenant }),
		signal: AbortSignal.timeout(10_000),
	});
	assert(response.ok, `DLP policy read failed (HTTP ${response.status})`);
	const saved = await boundedJson(response);
	assert(saved?.ok === true && saved.saved === true && saved.delivered === false &&
		saved.version === version && saved.policy?.version === version,
		"DLP policy revision is absent, changed, or already has an unsupported delivery contract");
	const parsed = DlpPolicySchema.safeParse(saved.policy);
	assert(parsed.success && parsed.data.tenantId === tenant, "Saved DLP policy is invalid or belongs to another tenant");
	return parsed.data;
}

export function signSavedDlpRevision({ policy, tenant, expiresAt, privateKey, carried = {}, now = new Date() }) {
	const parsed = DlpPolicySchema.parse(policy);
	assert(parsed.tenantId === tenant, "DLP policy tenant mismatch");
	assert(privateKey.asymmetricKeyType === "ed25519", "DLP signing key must be Ed25519");
	validateExpiry(expiresAt, now);
	const payload = {
		schema_version: 1,
		tenant_id: tenant,
		issued_at: now.toISOString(),
		expires_at: expiresAt,
		dlp: { enabled: true, policy: parsed },
		// Agent permission profiles share this signed bundle; keep a verified section.
		...(carried.agent_profiles !== undefined ? { agent_profiles: carried.agent_profiles } : {}),
	};
	return {
		alg: "ed25519",
		payload,
		sig_b64: sign(null, Buffer.from(canonicalDetectorPolicyPayload(payload)), privateKey).toString("base64"),
	};
}

async function readSmallRegularFile(path, maxBytes, label) {
	const info = await lstat(path);
	assert(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= maxBytes,
		`${label} must be a small regular file`);
	return readFile(path);
}

export async function installSignedDlpBundle(outputDir, runtime, bundle) {
	assert(RUNTIMES.has(runtime), "Unsupported agent runtime");
	const serialized = `${JSON.stringify(bundle)}\n`;
	assert(Buffer.byteLength(serialized) <= MAX_RESPONSE_BYTES, "Signed DLP bundle exceeds runtime size limit");
	await mkdir(outputDir, { recursive: true, mode: 0o700 });
	const directory = await lstat(outputDir);
	assert(directory.isDirectory() && !directory.isSymbolicLink() &&
		resolve(await realpath(outputDir)).toLowerCase() === resolve(outputDir).toLowerCase(),
		"DLP output directory must not redirect to another location");
	const target = join(outputDir, `${runtime}.json`);
	try {
		const current = await lstat(target);
		assert(current.isFile() && !current.isSymbolicLink() && current.size <= MAX_RESPONSE_BYTES,
			"Existing DLP bundle is not a bounded regular file");
		let old;
		try { old = JSON.parse(await readFile(target, "utf8")); } catch { old = null; }
		if (old?.payload?.tenant_id === bundle.payload.tenant_id) {
			assert(!(old.payload.dlp?.policy?.version > bundle.payload.dlp.policy.version),
				"Refusing to replace a newer DLP policy revision");
		}
	} catch (error) {
		if (error.code !== "ENOENT") throw error;
	}
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
	assert(Object.keys(args).every((key) => ["--endpoint", "--tenant", "--version", "--runtime",
		"--expires-at", "--token-file", "--private-key", "--output-dir"].includes(key)), "Unknown option");
	return args;
}

export async function main(argv, { fetcher = fetch } = {}) {
	const args = parseArgs(argv);
	const request = {
		endpoint: args["--endpoint"], tenant: args["--tenant"],
		version: Number(args["--version"]), runtime: args["--runtime"],
		expiresAt: args["--expires-at"],
	};
	validateRequest(request);
	assert(args["--token-file"] && args["--private-key"] && args["--output-dir"],
		"Token file, private key and output directory are required");
	const token = (await readSmallRegularFile(args["--token-file"], 8192, "AAL2 access token")).toString("utf8").trim();
	assert(token && !/\s/.test(token), "Invalid AAL2 access token file");
	const key = createPrivateKey(await readSmallRegularFile(args["--private-key"], 32768, "DLP signing key"));
	const policy = await readSavedDlpRevision({ ...request, token, fetcher });
	// Publishing DLP must not silently drop agent permission profiles already
	// signed into this runtime's bundle. Only a same-tenant section that verifies
	// against this signing key is carried over; anything else is left behind.
	let carried = {};
	try {
		const { sections } = carriedSections(await readInstalledBundle(args["--output-dir"], request.runtime), {
			tenant: request.tenant, publicKey: createPublicKey(key), replace: "dlp",
		});
		if (sections.agent_profiles !== undefined) carried = { agent_profiles: sections.agent_profiles };
	} catch {
		carried = {};
	}
	const bundle = signSavedDlpRevision({ policy, tenant: request.tenant, expiresAt: request.expiresAt, privateKey: key, carried });
	const output = await installSignedDlpBundle(args["--output-dir"], request.runtime, bundle);
	return { output, tenant: request.tenant, version: request.version, runtime: request.runtime,
		status: "signed_bundle_written_not_agent_verified" };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main(process.argv.slice(2)).then((result) => console.log(JSON.stringify(result)),
		(error) => { console.error(error instanceof Error ? error.message : "DLP provisioning failed"); process.exitCode = 1; });
}
