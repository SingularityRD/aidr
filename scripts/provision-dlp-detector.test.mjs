import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { test } from "node:test";
import { canonicalDetectorPolicyPayload, loadProvisionedDetectorContext, scanDlpInput } from "../packages/core/dist/index.js";
import { installSignedDlpBundle, main, readSavedDlpRevision, signSavedDlpRevision, validateRequest } from "./provision-dlp-detector.mjs";

const TENANT = "22222222-2222-4222-8222-222222222222";
const MARKER = "AIDR-TENANT-SYNTHETIC-RESTRICTED";
const ENDPOINT = "https://example.invalid/functions/v1/policy-management";

function policy(tenant = TENANT) {
	return {
		version: 7, tenantId: tenant, maxContentBytes: 4096,
		supportedFormats: ["application/json"], unavailableAction: "block",
		labels: [{ id: "restricted", tenantId: tenant, name: "Restricted", sensitivity: "restricted" }],
		rules: [{ id: "marker", tenantId: tenant, labelId: "restricted", name: "Synthetic marker",
			action: "block", directions: ["input"], matchers: [{ type: "keyword", values: [MARKER], wholeWord: false }] }],
		exceptions: [],
	};
}

function savedResponse(body) {
	return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

test("publisher accepts only HTTPS, a specific tenant/runtime/revision and a bounded expiry", () => {
	const now = new Date("2026-09-23T00:00:00.000Z");
	const request = { endpoint: ENDPOINT, tenant: TENANT, version: 7, runtime: "opencode",
		expiresAt: "2026-09-23T01:00:00.000Z" };
	assert.equal(validateRequest(request, now).href, ENDPOINT);
	assert.throws(() => validateRequest({ ...request, endpoint: ENDPOINT.replace("https:", "http:") }, now), /HTTPS/);
	assert.throws(() => validateRequest({ ...request, tenant: "other" }, now), /tenant/);
	assert.throws(() => validateRequest({ ...request, runtime: ".." }, now), /runtime/);
	assert.throws(() => validateRequest({ ...request, version: 0 }, now), /revision/);
	assert.throws(() => validateRequest({ ...request, expiresAt: "2026-09-25T00:00:00.000Z" }, now), /24 hours/);
	assert.throws(() => validateRequest({ ...request, expiresAt: "2026-09-23" }, now), /RFC3339/);
	assert.throws(() => validateRequest({ ...request, expiresAt: "2026-02-30T00:00:00Z" },
		new Date("2026-02-28T00:00:00Z")), /real UTC/);
});

test("MFA-protected saved revision must match the explicit tenant and version before signing", async () => {
	const response = { ok: true, saved: true, delivered: false, version: 7, policy: policy() };
	const fetcher = async (_url, init) => {
		assert.equal(init.redirect, "error");
		assert.equal(init.headers.Authorization, "Bearer synthetic-token");
		assert.deepEqual(JSON.parse(init.body), { action: "read_dlp_policy", tenant_id: TENANT });
		return savedResponse(response);
	};
	assert.equal((await readSavedDlpRevision({ endpoint: ENDPOINT, token: "synthetic-token",
		tenant: TENANT, version: 7, fetcher })).version, 7);
	for (const invalid of [{ ...response, version: 6 }, { ...response, saved: false },
		{ ...response, delivered: true }, { ...response, policy: policy("33333333-3333-4333-8333-333333333333") }]) {
		await assert.rejects(readSavedDlpRevision({ endpoint: ENDPOINT, token: "synthetic-token",
			tenant: TENANT, version: 7, fetcher: async () => savedResponse(invalid) }), /revision|invalid/);
	}
});

test("operator command reads protected token/key files and writes only a not-verified bundle", async () => {
	const scratch = await mkdtemp(join(tmpdir(), "aidr-dlp-command-"));
	try {
		const { privateKey } = generateKeyPairSync("ed25519");
		const tokenFile = join(scratch, "token");
		const keyFile = join(scratch, "key.pem");
		const outputDir = join(scratch, "detectors");
		await writeFile(tokenFile, "synthetic-token\n");
		await writeFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }));
		const expiry = new Date(Date.now() + 300_000).toISOString();
		const result = await main(["--endpoint", ENDPOINT, "--tenant", TENANT, "--version", "7",
			"--runtime", "opencode", "--expires-at", expiry, "--token-file", tokenFile,
			"--private-key", keyFile, "--output-dir", outputDir], {
			fetcher: async (_url, init) => {
				assert.equal(init.headers.Authorization, "Bearer synthetic-token");
				return savedResponse({ ok: true, saved: true, delivered: false, version: 7, policy: policy() });
			},
		});
		assert.equal(result.status, "signed_bundle_written_not_agent_verified");
		assert.equal(result.output, join(outputDir, "opencode.json"));
		assert.equal(JSON.parse(await readFile(result.output, "utf8")).payload.dlp.policy.version, 7);
	} finally {
		const canonicalScratch = await realpath(scratch);
		assert.equal(dirname(canonicalScratch), await realpath(tmpdir()));
		assert.match(basename(canonicalScratch), /^aidr-dlp-command-/);
		await rm(canonicalScratch, { recursive: true, force: true });
	}
});

for (const premiumModules of [["premium_intel"], ["runtime_detectors"]]) {
test(`saved DLP revision enforces with signed entitlement modules ${premiumModules.join(",")}`, async () => {
	const scratch = await mkdtemp(join(tmpdir(), "aidr-dlp-delivery-"));
	const priorHome = process.env.HOME;
	try {
		process.env.HOME = scratch;
		const stateDir = join(scratch, ".singularity-aidr");
		await mkdir(stateDir, { recursive: true });
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		await writeFile(join(stateDir, "config.json"), JSON.stringify({
			mode: "managed", control_plane: { enabled: false },
			licensing: { public_keys_pem: [publicPem], require_signed_entitlements: true },
		}));
		const now = Date.now();
		const entitlement = { schema_version: 2, tenant_id: TENANT, subscription_tier: "enterprise",
			included_agents: 1, extra_agents: 0, allowed_agents: 1,
			premium_modules: premiumModules, issued_at: new Date(now - 60_000).toISOString(),
			expires_at: new Date(now + 600_000).toISOString(), grace_until: new Date(now + 900_000).toISOString(),
			serial: "synthetic-signed-entitlement", revocation_epoch: 1 };
		await writeFile(join(stateDir, "managed.json"), JSON.stringify({ entitlement, entitlement_alg: "ed25519",
			entitlement_key_id: "synthetic-test", entitlement_sig: sign(null,
				Buffer.from(canonicalDetectorPolicyPayload(entitlement)), privateKey).toString("base64") }));
		const bundle = signSavedDlpRevision({ policy: policy(), tenant: TENANT,
			expiresAt: new Date(now + 300_000).toISOString(), privateKey });
		const output = await installSignedDlpBundle(join(stateDir, "detectors"), "opencode", bundle);
		assert.equal(JSON.parse(await readFile(output, "utf8")).payload.dlp.policy.version, 7);
		const context = await loadProvisionedDetectorContext("opencode");
		assert.equal(context.runtimeDetectors?.tenantId, TENANT);
		assert.equal(scanDlpInput(context.runtimeDetectors.dlp.policy, { tenantId: TENANT,
			content: JSON.stringify({ command: MARKER }), contentType: "application/json" }).action, "block");
		assert.equal(scanDlpInput(context.runtimeDetectors.dlp.policy, { tenantId: TENANT,
			content: JSON.stringify({ command: "ordinary harmless text" }), contentType: "application/json" }).action, "allow");
		const old = signSavedDlpRevision({ policy: { ...policy(), version: 6 }, tenant: TENANT,
			expiresAt: new Date(now + 300_000).toISOString(), privateKey });
		await assert.rejects(installSignedDlpBundle(join(stateDir, "detectors"), "opencode", old), /newer DLP/);
		assert.equal(JSON.parse(await readFile(output, "utf8")).payload.dlp.policy.version, 7);
		bundle.payload.dlp.policy.rules[0].name = "tampered";
		await installSignedDlpBundle(join(stateDir, "detectors"), "opencode", bundle);
		await assert.rejects(loadProvisionedDetectorContext("opencode"), /trust or tenant binding/);
	} finally {
		if (priorHome === undefined) delete process.env.HOME;
		else process.env.HOME = priorHome;
		const canonicalScratch = await realpath(scratch);
		assert.equal(dirname(canonicalScratch), await realpath(tmpdir()));
		assert.match(basename(canonicalScratch), /^aidr-dlp-delivery-/);
		await rm(canonicalScratch, { recursive: true, force: true });
	}
});
}
