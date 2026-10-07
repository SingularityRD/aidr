import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	agentProfileTemplateDocument,
	canonicalDetectorPolicyPayload,
	evaluateToolCall,
	loadProvisionedDetectorContext,
} from "../packages/core/dist/index.js";
import {
	carriedSections,
	installBundle,
	main,
	readInstalledBundle,
	readStagedProfileRevision,
	signAgentProfileBundle,
	stagedProfileDigest,
	validateExpiry,
	validateStagedRequest,
} from "./provision-agent-profiles.mjs";
import { signSavedDlpRevision } from "./provision-dlp-detector.mjs";

const TENANT = "33333333-3333-4333-8333-333333333333";

function dlpPolicy() {
	return {
		version: 3, tenantId: TENANT, supportedFormats: ["application/json"],
		labels: [{ id: "restricted", tenantId: TENANT, name: "Restricted", sensitivity: "restricted" }],
		rules: [{ id: "marker", tenantId: TENANT, labelId: "restricted", name: "Marker", action: "block",
			directions: ["input"], matchers: [{ type: "keyword", values: ["SYNTHETIC-MARKER"], wholeWord: false }] }],
		exceptions: [],
	};
}

async function managedHome(scratch, publicPem, privateKey) {
	const stateDir = join(scratch, ".singularity-aidr");
	await mkdir(stateDir, { recursive: true });
	await writeFile(join(stateDir, "config.json"), JSON.stringify({
		mode: "managed", control_plane: { enabled: false }, heuristics_enabled: false,
		logging: { enabled: false }, cache: { enabled: false },
		licensing: { public_keys_pem: [publicPem], require_signed_entitlements: true },
	}));
	const now = Date.now();
	const entitlement = { schema_version: 2, tenant_id: TENANT, subscription_tier: "enterprise",
		included_agents: 1, extra_agents: 0, allowed_agents: 1, premium_modules: ["runtime_detectors"],
		issued_at: new Date(now - 60_000).toISOString(), expires_at: new Date(now + 600_000).toISOString(),
		grace_until: new Date(now + 900_000).toISOString(), serial: "synthetic", revocation_epoch: 1 };
	await writeFile(join(stateDir, "managed.json"), JSON.stringify({ entitlement, entitlement_alg: "ed25519",
		entitlement_key_id: "synthetic", entitlement_sig: sign(null,
			Buffer.from(canonicalDetectorPolicyPayload(entitlement)), privateKey).toString("base64") }));
	return stateDir;
}

test("expiry must be a UTC timestamp within 24 hours", () => {
	const now = new Date("2026-09-25T00:00:00.000Z");
	assert.doesNotThrow(() => validateExpiry("2026-09-25T12:00:00Z", now));
	assert.throws(() => validateExpiry("2026-09-27T00:00:00Z", now), /24 hours/);
	assert.throws(() => validateExpiry("tomorrow", now), /RFC3339/);
});

test("an invalid profile document is refused before anything is signed", () => {
	const { privateKey } = generateKeyPairSync("ed25519");
	assert.throws(() => signAgentProfileBundle({
		source: JSON.stringify({ version: 1, profiles: [{ name: "x", default: "sometimes" }] }),
		tenant: TENANT, expiresAt: new Date(Date.now() + 60_000).toISOString(), privateKey,
	}), /profiles\.0\.default/);
});

test("signed profiles reach the evaluator, keep the DLP section and survive a DLP republish", async () => {
	const scratch = await mkdtemp(join(tmpdir(), "aidr-profile-delivery-"));
	const priorHome = process.env.HOME;
	try {
		process.env.HOME = scratch;
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const stateDir = await managedHome(scratch, publicPem, privateKey);
		const detectors = join(stateDir, "detectors");
		const expiresAt = new Date(Date.now() + 300_000).toISOString();

		// DLP first, then profiles: the DLP section is carried into the new bundle.
		await installBundle(detectors, "claude-code",
			signSavedDlpRevision({ policy: dlpPolicy(), tenant: TENANT, expiresAt, privateKey }));
		const keyFile = join(scratch, "signing.pem");
		await writeFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }));
		const profilesFile = join(scratch, "profiles.json");
		await writeFile(profilesFile, JSON.stringify(agentProfileTemplateDocument("locked-down")));
		const result = await main(["--tenant", TENANT, "--runtime", "claude-code", "--profiles", profilesFile,
			"--expires-at", expiresAt, "--private-key", keyFile, "--output-dir", detectors]);
		assert.deepEqual(result.profiles, ["locked-down"]);
		assert.deepEqual(result.carried_sections, ["dlp"]);

		const context = await loadProvisionedDetectorContext("claude-code");
		assert.equal(context.runtimeDetectors?.dlp?.enabled, true);
		assert.equal(context.agentProfiles?.layers[0]?.source, "managed");
		const verdict = await evaluateToolCall(
			{ sessionId: "s", toolName: "Bash", toolInput: { command: "ls" }, artifacts: [] },
			{ threatsDir: join(scratch, "none"), allowlistsDir: join(scratch, "none"), agentRuntime: "claude-code", ...context },
		);
		assert.equal(verdict.decision, "deny");
		assert.equal(verdict.agentProfile?.profile, "locked-down");

		// Republishing DLP keeps the verified profile section.
		const installed = await readInstalledBundle(detectors, "claude-code");
		const { sections } = carriedSections(installed, { tenant: TENANT, publicKey, replace: "dlp" });
		await installBundle(detectors, "claude-code", signSavedDlpRevision({ policy: dlpPolicy(), tenant: TENANT,
			expiresAt, privateKey, carried: { agent_profiles: sections.agent_profiles } }));
		const after = JSON.parse(await readFile(join(detectors, "claude-code.json"), "utf8"));
		assert.equal(after.payload.agent_profiles.profiles[0].name, "locked-down");
		assert.ok((await loadProvisionedDetectorContext("claude-code")).agentProfiles);
	} finally {
		if (priorHome === undefined) delete process.env.HOME;
		else process.env.HOME = priorHome;
		await rm(scratch, { recursive: true, force: true });
	}
});

test("sections of a bundle that does not verify are never re-signed", async () => {
	const scratch = await mkdtemp(join(tmpdir(), "aidr-profile-carry-"));
	try {
		const { publicKey } = generateKeyPairSync("ed25519");
		const other = generateKeyPairSync("ed25519");
		const expiresAt = new Date(Date.now() + 300_000).toISOString();
		const foreign = signSavedDlpRevision({ policy: dlpPolicy(), tenant: TENANT, expiresAt, privateKey: other.privateKey });
		await installBundle(scratch, "codex", foreign);
		const installed = await readInstalledBundle(scratch, "codex");
		assert.throws(() => carriedSections(installed, { tenant: TENANT, publicKey, replace: "agent_profiles" }),
			/does not verify/);
		// A different tenant's bundle is simply replaced, never merged.
		assert.deepEqual(
			carriedSections(installed, { tenant: "another-tenant", publicKey, replace: "agent_profiles" }).sections,
			{},
		);
		assert.equal(await readInstalledBundle(scratch, "cursor"), null);
	} finally {
		await rm(scratch, { recursive: true, force: true });
	}
});

const ENDPOINT = "https://control.example.test/functions/v1/policy-management";

function stagedAnswer(document, overrides = {}) {
	return {
		ok: true, tenant_id: TENANT, current: true, current_version: 4,
		revision: { version: 4, policy: document, policy_sha256: stagedProfileDigest(document), profile_count: 1 },
		delivered: false, delivery_status: "staged_not_signed",
		...overrides,
	};
}

function fetcherFor(body, status = 200) {
	const calls = [];
	const fetcher = async (url, init) => {
		calls.push({ url, init });
		return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
	};
	return { fetcher, calls };
}

test("a staged revision is pulled with the AAL2 token and must be current, same-tenant and digest-exact", async () => {
	const document = agentProfileTemplateDocument("ci-agent");
	const ok = fetcherFor(stagedAnswer(document));
	const pulled = await readStagedProfileRevision({ endpoint: ENDPOINT, token: "aal2-token", tenant: TENANT, revision: 4, fetcher: ok.fetcher });
	assert.deepEqual(JSON.parse(pulled.source), document);
	assert.equal(pulled.sha256, stagedProfileDigest(document));
	assert.equal(ok.calls[0].init.headers.Authorization, "Bearer aal2-token");
	assert.equal(ok.calls[0].init.redirect, "error");
	assert.deepEqual(JSON.parse(ok.calls[0].init.body), { action: "read_agent_profile_revision", tenant_id: TENANT, version: 4 });

	const refusals = [
		[stagedAnswer(document, { current: false, current_version: 5 }), /not the current staged revision \(current: 5\)/],
		[stagedAnswer(document, { tenant_id: "44444444-4444-4444-8444-444444444444" }), /another tenant/],
		[{ ...stagedAnswer(document), revision: { ...stagedAnswer(document).revision, policy_sha256: "0".repeat(64) } }, /digest/],
		[{ ...stagedAnswer(document), revision: { ...stagedAnswer(document).revision, version: 3 } }, /absent or changed/],
	];
	for (const [body, pattern] of refusals) {
		const { fetcher } = fetcherFor(body);
		await assert.rejects(readStagedProfileRevision({ endpoint: ENDPOINT, token: "t", tenant: TENANT, revision: 4, fetcher }), pattern);
	}
	const { fetcher: forbidden } = fetcherFor({ error: "mfa_required" }, 403);
	await assert.rejects(readStagedProfileRevision({ endpoint: ENDPOINT, token: "t", tenant: TENANT, revision: 4, fetcher: forbidden }), /HTTP 403/);
	for (const endpoint of ["http://control.example.test/functions/v1/policy-management", `${ENDPOINT}?x=1`,
		"https://user:pw@control.example.test/functions/v1/policy-management", "https://control.example.test/functions/v1/policy"]) {
		assert.throws(() => validateStagedRequest({ endpoint, tenant: TENANT, revision: 4 }), /Profile endpoint/);
	}
	assert.throws(() => validateStagedRequest({ endpoint: ENDPOINT, tenant: "not-a-uuid", revision: 4 }), /tenant/);
	assert.throws(() => validateStagedRequest({ endpoint: ENDPOINT, tenant: TENANT, revision: 0 }), /revision/);
});

test("one command signs the staged revision into the bundle the connectors verify", async () => {
	const scratch = await mkdtemp(join(tmpdir(), "aidr-profile-staged-"));
	const priorHome = process.env.HOME;
	try {
		process.env.HOME = scratch;
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const stateDir = await managedHome(scratch, publicPem, privateKey);
		const detectors = join(stateDir, "detectors");
		const keyFile = join(scratch, "signing.pem");
		await writeFile(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }));
		const tokenFile = join(scratch, "token");
		await writeFile(tokenFile, "aal2-token\n");
		const document = agentProfileTemplateDocument("locked-down");
		const { fetcher } = fetcherFor(stagedAnswer(document));
		const expiresAt = new Date(Date.now() + 300_000).toISOString();
		const result = await main(["--tenant", TENANT, "--runtime", "codex", "--endpoint", ENDPOINT,
			"--token-file", tokenFile, "--revision", "4", "--expires-at", expiresAt,
			"--private-key", keyFile, "--output-dir", detectors], { fetcher });
		assert.equal(result.staged_revision, 4);
		assert.equal(result.policy_sha256, stagedProfileDigest(document));
		assert.deepEqual(result.profiles, ["locked-down"]);
		const context = await loadProvisionedDetectorContext("codex");
		assert.equal(context.agentProfiles?.layers[0]?.source, "managed");

		// Mixing sources, or a partial staged request, is refused before any read.
		await assert.rejects(main(["--tenant", TENANT, "--runtime", "codex", "--endpoint", ENDPOINT, "--profiles", keyFile,
			"--expires-at", expiresAt, "--private-key", keyFile, "--output-dir", detectors], { fetcher }), /either --profiles/);
		await assert.rejects(main(["--tenant", TENANT, "--runtime", "codex", "--endpoint", ENDPOINT,
			"--expires-at", expiresAt, "--private-key", keyFile, "--output-dir", detectors], { fetcher }), /needs --endpoint, --token-file and --revision/);
	} finally {
		if (priorHome === undefined) delete process.env.HOME;
		else process.env.HOME = priorHome;
		await rm(scratch, { recursive: true, force: true });
	}
});
