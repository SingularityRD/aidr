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
	signAgentProfileBundle,
	validateExpiry,
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
