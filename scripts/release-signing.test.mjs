import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
	cp,
	mkdtemp,
	mkdir,
	readdir,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "..");
const signScript = path.join(repoRoot, "scripts", "release-sign.mjs");
const verifyScript = path.join(repoRoot, "scripts", "release-verify.mjs");
const temporaryDirectories = [];

afterEach(async () => {
	await Promise.all(
		temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
	);
});

test("artifact-only receiver verifies without the signer key, checkout, or package manager", async () => {
	const fixture = await createFixture();
	assert.equal(sign(fixture, { sequence: 7 }).status, 0);
	const receiver = await mkdtemp(path.join(os.tmpdir(), "aidr-independent-release-fixture-"));
	temporaryDirectories.push(receiver);
	const bundle = path.join(receiver, "delivery");
	await cp(fixture.bundle, bundle, { recursive: true });
	for (const name of ["release-verify.mjs", "release-signing-lib.mjs"]) await cp(path.join(repoRoot, "scripts", name), path.join(receiver, name));
	const policy = path.join(receiver, "independently-delivered-policy.json");
	await cp(fixture.policy, policy);
	await rm(fixture.privateKey);
	const args = [path.join(receiver, "release-verify.mjs"), "--bundle", bundle, "--policy", policy, "--state", path.join(receiver, "protected-state.json"), "--record"];
	const runReceiver = () => spawnSync(process.execPath, args, { cwd: receiver, env: { PATH: "" }, encoding: "utf8", windowsHide: true });
	const checked = runReceiver();
	assert.equal(checked.status, 0, checked.stderr);
	assert.equal(JSON.parse(checked.stdout).artifacts_verified, 1);
	assert.ok(!(await readdir(receiver)).some((name) => /private|node_modules|\.git/.test(name)));
	await writeFile(path.join(bundle, "agent.tgz"), "changed after transfer\n");
	const tampered = runReceiver();
	assert.equal(tampered.status, 1);
	assert.match(tampered.stderr, /digest|size|inventory/i);
});

test("signs an exact release and runs an installer only after verification", async () => {
	const fixture = await createFixture();
	const signed = sign(fixture, { sequence: 7 });
	assert.equal(signed.status, 0, signed.stderr);
	assert.equal(JSON.parse(signed.stdout).status, "signed");
	assert.deepEqual((await readdir(fixture.bundle)).sort(), [
		"agent.tgz",
		"aidr-release.manifest.json",
		"aidr-release.manifest.sig",
		"release-inventory.json",
		"release-metadata.json",
	]);

	const installer = path.join(fixture.root, "installer.mjs");
	const marker = path.join(fixture.root, "installed.json");
	await writeFile(
		installer,
		`import { writeFileSync } from "node:fs";\nwriteFileSync(process.argv[2], JSON.stringify({ digest: process.env.AIDR_VERIFIED_RELEASE_MANIFEST_SHA256, sequence: process.env.AIDR_VERIFIED_RELEASE_SEQUENCE, version: process.env.AIDR_VERIFIED_RELEASE_VERSION }));\n`,
	);
	const verified = run(verifyScript, [
		"--bundle",
		fixture.bundle,
		"--policy",
		fixture.policy,
		"--state",
		fixture.state,
		"--receipt",
		fixture.receipt,
		"--",
		process.execPath,
		installer,
		marker,
	]);
	assert.equal(verified.status, 0, verified.stderr);
	const result = JSON.parse(verified.stdout.trim().split(/\r?\n/).at(-1));
	assert.equal(result.status, "installed");
	assert.equal(result.artifacts_verified, 1);
	assert.equal(result.anti_rollback_state_recorded, true);
	const markerValue = JSON.parse(await readFile(marker, "utf8"));
	assert.equal(markerValue.digest, result.manifest_sha256);
	assert.equal(markerValue.sequence, "7");
	assert.equal(markerValue.version, "1.2.3");
	const state = JSON.parse(await readFile(fixture.state, "utf8"));
	assert.equal(state.records["singularity-aidr/stable"].highest_release_sequence, 7);
	assert.equal(state.records["singularity-aidr/stable"].manifest_sha256, result.manifest_sha256);
	const receipt = JSON.parse(await readFile(fixture.receipt, "utf8"));
	assert.equal(receipt.status, "installed");
	assert.equal(receipt.policy_id, "customer-release-policy");

	// Re-verifying the exact same sequence and digest is idempotent, including
	// replacement of the protected state file on Windows.
	const repeated = verify(fixture, ["--record"]);
	assert.equal(repeated.status, 0, repeated.stderr);
});

test("refuses to sign a candidate recorded as a dirty local rehearsal", async () => {
	const fixture = await createFixture();
	const metadataPath = path.join(fixture.bundle, "release-metadata.json");
	const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
	metadata.worktree_dirty = true;
	await writeFile(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);
	const result = sign(fixture, { sequence: 8 });
	assert.equal(result.status, 1);
	assert.match(result.stderr, /dirty or unproven worktree candidates cannot be signed/);
	await assert.rejects(stat(path.join(fixture.bundle, "aidr-release.manifest.sig")), /ENOENT/);
});

test("refuses to sign a candidate with no worktree cleanliness proof", async () => {
	const fixture = await createFixture();
	const metadataPath = path.join(fixture.bundle, "release-metadata.json");
	const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
	delete metadata.worktree_dirty;
	await writeFile(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);
	const result = sign(fixture, { sequence: 8 });
	assert.equal(result.status, 1);
	assert.match(result.stderr, /release worktree status is missing/);
	await assert.rejects(stat(path.join(fixture.bundle, "aidr-release.manifest.sig")), /ENOENT/);
});

test("rejects artifact tampering before the installer can execute", async () => {
	const fixture = await createFixture();
	assert.equal(sign(fixture, { sequence: 8 }).status, 0);
	await writeFile(path.join(fixture.bundle, "agent.tgz"), "tampered bytes");
	const marker = path.join(fixture.root, "must-not-exist");
	const result = verify(fixture, ["--", process.execPath, "-e", `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "bad")`]);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /artifact (digest|size) mismatch/);
	await assert.rejects(stat(marker), /ENOENT/);
});

test("rejects a modified detached Ed25519 signature", async () => {
	const fixture = await createFixture();
	assert.equal(sign(fixture, { sequence: 81 }).status, 0);
	const signaturePath = path.join(fixture.bundle, "aidr-release.manifest.sig");
	const envelope = JSON.parse(await readFile(signaturePath, "utf8"));
	const signature = Buffer.from(envelope.signature_b64, "base64");
	signature[0] ^= 1;
	envelope.signature_b64 = signature.toString("base64");
	await writeFile(signaturePath, `${JSON.stringify(envelope, null, 2)}\n`);
	const result = verify(fixture);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /Ed25519 signature does not verify/);
});

test("enforces signer allowlists and revocation by key id or fingerprint", async () => {
	const fixture = await createFixture();
	assert.equal(sign(fixture, { sequence: 9 }).status, 0);
	const unknownPolicy = buildPolicy(fixture.keys, {
		trustedSigners: [{ ...fixture.keys.signer, key_id: "different-key" }],
	});
	await writeFile(fixture.policy, JSON.stringify(unknownPolicy));
	const unknown = verify(fixture);
	assert.equal(unknown.status, 1);
	assert.match(unknown.stderr, /not in the trusted allowlist/);

	await writeFile(fixture.policy, JSON.stringify(buildPolicy(fixture.keys, { revokedKeyIds: ["release-key-1"] })));
	const revokedKey = verify(fixture);
	assert.equal(revokedKey.status, 1);
	assert.match(revokedKey.stderr, /signer is revoked/);

	await writeFile(
		fixture.policy,
		JSON.stringify(buildPolicy(fixture.keys, { revokedFingerprints: [fixture.keys.fingerprint] })),
	);
	const revokedFingerprint = verify(fixture);
	assert.equal(revokedFingerprint.status, 1);
	assert.match(revokedFingerprint.stderr, /signer is revoked/);
});

test("rejects expired releases and validity windows longer than policy permits", async () => {
	const expired = await createFixture();
	assert.equal(
		sign(expired, {
			sequence: 10,
			issuedAt: new Date(Date.now() - 7_200_000).toISOString(),
			expiresAt: new Date(Date.now() - 3_600_000).toISOString(),
		}).status,
		0,
	);
	const expiredResult = verify(expired);
	assert.equal(expiredResult.status, 1);
	assert.match(expiredResult.stderr, /has expired/);

	const tooLong = await createFixture();
	assert.equal(
		sign(tooLong, {
			sequence: 11,
			issuedAt: new Date(Date.now() - 1000).toISOString(),
			expiresAt: new Date(Date.now() + 10_800_000).toISOString(),
		}).status,
		0,
	);
	const tooLongResult = verify(tooLong);
	assert.equal(tooLongResult.status, 1);
	assert.match(tooLongResult.stderr, /validity exceeds signer policy maximum/);
});

test("allows an older rollback candidate only when protected policy permits its lifetime", async () => {
	const fixture = await createFixture();
	const day = 86_400_000;
	const now = Date.now();
	fixture.keys.signer.valid_from = new Date(now - 11 * day).toISOString();
	fixture.keys.signer.valid_until = new Date(now + 2 * day).toISOString();
	await writeFile(
		fixture.policy,
		JSON.stringify(buildPolicy(fixture.keys, { maximumSignatureLifetimeSeconds: 10 * 86_400 })),
	);
	assert.equal(
		sign(fixture, {
			sequence: 111,
			issuedAt: new Date(now - 9 * day).toISOString(),
			expiresAt: new Date(now + day).toISOString(),
		}).status,
		0,
	);
	const permitted = verify(fixture);
	assert.equal(permitted.status, 0, permitted.stderr);

	await writeFile(
		fixture.policy,
		JSON.stringify(buildPolicy(fixture.keys, { maximumSignatureLifetimeSeconds: 8 * 86_400 })),
	);
	const rejected = verify(fixture);
	assert.equal(rejected.status, 1);
	assert.match(rejected.stderr, /validity exceeds signer policy maximum/);
});

test("rejects rollback and same-sequence equivocation", async () => {
	const rollback = await createFixture();
	assert.equal(sign(rollback, { sequence: 12 }).status, 0);
	await writeState(rollback.state, 13, "a".repeat(64));
	const rollbackResult = verify(rollback);
	assert.equal(rollbackResult.status, 1);
	assert.match(rollbackResult.stderr, /release rollback rejected/);

	const equivocation = await createFixture();
	assert.equal(sign(equivocation, { sequence: 14 }).status, 0);
	await writeState(equivocation.state, 14, "b".repeat(64));
	const equivocationResult = verify(equivocation);
	assert.equal(equivocationResult.status, 1);
	assert.match(equivocationResult.stderr, /release equivocation rejected/);
});

test("keeps private keys and trust policy outside the signed bundle", async () => {
	const fixture = await createFixture();
	const bundledKey = path.join(fixture.bundle, "release-private.pem");
	await writeFile(bundledKey, fixture.keys.privateKeyPem, { mode: 0o600 });
	const signing = run(signScript, signArguments(fixture, { sequence: 15, privateKey: bundledKey }));
	assert.equal(signing.status, 1);
	assert.match(signing.stderr, /(untracked file|outside the release bundle)/);
	await assert.rejects(stat(path.join(fixture.bundle, "aidr-release.manifest.json")), /ENOENT/);

	await rm(bundledKey);
	assert.equal(sign(fixture, { sequence: 15 }).status, 0);
	const bundledPolicy = path.join(fixture.bundle, "policy.json");
	await writeFile(bundledPolicy, await readFile(fixture.policy));
	const verification = run(verifyScript, [
		"--bundle",
		fixture.bundle,
		"--policy",
		bundledPolicy,
		"--state",
		fixture.state,
	]);
	assert.equal(verification.status, 1);
	assert.match(verification.stderr, /(untracked file|stored outside the release bundle)/);
});

test("does not advance anti-rollback state when the verified installer fails", async () => {
	const fixture = await createFixture();
	assert.equal(sign(fixture, { sequence: 16 }).status, 0);
	const installer = path.join(fixture.root, "failing-installer.mjs");
	await writeFile(installer, "process.exit(23);\n");
	const result = verify(fixture, ["--", process.execPath, installer]);
	assert.equal(result.status, 23, result.stderr);
	assert.match(result.stderr, /anti-rollback state was not advanced/);
	await assert.rejects(stat(fixture.state), /ENOENT/);
	await assert.rejects(stat(`${fixture.state}.lock`), /ENOENT/);
});

test("rejects unsafe receipt destinations before running an installer", async () => {
	const fixture = await createFixture();
	assert.equal(sign(fixture, { sequence: 18 }).status, 0);
	const originalPolicy = await readFile(fixture.policy);
	const destinations = [
		[path.join(fixture.bundle, "receipt.json"), /outside the release bundle/],
		[fixture.state, /anti-rollback state must use different paths/],
		[fixture.policy, /signer policy must use different paths/],
		[fixture.root, /receipt must be a regular file path/],
	];
	for (const [index, [receiptPath, expectedError]] of destinations.entries()) {
		const marker = path.join(fixture.root, `installer-marker-${index}`);
		const result = verify(fixture, [
			"--receipt",
			receiptPath,
			"--",
			process.execPath,
			"-e",
			`require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran")`,
		]);
		assert.equal(result.status, 1);
		assert.match(result.stderr, expectedError);
		await assert.rejects(stat(marker), /ENOENT/);
		await assert.rejects(stat(fixture.state), /ENOENT/);
		assert.deepEqual(await readFile(fixture.policy), originalPolicy);
	}
});

test("fails closed when another installation holds the anti-rollback lock", async () => {
	const fixture = await createFixture();
	assert.equal(sign(fixture, { sequence: 17 }).status, 0);
	await mkdir(path.dirname(fixture.state), { recursive: true });
	await writeFile(`${fixture.state}.lock`, JSON.stringify({ pid: 123, acquired_at: new Date().toISOString() }));
	const result = verify(fixture, ["--record"]);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /holds the anti-rollback lock/);
	await assert.rejects(stat(fixture.state), /ENOENT/);
});

async function createFixture() {
	const root = await mkdtemp(path.join(os.tmpdir(), "aidr-release-signing-"));
	temporaryDirectories.push(root);
	const bundle = path.join(root, "bundle");
	await mkdir(bundle);
	const artifact = Buffer.from("signed release payload\n");
	const digest = createHash("sha256").update(artifact).digest("hex");
	await writeFile(path.join(bundle, "agent.tgz"), artifact);
	await writeFile(
		path.join(bundle, "release-metadata.json"),
		`${JSON.stringify({
			schema_version: 1,
			release_tag: "v1.2.3",
			release_version: "1.2.3",
			git_sha: "1".repeat(40),
			source_date_epoch: 1_789_167_600,
			worktree_dirty: false,
			artifacts: [{ path: "agent.tgz", size: artifact.byteLength, sha256: digest }],
		}, null, 2)}\n`,
	);
	await writeFile(
		path.join(bundle, "release-inventory.json"),
		`${JSON.stringify({
			schema_version: 1,
			artifacts: [
				{
					source_path: "release-output/agent.tgz",
					staged_path: "agent.tgz",
					kind: "release-artifact",
					sha256: digest,
				},
			],
		}, null, 2)}\n`,
	);
	const keys = createKeys();
	const privateKey = path.join(root, "offline-private.pem");
	await writeFile(privateKey, keys.privateKeyPem, { mode: 0o600 });
	const policy = path.join(root, "signer-policy.json");
	await writeFile(policy, `${JSON.stringify(buildPolicy(keys), null, 2)}\n`);
	return {
		root,
		bundle,
		privateKey,
		policy,
		state: path.join(root, "operator-state", "release-state.json"),
		receipt: path.join(root, "operator-state", "verification-receipt.json"),
		keys,
	};
}

function createKeys() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
	const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
	const fingerprint = `sha256:${createHash("sha256")
		.update(publicKey.export({ type: "spki", format: "der" }))
		.digest("hex")}`;
	return {
		privateKeyPem,
		fingerprint,
		signer: {
			key_id: "release-key-1",
			public_key_pem: publicKeyPem,
			fingerprint_sha256: fingerprint,
			valid_from: new Date(Date.now() - 86_400_000).toISOString(),
			valid_until: new Date(Date.now() + 86_400_000).toISOString(),
		},
	};
}

function buildPolicy(keys, overrides = {}) {
	return {
		schema_version: 1,
		policy_id: "customer-release-policy",
		product_id: "singularity-aidr",
		allowed_channels: ["stable"],
		minimum_release_sequence: 1,
		maximum_signature_lifetime_seconds: overrides.maximumSignatureLifetimeSeconds ?? 7200,
		trusted_signers: overrides.trustedSigners ?? [keys.signer],
		revoked_key_ids: overrides.revokedKeyIds ?? [],
		revoked_fingerprints: overrides.revokedFingerprints ?? [],
	};
}

function sign(fixture, overrides = {}) {
	return run(signScript, signArguments(fixture, overrides));
}

function signArguments(fixture, overrides = {}) {
	return [
		"--bundle",
		fixture.bundle,
		"--private-key",
		overrides.privateKey ?? fixture.privateKey,
		"--key-id",
		"release-key-1",
		"--sequence",
		String(overrides.sequence),
		"--issued-at",
		overrides.issuedAt ?? new Date(Date.now() - 1000).toISOString(),
		"--expires-at",
		overrides.expiresAt ?? new Date(Date.now() + 3_600_000).toISOString(),
	];
}

function verify(fixture, extraArguments = []) {
	return run(verifyScript, [
		"--bundle",
		fixture.bundle,
		"--policy",
		fixture.policy,
		"--state",
		fixture.state,
		...extraArguments,
	]);
}

function run(script, arguments_) {
	return spawnSync(process.execPath, [script, ...arguments_], {
		cwd: repoRoot,
		encoding: "utf8",
		windowsHide: true,
	});
}

async function writeState(statePath, sequence, digest) {
	await mkdir(path.dirname(statePath), { recursive: true });
	await writeFile(
		statePath,
		JSON.stringify({
			schema_version: 1,
			records: {
				"singularity-aidr/stable": {
					highest_release_sequence: sequence,
					manifest_sha256: digest,
					release_version: "future",
					recorded_at: new Date().toISOString(),
				},
			},
		}),
	);
}
