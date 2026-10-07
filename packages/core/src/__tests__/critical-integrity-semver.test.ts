import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
	getDegradedSafeModeReason,
	isDegradedSafeMode,
	verifyArtifactIntegrity,
	verifyArtifactIntegrityAndLog,
} from "../integrity/index.js";
import { compareSemver } from "../intel/semver.js";
import { makeTmpDir } from "./test-utils.js";

const ARTIFACT_ID = "test/integrity-artifact";
const ARTIFACT_FILE = "payload.txt";
const ARTIFACT_CONTENT = "signed artifact payload\n";

function sha256Hex(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex");
}

async function writeArtifact(params: {
	dir: string;
	privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
	content?: string;
	writeFileContent?: boolean;
	signature?: "valid" | "missing" | "malformed" | "wrong-key";
	signWith?: ReturnType<typeof generateKeyPairSync>["privateKey"];
}): Promise<void> {
	const content = params.content ?? ARTIFACT_CONTENT;
	await mkdir(params.dir, { recursive: true });
	if (params.writeFileContent !== false) {
		await writeFile(join(params.dir, ARTIFACT_FILE), content, "utf8");
	}

	const manifestRaw = `${JSON.stringify({
		schema_version: 1,
		artifact_id: ARTIFACT_ID,
		artifact_version: "1.2.3",
		created_at: new Date().toISOString(),
		files: [{ path: ARTIFACT_FILE, sha256: sha256Hex(content) }],
	})}\n`;
	await writeFile(join(params.dir, "aidr-artifact.manifest.json"), manifestRaw, "utf8");

	if (params.signature === "missing") return;
	const signature =
		params.signature === "malformed"
			? "not-a-base64-ed25519-signature"
			: sign(null, Buffer.from(manifestRaw, "utf8"), params.signWith ?? params.privateKey).toString(
					"base64",
				);
	await writeFile(join(params.dir, "aidr-artifact.manifest.sig"), signature, "utf8");
}

async function writeIntegrityConfig(configPath: string, publicKeyPem?: string): Promise<void> {
	await writeFile(
		configPath,
		JSON.stringify({
			integrity: {
				enabled: true,
				verify_on_start: true,
				public_keys_pem: publicKeyPem ? [publicKeyPem] : [],
			},
			logging: { enabled: false },
		}),
		"utf8",
	);
}

describe("critical integrity and semver behavior", () => {
	it("handles valid, missing, tampered, and missing-file artifacts with safe-mode transitions", async () => {
		const root = await makeTmpDir();
		const configPath = join(root, "config.json");
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		await writeIntegrityConfig(configPath, publicKeyPem);

		expect(isDegradedSafeMode()).toBe(false);
		expect(getDegradedSafeModeReason()).toBeUndefined();

		const validDir = join(root, "valid");
		await writeArtifact({ dir: validDir, privateKey, signature: "valid" });
		await expect(
			verifyArtifactIntegrityAndLog({
				artifactDir: validDir,
				artifactId: ARTIFACT_ID,
				configPath,
			}),
		).resolves.toMatchObject({ status: "ok" });
		expect(isDegradedSafeMode()).toBe(false);

		const missingDir = join(root, "missing");
		await expect(
			verifyArtifactIntegrityAndLog({
				artifactDir: missingDir,
				artifactId: ARTIFACT_ID,
				configPath,
			}),
		).resolves.toMatchObject({ status: "missing_manifest" });
		expect(isDegradedSafeMode()).toBe(false);

		const missingFileDir = join(root, "missing-file");
		await writeArtifact({
			dir: missingFileDir,
			privateKey,
			writeFileContent: false,
			signature: "valid",
		});
		await expect(
			verifyArtifactIntegrityAndLog({
				artifactDir: missingFileDir,
				artifactId: ARTIFACT_ID,
				configPath,
			}),
		).resolves.toMatchObject({ status: "missing_file" });
		expect(isDegradedSafeMode()).toBe(true);
		expect(getDegradedSafeModeReason()).toBe(`${ARTIFACT_ID}:missing_file`);

		const tamperedDir = join(root, "tampered");
		await writeArtifact({ dir: tamperedDir, privateKey, signature: "valid" });
		await writeFile(join(tamperedDir, ARTIFACT_FILE), "tampered artifact payload\n", "utf8");
		await expect(
			verifyArtifactIntegrityAndLog({
				artifactDir: tamperedDir,
				artifactId: ARTIFACT_ID,
				configPath,
			}),
		).resolves.toMatchObject({ status: "hash_mismatch" });
		expect(isDegradedSafeMode()).toBe(true);
		expect(getDegradedSafeModeReason()).toBe(`${ARTIFACT_ID}:hash_mismatch`);
	});

	it("rejects missing, malformed, and cryptographically invalid signatures", async () => {
		const root = await makeTmpDir();
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

		const missingSignatureDir = join(root, "missing-signature");
		await writeArtifact({ dir: missingSignatureDir, privateKey, signature: "missing" });
		await expect(
			verifyArtifactIntegrity({
				artifactDir: missingSignatureDir,
				publicKeysPem: [publicKeyPem],
				verifySignatures: true,
				expectedArtifactId: ARTIFACT_ID,
			}),
		).resolves.toMatchObject({ status: "missing_signature" });

		const malformedSignatureDir = join(root, "malformed-signature");
		await writeArtifact({ dir: malformedSignatureDir, privateKey, signature: "malformed" });
		await expect(
			verifyArtifactIntegrity({
				artifactDir: malformedSignatureDir,
				publicKeysPem: [publicKeyPem],
				verifySignatures: true,
				expectedArtifactId: ARTIFACT_ID,
			}),
		).resolves.toMatchObject({ status: "bad_signature" });

		const wrongKey = generateKeyPairSync("ed25519");
		const invalidSignatureDir = join(root, "invalid-signature");
		await writeArtifact({
			dir: invalidSignatureDir,
			privateKey,
			signature: "wrong-key",
			signWith: wrongKey.privateKey,
		});
		await expect(
			verifyArtifactIntegrity({
				artifactDir: invalidSignatureDir,
				publicKeysPem: [publicKeyPem],
				verifySignatures: true,
				expectedArtifactId: ARTIFACT_ID,
			}),
		).resolves.toMatchObject({ status: "bad_signature" });
	});

	it("fails commercial startup on missing manifests, missing keys, and tampered files", async () => {
		const previousCommercial = process.env.AIDR_COMMERCIAL;
		process.env.AIDR_COMMERCIAL = "1";
		try {
			const root = await makeTmpDir();
			const noKeyConfigPath = join(root, "no-key-config.json");
			await writeIntegrityConfig(noKeyConfigPath);

			await expect(
				verifyArtifactIntegrityAndLog({
					artifactDir: join(root, "missing-manifest"),
					artifactId: ARTIFACT_ID,
					configPath: noKeyConfigPath,
				}),
			).rejects.toThrow(`${ARTIFACT_ID}: missing_manifest`);

			const { privateKey, publicKey } = generateKeyPairSync("ed25519");
			// No trust keys provisioned (un-enrolled/offline): the signature cannot be
			// checked, so startup proceeds on verified digests and local detection
			// keeps enforcing; a tampered file still fails closed.
			const noKeyDir = join(root, "no-key");
			await writeArtifact({ dir: noKeyDir, privateKey, signature: "valid" });
			await expect(
				verifyArtifactIntegrityAndLog({
					artifactDir: noKeyDir,
					artifactId: ARTIFACT_ID,
					configPath: noKeyConfigPath,
				}),
			).resolves.toMatchObject({
				status: "no_public_keys",
				reason: "signature_unverified_digests_ok",
			});
			await writeFile(join(noKeyDir, ARTIFACT_FILE), "tampered artifact payload\n", "utf8");
			await expect(
				verifyArtifactIntegrityAndLog({
					artifactDir: noKeyDir,
					artifactId: ARTIFACT_ID,
					configPath: noKeyConfigPath,
				}),
			).rejects.toThrow(`${ARTIFACT_ID}: hash_mismatch`);

			const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
			const keyedConfigPath = join(root, "keyed-config.json");
			await writeIntegrityConfig(keyedConfigPath, publicKeyPem);
			const tamperedDir = join(root, "tampered-commercial");
			await writeArtifact({ dir: tamperedDir, privateKey, signature: "valid" });
			await writeFile(join(tamperedDir, ARTIFACT_FILE), "tampered artifact payload\n", "utf8");
			await expect(
				verifyArtifactIntegrityAndLog({
					artifactDir: tamperedDir,
					artifactId: ARTIFACT_ID,
					configPath: keyedConfigPath,
				}),
			).rejects.toThrow(`${ARTIFACT_ID}: hash_mismatch`);
		} finally {
			if (previousCommercial === undefined) delete process.env.AIDR_COMMERCIAL;
			else process.env.AIDR_COMMERCIAL = previousCommercial;
		}
	});

	it("compares supported versions and handles unsupported or invalid semver inputs deterministically", () => {
		expect(compareSemver("1.10.0", "1.2.0")).toBeGreaterThan(0);
		expect(compareSemver("2.0.0", "2.0.0")).toBe(0);
		expect(compareSemver("latest", "stable")).toBeLessThan(0);
		expect(() => compareSemver("not-a-version", "still-not-a-version")).not.toThrow();
		expect(compareSemver("not-a-version", "not-a-version")).toBe(0);
	});
});
