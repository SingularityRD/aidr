import { createHash, createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import {
	cpSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	applyUpdate,
	checkForUpdates,
	downloadUpdate,
	getSyncStatus,
	validateAigDataBundle,
} from "../aig-sync.js";

const SOURCE_GENERATED = resolve(process.cwd(), "packages/core/src/generated");
const INDEX_FILES = [
	"aig-cve-index.json",
	"aig-fingerprints.json",
	"aig-mcp-categories.json",
] as const;
let tempDir: string;
let previousGeneratedDir: string | undefined;

function signPayload(
	manifest: Record<string, unknown>,
	privateKey: KeyObject,
	keyId: string,
): void {
	delete manifest.signature;
	const signer = createSign("RSA-SHA256");
	signer.update(JSON.stringify(manifest));
	signer.end();
	manifest.signature = {
		algorithm: "RSA-SHA256",
		key_id: keyId,
		value: signer.sign(privateKey, "base64"),
	};
}

function signManifest(keyId = "aig-release-1"): {
	publicKey: string;
	fingerprint: string;
	privateKey: KeyObject;
} {
	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
	const fingerprint = createHash("sha256")
		.update(publicKey.export({ type: "spki", format: "der" }))
		.digest("hex");
	const manifestPath = join(tempDir, "aig-data-manifest.json");
	const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
	signPayload(manifest, privateKey, keyId);
	writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");
	return { publicKey: publicKeyPem, fingerprint, privateKey };
}

function mockRemoteBundle(): ReturnType<typeof vi.spyOn> {
	return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
		const url =
			input instanceof URL ? input : new URL(typeof input === "string" ? input : input.url);
		const file = url.pathname.split("/").at(-1) ?? "";
		if (![...INDEX_FILES, "aig-data-manifest.json"].includes(file as (typeof INDEX_FILES)[number]))
			return new Response(null, { status: 404 });
		return new Response(readFileSync(join(tempDir, file)));
	});
}

function stageSignedRelease(
	releaseSequence: number,
	suffix: string,
	privateKey: KeyObject,
): { bundleId: string; releaseId: string } {
	const manifest = JSON.parse(
		readFileSync(join(tempDir, "aig-data-manifest.json"), "utf8"),
	) as Record<string, unknown> & {
		artifacts: Record<string, { sha256: string; bytes: number }>;
	};
	manifest.release_sequence = releaseSequence;
	manifest.generated = `2026-09-${String(releaseSequence).padStart(2, "0")}T00:00:00.000Z`;
	const artifacts = Object.fromEntries(
		INDEX_FILES.map((file) => [
			file,
			file === INDEX_FILES[0]
				? Buffer.concat([readFileSync(join(tempDir, file)), Buffer.from(suffix)])
				: readFileSync(join(tempDir, file)),
		]),
	) as Record<string, Buffer>;
	for (const file of INDEX_FILES) {
		const bytes = artifacts[file] as Buffer;
		manifest.artifacts[file] = {
			sha256: createHash("sha256").update(bytes).digest("hex"),
			bytes: bytes.byteLength,
		};
	}
	manifest.bundle_id = createHash("sha256")
		.update(
			JSON.stringify(
				Object.fromEntries(INDEX_FILES.map((file) => [file, manifest.artifacts[file]])),
			),
		)
		.digest("hex");
	signPayload(manifest, privateKey, "aig-release-1");
	const manifestBytes = Buffer.from(JSON.stringify(manifest));
	const manifestHash = createHash("sha256").update(manifestBytes).digest("hex");
	const bundleId = manifest.bundle_id as string;
	const releaseId = `${bundleId}-${manifestHash}`;
	const releaseDir = join(tempDir, "releases", releaseId);
	mkdirSync(releaseDir, { recursive: true });
	for (const file of INDEX_FILES) writeFileSync(join(releaseDir, file), artifacts[file] as Buffer);
	writeFileSync(join(releaseDir, "aig-data-manifest.json"), manifestBytes);
	writeFileSync(
		join(tempDir, "staged.json"),
		JSON.stringify({ bundle_id: bundleId, manifest_sha256: manifestHash, release_id: releaseId }),
	);
	return { bundleId, releaseId };
}

beforeEach(() => {
	tempDir = mkdtempSync(join(tmpdir(), "aig-sync-test-"));
	for (const file of [
		"aig-cve-index.json",
		"aig-fingerprints.json",
		"aig-mcp-categories.json",
		"aig-data-manifest.json",
	]) {
		cpSync(join(SOURCE_GENERATED, file), join(tempDir, file));
	}
	previousGeneratedDir = process.env.AIG_GENERATED_DIR;
});

afterEach(() => {
	vi.restoreAllMocks();
	if (previousGeneratedDir === undefined) delete process.env.AIG_GENERATED_DIR;
	else process.env.AIG_GENERATED_DIR = previousGeneratedDir;
	rmSync(tempDir, { recursive: true, force: true });
});

describe("AIG sync bundle contract", () => {
	it("reports a valid generated bundle and does not request a redundant update", async () => {
		const status = await getSyncStatus({ mode: "local", generated_dir: tempDir });
		expect(status.manifestValid).toBe(true);
		expect(status.signaturePresent).toBe(false);
		expect(status.bundleId).toMatch(/^[a-f0-9]{64}$/);
		// Assert the count matches the shipped bundle rather than a hardcoded
		// total: a literal here only encodes which dataset revision was current
		// when the test was written, so a legitimate AIG upgrade fails the suite
		// for no security reason. What matters is that the reported count equals
		// the actual compiled data and is non-trivial.
		const shippedCves = (
			JSON.parse(readFileSync(join(SOURCE_GENERATED, "aig-cve-index.json"), "utf8")) as {
				cves: unknown[];
			}
		).cves.length;
		expect(shippedCves).toBeGreaterThan(1000);
		expect(status.cveCount).toBe(shippedCves);
		expect((await checkForUpdates({ mode: "local", generated_dir: tempDir })).updateAvailable).toBe(
			false,
		);
	});

	it("fails closed when an index is changed after manifest generation", async () => {
		const path = join(tempDir, "aig-cve-index.json");
		writeFileSync(path, `${readFileSync(path, "utf8")}\n`, "utf8");
		const validation = await validateAigDataBundle(tempDir);
		expect(validation.valid).toBe(false);
		expect(validation.error).toContain("hash/size mismatch");
		const status = await checkForUpdates({ mode: "local", generated_dir: tempDir });
		expect(status.updateAvailable).toBe(true);
		expect(status.manifestValid).toBe(false);
	});

	it("requires a signature when release policy is enabled", async () => {
		const validation = await validateAigDataBundle(tempDir, {
			require_signed: true,
			public_key: "",
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: "0".repeat(64),
		});
		expect(validation.valid).toBe(false);
		expect(validation.error).toContain("signed manifest required");
	});

	it("accepts a signed bundle only when key ID, SPKI fingerprint and signature match", async () => {
		const trust = signManifest();
		const validation = await validateAigDataBundle(tempDir, {
			require_signed: true,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		});
		expect(validation).toMatchObject({ valid: true, signaturePresent: true, error: null });
	});

	it("rejects an EC key mislabeled as an RSA-SHA256 signer", async () => {
		const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const fingerprint = createHash("sha256")
			.update(publicKey.export({ type: "spki", format: "der" }))
			.digest("hex");
		const manifestPath = join(tempDir, "aig-data-manifest.json");
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
		signPayload(manifest, privateKey, "aig-release-1");
		writeFileSync(manifestPath, JSON.stringify(manifest));

		expect(
			await validateAigDataBundle(tempDir, {
				require_signed: true,
				public_key: publicKeyPem,
				trusted_key_id: "aig-release-1",
				trusted_public_key_sha256: fingerprint,
			}),
		).toMatchObject({ valid: false, error: "manifest public key is invalid" });
	});

	it("loads the trusted public key from an explicit path", async () => {
		const trust = signManifest();
		const publicKeyPath = join(tempDir, "aig-public.pem");
		writeFileSync(publicKeyPath, trust.publicKey, "utf8");
		const validation = await validateAigDataBundle(tempDir, {
			require_signed: true,
			public_key_path: publicKeyPath,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		});
		expect(validation).toMatchObject({ valid: true, signaturePresent: true, error: null });
	});

	it("rejects a cryptographically valid signature from an untrusted key ID", async () => {
		const trust = signManifest("untrusted-key");
		const validation = await validateAigDataBundle(tempDir, {
			require_signed: true,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		});
		expect(validation).toMatchObject({ valid: false, error: "manifest signer is not trusted" });
	});

	it("rejects a valid signature when the public key SPKI fingerprint is not trusted", async () => {
		const trust = signManifest();
		const validation = await validateAigDataBundle(tempDir, {
			require_signed: true,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: "0".repeat(64),
		});
		expect(validation).toMatchObject({ valid: false, error: "manifest public key is not trusted" });
	});

	it("rejects an incomplete trusted signer policy in signed mode", async () => {
		const trust = signManifest();
		for (const policy of [
			{ trusted_key_id: "", trusted_public_key_sha256: trust.fingerprint },
			{ trusted_key_id: "aig-release-1", trusted_public_key_sha256: "not-a-sha256" },
		]) {
			const validation = await validateAigDataBundle(tempDir, {
				require_signed: true,
				public_key: trust.publicKey,
				...policy,
			});
			expect(validation).toMatchObject({
				valid: false,
				error: "trusted signing policy is incomplete",
			});
		}
	});

	it("rejects an oversized declared artifact before reading it", async () => {
		const manifestPath = join(tempDir, "aig-data-manifest.json");
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
			artifacts: Record<string, { bytes: number }>;
		};
		const artifactName = INDEX_FILES[0];
		if (!artifactName) throw new Error("Expected a seeded artifact name");
		const artifact = manifest.artifacts[artifactName];
		if (!artifact) throw new Error("Expected the seeded artifact manifest entry");
		artifact.bytes = 32 * 1024 * 1024 + 1;
		writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");
		const validation = await validateAigDataBundle(tempDir);
		expect(validation).toMatchObject({ valid: false, error: "manifest missing or malformed" });
	});
});

describe("AIG HTTP sync trust boundary", () => {
	it("requires HTTPS before making a network request", async () => {
		const fetchMock = vi.spyOn(globalThis, "fetch");
		const downloaded = await downloadUpdate({
			mode: "http",
			remote_url: "http://updates.example.test/aig",
			cache_dir: tempDir,
		});
		expect(downloaded).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("allows loopback HTTP only by explicit opt-in and refuses redirects", async () => {
		const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
			new Response(null, {
				status: 302,
				headers: { location: "https://elsewhere.example/aig-data-manifest.json" },
			}),
		);
		const downloaded = await downloadUpdate({
			mode: "http",
			remote_url: "http://127.0.0.1:8787/aig",
			allow_insecure_loopback: true,
			cache_dir: tempDir,
		});
		expect(downloaded).toBe(false);
		expect(fetchMock).toHaveBeenCalledWith(
			expect.any(URL),
			expect.objectContaining({ redirect: "manual" }),
		);
	});

	it("refuses a response whose effective URL changes origin", async () => {
		const response = new Response("{}");
		Object.defineProperty(response, "url", {
			value: "https://cdn.example.test/aig-data-manifest.json",
		});
		vi.spyOn(globalThis, "fetch").mockResolvedValue(response);
		const downloaded = await downloadUpdate({
			mode: "http",
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
		});
		expect(downloaded).toBe(false);
	});

	it("requires a signed manifest in HTTP mode even when the caller opts out", async () => {
		const manifest = readFileSync(join(tempDir, "aig-data-manifest.json"), "utf8");
		const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(manifest));
		const downloaded = await downloadUpdate({
			mode: "http",
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			require_signed: false,
		});
		expect(downloaded).toBe(false);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("stages a bounded, trusted bundle without rewriting artifact bytes", async () => {
		const trust = signManifest();
		const fetchMock = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValueOnce(new Response(readFileSync(join(tempDir, "aig-data-manifest.json"))));
		for (const file of INDEX_FILES) {
			fetchMock.mockResolvedValueOnce(new Response(readFileSync(join(tempDir, file))));
		}
		const downloaded = await downloadUpdate({
			mode: "http",
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		});
		expect(downloaded).toBe(true);
		expect(fetchMock).toHaveBeenCalledTimes(4);
	});

	it("reuses an identical content-addressed release across concurrent and repeated downloads", async () => {
		const trust = signManifest();
		const fetchMock = mockRemoteBundle();
		const config = {
			mode: "http" as const,
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		};

		expect(await Promise.all([downloadUpdate(config), downloadUpdate(config)])).toEqual([
			true,
			true,
		]);
		expect(await downloadUpdate(config)).toBe(true);

		const manifest = JSON.parse(readFileSync(join(tempDir, "aig-data-manifest.json"), "utf8")) as {
			bundle_id: string;
		};
		const staged = JSON.parse(readFileSync(join(tempDir, "staged.json"), "utf8")) as {
			release_id: string;
		};
		expect(
			(await validateAigDataBundle(join(tempDir, "releases", staged.release_id), config)).valid,
		).toBe(true);
		expect(staged.release_id).toMatch(new RegExp(`^${manifest.bundle_id}-[a-f0-9]{64}$`));
		expect(readdirSync(tempDir).filter((entry) => entry.startsWith(".staging-"))).toEqual([]);
		expect(fetchMock).toHaveBeenCalledTimes(12);
	});

	it("repairs a corrupt exact release identity from the validated staged bundle", async () => {
		const trust = signManifest();
		mockRemoteBundle();
		const manifestBytes = readFileSync(join(tempDir, "aig-data-manifest.json"));
		const manifest = JSON.parse(manifestBytes.toString("utf8")) as {
			bundle_id: string;
		};
		const releaseId = `${manifest.bundle_id}-${createHash("sha256").update(manifestBytes).digest("hex")}`;
		const releaseDir = join(tempDir, "releases", releaseId);
		mkdirSync(releaseDir, { recursive: true });
		writeFileSync(join(releaseDir, "keep.txt"), "do-not-delete", "utf8");

		const config = {
			mode: "http" as const,
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		};
		expect(await downloadUpdate(config)).toBe(true);
		expect(existsSync(join(releaseDir, "keep.txt"))).toBe(false);
		expect(await validateAigDataBundle(releaseDir, config)).toMatchObject({ valid: true });
		expect(existsSync(join(tempDir, "staged.json"))).toBe(true);
	});

	it("refuses a staged manifest whose bytes no longer match its pointer", async () => {
		const trust = signManifest();
		mockRemoteBundle();
		const config = {
			mode: "http" as const,
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		};
		expect(await downloadUpdate(config)).toBe(true);
		const staged = JSON.parse(readFileSync(join(tempDir, "staged.json"), "utf8")) as {
			release_id: string;
		};
		const manifestPath = join(tempDir, "releases", staged.release_id, "aig-data-manifest.json");
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
		manifest.generated = "2099-01-01T00:00:00.000Z";
		signPayload(manifest, trust.privateKey, "aig-release-1");
		writeFileSync(manifestPath, JSON.stringify(manifest));
		expect(
			await validateAigDataBundle(join(tempDir, "releases", staged.release_id), config),
		).toMatchObject({ valid: true });

		expect(await applyUpdate(config)).toBe(false);
		expect(existsSync(join(tempDir, "active.json"))).toBe(false);
	});

	it("requests repair when the active same-bundle release is corrupt", async () => {
		const trust = signManifest();
		const manifest = JSON.parse(readFileSync(join(tempDir, "aig-data-manifest.json"), "utf8")) as {
			bundle_id: string;
		};
		const releaseDir = join(tempDir, "releases", manifest.bundle_id);
		mkdirSync(releaseDir, { recursive: true });
		for (const file of [...INDEX_FILES, "aig-data-manifest.json"])
			cpSync(join(tempDir, file), join(releaseDir, file));
		writeFileSync(join(releaseDir, INDEX_FILES[0]), "{}", "utf8");
		writeFileSync(join(tempDir, "active.json"), JSON.stringify({ bundle_id: manifest.bundle_id }));
		const fetchMock = mockRemoteBundle();

		const status = await checkForUpdates({
			mode: "http",
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		});

		expect(status).toMatchObject({ manifestValid: false, updateAvailable: true });
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const config = {
			mode: "http" as const,
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		};
		expect(await downloadUpdate(config)).toBe(true);
		expect(await applyUpdate(config)).toBe(true);
		const active = JSON.parse(readFileSync(join(tempDir, "active.json"), "utf8")) as {
			release_id: string;
		};
		expect(active.release_id).toMatch(new RegExp(`^${manifest.bundle_id}-[a-f0-9]{64}$`));
		expect(readFileSync(join(releaseDir, INDEX_FILES[0]), "utf8")).toBe("{}");
	});

	it("rejects a manifest whose Content-Length exceeds the hard limit", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValue(
			new Response("{}", { headers: { "content-length": String(1024 * 1024 + 1) } }),
		);
		const downloaded = await downloadUpdate({
			mode: "http",
			remote_url: "http://localhost:8787/aig",
			allow_insecure_loopback: true,
			cache_dir: tempDir,
		});
		expect(downloaded).toBe(false);
	});

	it("enforces the manifest byte limit while streaming when Content-Length is absent", async () => {
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new Uint8Array(600 * 1024));
				controller.enqueue(new Uint8Array(600 * 1024));
				controller.close();
			},
		});
		vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(body));
		const downloaded = await downloadUpdate({
			mode: "http",
			remote_url: "http://localhost:8787/aig",
			allow_insecure_loopback: true,
			cache_dir: tempDir,
		});
		expect(downloaded).toBe(false);
	});

	it("upgrades a signed legacy bundle with a later timestamp to release sequence 1", async () => {
		const trust = signManifest();
		const candidate = JSON.parse(
			readFileSync(join(tempDir, "aig-data-manifest.json"), "utf8"),
		) as Record<string, unknown> & {
			bundle_id: string;
			artifacts: Record<string, { sha256: string; bytes: number }>;
		};
		const legacyManifest = structuredClone(candidate);
		delete legacyManifest.signature;
		delete legacyManifest.release_sequence;
		legacyManifest.generated = "2099-01-01T00:00:00.000Z";
		const changedArtifact = Buffer.concat([
			readFileSync(join(tempDir, INDEX_FILES[0])),
			Buffer.from("\n"),
		]);
		legacyManifest.artifacts[INDEX_FILES[0]] = {
			sha256: createHash("sha256").update(changedArtifact).digest("hex"),
			bytes: changedArtifact.byteLength,
		};
		legacyManifest.bundle_id = createHash("sha256")
			.update(
				JSON.stringify(
					Object.fromEntries(INDEX_FILES.map((file) => [file, legacyManifest.artifacts[file]])),
				),
			)
			.digest("hex");
		signPayload(legacyManifest, trust.privateKey, "aig-release-1");
		const legacyDir = join(tempDir, "releases", legacyManifest.bundle_id);
		mkdirSync(legacyDir, { recursive: true });
		for (const file of INDEX_FILES)
			if (file === INDEX_FILES[0]) writeFileSync(join(legacyDir, file), changedArtifact);
			else cpSync(join(tempDir, file), join(legacyDir, file));
		writeFileSync(join(legacyDir, "aig-data-manifest.json"), JSON.stringify(legacyManifest));
		writeFileSync(
			join(tempDir, "active.json"),
			JSON.stringify({ bundle_id: legacyManifest.bundle_id }),
		);
		mockRemoteBundle();
		const config = {
			mode: "http" as const,
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		};

		expect(await checkForUpdates(config)).toMatchObject({
			manifestValid: true,
			updateAvailable: true,
			lastError: null,
		});
		expect(await downloadUpdate(config)).toBe(true);
		expect(await applyUpdate(config)).toBe(true);
		const active = JSON.parse(readFileSync(join(tempDir, "active.json"), "utf8")) as {
			bundle_id: string;
			release_id: string;
		};
		expect(active.bundle_id).toBe(candidate.bundle_id);
		expect(active.release_id).toMatch(new RegExp(`^${candidate.bundle_id}-[a-f0-9]{64}$`));
		expect(existsSync(legacyDir)).toBe(true);
	});

	it("rejects a different bundle at the same signed release sequence", async () => {
		const trust = signManifest();
		const remote = JSON.parse(
			readFileSync(join(tempDir, "aig-data-manifest.json"), "utf8"),
		) as Record<string, unknown> & {
			artifacts: Record<string, { sha256: string; bytes: number }>;
		};
		remote.generated = "2000-01-01T00:00:00.000Z";
		const artifactName = INDEX_FILES[0];
		if (!artifactName) throw new Error("Expected a seeded artifact name");
		const artifact = remote.artifacts[artifactName];
		if (!artifact) throw new Error("Expected the seeded artifact manifest entry");
		remote.artifacts[artifactName] = {
			...artifact,
			sha256: "f".repeat(64),
		};
		remote.bundle_id = createHash("sha256")
			.update(
				JSON.stringify(
					Object.fromEntries(INDEX_FILES.map((file) => [file, remote.artifacts[file]])),
				),
			)
			.digest("hex");
		signPayload(remote, trust.privateKey, "aig-release-1");
		const fetchMock = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response(JSON.stringify(remote)));

		const status = await checkForUpdates({
			mode: "http",
			remote_url: "http://localhost:8787/aig",
			allow_insecure_loopback: true,
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		});
		expect(status.updateAvailable).toBe(false);
		expect(status.lastError).toContain(
			`conflicting AIG bundle at release sequence ${remote.release_sequence}`,
		);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("serializes promotion so a late lower sequence cannot replace a newer active release", async () => {
		const trust = signManifest();
		const config = {
			mode: "http" as const,
			remote_url: "https://updates.example.test/aig",
			cache_dir: tempDir,
			public_key: trust.publicKey,
			trusted_key_id: "aig-release-1",
			trusted_public_key_sha256: trust.fingerprint,
		};

		stageSignedRelease(2, "\n ", trust.privateKey);
		const lowerPromotion = applyUpdate(config);
		const higher = stageSignedRelease(3, "\n  ", trust.privateKey);
		const higherPromotion = applyUpdate(config);

		const [lowerResult, higherResult] = await Promise.all([lowerPromotion, higherPromotion]);
		expect(higherResult).toBe(true);
		expect(typeof lowerResult).toBe("boolean");
		const active = JSON.parse(readFileSync(join(tempDir, "active.json"), "utf8")) as {
			bundle_id: string;
			release_id: string;
		};
		expect(active).toMatchObject({ bundle_id: higher.bundleId, release_id: higher.releaseId });
	});
});
