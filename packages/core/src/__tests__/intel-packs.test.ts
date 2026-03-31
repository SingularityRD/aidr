import { createCipheriv, createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	activatePackVersion,
	loadMergedIntelFromDisk,
	rollbackPackVersion,
} from "../intel/loader.js";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";
import { makeTmpDir } from "./test-utils.js";

function sha256Hex(s: string): string {
	return createHash("sha256").update(s, "utf8").digest("hex");
}

function sha256HexBytes(b: Uint8Array): string {
	return createHash("sha256").update(b).digest("hex");
}

function encryptAes256GcmEnvelope(params: {
	key: Uint8Array;
	iv: Uint8Array;
	plaintext: Uint8Array;
}): Uint8Array {
	const cipher = createCipheriv("aes-256-gcm", Buffer.from(params.key), Buffer.from(params.iv));
	const ciphertext = Buffer.concat([cipher.update(Buffer.from(params.plaintext)), cipher.final()]);
	const tag = cipher.getAuthTag();
	return new Uint8Array(Buffer.concat([Buffer.from(params.iv), ciphertext, tag]));
}

describe("intel packs", () => {
	let dir: string;
	let prevHome: string | undefined;

	beforeEach(async () => {
		dir = await makeTmpDir();
		prevHome = process.env.HOME;
		process.env.HOME = dir;
	});
	afterEach(() => {
		if (prevHome === undefined) delete process.env.HOME;
		else process.env.HOME = prevHome;
	});

	async function writeSignedPackVersion(params: {
		base: string;
		packId: string;
		version: string;
		privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
		files: Array<{ kind: string; name: string; content: string }>;
		expiresAt?: string;
	}) {
		const packsDir = join(params.base, "packs", params.packId, params.version);
		await mkdir(packsDir, { recursive: true });

		const manifestFiles: Array<{ kind: string; path: string; sha256: string }> = [];
		for (const f of params.files) {
			await writeFile(join(packsDir, f.name), f.content, "utf8");
			manifestFiles.push({
				kind: f.kind,
				path: f.name,
				sha256: sha256Hex(f.content),
			});
		}

		const manifestObj: Record<string, unknown> = {
			pack_id: params.packId,
			version: params.version,
			issued_at: new Date().toISOString(),
			expires_at: params.expiresAt,
			key_id: "k1",
			files: manifestFiles,
		};
		const manifestJson = `${JSON.stringify(manifestObj, null, 2)}\n`;
		await writeFile(join(packsDir, "manifest.json"), manifestJson, "utf8");

		const sig = sign(null, Buffer.from(manifestJson, "utf8"), params.privateKey).toString("base64");
		await writeFile(join(packsDir, "manifest.sig"), `${sig}\n`, "utf8");
	}

	async function writeSignedEncryptedPackVersion(params: {
		base: string;
		packId: string;
		version: string;
		privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
		kind: string;
		name: string;
		plaintext: string;
		keyId: string;
		key: Uint8Array;
		expiresAt?: string;
		ciphertextSha256Override?: string;
	}) {
		const packsDir = join(params.base, "packs", params.packId, params.version);
		await mkdir(packsDir, { recursive: true });

		const iv = new Uint8Array(12).fill(7);
		const plaintextBytes = Buffer.from(params.plaintext, "utf8");
		const blob = encryptAes256GcmEnvelope({ key: params.key, iv, plaintext: plaintextBytes });
		await writeFile(join(packsDir, params.name), Buffer.from(blob));

		const manifestObj: Record<string, unknown> = {
			pack_id: params.packId,
			version: params.version,
			issued_at: new Date().toISOString(),
			expires_at: params.expiresAt,
			key_id: "k1",
			files: [
				{
					kind: params.kind,
					path: params.name,
					encrypted: true,
					cipher: "aes-256-gcm",
					key_id: params.keyId,
					ciphertext_sha256: params.ciphertextSha256Override ?? sha256HexBytes(blob),
					sha256: sha256Hex(params.plaintext),
				},
			],
		};

		const manifestJson = `${JSON.stringify(manifestObj, null, 2)}\n`;
		await writeFile(join(packsDir, "manifest.json"), manifestJson, "utf8");

		const sig = sign(null, Buffer.from(manifestJson, "utf8"), params.privateKey).toString("base64");
		await writeFile(join(packsDir, "manifest.sig"), `${sig}\n`, "utf8");
	}

	it("loads signed packs and influences policy evaluation", async () => {
		const base = join(dir, ".singularity-aidr", "intel");
		await mkdir(base, { recursive: true });

		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ format: "pem", type: "spki" }).toString();

		await writeFile(
			join(base, "trusted-keys.json"),
			`${JSON.stringify({ k1: publicPem }, null, 2)}\n`,
			"utf8",
		);

		const urlDeny = "evil.example\n";
		const domainRisk = JSON.stringify(
			[{ domain: "risk.example", action: "deny", severity: "high", confidence: 0.93 }],
			null,
			2,
		);
		const packageDeny = "leftpad\n";

		await writeSignedPackVersion({
			base,
			packId: "test-pack",
			version: "1.0.0",
			privateKey,
			files: [
				{ kind: "url_denylist", name: "url-deny.txt", content: urlDeny },
				{ kind: "domain_risk", name: "domain-risk.json", content: `${domainRisk}\n` },
				{ kind: "package_name_denylist", name: "pkg-deny.txt", content: packageDeny },
			],
		});

		const merged = await loadMergedIntelFromDisk();
		expect(merged.urlDenyHosts.has("evil.example")).toBe(true);
		expect(merged.domainRisk.get("risk.example")?.action).toBe("deny");

		const config = ConfigSchema.parse({
			policy: { enabled: true },
			intel: { enabled: true, url_denylist_path: "~/.singularity-aidr/intel/url_denylist.txt" },
		});

		const verdict = await evaluatePolicy(
			"WebFetch",
			[{ type: "url", value: "https://evil.example/payload" }],
			config,
			{ url: "https://evil.example/payload" },
		);
		expect(verdict?.decision).toBe("deny");
		expect(verdict?.matchedThreatId).toBe("INTEL-URL-001");

		const verdict2 = await evaluatePolicy(
			"WebFetch",
			[{ type: "url", value: "https://risk.example/" }],
			config,
			{ url: "https://risk.example/" },
		);
		expect(verdict2?.decision).toBe("deny");
		expect(verdict2?.matchedThreatId).toBe("INTEL-DOMAIN-001");

		const verdict3 = await evaluatePolicy(
			"Bash",
			[{ type: "command", value: "npm install leftpad" }],
			config,
			{ command: "npm install leftpad" },
		);
		expect(verdict3?.decision).toBe("deny");
		expect(verdict3?.matchedThreatId).toBe("INTEL-PKG-001");
	});

	it("respects active pointer and supports rollback", async () => {
		const base = join(dir, ".singularity-aidr", "intel");
		await mkdir(base, { recursive: true });

		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ format: "pem", type: "spki" }).toString();
		await writeFile(
			join(base, "trusted-keys.json"),
			`${JSON.stringify({ k1: publicPem }, null, 2)}\n`,
			"utf8",
		);

		await writeSignedPackVersion({
			base,
			packId: "roll-pack",
			version: "1.0.0",
			privateKey,
			files: [{ kind: "url_denylist", name: "url-deny.txt", content: "v1.bad\n" }],
		});
		await writeSignedPackVersion({
			base,
			packId: "roll-pack",
			version: "2.0.0",
			privateKey,
			files: [{ kind: "url_denylist", name: "url-deny.txt", content: "v2.bad\n" }],
		});

		// Force active to v1 even though v2 is newer.
		await activatePackVersion({ packId: "roll-pack", version: "1.0.0" });
		const merged1 = await loadMergedIntelFromDisk();
		expect(merged1.urlDenyHosts.has("v1.bad")).toBe(true);
		expect(merged1.urlDenyHosts.has("v2.bad")).toBe(false);

		// Switch to v2 and rollback back to v1.
		await activatePackVersion({ packId: "roll-pack", version: "2.0.0" });
		const merged2 = await loadMergedIntelFromDisk();
		expect(merged2.urlDenyHosts.has("v2.bad")).toBe(true);

		await rollbackPackVersion({ packId: "roll-pack" });
		const merged3 = await loadMergedIntelFromDisk();
		expect(merged3.urlDenyHosts.has("v1.bad")).toBe(true);
	});

	it("supports grace verification for expired packs", async () => {
		const base = join(dir, ".singularity-aidr", "intel");
		await mkdir(base, { recursive: true });

		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ format: "pem", type: "spki" }).toString();
		await writeFile(
			join(base, "trusted-keys.json"),
			`${JSON.stringify({ k1: publicPem }, null, 2)}\n`,
			"utf8",
		);

		const expired = new Date(Date.now() - 60 * 60 * 1000).toISOString();
		await writeSignedPackVersion({
			base,
			packId: "exp-pack",
			version: "1.0.0",
			privateKey,
			expiresAt: expired,
			files: [{ kind: "plugin_signature_denylist", name: "plugin-sig.txt", content: "deadbeef\n" }],
		});

		const strictMerged = await loadMergedIntelFromDisk({ verificationMode: "strict" });
		expect(strictMerged.pluginSignatureDeny.has("deadbeef")).toBe(false);

		const graceMerged = await loadMergedIntelFromDisk({
			verificationMode: "grace",
			graceHours: 48,
		});
		expect(graceMerged.pluginSignatureDeny.has("deadbeef")).toBe(true);
	});

	it("loads encrypted pack files using entitlement keyring and verifies ciphertext sha256", async () => {
		const base = join(dir, ".singularity-aidr", "intel");
		await mkdir(base, { recursive: true });

		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ format: "pem", type: "spki" }).toString();
		await writeFile(
			join(base, "trusted-keys.json"),
			`${JSON.stringify({ k1: publicPem }, null, 2)}\n`,
			"utf8",
		);

		// Entitlement-provided keyring (preferred over intel/keys.json)
		const key = new Uint8Array(32).fill(9);
		await writeFile(
			join(dir, ".singularity-aidr", "entitlement.json"),
			`${JSON.stringify({ intel_keys: { ek1: Buffer.from(key).toString("base64") } }, null, 2)}\n`,
			"utf8",
		);

		await writeSignedEncryptedPackVersion({
			base,
			packId: "enc-pack",
			version: "1.0.0",
			privateKey,
			kind: "url_denylist",
			name: "url-deny.bin",
			plaintext: "enc.bad.example\n",
			keyId: "ek1",
			key,
		});

		const merged = await loadMergedIntelFromDisk();
		expect(merged.urlDenyHosts.has("enc.bad.example")).toBe(true);
	});

	it("rejects encrypted pack files when ciphertext sha256 mismatches", async () => {
		const base = join(dir, ".singularity-aidr", "intel");
		await mkdir(base, { recursive: true });

		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicPem = publicKey.export({ format: "pem", type: "spki" }).toString();
		await writeFile(
			join(base, "trusted-keys.json"),
			`${JSON.stringify({ k1: publicPem }, null, 2)}\n`,
			"utf8",
		);

		const key = new Uint8Array(32).fill(3);
		await writeFile(
			join(dir, ".singularity-aidr", "entitlement.json"),
			`${JSON.stringify({ intel_keys: { ek1: Buffer.from(key).toString("base64") } }, null, 2)}\n`,
			"utf8",
		);

		await writeSignedEncryptedPackVersion({
			base,
			packId: "enc-pack-bad",
			version: "1.0.0",
			privateKey,
			kind: "url_denylist",
			name: "url-deny.bin",
			plaintext: "mismatch.bad.example\n",
			keyId: "ek1",
			key,
			ciphertextSha256Override: "0".repeat(64),
		});

		const merged = await loadMergedIntelFromDisk();
		expect(merged.urlDenyHosts.has("mismatch.bad.example")).toBe(false);
	});
});
