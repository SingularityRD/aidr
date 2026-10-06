import { generateKeyPairSync, sign, verify } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { chmod, link, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	preparePrivateLocalDirectory: vi.fn(),
	preparePrivateLocalFile: vi.fn(),
	windowsTargetsAreAlreadyPrivate: vi.fn(),
	resolveSecretStore: vi.fn(),
	home: "",
	ref: 0,
}));

vi.mock("@singularityrd/aidr-core", () => ({
	preparePrivateLocalDirectory: mocks.preparePrivateLocalDirectory,
	preparePrivateLocalFile: mocks.preparePrivateLocalFile,
	windowsTargetsAreAlreadyPrivate: mocks.windowsTargetsAreAlreadyPrivate,
	resolveSecretStore: mocks.resolveSecretStore,
	resolvePath: (path: string) => (path.startsWith("~/") ? join(mocks.home, path.slice(2)) : path),
	createSecretReferenceId: () => `aidr-test-${++mocks.ref}`,
}));

import {
	generateLearningAuthority,
	type LearningAuthorityReference,
	loadLearningAuthority,
	prepareLearningOutput,
	readJsonFile,
	writePrivateNewJson,
} from "../utils/learning-authority.js";

let directory: string;
let vault: Map<string, string>;
let store: {
	kind: "windows-dpapi" | "macos-keychain" | "linux-secret-service" | "file-acl";
	location: "os-vault" | "config-file";
	osProtected: boolean;
	isAvailable: () => boolean;
	put: ReturnType<typeof vi.fn>;
	get: ReturnType<typeof vi.fn>;
	revoke: ReturnType<typeof vi.fn>;
};

beforeEach(async () => {
	directory = await mkdtemp(join(tmpdir(), "aidr-authority-"));
	mocks.home = directory;
	mocks.ref = 0;
	vault = new Map();
	store = {
		kind: "windows-dpapi",
		location: "os-vault",
		osProtected: true,
		isAvailable: () => true,
		put: vi.fn((id: string, secret: string) => {
			vault.set(id, secret);
		}),
		get: vi.fn((id: string) => vault.get(id) ?? null),
		revoke: vi.fn((id: string) => {
			vault.delete(id);
		}),
	};
	mocks.preparePrivateLocalDirectory.mockReset().mockImplementation((path: string) => {
		mkdirSync(path, { recursive: true, mode: 0o700 });
		if (process.platform !== "win32") chmodSync(path, 0o700);
	});
	mocks.resolveSecretStore.mockReset().mockReturnValue(store);
	mocks.preparePrivateLocalFile.mockReset();
	mocks.windowsTargetsAreAlreadyPrivate.mockReset().mockReturnValue(true);
});

afterEach(async () => {
	vi.restoreAllMocks();
	await rm(directory, { recursive: true, force: true });
});

function fallback(): void {
	store.kind = "file-acl";
	store.location = "config-file";
	store.osProtected = false;
}

async function generated(role: "execution" | "approval" = "execution"): Promise<{
	out: string;
	reference: LearningAuthorityReference;
}> {
	const out = join(directory, `${role}.json`);
	return { out, reference: await generateLearningAuthority({ role, out }) };
}

describe("learning authority custody", () => {
	it.each(["execution", "approval"] as const)(
		"keeps %s private keys in the vault and returns usable matching Ed25519 keys",
		async (role) => {
			const printed = vi.spyOn(console, "log").mockImplementation(() => {});
			const errors = vi.spyOn(console, "error").mockImplementation(() => {});
			store.put.mockImplementation((id: string, secret: string) => {
				expect(mocks.preparePrivateLocalDirectory).toHaveBeenCalledWith(
					join(directory, ".singularity-aidr", "secrets"),
				);
				vault.set(id, secret);
			});
			const { out, reference } = await generated(role);
			expect(reference.private.store).toBe("windows-dpapi");
			if (!("id" in reference.private)) throw new Error("Expected vault reference.");
			expect(reference.key_id).not.toBe(reference.private.id);
			const stored = await readFile(out, "utf8");
			expect(stored).not.toContain("PRIVATE KEY");
			expect(stored).not.toContain(vault.get(reference.private.id));
			expect(await readdir(directory)).toEqual(
				expect.arrayContaining([`${role}.json`, ".singularity-aidr"]),
			);
			const loaded = await loadLearningAuthority(out, role);
			const bytes = Buffer.from("authority ownership proof");
			expect(
				verify(null, bytes, loaded.publicKeyPem, sign(null, bytes, loaded.privateKeyPem)),
			).toBe(true);
			expect(loaded.keyId).toBe(reference.key_id);
			expect(printed).not.toHaveBeenCalled();
			expect(errors).not.toHaveBeenCalled();
		},
	);

	it("requires an explicit file fallback even when the ambient store resolves to file-acl", async () => {
		fallback();
		await expect(
			generateLearningAuthority({ role: "execution", out: join(directory, "implicit.json") }),
		).rejects.toThrow(/Could not create learning authority/);
		expect(store.put).not.toHaveBeenCalled();
		expect(await readdir(directory)).toEqual([]);
		const out = join(directory, "explicit.json");
		const reference = await generateLearningAuthority({
			role: "execution",
			out,
			secretStore: "file-acl",
		});
		expect(reference.private).toEqual({ store: "file-acl", path: `${out}.pkcs8` });
		const privateBytes = await readFile(`${out}.pkcs8`, "utf8");
		expect(privateBytes.trim()).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
		expect(privateBytes).not.toContain("PRIVATE KEY");
		expect(await readFile(out, "utf8")).not.toContain(privateBytes.trim());
		expect((await loadLearningAuthority(out, "execution")).privateKeyPem).toContain(
			"BEGIN PRIVATE KEY",
		);
		if (process.platform === "win32") expect(mocks.preparePrivateLocalFile).toHaveBeenCalled();
		expect(store.put).not.toHaveBeenCalled();
	});

	it("fails closed when the vault is unavailable and never relays backend secrets", async () => {
		mocks.resolveSecretStore.mockImplementation(() => {
			throw new Error("secret backend payload -----BEGIN PRIVATE KEY-----");
		});
		const out = join(directory, "failed.json");
		await expect(generateLearningAuthority({ role: "execution", out })).rejects.toThrow(
			"Could not create learning authority; check the role, new destination and credential store.",
		);
		expect(await readdir(directory)).toEqual([]);
	});

	it("uses the safe macOS vault adapter for new keys and preserves existing reference reads", async () => {
		store.kind = "macos-keychain";
		const { out, reference } = await generated();
		expect(store.put).toHaveBeenCalledOnce();
		expect(reference.private.store).toBe("macos-keychain");
		store.put.mockClear();
		expect((await loadLearningAuthority(out, "execution")).keyId).toBe(reference.key_id);
		expect(store.put).not.toHaveBeenCalled();
	});

	it("removes only its new vault entry when readback fails or publication loses a concurrent race", async () => {
		store.get.mockReturnValue(null);
		const out = join(directory, "failed.json");
		await expect(generateLearningAuthority({ role: "execution", out })).rejects.toThrow(
			/Could not create/,
		);
		expect(store.revoke).toHaveBeenCalledWith("aidr-test-1");
		expect(vault.size).toBe(0);
		store.get.mockImplementation((id: string) => {
			// A competing publisher arrives after preflight and key custody succeeds.
			mkdirSync(out);
			return vault.get(id) ?? null;
		});
		await expect(generateLearningAuthority({ role: "execution", out })).rejects.toThrow(
			/Could not create/,
		);
		expect(store.revoke).toHaveBeenCalledWith("aidr-test-2");
		expect(vault.size).toBe(0);
		expect(await readdir(out)).toEqual([]);
	});

	it("preserves pre-existing outputs and fallback files; failed fallback publication cleans up its own key file", async () => {
		const out = join(directory, "preserve.json");
		await writeFile(out, "sentinel");
		await expect(generateLearningAuthority({ role: "execution", out })).rejects.toThrow(
			/Could not create/,
		);
		expect(await readFile(out, "utf8")).toBe("sentinel");
		expect(mocks.resolveSecretStore).not.toHaveBeenCalled();
		fallback();
		const other = join(directory, "fallback.json");
		await writeFile(`${other}.pkcs8`, "existing-key");
		await expect(
			generateLearningAuthority({ role: "approval", out: other, secretStore: "file-acl" }),
		).rejects.toThrow(/Could not create/);
		expect(await readFile(`${other}.pkcs8`, "utf8")).toBe("existing-key");
		const race = join(directory, "race.json");
		let preparations = 0;
		mocks.preparePrivateLocalDirectory.mockImplementation((path: string) => {
			mkdirSync(path, { recursive: true, mode: 0o700 });
			if (++preparations === 3) mkdirSync(race);
		});
		await expect(
			generateLearningAuthority({ role: "approval", out: race, secretStore: "file-acl" }),
		).rejects.toThrow(/Could not create/);
		expect(await readdir(directory)).not.toContain("race.json.pkcs8");
		expect(await readdir(race)).toEqual([]);
		expect(store.put).not.toHaveBeenCalled();
	});

	it("rejects wrong roles, mismatched public keys, missing custody and non-Ed25519 keys", async () => {
		const { out, reference } = await generated();
		await expect(loadLearningAuthority(out, "approval")).rejects.toThrow(/Could not load/);
		const another = generateKeyPairSync("ed25519");
		await writeFile(
			out,
			JSON.stringify({
				...reference,
				public_key_pem: another.publicKey.export({ format: "pem", type: "spki" }),
			}),
		);
		await expect(loadLearningAuthority(out, "execution")).rejects.toThrow(/Could not load/);
		await writeFile(out, JSON.stringify(reference));
		if (!("id" in reference.private)) throw new Error("Expected vault reference.");
		vault.delete(reference.private.id);
		await expect(loadLearningAuthority(out, "execution")).rejects.toThrow(/Could not load/);
		const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
		vault.set(
			reference.private.id,
			ec.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
		);
		await writeFile(
			out,
			JSON.stringify({
				...reference,
				public_key_pem: ec.publicKey.export({ format: "pem", type: "spki" }),
			}),
		);
		await expect(loadLearningAuthority(out, "execution")).rejects.toThrow(/Could not load/);
	});

	it("bounds private key and reference inputs before parsing", async () => {
		fallback();
		const out = join(directory, "bounded.json");
		const reference = await generateLearningAuthority({
			role: "execution",
			out,
			secretStore: "file-acl",
		});
		await writeFile(`${out}.pkcs8`, "A".repeat(4097));
		await expect(loadLearningAuthority(out, "execution")).rejects.toThrow(/Could not load/);
		await writeFile(out, JSON.stringify({ ...reference, public_key_pem: "A".repeat(16 * 1024) }));
		await expect(loadLearningAuthority(out, "execution")).rejects.toThrow(/Could not load/);
	});

	it("rejects fallback custody whose private permissions cannot be established", async () => {
		fallback();
		const out = join(directory, "private.json");
		await generateLearningAuthority({ role: "execution", out, secretStore: "file-acl" });
		if (process.platform === "win32") {
			// A private parent does not make a file with an explicit foreign Allow ACE private.
			mocks.windowsTargetsAreAlreadyPrivate.mockReturnValue(false);
		} else await chmod(`${out}.pkcs8`, 0o644);
		mocks.preparePrivateLocalDirectory.mockClear();
		mocks.preparePrivateLocalFile.mockClear();
		await expect(loadLearningAuthority(out, "execution")).rejects.toThrow(/Could not load/);
		expect(mocks.preparePrivateLocalDirectory).not.toHaveBeenCalled();
		expect(mocks.preparePrivateLocalFile).not.toHaveBeenCalled();
		if (process.platform === "win32")
			expect(mocks.windowsTargetsAreAlreadyPrivate).toHaveBeenCalledWith([
				{ path: directory, directory: true },
				{ path: `${out}.pkcs8`, directory: false },
			]);
	});

	it("does not return a private key after its Windows ACL verification changes during the read", async () => {
		fallback();
		const out = join(directory, "changing-acl.json");
		await generateLearningAuthority({ role: "execution", out, secretStore: "file-acl" });
		if (process.platform === "win32") {
			mocks.windowsTargetsAreAlreadyPrivate.mockReturnValueOnce(true).mockReturnValueOnce(false);
			await expect(loadLearningAuthority(out, "execution")).rejects.toThrow(/Could not load/);
			expect(mocks.windowsTargetsAreAlreadyPrivate).toHaveBeenCalledTimes(2);
		} else {
			await chmod(`${out}.pkcs8`, 0o644);
			await expect(loadLearningAuthority(out, "execution")).rejects.toThrow(/Could not load/);
		}
	});
});

describe("bounded files and exclusive private output", () => {
	it("refuses readable-by-others authority handoffs without repairing supplied files", async () => {
		const path = join(directory, "handoff.json");
		await writePrivateNewJson(path, { signed: "private matcher policy" });
		if (process.platform === "win32") mocks.windowsTargetsAreAlreadyPrivate.mockReturnValue(false);
		else await chmod(path, 0o644);
		mocks.preparePrivateLocalDirectory.mockClear();
		mocks.preparePrivateLocalFile.mockClear();
		await expect(readJsonFile(path, 10 * 1024 * 1024, true)).rejects.toThrow(
			/bounded regular JSON/,
		);
		expect(mocks.preparePrivateLocalDirectory).not.toHaveBeenCalled();
		expect(mocks.preparePrivateLocalFile).not.toHaveBeenCalled();
	});

	it("preflights without reserving output and atomically permits only one concurrent publisher", async () => {
		const path = join(directory, "output.json");
		await prepareLearningOutput(path);
		expect(await readdir(directory)).toEqual([]);
		const results = await Promise.allSettled([
			writePrivateNewJson(path, { writer: 1 }),
			writePrivateNewJson(path, { writer: 2 }),
		]);
		expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		expect([1, 2]).toContain(((await readJsonFile(path)) as { writer: number }).writer);
		expect(await readdir(directory)).toEqual(["output.json"]);
		await expect(prepareLearningOutput(path)).rejects.toThrow(/new destination/);
		await expect(writePrivateNewJson(path, { writer: 3 })).rejects.toThrow(/new destination/);
	});

	it("rejects directories, hard links, oversized files and invalid JSON without returning file contents", async () => {
		const path = join(directory, "input.json");
		await expect(readJsonFile(directory)).rejects.toThrow(/bounded regular JSON/);
		await writeFile(path, JSON.stringify({ text: "larger than eight bytes" }));
		await expect(readJsonFile(path, 8)).rejects.toThrow(/bounded regular JSON/);
		await link(path, join(directory, "alias.json"));
		await expect(readJsonFile(path)).rejects.toThrow(/bounded regular JSON/);
		await writeFile(join(directory, "invalid.json"), "private-value invalid JSON");
		await expect(readJsonFile(join(directory, "invalid.json"))).rejects.toThrow(
			"Could not read a bounded regular JSON file.",
		);
	});

	it("refuses linked input and creates private output files", async () => {
		const target = join(directory, "target.json");
		await writePrivateNewJson(target, { value: true });
		if (process.platform === "win32") await link(target, join(directory, "link.json"));
		else await symlink(target, join(directory, "link.json"));
		await expect(readJsonFile(join(directory, "link.json"))).rejects.toThrow(
			/bounded regular JSON/,
		);
		const { stat } = await import("node:fs/promises");
		if (process.platform !== "win32") expect((await stat(target)).mode & 0o077).toBe(0);
		expect(mocks.preparePrivateLocalDirectory).toHaveBeenCalledWith(directory);
	});
});
