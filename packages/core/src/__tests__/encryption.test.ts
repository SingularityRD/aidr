import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import {
	decryptBuffer,
	decryptFile,
	deriveKey,
	encryptBuffer,
	encryptFile,
	isEncrypted,
	migrateToEncrypted,
} from "../encryption.js";
import { makeTmpDir } from "./test-utils.js";

// ── Helpers ───────────────────────────────────────────────────────────

const IV_LENGTH = 12;
const KEY_LENGTH = 32;

// ── Key derivation ────────────────────────────────────────────────────

describe("deriveKey", () => {
	it("returns a 32-byte buffer", () => {
		const key = deriveKey("test-installation-id");
		expect(key).toBeInstanceOf(Buffer);
		expect(key.length).toBe(KEY_LENGTH);
	});

	it("produces consistent keys for the same installation ID", () => {
		expect(deriveKey("test-id")).toEqual(deriveKey("test-id"));
	});

	it("produces different keys for different installation IDs", () => {
		expect(deriveKey("id-1")).not.toEqual(deriveKey("id-2"));
	});
});

// ── Buffer encryption / decryption ────────────────────────────────────

describe("encryptBuffer / decryptBuffer", () => {
	const key = deriveKey("test-id");

	it("encrypts and decrypts a buffer", () => {
		const plaintext = Buffer.from("hello, world!");
		const encrypted = encryptBuffer(plaintext, key);
		const decrypted = decryptBuffer(encrypted, key);
		expect(decrypted.toString()).toBe("hello, world!");
	});

	it("produces different ciphertexts for the same plaintext (random IV)", () => {
		const plaintext = Buffer.from("same data");
		const a = encryptBuffer(plaintext, key);
		const b = encryptBuffer(plaintext, key);
		expect(a.toString("hex")).not.toBe(b.toString("hex"));
	});

	it("throws on corrupted ciphertext", () => {
		const plaintext = Buffer.from("test");
		const encrypted = encryptBuffer(plaintext, key);
		encrypted[IV_LENGTH] ^= 0xff; // corrupt one byte
		expect(() => decryptBuffer(encrypted, key)).toThrow();
	});

	it("throws when payload is too short", () => {
		const tooShort = Buffer.alloc(8);
		expect(() => decryptBuffer(tooShort, key)).toThrow("too short");
	});

	it("handles empty buffers", () => {
		const plaintext = Buffer.alloc(0);
		const encrypted = encryptBuffer(plaintext, key);
		const decrypted = decryptBuffer(encrypted, key);
		expect(decrypted.length).toBe(0);
	});

	it("round-trips binary data", () => {
		const plaintext = Buffer.from([0x00, 0xff, 0xab, 0xcd, 0x00, 0x01]);
		const encrypted = encryptBuffer(plaintext, key);
		const decrypted = decryptBuffer(encrypted, key);
		expect([...decrypted]).toEqual([0x00, 0xff, 0xab, 0xcd, 0x00, 0x01]);
	});

	it("requires the correct key", () => {
		const plaintext = Buffer.from("secret");
		const encrypted = encryptBuffer(plaintext, deriveKey("owner"));
		expect(() => decryptBuffer(encrypted, deriveKey("attacker"))).toThrow();
	});
});

// ── Header detection ──────────────────────────────────────────────────

describe("isEncrypted", () => {
	it("returns true for a string with the header prefix", () => {
		expect(isEncrypted("AIDRENC:1:somebase64data")).toBe(true);
	});

	it("returns false for plain JSON", () => {
		expect(isEncrypted('{"urls":{}}')).toBe(false);
	});

	it("returns false for an empty string", () => {
		expect(isEncrypted("")).toBe(false);
	});

	it("works with Buffer input", () => {
		expect(isEncrypted(Buffer.from("AIDRENC:1:data"))).toBe(true);
		expect(isEncrypted(Buffer.from("plain"))).toBe(false);
	});

	it("returns false for short buffers", () => {
		expect(isEncrypted(Buffer.from("short"))).toBe(false);
	});
});

// ── File-level operations ─────────────────────────────────────────────

describe("encryptFile / decryptFile", () => {
	let dir: string;
	const key = deriveKey("test-id");

	beforeEach(async () => {
		dir = await makeTmpDir();
	});

	it("encrypts and decrypts a file", async () => {
		const fp = join(dir, "test.json");
		await writeFile(fp, '{"key": "value"}');

		await encryptFile(fp, key);

		const content = await readFile(fp, "utf-8");
		expect(content.startsWith("AIDRENC:1:")).toBe(true);

		const decrypted = await decryptFile(fp, key);
		expect(decrypted).toBe('{"key": "value"}');
	});

	it("is a no-op when the file is already encrypted", async () => {
		const fp = join(dir, "double.json");
		await writeFile(fp, "data");
		await encryptFile(fp, key);
		const once = await readFile(fp, "utf-8");
		await encryptFile(fp, key); // second call
		expect(await readFile(fp, "utf-8")).toBe(once);
	});

	it("falls back to plaintext for unencrypted files", async () => {
		const fp = join(dir, "plain.json");
		await writeFile(fp, "plain content");
		const result = await decryptFile(fp, key);
		expect(result).toBe("plain content");
	});
});

// ── Migration ─────────────────────────────────────────────────────────

describe("migrateToEncrypted", () => {
	let dir: string;
	const key = deriveKey("test-id");

	beforeEach(async () => {
		dir = await makeTmpDir();
	});

	it("migrates a plaintext file to encrypted format", async () => {
		const fp = join(dir, "cache.json");
		await writeFile(fp, '{"urls":{}}');

		await migrateToEncrypted(fp, key);

		const content = await readFile(fp, "utf-8");
		expect(content.startsWith("AIDRENC:1:")).toBe(true);

		const decrypted = await decryptFile(fp, key);
		expect(decrypted).toBe('{"urls":{}}');
	});

	it("is a no-op on already encrypted files", async () => {
		const fp = join(dir, "already.json");
		await writeFile(fp, "AIDRENC:1:c29tZWRhdGE=");

		await migrateToEncrypted(fp, key);

		expect(await readFile(fp, "utf-8")).toBe("AIDRENC:1:c29tZWRhdGE=");
	});

	it("preserves file content after migration round-trip", async () => {
		const fp = join(dir, "roundtrip.json");
		const original = JSON.stringify({ urls: { a: 1 }, commands: { b: 2 } });
		await writeFile(fp, original);

		await migrateToEncrypted(fp, key);
		const decrypted = await decryptFile(fp, key);

		expect(JSON.parse(decrypted)).toEqual({ urls: { a: 1 }, commands: { b: 2 } });
	});
});
