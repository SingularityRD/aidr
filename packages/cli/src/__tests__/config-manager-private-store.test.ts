import {
	chmodSync,
	linkSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmdirSync,
	rmSync,
	statSync,
	symlinkSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const testHome = mkdtempSync(join(tmpdir(), "aidr-private-config-"));
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome };
});

/**
 * This suite is about the private FILE store, which is now the explicitly
 * selected `file-acl` fallback (the OS vault is the default and a silently
 * chosen plaintext fallback is refused by design). Selecting it here is what
 * the suite has always been exercising; no assertion is relaxed by it.
 */
process.env.AIDR_SECRET_STORE = "file-acl";

const { createConfig, getConfig, updateConfig } = await import("../utils/config-manager.js");
type Environment = import("../utils/config-manager.js").Environment;
const configDir = join(testHome, ".singularity-aidr");
const configFile = join(configDir, "config.json");
const env: Environment = {
	agent: "claude",
	hasNode: true,
	nodeVersion: process.version,
	projectRoot: testHome,
};

afterEach(() => {
	let linked = false;
	try {
		linked = lstatSync(configDir).isSymbolicLink();
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
		throw error;
	}
	if (linked) {
		if (process.platform === "win32") rmdirSync(configDir);
		else unlinkSync(configDir);
	} else {
		rmSync(configDir, { recursive: true, force: true });
	}
});
afterAll(() => rmSync(testHome, { recursive: true, force: true }));

describe("private local config store", () => {
	it.skipIf(process.platform !== "win32")("writes a config without inherited read ACLs on Windows", async () => {
		await createConfig(env, false);
		expect((await createConfig(env, false)).outcome).toBe("reused");
		for (const path of [configDir, configFile]) {
			const acl = spawnSync("icacls.exe", [path], { encoding: "utf8", windowsHide: true, timeout: 10_000 });
			expect(acl.status).toBe(0);
			expect(acl.stdout).not.toMatch(/CodexSandboxUsers|\(RX\)/);
		}
	}, 120_000);

	it("creates and atomically updates a private credential file without rotating it", async () => {
		const created = await createConfig(env, false);
		expect(created.outcome).toBe("created");
		const oldKey = getConfig()?.apiKey;
		const oldInode = statSync(configFile).ino;
		updateConfig({ hooksInstalled: true });
		expect(getConfig()).toMatchObject({ apiKey: oldKey, hooksInstalled: true });
		expect(statSync(configFile).ino).not.toBe(oldInode);
		expect(readdirSync(configDir)).toEqual(["config.json"]);
		if (process.platform !== "win32") {
			expect(statSync(configDir).mode & 0o077).toBe(0);
			expect(statSync(configFile).mode & 0o077).toBe(0);
		}
		expect((await createConfig(env, false)).outcome).toBe("reused");
		expect(getConfig()?.apiKey).toBe(oldKey);
	});

	it("rotates the credential only for a forced setup", async () => {
		await createConfig(env, false);
		const originalKey = getConfig()?.apiKey;
		expect((await createConfig(env, false)).outcome).toBe("reused");
		expect(getConfig()?.apiKey).toBe(originalKey);
		expect((await createConfig(env, true)).outcome).toBe("created");
		expect(getConfig()?.apiKey).not.toBe(originalKey);
	});

	it("repairs legacy permissive POSIX permissions before reading", async () => {
		if (process.platform === "win32") return;
		mkdirSync(configDir, { mode: 0o777 });
		writeFileSync(configFile, JSON.stringify({ apiKey: "legacy-secret" }), { mode: 0o666 });
		chmodSync(configDir, 0o777);
		chmodSync(configFile, 0o666);
		expect(getConfig()?.apiKey).toBe("legacy-secret");
		expect(statSync(configDir).mode & 0o077).toBe(0);
		expect(statSync(configFile).mode & 0o077).toBe(0);
	});

	it("rejects a linked config directory without following it", async () => {
		const target = join(testHome, "target-directory");
		mkdirSync(target, { recursive: true });
		symlinkSync(target, configDir, process.platform === "win32" ? "junction" : "dir");
		await expect(createConfig(env, false)).rejects.toThrow(/directory/);
		expect(readdirSync(target)).toEqual([]);
		rmSync(target, { recursive: true, force: true });
	});

	it.skipIf(process.platform === "win32")(
		"rejects a linked config file without reading the target",
		async () => {
			mkdirSync(configDir);
			const target = join(testHome, "target-file");
			writeFileSync(target, JSON.stringify({ apiKey: "target-secret" }));
			symlinkSync(target, configFile, "file");
			expect(() => getConfig()).toThrow(/regular private file/);
			expect(() => updateConfig({ hooksInstalled: true })).toThrow(/regular private file/);
			expect(readFileSync(target, "utf8")).toContain("target-secret");
			rmSync(target, { force: true });
		},
	);

	it("rejects hard-linked credential files", async () => {
		await createConfig(env, false);
		const secondLink = join(testHome, "second-link");
		linkSync(configFile, secondLink);
		expect(() => getConfig()).toThrow(/regular private file/);
		expect(() => updateConfig({ hooksInstalled: true })).toThrow(/regular private file/);
		rmSync(secondLink, { force: true });
	});

	it("does not include a credential in malformed JSON errors", async () => {
		mkdirSync(configDir);
		writeFileSync(configFile, '{"apiKey":"private-value",broken', { mode: 0o600 });
		expect(() => getConfig()).toThrow("Local config is invalid.");
		try {
			getConfig();
		} catch (error) {
			expect(String(error)).not.toContain("private-value");
		}
	});
});
