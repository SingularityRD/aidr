import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const aclProcess = vi.hoisted(() => vi.fn((
	_command: string,
	_args: string[],
	_options: { env?: Record<string, string | undefined> },
) => ({ status: 0 })));
const testHome = mkdtempSync(join(tmpdir(), "aidr-acl-mock-"));
vi.mock("node:child_process", () => ({ spawnSync: aclProcess }));
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome };
});

/**
 * This suite pins the ACL-hardened file boundary specifically: it counts the
 * PowerShell ACL invocations and asserts the credential lands in `config.json`.
 * That layout is now the explicitly selected `file-acl` fallback, so the suite
 * selects it instead of relying on it being the silent default. Every assertion
 * is unchanged.
 */
process.env.AIDR_SECRET_STORE = "file-acl";

const { createConfig, getConfig, updateConfig } = await import("../utils/config-manager.js");
const configDir = join(testHome, ".singularity-aidr");
const configFile = join(configDir, "config.json");
const env = { agent: "claude" as const, hasNode: true, nodeVersion: process.version, projectRoot: testHome };

afterEach(() => {
	aclProcess.mockReset();
	aclProcess.mockReturnValue({ status: 0 });
	rmSync(configDir, { recursive: true, force: true });
});
afterAll(() => rmSync(testHome, { recursive: true, force: true }));

describe.skipIf(process.platform !== "win32")("Windows private config ACL boundary", () => {
	it("hardens the directory before writing and never invokes PowerShell for reads", async () => {
		await createConfig(env, false);
		expect(aclProcess).toHaveBeenCalledTimes(1);
		expect(aclProcess.mock.calls[0]?.[2]?.env?.AIDR_PRIVATE_ACL_PATH).toBe(configDir);
		getConfig();
		expect(aclProcess).toHaveBeenCalledTimes(1);
		updateConfig({ hooksInstalled: true });
		expect(aclProcess).toHaveBeenCalledTimes(2);
		expect(aclProcess.mock.calls[1]?.[2]?.env?.AIDR_PRIVATE_ACL_PATH).toBe(configDir);
	});

	it("does not write a credential when ACL hardening fails", async () => {
		aclProcess.mockReturnValueOnce({ status: 1 });
		await expect(createConfig(env, false)).rejects.toThrow("Local config Windows ACL could not be made private.");
		expect(existsSync(configFile)).toBe(false);
	});

	it("preserves the existing config when ACL hardening fails before an update", async () => {
		await createConfig(env, false);
		const prior = getConfig();
		aclProcess.mockReturnValueOnce({ status: 1 });
		expect(() => updateConfig({ hooksInstalled: true })).toThrow("Local config Windows ACL could not be made private.");
		expect(getConfig()).toEqual(prior);
	});

	it("repairs an existing credential during setup reuse", async () => {
		await createConfig(env, false);
		aclProcess.mockClear();
		expect((await createConfig(env, false)).outcome).toBe("reused");
		expect(aclProcess).toHaveBeenCalledTimes(2);
		expect(aclProcess.mock.calls[1]?.[2]?.env?.AIDR_PRIVATE_ACL_PATH).toBe(configFile);
	});
});
