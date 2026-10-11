import {
	chmodSync,
	mkdirSync,
	mkdtempSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type CompileCacheModuleApi,
	enableHookCompileCache,
	resolveHookCompileCacheDir,
} from "../hook-compile-cache.js";

const STATUS = { FAILED: 0, ENABLED: 1, ALREADY_ENABLED: 2, DISABLED: 3 };

function fakeModule(
	status = STATUS.ENABLED,
): CompileCacheModuleApi & { enableCompileCache: ReturnType<typeof vi.fn> } {
	return {
		enableCompileCache: vi.fn((directory?: string) => ({ status, directory })),
		constants: { compileCacheStatus: STATUS },
	};
}

const roots: string[] = [];
function home(): string {
	const root = mkdtempSync(join(tmpdir(), "aidr-compile-cache-"));
	roots.push(root);
	return root;
}

afterEach(() => {
	for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("enableHookCompileCache", () => {
	it("resolves the cache under the AIDR state directory of HOME", () => {
		expect(resolveHookCompileCacheDir({ HOME: "/home/u" })).toBe(
			join("/home/u", ".singularity-aidr", "compile-cache"),
		);
	});

	it.skipIf(process.platform === "win32")(
		"prepares a private 0700 directory before enabling the cache",
		() => {
			const HOME = home();
			const api = fakeModule();
			const result = enableHookCompileCache({ env: { HOME }, platform: "linux", moduleApi: api });
			const directory = join(HOME, ".singularity-aidr", "compile-cache");
			expect(result).toEqual({ status: "enabled", directory });
			expect(api.enableCompileCache).toHaveBeenCalledWith(directory);
			expect(statSync(directory).mode & 0o777).toBe(0o700);
		},
	);

	it.skipIf(process.platform === "win32")(
		"repairs a group/world-accessible existing cache directory",
		() => {
			const HOME = home();
			const directory = join(HOME, ".singularity-aidr", "compile-cache");
			mkdirSync(directory, { recursive: true });
			chmodSync(directory, 0o777);
			expect(
				enableHookCompileCache({ env: { HOME }, platform: "linux", moduleApi: fakeModule() })
					.status,
			).toBe("enabled");
			expect(statSync(directory).mode & 0o777).toBe(0o700);
		},
	);

	it.skipIf(process.platform === "win32")(
		"refuses a symlinked cache directory without enabling the cache",
		() => {
			const HOME = home();
			const elsewhere = join(HOME, "elsewhere");
			mkdirSync(elsewhere);
			mkdirSync(join(HOME, ".singularity-aidr"));
			symlinkSync(elsewhere, join(HOME, ".singularity-aidr", "compile-cache"));
			const api = fakeModule();
			expect(
				enableHookCompileCache({ env: { HOME }, platform: "linux", moduleApi: api }).status,
			).toBe("failed");
			expect(api.enableCompileCache).not.toHaveBeenCalled();
		},
	);

	it("never throws when the directory cannot be prepared", () => {
		const HOME = home();
		writeFileSync(join(HOME, ".singularity-aidr"), "not a directory");
		const api = fakeModule();
		const result = enableHookCompileCache({ env: { HOME }, platform: "linux", moduleApi: api });
		expect(result.status).toBe("failed");
		expect(api.enableCompileCache).not.toHaveBeenCalled();
	});

	it("never throws when Node's API throws", () => {
		const api: CompileCacheModuleApi = {
			enableCompileCache: () => {
				throw new Error("boom");
			},
			constants: { compileCacheStatus: STATUS },
		};
		const result = enableHookCompileCache({
			env: { HOME: home() },
			platform: "linux",
			moduleApi: api,
			prepareDirectory: () => {},
		});
		expect(result).toEqual({ status: "failed", reason: "boom" });
	});

	it.each(["1", "true", "TRUE"])(
		"is disabled by AIDR_DISABLE_COMPILE_CACHE=%s without touching the filesystem",
		(value) => {
			const prepareDirectory = vi.fn();
			const api = fakeModule();
			const result = enableHookCompileCache({
				env: { HOME: "/nonexistent", AIDR_DISABLE_COMPILE_CACHE: value },
				platform: "linux",
				moduleApi: api,
				prepareDirectory,
			});
			expect(result.status).toBe("disabled");
			expect(prepareDirectory).not.toHaveBeenCalled();
			expect(api.enableCompileCache).not.toHaveBeenCalled();
		},
	);

	it("is off by default on Windows and opt-in with AIDR_ENABLE_COMPILE_CACHE=1", () => {
		const prepareDirectory = vi.fn();
		const api = fakeModule();
		expect(
			enableHookCompileCache({
				env: { HOME: "C:\\Users\\u" },
				platform: "win32",
				moduleApi: api,
				prepareDirectory,
			}),
		).toEqual({
			status: "disabled",
			reason: "win32_default_off",
		});
		expect(prepareDirectory).not.toHaveBeenCalled();
		expect(
			enableHookCompileCache({
				env: { HOME: "C:\\Users\\u", AIDR_ENABLE_COMPILE_CACHE: "1" },
				platform: "win32",
				moduleApi: api,
				prepareDirectory,
			}).status,
		).toBe("enabled");
		expect(prepareDirectory).toHaveBeenCalledTimes(1);
	});

	it("reports an unsupported runtime (Node < 22.1, older Electron) without preparing a directory", () => {
		const prepareDirectory = vi.fn();
		expect(
			enableHookCompileCache({
				env: { HOME: "/h" },
				platform: "linux",
				moduleApi: {},
				prepareDirectory,
			}).status,
		).toBe("unsupported");
		expect(prepareDirectory).not.toHaveBeenCalled();
	});

	it("maps Node's statuses", () => {
		const prepareDirectory = () => {};
		const run = (status: number) =>
			enableHookCompileCache({
				env: { HOME: "/h" },
				platform: "linux",
				moduleApi: fakeModule(status),
				prepareDirectory,
			}).status;
		expect(run(STATUS.ALREADY_ENABLED)).toBe("already_enabled");
		expect(run(STATUS.DISABLED)).toBe("disabled");
		expect(run(STATUS.FAILED)).toBe("failed");
		// A runtime without the status constants is never reported as enabled.
		const noConstants = { enableCompileCache: () => ({ status: 1 }) };
		expect(
			enableHookCompileCache({
				env: { HOME: "/h" },
				platform: "linux",
				moduleApi: noConstants,
				prepareDirectory,
			}).status,
		).toBe("failed");
	});
});
