import { beforeEach, describe, expect, it, vi } from "vitest";
import { AutoContain, createDefaultContainConfig } from "../contain.js";
import { makeTmpDir } from "./test-utils.js";

describe("createDefaultContainConfig", () => {
	it("returns a valid default config", () => {
		const config = createDefaultContainConfig();
		expect(config.runtime).toBe("docker");
		expect(config.baseImage).toBe("alpine:latest");
		expect(config.networkMode).toBe("none");
		expect(config.readonlyMounts).toEqual([]);
		expect(config.timeoutSeconds).toBe(60);
	});
});

describe("AutoContain", () => {
	let _tmpDir: string;

	beforeEach(async () => {
		_tmpDir = await makeTmpDir();
	});

	describe("isolate", () => {
		it("runs operation without isolation when runtime unavailable", async () => {
			const contain = new AutoContain({
				runtime: "nonexistent-runtime",
				baseImage: "alpine:latest",
				networkMode: "none",
				readonlyMounts: [],
				timeoutSeconds: 60,
			});

			const operation = vi.fn().mockResolvedValue("success");
			const result = await contain.isolate(operation, { tool: "test", input: "test" });

			expect(operation).toHaveBeenCalled();
			expect(result.isolated).toBe(false);
			expect(result.result).toBe("success");
		});
	});

	describe("isolateCommand", () => {
		it("returns error when runtime unavailable", async () => {
			const contain = new AutoContain({
				runtime: "nonexistent-runtime",
				baseImage: "alpine:latest",
				networkMode: "none",
				readonlyMounts: [],
				timeoutSeconds: 60,
			});

			const result = await contain.isolateCommand("echo", ["hello"]);
			expect(result.isolated).toBe(false);
			expect(result.success).toBe(false);
			expect(result.exitCode).toBe(-1);
			expect(result.stderr).toContain("not available");
		});
	});
});
