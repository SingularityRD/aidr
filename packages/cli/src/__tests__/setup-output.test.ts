import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../utils/config-manager.js", () => ({ createConfig: vi.fn() }));
vi.mock("../utils/detect-env.js", () => ({ detectEnvironment: vi.fn() }));
vi.mock("../utils/install-hooks.js", () => ({ installHooks: vi.fn() }));
vi.mock("../utils/test-protection.js", () => ({
	loadBundledThreatCount: vi.fn(),
	verifyDetection: vi.fn(),
}));

import setupCommand from "../commands/setup.js";
import { createConfig } from "../utils/config-manager.js";
import { detectEnvironment } from "../utils/detect-env.js";
import { installHooks } from "../utils/install-hooks.js";
import { OPERATOR_NONINTERACTIVE_ENV } from "../utils/operator-confirm.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";

const stdout: string[] = [];
const stderr: string[] = [];

beforeEach(() => {
	stdout.length = 0;
	stderr.length = 0;
	vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		stdout.push(args.map(String).join(" "));
	});
	vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
		stderr.push(args.map(String).join(" "));
	});
	vi.spyOn(console, "warn").mockImplementation((...args: unknown[]) => {
		stderr.push(args.map(String).join(" "));
	});

	vi.mocked(detectEnvironment).mockResolvedValue({
		agent: "claude",
		hasNode: true,
		nodeVersion: "v24.0.0",
		projectRoot: "/workspace",
	});
	vi.mocked(createConfig).mockResolvedValue({
		path: "/workspace/test/.singularity-aidr/config.json",
		outcome: "created",
	});
	vi.mocked(installHooks).mockResolvedValue({
		summary: "claude detected - connector install required",
		followUp: ["install connector"],
	});
	vi.mocked(loadBundledThreatCount).mockResolvedValue(42);
	vi.mocked(verifyDetection).mockResolvedValue({
		ok: true,
		reason: "",
		detail: "42 rules, probe matched 1",
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("aidr setup output streams", () => {
	it("keeps progress on stderr and the final user summary on stdout", async () => {
		await setupCommand({});

		const progress = stderr.join("\n");
		expect(progress).toContain("Detecting environment...");
		expect(progress).toContain("✓ claude detected");
		expect(progress).toContain("Creating config...");
		expect(progress).toContain("✓ Config: /workspace/test/.singularity-aidr/config.json");
		expect(progress).toContain("Preparing connector setup guidance...");
		expect(progress).toContain("✓ claude detected - connector install required");
		expect(progress).toContain("Loading threat database...");
		expect(progress).toContain("✓ 42 rules active");
		expect(progress).toContain("Testing protection...");
		expect(progress).toContain("✓ Detection verified (42 rules, probe matched 1)");

		const summary = stdout.join("\n");
		expect(summary).toContain("AIDR Setup");
		expect(summary).toContain("✅ Setup complete!");
		expect(summary).toContain("Next steps:");
		expect(summary).toContain("install connector");
		expect(summary).not.toContain("Detecting environment...");
		expect(summary).not.toContain("42 rules active");
	});

	it("keeps setup failures with the progress transcript on stderr", async () => {
		vi.mocked(detectEnvironment).mockRejectedValue(new Error("detection failed"));
		vi.spyOn(process, "exit").mockImplementation(((code?: string | number | null) => {
			throw new Error(`exit ${code}`);
		}) as typeof process.exit);

		await expect(setupCommand({})).rejects.toThrow("exit 1");

		expect(stderr.join("\n")).toContain("Detecting environment...\nSetup failed: detection failed");
		expect(stdout.join("\n")).toContain("AIDR Setup");
		expect(stdout.join("\n")).not.toContain("Setup complete");
	});
});

describe("aidr setup --force operator confirmation", () => {
	function streams(isTTY: boolean, answer?: string) {
		const input = Object.assign(new PassThrough(), { isTTY });
		const output = Object.assign(new PassThrough(), { isTTY });
		output.resume();
		if (answer !== undefined) setTimeout(() => input.write(`${answer}\n`), 10);
		return { input, output };
	}

	beforeEach(() => {
		vi.mocked(createConfig).mockClear();
	});

	afterEach(() => {
		process.exitCode = undefined;
	});

	it("refuses a forced re-setup without a TTY and changes nothing", async () => {
		await setupCommand({ force: true }, { env: {}, streams: streams(false) });
		expect(createConfig).not.toHaveBeenCalled();
		expect(stderr.join("\n")).toContain("Nothing was changed");
		expect(process.exitCode).toBe(1);
	});

	it("refuses --yes without the operator automation variable", async () => {
		await setupCommand({ force: true, yes: true }, { env: {}, streams: streams(false) });
		expect(createConfig).not.toHaveBeenCalled();
		expect(stderr.join("\n")).toContain(OPERATOR_NONINTERACTIVE_ENV);
	});

	it("replaces the config after interactive confirmation", async () => {
		await setupCommand({ force: true }, { env: {}, streams: streams(true, "replace") });
		expect(createConfig).toHaveBeenCalledWith(expect.anything(), true, expect.anything());
	});

	it("accepts operator automation (--yes with the variable)", async () => {
		await setupCommand(
			{ force: true, yes: true },
			{ env: { [OPERATOR_NONINTERACTIVE_ENV]: "1" }, streams: streams(false) },
		);
		expect(createConfig).toHaveBeenCalledWith(expect.anything(), true, expect.anything());
	});

	it("does not ask for a plain setup without --force", async () => {
		await setupCommand({}, { env: {}, streams: streams(false) });
		expect(createConfig).toHaveBeenCalledWith(expect.anything(), false, expect.anything());
	});
});
