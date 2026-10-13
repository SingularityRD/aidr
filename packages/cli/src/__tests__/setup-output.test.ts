import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../utils/config-manager.js", () => ({ createConfig: vi.fn() }));
vi.mock("../utils/detect-env.js", () => ({ detectEnvironment: vi.fn() }));
vi.mock("../utils/install-hooks.js", () => ({
	installHooks: vi.fn(),
	recordHooksInstalled: vi.fn(),
}));
vi.mock("../utils/connector-install.js", () => ({
	HOST_IDS: ["claude-code", "cursor", "vscode", "openclaw", "opencode", "codex"],
	installConnectors: vi.fn(),
}));
vi.mock("../utils/test-protection.js", () => ({
	loadBundledThreatCount: vi.fn(),
	verifyDetection: vi.fn(),
}));

import setupCommand, { parseHosts } from "../commands/setup.js";
import { createConfig } from "../utils/config-manager.js";
import { installConnectors } from "../utils/connector-install.js";
import { detectEnvironment } from "../utils/detect-env.js";
import { installHooks, recordHooksInstalled } from "../utils/install-hooks.js";
import { OPERATOR_NONINTERACTIVE_ENV } from "../utils/operator-confirm.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";

const stdout: string[] = [];
const stderr: string[] = [];

function hostResult(action: string, state: string, followUp: string[] = []) {
	return {
		host: "codex",
		label: "Codex",
		action,
		detail: `codex ${action}`,
		changes: action === "installed" ? ["wrote /home/u/.codex/hooks.json"] : [],
		followUp,
		state,
	};
}

beforeEach(() => {
	vi.clearAllMocks();
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
		agent: "codex",
		detectedHosts: ["codex"],
		hasNode: true,
		nodeVersion: "v24.0.0",
	});
	vi.mocked(createConfig).mockResolvedValue({
		path: "/workspace/test/.singularity-aidr/config.json",
		outcome: "created",
		credential: "none",
	});
	vi.mocked(installConnectors).mockReturnValue([
		hostResult("installed", "installed", ["  Codex: review and trust the hooks with /hooks."]),
	] as never);
	vi.mocked(installHooks).mockResolvedValue({
		summary: "codex detected - connector install required",
		followUp: ["install connector by hand"],
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
	process.exitCode = undefined;
});

describe("aidr setup output streams", () => {
	it("keeps progress on stderr and the final user summary on stdout", async () => {
		await setupCommand({}, { env: {} });

		const progress = stderr.join("\n");
		expect(progress).toContain("Detecting environment...");
		expect(progress).toContain("✓ Agent hosts found: codex");
		expect(progress).toContain("Creating config...");
		expect(progress).toContain("✓ Config: /workspace/test/.singularity-aidr/config.json");
		expect(progress).toContain("Installing connectors...");
		expect(progress).toContain("✓ 42 rules active");
		expect(progress).toContain("✓ Detection verified (42 rules, probe matched 1)");

		const summary = stdout.join("\n");
		expect(summary).toContain("AIDR Setup");
		expect(summary).toContain("Codex        installed — codex installed");
		expect(summary).toContain("wrote /home/u/.codex/hooks.json");
		expect(summary).toContain("✅ Setup complete!");
		expect(summary).toContain("review and trust the hooks with /hooks");
		expect(summary).not.toContain("Detecting environment...");
		expect(summary).not.toContain("42 rules active");
		expect(recordHooksInstalled).toHaveBeenCalledWith(true);
	});

	it("keeps setup failures with the progress transcript on stderr", async () => {
		vi.mocked(detectEnvironment).mockRejectedValue(new Error("detection failed"));
		vi.spyOn(process, "exit").mockImplementation(((code?: string | number | null) => {
			throw new Error(`exit ${code}`);
		}) as typeof process.exit);

		await expect(setupCommand({}, { env: {} })).rejects.toThrow("exit 1");

		expect(stderr.join("\n")).toContain("Detecting environment...\nSetup failed: detection failed");
		expect(stdout.join("\n")).toContain("AIDR Setup");
		expect(stdout.join("\n")).not.toContain("Setup complete");
	});
});

describe("aidr setup connector install", () => {
	it("never claims protection when no connector is registered", async () => {
		vi.mocked(installConnectors).mockReturnValue([
			hostResult("manual", "runtime_present_not_installed", ["  Codex: install it"]),
		] as never);
		await setupCommand({}, { env: {} });
		const summary = stdout.join("\n");
		expect(summary).not.toContain("✅ Setup complete!");
		expect(summary).toContain("Protection is NOT yet active");
		expect(summary).toContain("Codex: install it");
		expect(recordHooksInstalled).toHaveBeenCalledWith(false);
	});

	it("exits non-zero when a host install failed", async () => {
		vi.mocked(installConnectors).mockReturnValue([
			hostResult("failed", "runtime_present_not_installed"),
		] as never);
		await setupCommand({}, { env: {} });
		expect(process.exitCode).toBe(1);
		expect(stdout.join("\n")).toContain("FAILED");
	});

	it("--dry-run writes no config, records nothing and passes dryRun to the installer", async () => {
		vi.mocked(installConnectors).mockReturnValue([
			hostResult("would_install", "runtime_present_not_installed"),
		] as never);
		await setupCommand({ dryRun: true, host: "codex,claude" }, { env: {} });
		expect(createConfig).not.toHaveBeenCalled();
		expect(recordHooksInstalled).not.toHaveBeenCalled();
		expect(vi.mocked(installConnectors).mock.calls[0]?.[1]).toMatchObject({
			dryRun: true,
			hosts: ["codex", "claude-code"],
		});
		expect(stdout.join("\n")).toContain("Dry run: no file was written");
	});

	it("--no-install keeps the guidance-only behaviour", async () => {
		await setupCommand({ install: false }, { env: {} });
		expect(installConnectors).not.toHaveBeenCalled();
		expect(stdout.join("\n")).toContain("install connector by hand");
	});

	it("rejects an unknown host instead of ignoring it", () => {
		expect(() => parseHosts("codex,emacs")).toThrow(/Unknown host emacs/);
		expect(parseHosts("Claude, code")).toEqual(["claude-code", "vscode"]);
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
