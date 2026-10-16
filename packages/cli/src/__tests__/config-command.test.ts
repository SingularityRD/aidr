import { PassThrough } from "node:stream";
import { ConfigSchema } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	getConfig: vi.fn(),
	replaceConfig: vi.fn(),
	readHiddenInput: vi.fn(),
}));

vi.mock("../utils/config-manager.js", () => ({
	getConfig: mocks.getConfig,
	replaceConfig: mocks.replaceConfig,
}));
vi.mock("../utils/secret-prompt.js", () => ({ readHiddenInput: mocks.readHiddenInput }));

import configCommand from "../commands/config.js";
import type { Config } from "../utils/config-manager.js";
import { OPERATOR_NONINTERACTIVE_ENV } from "../utils/operator-confirm.js";

function makeConfig(): Config {
	const config = {
		...ConfigSchema.parse({}),
		apiKey: "local-credential",
		environment: {
			agent: "claude",
			hasNode: true,
			nodeVersion: "v24.0.0",
			projectRoot: "/workspace",
		},
		version: "0.6.0",
		createdAt: "2026-09-23T00:00:00.000Z",
		hooksInstalled: false,
		agentConfigured: false,
	} as unknown as Config & Record<string, unknown>;
	(config.auth as unknown as Record<string, unknown>).unrecognized = "discard-me";
	config.unrecognized = true;
	return config;
}

/** Operator automation: --yes is honoured only with AIDR_OPERATOR_NONINTERACTIVE=1. */
const OPERATOR = { env: { [OPERATOR_NONINTERACTIVE_ENV]: "1" } };

const stdout: string[] = [];
const stderr: string[] = [];
let originalExitCode: string | number | undefined;

beforeEach(() => {
	stdout.length = 0;
	stderr.length = 0;
	originalExitCode = process.exitCode;
	vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		stdout.push(args.map(String).join(" "));
	});
	vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
		stderr.push(args.map(String).join(" "));
	});
	mocks.getConfig.mockReturnValue(makeConfig());
	mocks.replaceConfig.mockReset();
	mocks.readHiddenInput.mockReset();
});

afterEach(() => {
	process.exitCode = originalExitCode;
	vi.restoreAllMocks();
});

describe("aidr config -s", () => {
	it("persists validated typed data and strips unknown schema fields", async () => {
		await configCommand({ set: ["heuristics_enabled", "false"], yes: true }, OPERATOR);

		const saved = mocks.replaceConfig.mock.calls[0]?.[0] as Record<string, unknown>;
		expect(saved.heuristics_enabled).toBe(false);
		expect(saved.unrecognized).toBeUndefined();
		expect(saved.auth).not.toHaveProperty("unrecognized");
		expect(stdout.join("\n")).toContain("heuristics_enabled = false");
	});

	it("rejects a path whose nested field is stripped by the schema", async () => {
		await configCommand({ set: ["auth.unrecognized", "value"] });

		expect(mocks.replaceConfig).not.toHaveBeenCalled();
		expect(stderr.join("\n")).toContain("Unknown configuration field");
	});

	it("prompts invisibly for a secret and redacts it from output", async () => {
		mocks.readHiddenInput.mockResolvedValue("sensitive-auth-value");

		await configCommand({ set: ["auth.api_key"], yes: true }, OPERATOR);

		expect(mocks.readHiddenInput).toHaveBeenCalledOnce();
		expect(
			(mocks.replaceConfig.mock.calls[0]?.[0] as unknown as { auth: { api_key?: string } }).auth
				.api_key,
		).toBe("sensitive-auth-value");
		expect(stdout.join("\n")).toContain("auth.api_key = [redacted]");
		expect(stdout.join("\n")).not.toContain("sensitive-auth-value");
	});

	it("does not accept a secret value supplied as an argument", async () => {
		await configCommand({ set: ["auth.api_key", "shell-history-secret"] });

		expect(mocks.replaceConfig).not.toHaveBeenCalled();
		expect(mocks.readHiddenInput).not.toHaveBeenCalled();
		expect(stderr.join("\n")).not.toContain("shell-history-secret");
		expect(stderr.join("\n")).toContain("cannot be passed as command-line arguments");
	});

	it.each([
		["auth", '{"api_key":"shell-history-secret"}'],
		["auth", '{"enrollment_token":"shell-history-secret"}'],
		["nvd_check", '{"api_key":"shell-history-secret"}'],
	])("rejects secrets nested in a %s object argument", async (key, value) => {
		await configCommand({ set: [key, value] });
		expect(mocks.replaceConfig).not.toHaveBeenCalled();
		expect(stderr.join("\n")).toContain("hidden prompt");
		expect([...stderr, ...stdout].join("\n")).not.toContain("shell-history-secret");
		expect(process.exitCode).toBe(1);
	});

	it.each([{ set: ["heuristics_enabled", "false"] }, { get: "heuristics_enabled" }])(
		"returns a failure exit code when configuration is missing: %j",
		async (options) => {
			mocks.getConfig.mockReturnValue(null);
			await configCommand(options);
			expect(mocks.replaceConfig).not.toHaveBeenCalled();
			expect(process.exitCode).toBe(1);
		},
	);

	it("reports a configuration read error without exposing backend details", async () => {
		mocks.getConfig.mockImplementationOnce(() => {
			throw new Error("backend-secret-value");
		});
		await configCommand({ list: true });
		expect(stderr.join("\n")).toContain("could not be read");
		expect(stderr.join("\n")).not.toContain("backend-secret-value");
		expect(process.exitCode).toBe(1);
	});

	it("reports a failed save without claiming it succeeded or exposing backend details", async () => {
		mocks.replaceConfig.mockImplementationOnce(() => {
			throw new Error("backend-secret-value");
		});
		await configCommand({ set: ["heuristics_enabled", "false"], yes: true }, OPERATOR);
		expect(stderr.join("\n")).toContain("could not be saved");
		expect(stderr.join("\n")).not.toContain("backend-secret-value");
		expect(stdout.join("\n")).not.toContain("Set heuristics_enabled");
		expect(process.exitCode).toBe(1);
	});

	it("rejects malformed read paths with a controlled failure", async () => {
		await configCommand({ get: "auth..api_key" });
		expect(stderr.join("\n")).toContain("Invalid configuration path");
		expect(process.exitCode).toBe(1);
	});
});

describe("aidr config -g", () => {
	it("returns the effective default for a field absent from config.json", async () => {
		const config = makeConfig() as unknown as Record<string, unknown>;
		delete config.mode;
		mocks.getConfig.mockReturnValue(config);
		await configCommand({ get: "mode" });
		expect(stdout.join("\n")).toBe("local");
		expect(process.exitCode).not.toBe(1);
	});

	it("returns a stored value over the default", async () => {
		mocks.getConfig.mockReturnValue({ ...makeConfig(), mode: "managed" });
		await configCommand({ get: "mode" });
		expect(stdout.join("\n")).toBe("managed");
	});

	it("rejects a key the configuration does not have (a typo is not 'not set')", async () => {
		await configCommand({ get: "no_such_field" });
		expect(stderr.join("\n")).toContain("Unknown configuration key: no_such_field");
		expect(process.exitCode).toBe(1);
	});

	it("reports an optional field that is simply unset as not set", async () => {
		await configCommand({ get: "auth.api_key" });
		expect(process.exitCode).not.toBe(1);
	});
});

/** A TTY pair whose input answers the confirmation prompt once. */
function ttyStreams(answer: string) {
	const input = Object.assign(new PassThrough(), { isTTY: true });
	const output = Object.assign(new PassThrough(), { isTTY: true });
	output.resume();
	setTimeout(() => input.write(`${answer}\n`), 10);
	return { input, output };
}

/** Non-TTY streams, as an agent tool call sees them. */
function pipeStreams() {
	const output = new PassThrough();
	output.resume();
	return { input: new PassThrough(), output };
}

describe("aidr config -s operator confirmation for protection-weakening changes", () => {
	it.each([
		["heuristics_enabled", "false"],
		["sensitivity", "relaxed"],
		["disabled_threats", '["CLT-SELF-001"]'],
		["amsi_check.enabled", "false"],
		["poisoning_protection.enabled", "false"],
		["prompt_protection.pii", "off"],
		["cache.ttl_clean_seconds", "999999"],
		["mode", "managed"],
	])("refuses %s=%s without a TTY or operator automation", async (key, value) => {
		await configCommand({ set: [key, value] }, { env: {}, streams: pipeStreams() });
		expect(mocks.replaceConfig).not.toHaveBeenCalled();
		expect(stderr.join("\n")).toContain("interactive terminal");
		expect(stderr.join("\n")).toContain("No changes saved");
		expect(process.exitCode).toBe(1);
	});

	it("refuses --yes unless the operator automation variable is set", async () => {
		await configCommand(
			{ set: ["heuristics_enabled", "false"], yes: true },
			{ env: {}, streams: pipeStreams() },
		);
		expect(mocks.replaceConfig).not.toHaveBeenCalled();
		expect(stderr.join("\n")).toContain(OPERATOR_NONINTERACTIVE_ENV);
	});

	it("saves a weakening change once the operator types the confirmation word", async () => {
		await configCommand(
			{ set: ["sensitivity", "relaxed"] },
			{ env: {}, streams: ttyStreams("change") },
		);
		const saved = mocks.replaceConfig.mock.calls[0]?.[0] as unknown as { sensitivity: string };
		expect(saved.sensitivity).toBe("relaxed");
	});

	it("does not save when the operator types anything else", async () => {
		await configCommand(
			{ set: ["heuristics_enabled", "false"] },
			{ env: {}, streams: ttyStreams("no") },
		);
		expect(mocks.replaceConfig).not.toHaveBeenCalled();
		expect(process.exitCode).toBe(1);
	});

	it("requires confirmation to replace a secret", async () => {
		mocks.readHiddenInput.mockResolvedValue("new-secret");
		await configCommand({ set: ["auth.api_key"] }, { env: {}, streams: pipeStreams() });
		expect(mocks.replaceConfig).not.toHaveBeenCalled();
		expect([...stderr, ...stdout].join("\n")).not.toContain("new-secret");
	});

	it.each([
		["heuristics_enabled", "true"],
		["sensitivity", "paranoid"],
		["sensitivity", "balanced"],
		["url_check.enabled", "true"],
		["disabled_threats", "[]"],
	])("applies tightening %s=%s without confirmation", async (key, value) => {
		await configCommand({ set: [key, value] }, { env: {}, streams: pipeStreams() });
		expect(mocks.replaceConfig).toHaveBeenCalledOnce();
		expect(process.exitCode).not.toBe(1);
	});

	it("treats a lower sensitivity relative to the stored value as weakening", async () => {
		mocks.getConfig.mockReturnValue({ ...makeConfig(), sensitivity: "paranoid" });
		await configCommand({ set: ["sensitivity", "balanced"] }, { env: {}, streams: pipeStreams() });
		expect(mocks.replaceConfig).not.toHaveBeenCalled();
	});

	it("allows shrinking disabled_threats but not adding to it", async () => {
		mocks.getConfig.mockReturnValue({ ...makeConfig(), disabled_threats: ["A", "B"] });
		await configCommand(
			{ set: ["disabled_threats", '["A"]'] },
			{ env: {}, streams: pipeStreams() },
		);
		expect(mocks.replaceConfig).toHaveBeenCalledOnce();
		mocks.replaceConfig.mockReset();
		mocks.getConfig.mockReturnValue({ ...makeConfig(), disabled_threats: ["A"] });
		await configCommand(
			{ set: ["disabled_threats", '["A","C"]'] },
			{ env: {}, streams: pipeStreams() },
		);
		expect(mocks.replaceConfig).not.toHaveBeenCalled();
	});
});
