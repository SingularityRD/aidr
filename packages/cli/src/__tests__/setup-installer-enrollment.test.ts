/**
 * The Windows installer's company connection page hands the control-plane
 * address and the one-time enrollment code to `aidr setup` through
 * ~/.singularity-aidr/installer-enrollment.json (written by the MSI custom action
 * with a user-only ACL). Setup applies it only with operator confirmation (the
 * installer runs it with --yes and AIDR_OPERATOR_NONINTERACTIVE=1), switches
 * the config to managed mode for the next AI tool start, and deletes the file.
 *
 * `config-manager` captures the home directory at import time, so HOME is
 * redirected before the modules are imported (as setup-release-key.test.ts does).
 */

import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const testHome = mkdtempSync(join(tmpdir(), "aidr-setup-enrollment-"));
const originalHome = process.env.HOME;
process.env.HOME = testHome;
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome };
});

const { default: setupCommand } = await import("../commands/setup.js");
const {
	enrollmentProblem,
	INSTALLER_ENROLLMENT_MAX_AGE_MS,
	installerEnrollmentPath,
	readInstallerEnrollment,
} = await import("../utils/installer-enrollment.js");

const CODE = `aidr_enroll_${"A".repeat(20)}-_${"b".repeat(21)}`;
const handoffFile = installerEnrollmentPath(testHome);
const configFile = join(testHome, ".singularity-aidr", "config.json");

afterEach(() => {
	rmSync(join(testHome, ".singularity-aidr"), { recursive: true, force: true });
	process.exitCode = 0;
});
afterAll(() => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(testHome, { recursive: true, force: true });
});

function writeHandoff(fields: Record<string, unknown>): void {
	mkdirSync(join(testHome, ".singularity-aidr"), { recursive: true });
	writeFileSync(
		handoffFile,
		JSON.stringify({
			format: "aidr-installer-enrollment/1",
			control_plane_url: "https://aidr.example.com.tr",
			enrollment_code: CODE,
			created_at: new Date().toISOString(),
			...fields,
		}),
	);
}

async function setup(options: Record<string, unknown>, env: NodeJS.ProcessEnv): Promise<string> {
	const lines: string[] = [];
	const spies = [
		vi.spyOn(console, "log").mockImplementation((...args) => void lines.push(args.join(" "))),
		vi.spyOn(console, "error").mockImplementation((...args) => void lines.push(args.join(" "))),
		vi.spyOn(console, "warn").mockImplementation((...args) => void lines.push(args.join(" "))),
	];
	const prompt = new PassThrough();
	prompt.on("data", (chunk) => lines.push(String(chunk)));
	try {
		await setupCommand(
			{ host: "claude-code", ...options },
			{
				home: testHome,
				standaloneRoot: null,
				commercial: false,
				env,
				streams: { input: new PassThrough(), output: prompt },
			},
		);
	} finally {
		for (const spy of spies) spy.mockRestore();
	}
	return lines.join("\n");
}

const config = () => JSON.parse(readFileSync(configFile, "utf8"));
const operator = { ...process.env, AIDR_OPERATOR_NONINTERACTIVE: "1" };

describe("installer company connection format", () => {
	it("accepts an https address and an enrollment code, and nothing looser", () => {
		expect(enrollmentProblem("https://aidr.example.com.tr", CODE)).toBe("");
		expect(enrollmentProblem("https://aidr.example.com.tr:8443/tenant/v1", "")).toBe("");
		expect(enrollmentProblem("", CODE)).toBe("");
		expect(enrollmentProblem("", "")).toBe("url");
		for (const url of [
			"http://aidr.example.com",
			"https://",
			"https://aidr.example.com/?a=1",
			"https://aidr.example.com;x",
			"https://user@aidr.example.com",
			`https://${"a".repeat(600)}.com`,
			"https://aidr.example.com\n",
		]) {
			expect(enrollmentProblem(url, CODE)).toBe("url");
		}
		for (const code of [
			"aidr_enroll_short",
			`${CODE}x`,
			CODE.replace("aidr_enroll_", "aidr_api_"),
			`${CODE.slice(0, -1)}=`,
		]) {
			expect(enrollmentProblem("https://aidr.example.com", code)).toBe("code");
		}
	});

	it("reads a fresh handoff, refuses a malformed or a link one and expires an old one", () => {
		expect(readInstallerEnrollment(testHome).state).toBe("none");
		writeHandoff({});
		expect(readInstallerEnrollment(testHome)).toEqual({
			state: "ready",
			enrollment: { controlPlaneUrl: "https://aidr.example.com.tr", enrollmentCode: CODE },
		});
		const later = Date.now() + INSTALLER_ENROLLMENT_MAX_AGE_MS + 60_000;
		expect(readInstallerEnrollment(testHome, later).state).toBe("expired");
		writeHandoff({ format: "other/1" });
		expect(readInstallerEnrollment(testHome).state).toBe("invalid");
		writeHandoff({ enrollment_code: "aidr_enroll_x" });
		expect(readInstallerEnrollment(testHome)).toEqual({
			state: "invalid",
			reason: "the enrollment code is malformed",
		});
		writeFileSync(handoffFile, "{not json");
		const invalid = readInstallerEnrollment(testHome);
		expect(invalid).toEqual({ state: "invalid", reason: "not valid JSON" });
		if (process.platform !== "win32") {
			const elsewhere = join(testHome, "elsewhere.json");
			writeFileSync(elsewhere, "{}");
			rmSync(handoffFile);
			symlinkSync(elsewhere, handoffFile);
			expect(readInstallerEnrollment(testHome)).toEqual({
				state: "invalid",
				reason: "not a regular file",
			});
		}
	});
});

describe("aidr setup and the installer's company connection", () => {
	it("applies it with operator confirmation, switches to managed mode and deletes the file", async () => {
		writeHandoff({});
		const output = await setup({ yes: true }, operator);
		expect(output).toContain("Company address: https://aidr.example.com.tr");
		expect(output).toContain("Connected to your company (https://aidr.example.com.tr)");
		expect(output).not.toContain(CODE);
		const saved = config();
		expect(saved.mode).toBe("managed");
		expect(saved.control_plane.endpoint).toBe("https://aidr.example.com.tr");
		expect(saved.auth.enrollment_token ?? saved.auth.enrollment_token_ref).toBeTruthy();
		expect(existsSync(handoffFile)).toBe(false);
	}, 60_000);

	it("an address without a code uses device approval; no address means the Singularity AIDR service", async () => {
		writeHandoff({ enrollment_code: "" });
		const output = await setup({ yes: true }, operator);
		expect(output).toContain("it shows a code and a link");
		expect(config().auth?.enrollment_token).toBeUndefined();
		rmSync(join(testHome, ".singularity-aidr"), { recursive: true, force: true });
		writeHandoff({ control_plane_url: "" });
		await setup({ yes: true }, operator);
		expect(config().control_plane.endpoint).toBe("https://aidr.singularityrd.com");
	}, 60_000);

	it("without confirmation (an agent, no terminal) nothing changes and the file waits for the operator", async () => {
		writeHandoff({});
		const output = await setup({}, { ...process.env, AIDR_OPERATOR_NONINTERACTIVE: "" });
		expect(output).toContain("was not applied");
		expect(config().mode).not.toBe("managed");
		expect(existsSync(handoffFile)).toBe(true);
		const withoutVariable = await setup(
			{ yes: true },
			{ ...process.env, AIDR_OPERATOR_NONINTERACTIVE: "" },
		);
		expect(withoutVariable).toContain("was not applied");
		expect(config().mode).not.toBe("managed");
	}, 60_000);

	it("a malformed or expired handoff is deleted without being applied", async () => {
		writeHandoff({ control_plane_url: "http://evil.example.com" });
		const output = await setup({ yes: true }, operator);
		expect(output).toContain("could not be used (the company address is not https)");
		expect(config().mode).not.toBe("managed");
		expect(existsSync(handoffFile)).toBe(false);
		writeHandoff({
			created_at: new Date(Date.now() - INSTALLER_ENROLLMENT_MAX_AGE_MS - 60_000).toISOString(),
		});
		expect(await setup({ yes: true }, operator)).toContain("older than 3 days");
		expect(existsSync(handoffFile)).toBe(false);
	}, 60_000);

	it("an already enrolled computer keeps its connection", async () => {
		writeHandoff({});
		await setup({ yes: true }, operator);
		const enrolled = config();
		enrolled.auth = { ...enrolled.auth, api_key: "existing-device-key" };
		writeFileSync(configFile, JSON.stringify(enrolled));
		writeHandoff({ control_plane_url: "https://other.example.com" });
		const output = await setup({ yes: true }, operator);
		expect(output).toContain("already connected to https://aidr.example.com.tr");
		expect(config().control_plane.endpoint).toBe("https://aidr.example.com.tr");
		expect(existsSync(handoffFile)).toBe(false);
	}, 60_000);
});
