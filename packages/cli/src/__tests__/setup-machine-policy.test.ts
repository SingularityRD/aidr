/**
 * A machine-wide install (Intune/SCCM/GPO in the SYSTEM context, or a root
 * package install) cannot answer the "connect" confirmation for every user:
 * Active Setup runs plain `aidr setup` at each user's logon, with no terminal
 * and no --yes. The administrator's machine policy (HKLM\SOFTWARE\Policies\
 * Singularity AIDR, /etc/singularity-aidr/managed.json) is what connects those
 * users, without confirmation, because only an administrator can write it.
 *
 * `config-manager` captures the home directory at import time, so HOME is
 * redirected before the modules are imported (as setup-installer-enrollment.test.ts does).
 */
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import type { MachinePolicyRead } from "@singularityrd/aidr-core";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { registryOf, signedPacket, signingKey } from "./customer-packet-fixtures.js";

const testHome = mkdtempSync(join(tmpdir(), "aidr-setup-machine-policy-"));
const originalHome = process.env.HOME;
process.env.HOME = testHome;
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome };
});

const { default: setupCommand } = await import("../commands/setup.js");
const { installerEnrollmentPath } = await import("../utils/installer-enrollment.js");

const ENDPOINT = "https://aidr.corp.example/functions/v1";
const FLEET_KEY = `aidr_fleet_${"F".repeat(43)}`;
const configFile = join(testHome, ".singularity-aidr", "config.json");
const packetDir = mkdtempSync(join(tmpdir(), "aidr-policy-packet-"));
const packetFile = join(packetDir, "customer-packet.json");
const packetKey = signingKey();
// No terminal, no --yes, no AIDR_OPERATOR_NONINTERACTIVE: what Active Setup runs.
const activeSetupEnv: NodeJS.ProcessEnv = Object.fromEntries(
	Object.entries(process.env).filter(([name]) => name !== "AIDR_OPERATOR_NONINTERACTIVE"),
);

afterEach(() => {
	rmSync(join(testHome, ".singularity-aidr"), { recursive: true, force: true });
	rmSync(packetFile, { force: true });
	process.exitCode = 0;
});
afterAll(() => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(testHome, { recursive: true, force: true });
	rmSync(packetDir, { recursive: true, force: true });
});

async function setup(
	machinePolicy: MachinePolicyRead,
	options: Record<string, unknown> = {},
): Promise<string> {
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
				env: activeSetupEnv,
				streams: { input: new PassThrough(), output: prompt },
				machinePolicy,
				customerPacket: { paths: [packetFile], registry: registryOf(packetKey) },
			},
		);
	} finally {
		for (const spy of spies) spy.mockRestore();
	}
	return lines.join("\n");
}

const config = () => JSON.parse(readFileSync(configFile, "utf8"));
const loaded = (policy: Record<string, unknown>): MachinePolicyRead => ({
	state: "loaded",
	source: "/etc/singularity-aidr/managed.json",
	policy,
});

describe("aidr setup with a machine policy", () => {
	it("connects every user non-interactively and never copies the fleet key", async () => {
		const output = await setup(
			loaded({
				control_plane_url: ENDPOINT,
				enrollment_key: FLEET_KEY,
				offline_policy: "keep_enforcing_local",
			}),
		);
		expect(output).toContain("Machine policy set by your administrator");
		expect(output).toContain(`Connected to your company (${ENDPOINT}) by the machine policy`);
		expect(output).toContain("keeps working locally");
		expect(output).not.toMatch(/Type .connect./);
		const written = config();
		expect(written.mode).toBe("managed");
		expect(written.control_plane).toMatchObject({ enabled: true, endpoint: ENDPOINT });
		expect(JSON.stringify(written)).not.toContain(FLEET_KEY);

		// Rerun at the next logon: nothing to change.
		const again = await setup(loaded({ control_plane_url: ENDPOINT, enrollment_key: FLEET_KEY }));
		expect(again).toContain(`Connected to ${ENDPOINT} as the machine policy says`);
	});

	it("asks for console approval when the policy has no fleet key", async () => {
		const output = await setup(loaded({ control_plane_url: ENDPOINT }));
		expect(output).toContain("approve this computer there");
		expect(config().mode).toBe("managed");
	});

	it("without a machine policy the same unattended run does not connect (unchanged)", async () => {
		mkdirSync(join(testHome, ".singularity-aidr"), { recursive: true });
		writeFileSync(
			installerEnrollmentPath(testHome),
			JSON.stringify({
				format: "aidr-installer-enrollment/1",
				control_plane_url: "https://typed.example.com",
				enrollment_code: "",
				created_at: new Date().toISOString(),
			}),
		);
		await setup({ state: "none" });
		expect(config().mode).not.toBe("managed");
		expect(existsSync(installerEnrollmentPath(testHome))).toBe(true);
	});

	it("the machine policy wins over the installer handoff, which is deleted", async () => {
		mkdirSync(join(testHome, ".singularity-aidr"), { recursive: true });
		writeFileSync(
			installerEnrollmentPath(testHome),
			JSON.stringify({
				format: "aidr-installer-enrollment/1",
				control_plane_url: "https://typed.example.com",
				enrollment_code: "",
				created_at: new Date().toISOString(),
			}),
		);
		const output = await setup(loaded({ control_plane_url: ENDPOINT }));
		expect(output).toContain("the machine policy decides the company connection");
		expect(existsSync(installerEnrollmentPath(testHome))).toBe(false);
		expect(config().control_plane.endpoint).toBe(ENDPOINT);
	});

	it("reports a refused policy and keeps local protection", async () => {
		const output = await setup({
			state: "refused",
			source: "/etc/singularity-aidr/managed.json",
			reason: "must be owned by root and not writable by group or others",
		});
		expect(output).toContain("was refused (must be owned by root");
		expect(config().mode).not.toBe("managed");
	});

	it("dry run says what it would connect and writes nothing", async () => {
		const output = await setup(loaded({ control_plane_url: ENDPOINT }), { dryRun: true });
		expect(output).toContain(`Would connect to ${ENDPOINT}`);
		expect(existsSync(configFile)).toBe(false);
	});
});

describe("deployment signing keys from the customer packet", () => {
	it("are trusted for signed entitlements after setup", async () => {
		const deploymentKey = generateKeyPairSync("ed25519")
			.publicKey.export({ type: "spki", format: "pem" })
			.toString();
		writeFileSync(
			packetFile,
			JSON.stringify(
				signedPacket(packetKey, Date.now(), 365, { licensing_public_keys_pem: [deploymentKey] }),
			),
		);
		const output = await setup({ state: "none" });
		expect(output).toContain("deployment signing keys from the customer packet are trusted (1)");
		expect(config().licensing.public_keys_pem).toEqual([deploymentKey]);
	});

	it("a packet with something that is not an Ed25519 key is refused", async () => {
		const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 })
			.publicKey.export({ type: "spki", format: "pem" })
			.toString();
		writeFileSync(
			packetFile,
			JSON.stringify(
				signedPacket(packetKey, Date.now(), 365, { licensing_public_keys_pem: [rsa] }),
			),
		);
		const output = await setup({ state: "none" });
		expect(output).toMatch(/customer packet .* was refused/);
		expect(config().licensing?.public_keys_pem ?? []).toEqual([]);
	});
});
