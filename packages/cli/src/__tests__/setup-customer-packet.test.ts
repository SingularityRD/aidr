/**
 * A per-customer installer places a vendor-signed customer packet next to the
 * bundle (and a machine copy). `aidr setup` verifies it, records the license
 * for this user, applies its preset and company address, and never lets a
 * refused packet or an ended license stop local detection from installing.
 *
 * `config-manager` captures the home directory at import time, so HOME is
 * redirected before the modules are imported (as setup-installer-enrollment.test.ts does).
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { registryOf, signedPacket, signingKey } from "./customer-packet-fixtures.js";

const testHome = mkdtempSync(join(tmpdir(), "aidr-setup-packet-"));
const originalHome = process.env.HOME;
process.env.HOME = testHome;
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome };
});

const { default: setupCommand } = await import("../commands/setup.js");
const { default: statusCommand } = await import("../commands/status.js");
const { runDoctor } = await import("../commands/doctor.js");
const { customerFilePath, licenseFilePath } = await import("../utils/customer-packet.js");
const { installerEnrollmentPath } = await import("../utils/installer-enrollment.js");

const key = signingKey();
const registry = registryOf(key);
const NOW = Date.now();
const packetDir = mkdtempSync(join(tmpdir(), "aidr-packet-files-"));
const packetFile = join(packetDir, "config", "customer-packet.json");
const configFile = join(testHome, ".singularity-aidr", "config.json");
const operator = { ...process.env, AIDR_OPERATOR_NONINTERACTIVE: "1" };
const customerPacket = { paths: [packetFile], registry };

afterEach(() => {
	rmSync(join(testHome, ".singularity-aidr"), { recursive: true, force: true });
	rmSync(packetFile, { force: true });
	process.exitCode = 0;
	vi.unstubAllEnvs();
});
afterAll(() => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(testHome, { recursive: true, force: true });
	rmSync(packetDir, { recursive: true, force: true });
});

function placePacket(document: unknown): void {
	mkdirSync(join(packetDir, "config"), { recursive: true });
	writeFileSync(packetFile, JSON.stringify(document));
}

async function capture(run: () => Promise<unknown>): Promise<string> {
	const lines: string[] = [];
	const spies = [
		vi.spyOn(console, "log").mockImplementation((...args) => void lines.push(args.join(" "))),
		vi.spyOn(console, "error").mockImplementation((...args) => void lines.push(args.join(" "))),
		vi.spyOn(console, "warn").mockImplementation((...args) => void lines.push(args.join(" "))),
	];
	try {
		await run();
	} finally {
		for (const spy of spies) spy.mockRestore();
	}
	return lines.join("\n");
}

function setup(options: Record<string, unknown>, env: NodeJS.ProcessEnv = operator) {
	const prompt = new PassThrough();
	const lines: string[] = [];
	prompt.on("data", (chunk) => lines.push(String(chunk)));
	return capture(() =>
		setupCommand(
			{ host: "claude-code", ...options },
			{
				home: testHome,
				standaloneRoot: null,
				commercial: false,
				env,
				streams: { input: new PassThrough(), output: prompt },
				customerPacket,
			},
		),
	).then((output) => `${output}\n${lines.join("")}`);
}

const config = () => JSON.parse(readFileSync(configFile, "utf8"));

describe("aidr setup with a customer packet", () => {
	it("records the license, applies the preset and the company address", async () => {
		placePacket(signedPacket(key, NOW));
		const output = await setup({ yes: true });
		expect(output).toContain("Customer: TÜBİTAK BİLGEM (bilgem). License active; updates until");
		expect(output).toContain("Set by the installer for TÜBİTAK BİLGEM");
		expect(output).toContain("Detection");
		const license = JSON.parse(readFileSync(licenseFilePath(testHome), "utf8"));
		expect(license.payload.customer_id).toBe("bilgem");
		expect(JSON.parse(readFileSync(customerFilePath(testHome), "utf8"))).toMatchObject({
			customer_id: "bilgem",
			packet_id: "PKT-BILGEM-1",
		});
		const saved = config();
		expect(saved.sensitivity).toBe("paranoid");
		expect(saved.mode).toBe("managed");
		expect(saved.control_plane.endpoint).toBe("https://aidr.bilgem.example.tr");
		// Rerun: nothing to confirm again while the console approval is pending.
		const again = await setup({}, { ...process.env, AIDR_OPERATOR_NONINTERACTIVE: "" });
		expect(again).not.toContain("was not applied");
	}, 60_000);

	it("keeps a sensitivity the configuration already chose", async () => {
		placePacket(signedPacket(key, NOW));
		await setup({});
		const current = config();
		writeFileSync(configFile, JSON.stringify({ ...current, sensitivity: "balanced" }));
		await setup({});
		expect(config().sensitivity).toBe("balanced");
	}, 60_000);

	it("refuses a tampered packet, says so plainly and still installs local detection", async () => {
		const packet = signedPacket(key, NOW);
		packet.payload.control_plane_url = "https://attacker.example";
		placePacket(packet);
		const output = await setup({ yes: true });
		expect(output).toContain(`The customer packet ${packetFile} was refused`);
		expect(output).toContain("Local detection is installed anyway");
		expect(output).toMatch(/Detection .*rules/);
		expect(existsSync(licenseFilePath(testHome))).toBe(false);
		expect(config().mode).not.toBe("managed");
	}, 60_000);

	it("refuses a packet signed by a key that is not trusted", async () => {
		placePacket(signedPacket(signingKey("other-key"), NOW));
		const output = await setup({ yes: true });
		expect(output).toContain("was refused (customer packet was signed by an untrusted key)");
		expect(existsSync(licenseFilePath(testHome))).toBe(false);
	}, 60_000);

	it("completes with an ended license and says that updates stopped", async () => {
		placePacket(signedPacket(key, NOW, -120));
		const output = await setup({ yes: true });
		expect(output).toContain("License ended; updates until");
		expect(output).toContain("new updates stopped on");
		expect(output).toContain("Local detection keeps working");
		expect(existsSync(licenseFilePath(testHome))).toBe(true);
		const status = await capture(() => statusCommand({}, { customerPacket }));
		expect(status).toContain("license ended. Updates stopped on");
		expect(status).toContain("detection continues");
		const doctor = await runDoctor({
			customerPacket,
			connectors: () => [],
			loadDetectors: async () => ({}),
		});
		const check = doctor.checks.find((entry) => entry.id === "customer_license");
		expect(check?.status).toBe("warn");
		expect(check?.detail).toMatchObject({ license_state: "expired", local_detection: "enforced" });
	}, 60_000);

	it("lets the installer's enrollment code win and fills its empty address from the packet", async () => {
		placePacket(signedPacket(key, NOW));
		const code = `aidr_enroll_${"A".repeat(43)}`;
		mkdirSync(join(testHome, ".singularity-aidr"), { recursive: true });
		writeFileSync(
			installerEnrollmentPath(testHome),
			JSON.stringify({
				format: "aidr-installer-enrollment/1",
				control_plane_url: "",
				enrollment_code: code,
				created_at: new Date().toISOString(),
			}),
		);
		const output = await setup({ yes: true });
		expect(output).toContain("Connected to your company (https://aidr.bilgem.example.tr)");
		const saved = config();
		expect(saved.control_plane.endpoint).toBe("https://aidr.bilgem.example.tr");
		expect(saved.auth.enrollment_token ?? saved.auth.enrollment_token_ref).toBeTruthy();
		expect(existsSync(installerEnrollmentPath(testHome))).toBe(false);
	}, 60_000);

	it("a dry run reports the packet and writes nothing", async () => {
		placePacket(signedPacket(key, NOW));
		const output = await setup({ dryRun: true });
		expect(output).toContain("Would apply the customer packet for TÜBİTAK BİLGEM (bilgem)");
		expect(existsSync(licenseFilePath(testHome))).toBe(false);
	}, 60_000);

	it("status shows the customer and the update date in Turkish", async () => {
		placePacket(signedPacket(key, NOW));
		vi.stubEnv("AIDR_LOCALE", "tr");
		const status = await capture(() => statusCommand({}, { customerPacket }));
		expect(status).toMatch(
			/Müşteri: TÜBİTAK BİLGEM \(bilgem\); lisans etkin\. Güncellemeler şu tarihe kadar: \d{4}-\d{2}-\d{2}\./,
		);
		vi.stubEnv("AIDR_LOCALE", "en");
		const json = JSON.parse(await capture(() => statusCommand({ json: true }, { customerPacket })));
		expect(json.customer).toMatchObject({
			state: "verified",
			customer_id: "bilgem",
			license_state: "active",
		});
	}, 60_000);
});
