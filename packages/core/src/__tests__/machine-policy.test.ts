import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { isInvalidConfig, loadConfig } from "../config.js";
import {
	type MachinePolicyDeps,
	type MachinePolicyRead,
	overlayMachinePolicy,
	parseMachinePolicy,
	parseRegQueryOutput,
	readMachinePolicy,
	WINDOWS_MACHINE_POLICY_KEY,
} from "../machine-policy.js";

const ed25519 = () => generateKeyPairSync("ed25519").publicKey;
const pemOf = (key = ed25519()) => key.export({ type: "spki", format: "pem" }).toString();
const base64Of = (key = ed25519()) =>
	key.export({ type: "spki", format: "der" }).toString("base64");
const FLEET_KEY = `aidr_fleet_${"A".repeat(43)}`;

function linuxDeps(
	document: unknown,
	overrides: Partial<{
		uid: number;
		mode: number;
		dirUid: number;
		dirMode: number;
		missing: boolean;
	}> = {},
): MachinePolicyDeps {
	return {
		platform: "linux",
		path: "/etc/singularity-aidr/managed.json",
		stat: (path) => {
			if (overrides.missing) throw Object.assign(new Error("missing"), { code: "ENOENT" });
			const directory = path === "/etc/singularity-aidr";
			return {
				uid: directory ? (overrides.dirUid ?? 0) : (overrides.uid ?? 0),
				mode: directory ? (overrides.dirMode ?? 0o40755) : (overrides.mode ?? 0o100644),
				size: 100,
				isFile: () => !directory,
			};
		},
		readFile: () => (typeof document === "string" ? document : JSON.stringify(document)),
	};
}

describe("machine policy contract", () => {
	it("accepts every contract key and normalises public keys to PEM", () => {
		const parsed = parseMachinePolicy({
			control_plane_url: "https://aidr.corp.example/functions/v1",
			enrollment_key: FLEET_KEY,
			licensing_public_keys_pem: [pemOf(), base64Of()],
			ca_file: "/etc/pki/corp-ca.pem",
			use_os_trust_store: true,
			https_proxy: "http://proxy.corp.example:3128",
			no_proxy: "corp.example,10.0.0.0",
			support_contact_url: "mailto:bt-destek@corp.example",
			privacy_notice_url: "https://corp.example/aydinlatma",
			approvals_mode: "dashboard_only",
			offline_policy: "keep_enforcing_local",
		});
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) return;
		expect(parsed.policy.licensing_public_keys_pem).toHaveLength(2);
		for (const key of parsed.policy.licensing_public_keys_pem ?? []) {
			expect(key).toMatch(/^-----BEGIN PUBLIC KEY-----/);
		}
	});

	it.each([
		["plain HTTP control plane", { control_plane_url: "http://aidr.corp.example" }],
		["single-use code instead of a fleet key", { enrollment_key: `aidr_enroll_${"A".repeat(43)}` }],
		["something that is not a key", { licensing_public_keys_pem: ["not-a-key"] }],
		["relative CA path", { ca_file: "corp-ca.pem" }],
		["unknown offline policy", { offline_policy: "fail_open" }],
		["unknown key", { control_plane: "https://x.example" }],
	])("refuses the whole policy for a %s", (_name, raw) => {
		const parsed = parseMachinePolicy(raw as Record<string, unknown>);
		expect(parsed.ok).toBe(false);
	});

	it("treats empty values (an MSI property that was not passed) as unset", () => {
		const parsed = parseMachinePolicy({
			control_plane_url: "",
			offline_policy: "block_after_grace",
		});
		expect(parsed).toEqual({ ok: true, policy: { offline_policy: "block_after_grace" } });
	});
});

describe("reading the machine policy", () => {
	it("reads the Linux file only when root owns it and nobody else can write it", () => {
		const document = { control_plane_url: "https://aidr.corp.example" };
		expect(readMachinePolicy(linuxDeps(document)).state).toBe("loaded");
		expect(readMachinePolicy(linuxDeps(document, { missing: true }))).toEqual({ state: "none" });
		for (const unsafe of [
			{ uid: 1000 },
			{ mode: 0o100666 },
			{ mode: 0o100664 },
			{ dirUid: 1000 },
			{ dirMode: 0o40777 },
		]) {
			const read = readMachinePolicy(linuxDeps(document, unsafe));
			expect(read.state, JSON.stringify(unsafe)).toBe("refused");
		}
		expect(readMachinePolicy(linuxDeps("{not json")).state).toBe("refused");
		expect(readMachinePolicy(linuxDeps([1, 2])).state).toBe("refused");
	});

	it("reads the HKLM policy key with reg.exe, including multi-string public keys", () => {
		const keyA = base64Of();
		const keyB = base64Of();
		const output = [
			"",
			"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Singularity AIDR",
			"    MdmManaged    REG_DWORD    0x1",
			"    control_plane_url    REG_SZ    https://aidr.corp.example/functions/v1",
			`    licensing_public_keys_pem    REG_MULTI_SZ    ${keyA}\\0${keyB}`,
			"    use_os_trust_store    REG_DWORD    0x1",
			"    offline_policy    REG_SZ    block_after_grace",
			"    enrollment_key    REG_SZ    ",
			"",
		].join("\r\n");
		const queried: string[] = [];
		const read = readMachinePolicy({
			platform: "win32",
			regQueryKey: (key) => {
				queried.push(key);
				return output;
			},
		});
		expect(queried).toEqual([WINDOWS_MACHINE_POLICY_KEY]);
		expect(read.state).toBe("loaded");
		if (read.state !== "loaded") return;
		expect(read.policy.control_plane_url).toBe("https://aidr.corp.example/functions/v1");
		expect(read.policy.licensing_public_keys_pem).toHaveLength(2);
		expect(read.policy.use_os_trust_store).toBe(true);
		expect(read.policy.offline_policy).toBe("block_after_grace");
		expect(read.policy.enrollment_key).toBeUndefined();
		// The device-management marker alone is not a machine policy.
		expect(
			readMachinePolicy({
				platform: "win32",
				regQueryKey: () => "    MdmManaged    REG_DWORD    0x1\r\n",
			}),
		).toEqual({ state: "none" });
		expect(readMachinePolicy({ platform: "win32", regQueryKey: () => null })).toEqual({
			state: "none",
		});
	});

	it("parses PEM blocks and separators in a single registry string", () => {
		const pem = pemOf().trim();
		const raw = parseRegQueryOutput(
			`    licensing_public_keys_pem    REG_SZ    ${pem.replaceAll("\n", " ")} ; ${base64Of()}\r\n`,
		);
		const parsed = parseMachinePolicy(raw);
		expect(parsed.ok && parsed.policy.licensing_public_keys_pem?.length).toBe(2);
	});
});

describe("machine policy in configuration loading", () => {
	const keys = [pemOf()];
	const policy: MachinePolicyRead = {
		state: "loaded",
		source: "test",
		policy: {
			control_plane_url: "https://aidr.corp.example/functions/v1",
			enrollment_key: FLEET_KEY,
			licensing_public_keys_pem: keys,
			ca_file: "/etc/pki/corp-ca.pem",
			support_contact_url: "https://corp.example/destek",
			privacy_notice_url: "https://corp.example/aydinlatma",
			approvals_mode: "dashboard_only",
			offline_policy: "keep_enforcing_local",
		},
	};
	const none: MachinePolicyRead = { state: "none" };

	it("wins over the user's config for its keys", async () => {
		const user = {
			mode: "managed",
			control_plane: {
				endpoint: "https://user-chosen.example",
				remote_policy_required: true,
			},
			licensing: { public_keys_pem: ["user-key"] },
			operator_approvals: { dashboard_only: false },
		};
		const config = await loadConfig("unused.json", undefined, undefined, {
			raw: JSON.stringify(user),
			machinePolicy: policy,
		});
		expect(isInvalidConfig(config)).toBe(false);
		expect(config.control_plane.endpoint).toBe("https://aidr.corp.example/functions/v1");
		expect(config.licensing.public_keys_pem).toEqual(keys);
		expect(config.network.ca_file).toBe("/etc/pki/corp-ca.pem");
		expect(config.organization).toEqual({
			support_contact_url: "https://corp.example/destek",
			privacy_notice_url: "https://corp.example/aydinlatma",
		});
		expect(config.operator_approvals.approvals_mode).toBe("dashboard_only");
		expect(config.operator_approvals.dashboard_only).toBe(true);
		expect(config.control_plane.offline_policy).toBe("keep_enforcing_local");
		expect(config.control_plane.remote_policy_required).toBe(false);
		// Managed and without a credential: the fleet key enrolls it.
		expect(config.auth.enrollment_token).toBe(FLEET_KEY);
	});

	it("never replaces a credential and never enrolls a local-mode install", async () => {
		const enrolled = await loadConfig("unused.json", undefined, undefined, {
			raw: JSON.stringify({ mode: "managed", auth: { api_key: "existing" } }),
			machinePolicy: policy,
		});
		expect(enrolled.auth.enrollment_token).toBeUndefined();
		expect(enrolled.auth.api_key).toBe("existing");
		const local = await loadConfig("unused.json", undefined, undefined, {
			raw: null,
			machinePolicy: policy,
		});
		expect(local.mode).toBe("local");
		expect(local.auth.enrollment_token).toBeUndefined();
		// Fresh install still gets the deployment's keys and endpoint.
		expect(local.licensing.public_keys_pem).toEqual(keys);
	});

	it("keeps the fail-closed fallback for an invalid user config", async () => {
		const config = await loadConfig("unused.json", undefined, undefined, {
			raw: "{broken",
			machinePolicy: policy,
		});
		expect(isInvalidConfig(config)).toBe(true);
		expect(config.control_plane.remote_policy_required).toBe(true);
		expect(config.control_plane.endpoint).toBe("https://aidr.corp.example/functions/v1");
	});

	it("block_after_grace requires central policy; no policy leaves the config as written", async () => {
		const blocking = await loadConfig("unused.json", undefined, undefined, {
			raw: JSON.stringify({ mode: "managed", control_plane: { remote_policy_required: false } }),
			machinePolicy: {
				state: "loaded",
				source: "test",
				policy: { offline_policy: "block_after_grace" },
			},
		});
		expect(blocking.control_plane.remote_policy_required).toBe(true);
		const plain = await loadConfig("unused.json", undefined, undefined, {
			raw: JSON.stringify({ control_plane: { remote_policy_required: true } }),
			machinePolicy: none,
		});
		expect(plain.control_plane.remote_policy_required).toBe(true);
		expect(plain.control_plane.offline_policy).toBeUndefined();
	});

	it("lays the policy over a section without dropping the user's other keys", () => {
		const overlaid = overlayMachinePolicy(
			{ control_plane: { allow_insecure_loopback: true } },
			{
				control_plane_url: "https://aidr.corp.example",
			},
		);
		expect(overlaid.control_plane).toEqual({
			allow_insecure_loopback: true,
			endpoint: "https://aidr.corp.example",
		});
	});
});
