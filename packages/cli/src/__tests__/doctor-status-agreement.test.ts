/**
 * `aidr status` and `aidr doctor` must tell an administrator the same thing:
 * the same mode (a release build is always managed, exactly as the hooks
 * enforce it) and the same release-key state, with a missing key in red and
 * the one command that fixes it. Doctor prints one line per check, in the
 * user's language, with the explanation behind `--verbose`.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	clearOperatorApprovalKeyCache,
	type OperatorApprovalStoreOptions,
} from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatDoctorReport, runDoctor } from "../commands/doctor.js";
import statusCommand from "../commands/status.js";
import type { ConnectorStatus } from "../utils/connector-status.js";
import { localTime } from "../utils/local-time.js";
import { releaseKeyState } from "../utils/release-key.js";

let home: string;
let originalHome: string | undefined;
let store: OperatorApprovalStoreOptions;

const installed: ConnectorStatus = {
	id: "codex",
	label: "Codex",
	state: "installed",
	detail: "test",
	evidence: [],
};

function doctor() {
	return runDoctor({
		connectors: () => [installed],
		operatorApprovals: store,
		loadDetectors: async () => ({}),
		agentEnvironment: () => ({
			schema_version: 1,
			scanned_at: "2026-10-13T00:00:00.000Z",
			hosts: [],
			findings: [],
			unreadable: [],
			scope: "test",
		}),
	});
}

async function statusJson(): Promise<Record<string, unknown>> {
	const lines: string[] = [];
	vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		lines.push(args.map(String).join(" "));
	});
	await statusCommand({ json: true });
	vi.mocked(console.log).mockRestore();
	return JSON.parse(lines.join("\n")) as Record<string, unknown>;
}

async function statusText(): Promise<string> {
	const lines: string[] = [];
	vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		lines.push(args.map(String).join(" "));
	});
	await statusCommand();
	vi.mocked(console.log).mockRestore();
	return lines.join("\n");
}

function writeConfig(config: Record<string, unknown>): void {
	writeFileSync(join(home, ".singularity-aidr", "config.json"), JSON.stringify(config));
}

function publicKeyPem(): string {
	return generateKeyPairSync("ed25519")
		.publicKey.export({ type: "spki", format: "pem" })
		.toString();
}

beforeEach(() => {
	originalHome = process.env.HOME;
	home = mkdtempSync(join(tmpdir(), "aidr-doctor-status-"));
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true, mode: 0o700 });
	process.env.HOME = home;
	clearOperatorApprovalKeyCache();
	const key = randomBytes(32);
	store = {
		path: join(home, ".singularity-aidr", "approvals.json"),
		keyProvider: { load: () => ({ key, location: "os-vault", store: "macos-keychain" }) },
	};
	process.exitCode = undefined;
});

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	process.exitCode = undefined;
	clearOperatorApprovalKeyCache();
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(home, { recursive: true, force: true });
});

describe("mode: status and doctor agree", () => {
	it("both report local mode on a development build without a config", async () => {
		const report = await doctor();
		const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
		expect(byId.configuration?.summary).toBe("Mode: local.");
		const status = (await statusJson()) as { configuration: { mode: string } };
		expect(status.configuration.mode).toBe("local");
	});

	it("both report managed for a release build even when the file says local", async () => {
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		writeConfig({ mode: "local" });
		const report = await doctor();
		const configuration = report.checks.find((c) => c.id === "configuration");
		expect(configuration?.summary).toBe("Mode: managed.");
		expect(configuration?.notes).toContain("release build: always managed");
		const status = (await statusJson()) as {
			configuration: { mode: string; release_build: boolean };
		};
		// Before: status parsed the file itself and printed "mode: local".
		expect(status.configuration).toMatchObject({ mode: "managed", release_build: true });
		expect(await statusText()).toContain("mode: managed (release build: always managed)");
	});
});

describe("release verification key", () => {
	it("is red in both, with the fix command, when a release build has no key", async () => {
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		const report = await doctor();
		const integrity = report.checks.find((c) => c.id === "integrity");
		expect(integrity?.status).toBe("fail");
		expect(integrity?.summary).toContain("MISSING");
		expect(integrity?.summary).toContain("aidr setup --release-key <file.pem>");
		expect(report.ok).toBe(false);

		const status = (await statusJson()) as {
			integrity: { status: string };
			configuration_ready: boolean;
		};
		expect(status.integrity.status).toBe("missing");
		expect(status.configuration_ready).toBe(false);
		const text = await statusText();
		expect(text).toContain(`✗ Release verification key MISSING`);
		expect(text).toContain("aidr setup --release-key <file.pem>");
		expect(process.exitCode).toBe(1);
	});

	it("is green with a configured key and red for a key that is not a public key", async () => {
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		writeConfig({ integrity: { public_keys_pem: [publicKeyPem()] } });
		let integrity = (await doctor()).checks.find((c) => c.id === "integrity");
		expect(integrity?.status).toBe("ok");
		expect(integrity?.summary).toContain("1 key(s) configured");

		writeConfig({ integrity: { public_keys_pem: ["-----BEGIN PUBLIC KEY-----\nnot a key\n"] } });
		integrity = (await doctor()).checks.find((c) => c.id === "integrity");
		expect(integrity?.status).toBe("fail");
		expect(integrity?.summary).toContain("unusable");
	});

	it("does not fail a development build that has no key", () => {
		expect(
			releaseKeyState(
				{ integrity: { enabled: false, public_keys_pem: [], verify_on_start: true } },
				false,
			),
		).toMatchObject({ status: "off" });
		expect(
			releaseKeyState(
				{ integrity: { enabled: true, public_keys_pem: [], verify_on_start: true } },
				false,
			),
		).toMatchObject({ status: "digests_only" });
	});
});

describe("doctor output", () => {
	it("prints one line per check and the details only with --verbose", async () => {
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		const report = await doctor();
		const short = formatDoctorReport(report);
		// Title + one line per check + footer + the hint that details exist.
		expect(short).toHaveLength(report.checks.length + 3);
		expect(short.at(-1)).toBe("Details for each line: aidr doctor --verbose");
		const verbose = formatDoctorReport(report, true);
		expect(verbose.length).toBeGreaterThan(short.length);
		expect(verbose.join("\n")).toContain("Ask your IT admin for the key file");
		expect(short.join("\n")).not.toContain("Ask your IT admin");
	});

	it("keeps the long key-custody explanation out of the one-line summary", async () => {
		const key = randomBytes(32);
		const sealed: OperatorApprovalStoreOptions = {
			...store,
			keyProvider: {
				load: () => ({ key, location: "encrypted-file", store: "encrypted-file" }),
				anchor: () => ({ location: "encrypted-file", read: () => null, write: () => undefined }),
			},
		};
		clearOperatorApprovalKeyCache();
		const report = await runDoctor({
			connectors: () => [installed],
			operatorApprovals: sealed,
			loadDetectors: async () => ({}),
		});
		const approvals = report.checks.find((c) => c.id === "operator_approvals");
		expect(approvals?.summary).not.toContain("AES-256-GCM");
		expect(approvals?.notes?.join(" ")).toContain("AES-256-GCM");
	});

	it("is fully Turkish with AIDR_LOCALE=tr", async () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		const report = await doctor();
		const lines = formatDoctorReport(report, true).join("\n");
		expect(lines).toContain("Singularity AIDR tanılama");
		expect(lines).toContain("Mod: yerel.");
		expect(lines).toContain("Sürüm imzası denetimi: kapalı (geliştirme sürümü).");
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		const release = formatDoctorReport(await doctor()).join("\n");
		expect(release).toContain("Mod: yönetilen.");
		expect(release).toContain(
			"✗ Sürüm doğrulama anahtarı EKSİK: Singularity AIDR kendi kurulumunu doğrulayamıyor ve her araç çağrısını engelleyebilir. Çözüm: aidr setup --release-key <anahtar.pem>",
		);
		expect(lines).toContain("tehdit kuralı yüklendi");
		expect(lines).toContain("Hook kayıtlı yapay zekâ araçları: Codex.");
		for (const english of [
			"Mode:",
			"Hooks registered",
			"DLP is not active",
			"Last verdict",
			"No verdict",
		]) {
			expect(lines).not.toContain(english);
		}
	});
});

describe("doctor AMSI check (D3)", () => {
	const base = { checkedAt: "2026-10-14T00:00:00.000Z", version: "x", host: "h" };
	async function amsiCheck(record: unknown) {
		const report = await runDoctor({
			connectors: () => [installed],
			operatorApprovals: store,
			loadDetectors: async () => ({}),
			agentEnvironment: () => ({
				schema_version: 1,
				scanned_at: "2026-10-13T00:00:00.000Z",
				hosts: [],
				findings: [],
				unreadable: [],
				scope: "test",
			}),
			amsiStatus: async () => record as never,
		});
		return report.checks.find((check) => check.id === "amsi");
	}

	it("reports nothing where AMSI does not apply", async () => {
		expect(await amsiCheck(null)).toBeUndefined();
	});

	it("warns, with the reason behind --verbose, when AMSI cannot run", async () => {
		const check = await amsiCheck({
			state: "unavailable",
			kind: "constrained_language",
			reason: "PowerShell runs in ConstrainedLanguage mode",
			...base,
		});
		expect(check).toMatchObject({ status: "warn" });
		expect(check?.summary).toContain("NOT scanned by AMSI");
		expect(check?.notes).toEqual(["PowerShell runs in ConstrainedLanguage mode"]);
	});

	it("warns on the slow PowerShell fallback and is ok with the native backend", async () => {
		expect(
			await amsiCheck({ state: "available", backend: "powershell-persistent", ...base }),
		).toMatchObject({ status: "warn" });
		expect(await amsiCheck({ state: "available", backend: "native-koffi", ...base })).toMatchObject(
			{ status: "ok" },
		);
	});
});

describe("local time", () => {
	it("prints a stored UTC time in the machine's zone with its offset", () => {
		vi.stubEnv("TZ", "Europe/Istanbul");
		expect(localTime("2026-10-13T14:29:33.327Z")).toBe("2026-10-13 17:29:33 (UTC+3)");
		vi.stubEnv("TZ", "UTC");
		expect(localTime("2026-10-13T14:29:33.327Z")).toBe("2026-10-13 14:29:33 (UTC)");
		expect(localTime("not a date")).toBe("not a date");
	});
});
