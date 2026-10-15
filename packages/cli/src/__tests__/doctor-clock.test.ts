/**
 * `aidr doctor` compares the machine clock with the control plane's. Signed
 * licences (expiry and grace), approval tokens, enrollment codes and device
 * sessions are all time-checked, so a drifting endpoint clock shows up here
 * before it shows up as an unexplained rejection.
 */
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	clearOperatorApprovalKeyCache,
	type OperatorApprovalStoreOptions,
} from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	CLOCK_FAIL_SECONDS,
	CLOCK_WARN_SECONDS,
	formatDoctorReport,
	runDoctor,
	type ServerTimeSample,
} from "../commands/doctor.js";

let home: string;
let originalHome: string | undefined;
let store: OperatorApprovalStoreOptions;
let configPath: string;

const ENDPOINT = "https://aidr-api.customer.example";

function writeConfig(config: Record<string, unknown>): void {
	writeFileSync(configPath, JSON.stringify(config));
}

function managed(): void {
	writeConfig({ mode: "managed", control_plane: { enabled: true, endpoint: ENDPOINT } });
}

/** A server whose clock is `offsetSeconds` behind the local one (negative: ahead). */
function serverBehindBy(offsetSeconds: number, roundTripMs = 40) {
	const calls: string[] = [];
	const serverTime = async (endpoint: string): Promise<ServerTimeSample> => {
		calls.push(endpoint);
		const sentAt = 1_800_000_000_000;
		const receivedAt = sentAt + roundTripMs;
		return { sentAt, receivedAt, serverAt: sentAt + roundTripMs / 2 - offsetSeconds * 1_000 };
	};
	return { calls, serverTime };
}

async function clockCheck(serverTime?: (endpoint: string) => Promise<ServerTimeSample>) {
	const report = await runDoctor({
		configPath,
		connectors: () => [],
		operatorApprovals: store,
		loadDetectors: async () => ({}),
		agentEnvironment: () => ({
			schema_version: 1,
			scanned_at: "2026-10-14T00:00:00.000Z",
			hosts: [],
			findings: [],
			unreadable: [],
			scope: "test",
		}),
		...(serverTime ? { serverTime } : {}),
	});
	return { report, check: report.checks.find((c) => c.id === "clock") };
}

beforeEach(() => {
	originalHome = process.env.HOME;
	home = mkdtempSync(join(tmpdir(), "aidr-doctor-clock-"));
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true, mode: 0o700 });
	process.env.HOME = home;
	configPath = join(home, ".singularity-aidr", "config.json");
	clearOperatorApprovalKeyCache();
	const key = randomBytes(32);
	store = {
		path: join(home, ".singularity-aidr", "approvals.json"),
		keyProvider: { load: () => ({ key, location: "os-vault", store: "macos-keychain" }) },
	};
});

afterEach(() => {
	vi.unstubAllEnvs();
	clearOperatorApprovalKeyCache();
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(home, { recursive: true, force: true });
});

describe("doctor clock check", () => {
	it("makes no network call and adds no line in local mode", async () => {
		writeConfig({ mode: "local", control_plane: { endpoint: ENDPOINT } });
		const server = serverBehindBy(3_600);
		const { check } = await clockCheck(server.serverTime);
		expect(check).toBeUndefined();
		expect(server.calls).toEqual([]);
	});

	it("is ok when the clocks agree within the warning threshold", async () => {
		managed();
		const server = serverBehindBy(2);
		const { check } = await clockCheck(server.serverTime);
		expect(server.calls).toEqual([ENDPOINT]);
		expect(check?.status).toBe("ok");
		expect(check?.summary).toBe(`Clock: within ${CLOCK_WARN_SECONDS} s of the control plane.`);
		expect(check?.detail).toMatchObject({ state: "compared" });
	});

	it("treats an offset inside the Date header's resolution as in sync", async () => {
		managed();
		const { check } = await clockCheck(serverBehindBy(0.9).serverTime);
		expect(check?.detail).toMatchObject({ offset_ms: 0 });
	});

	it("warns on drift above the warning threshold and names the direction", async () => {
		managed();
		const { check, report } = await clockCheck(serverBehindBy(CLOCK_WARN_SECONDS + 30).serverTime);
		expect(check?.status).toBe("warn");
		expect(check?.summary).toContain(`${CLOCK_WARN_SECONDS + 30} s ahead of the control plane`);
		expect(report.checks.filter((c) => c.status === "fail").map((c) => c.id)).not.toContain(
			"clock",
		);
	});

	it("fails the doctor when the clock is further off than signed artifacts tolerate", async () => {
		managed();
		const { check, report } = await clockCheck(
			serverBehindBy(-(CLOCK_FAIL_SECONDS + 120)).serverTime,
		);
		expect(check?.status).toBe("fail");
		expect(check?.summary).toContain(`${CLOCK_FAIL_SECONDS + 120} s behind the control plane`);
		expect(check?.summary).toContain("NTP");
		expect(report.ok).toBe(false);
	});

	it("never reports an unreachable control plane or a missing Date header as a pass", async () => {
		managed();
		const unreachable = await clockCheck(async () => {
			throw new Error("connect ECONNREFUSED");
		});
		expect(unreachable.check?.status).toBe("warn");
		expect(unreachable.check?.summary).toContain("not a clean result");
		expect(unreachable.check?.summary).toContain("ECONNREFUSED");

		const noHeader = await clockCheck(async () => ({ sentAt: 1, receivedAt: 2, serverAt: null }));
		expect(noHeader.check?.status).toBe("warn");
		expect(noHeader.check?.detail).toMatchObject({ state: "no_date_header" });
	});

	it("speaks Turkish with AIDR_LOCALE=tr and explains why with --verbose", async () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		managed();
		const { report } = await clockCheck(serverBehindBy(-(CLOCK_FAIL_SECONDS + 1)).serverTime);
		const text = formatDoctorReport(report, true).join("\n");
		expect(text).toContain(`Saat kontrol sunucusundan ${CLOCK_FAIL_SECONDS + 1} sn geride`);
		expect(text).toContain("aynı NTP kaynağına");
	});
});
