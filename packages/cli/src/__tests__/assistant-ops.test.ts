/**
 * Setup Assistant operations against a scratch HOME and fakes: detection,
 * setup (plain `aidr setup --host` semantics), verify, status, device-code
 * enrollment (fake control plane), the installer's enrollment handoff file,
 * Browser Guard links and the browser launcher.
 */
import { EventEmitter } from "node:events";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ControlPlaneConfigSchema, type VerifiedCustomerPacket } from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createEnrollment,
	normalizeEndpoint,
	readPendingEnrollment,
} from "../assistant/enrollment.js";
import { browserLauncher, openInBrowser } from "../assistant/open-browser.js";
import {
	browserGuardLinks,
	createLocalOps,
	dashboardFor,
	hostOutcome,
	safeHttpsUrl,
} from "../assistant/operations.js";
import type { SetupEvent } from "../assistant/types.js";
import { getConfig } from "../utils/config-manager.js";
import type { HostInstallResult } from "../utils/connector-install.js";

const POSIX = process.platform !== "win32";
const t0 = Date.UTC(2026, 9, 13, 12, 0);
let home: string;

beforeEach(() => {
	// config-manager writes ~/.singularity-aidr of this file's isolated HOME.
	home = process.env.HOME as string;
	// Never wipe a real profile: refuse unless HOME is a temporary directory.
	if (!home || !resolve(home).startsWith(resolve(tmpdir()))) {
		throw new Error(`refusing to clear a non-temporary HOME: ${home}`);
	}
	rmSync(join(home, ".singularity-aidr"), { recursive: true, force: true });
	rmSync(join(home, ".config"), { recursive: true, force: true });
	rmSync(join(home, ".claude"), { recursive: true, force: true });
});

afterEach(() => {
	vi.restoreAllMocks();
});

function quiet() {
	vi.spyOn(console, "error").mockImplementation(() => {});
	vi.spyOn(console, "log").mockImplementation(() => {});
	vi.spyOn(console, "warn").mockImplementation(() => {});
}

function opencodePresent() {
	mkdirSync(join(home, ".config", "opencode"), { recursive: true });
	writeFileSync(join(home, ".config", "opencode", "opencode.json"), "{}\n");
}

const env = (): NodeJS.ProcessEnv => ({ HOME: home, PATH: "/nonexistent" });

describe("detect", () => {
	it("lists all six tools with the status measurement and preview flags", async () => {
		opencodePresent();
		const tools = await createLocalOps({ home, env: env() }).detect();
		expect(tools.map((tool) => tool.id)).toEqual([
			"claude-code",
			"cursor",
			"vscode",
			"openclaw",
			"opencode",
			"codex",
		]);
		expect(tools.find((tool) => tool.id === "opencode")?.state).toBe(
			"runtime_present_not_installed",
		);
		expect(tools.find((tool) => tool.id === "codex")?.state).toBe("not_detected");
		expect(tools.filter((tool) => tool.preview).map((tool) => tool.id)).toEqual([
			"cursor",
			"vscode",
		]);
	});
});

describe("setup", () => {
	it("registers the selected tool like 'aidr setup --host', streams progress and records the restart", async () => {
		quiet();
		opencodePresent();
		const ops = createLocalOps({ home, env: env(), standaloneRoot: null, commercial: false });
		const events: SetupEvent[] = [];
		const summary = await ops.setup(["opencode"], (event) => events.push(event));
		expect(summary.failure).toBeUndefined();
		expect(summary.rules).toBeGreaterThan(0);
		expect(events.map((event) => event.type)).toEqual(["rules", "host-start", "host-done"]);
		expect(summary.hosts).toHaveLength(1);
		expect(summary.hosts[0]).toMatchObject({ id: "opencode", outcome: "restart" });
		expect(summary.ok).toBe(true);
		const opencode = JSON.parse(
			readFileSync(join(home, ".config", "opencode", "opencode.json"), "utf8"),
		);
		expect(opencode.plugin).toContain("@singularityrd/aidr-opencode");
		// The same ledger and config plain setup writes.
		expect(
			JSON.parse(readFileSync(join(home, ".singularity-aidr", "last-setup.json"), "utf8"))
				.registered,
		).toEqual(["opencode"]);
		expect(existsSync(join(home, ".singularity-aidr", "config.json"))).toBe(true);
		// A rerun changes nothing and says so.
		const again = await ops.setup(["opencode"], () => {});
		expect(again.hosts[0].outcome).toBe("protected");
	});

	it("refuses unknown or empty host selections", async () => {
		const ops = createLocalOps({ home, env: env(), standaloneRoot: null });
		await expect(ops.setup(["opencode", "rm -rf"], () => {})).rejects.toThrow(/Unknown host/);
		await expect(ops.setup([], () => {})).rejects.toThrow(/Unknown host/);
	});

	it("maps connector results to protected / restart / manual / failed", () => {
		const entry = (action: string, state: string, followUp: string[] = []) =>
			({
				host: "codex",
				label: "Codex",
				action,
				detail: "",
				changes: [],
				followUp,
				state,
			}) as HostInstallResult;
		expect(hostOutcome(entry("already_installed", "installed"))).toBe("protected");
		expect(hostOutcome(entry("installed", "installed"))).toBe("restart");
		expect(hostOutcome(entry("updated", "installed"))).toBe("restart");
		expect(hostOutcome(entry("manual", "runtime_present_not_installed", ["  run x"]))).toBe(
			"manual",
		);
		expect(hostOutcome(entry("failed", "runtime_present_not_installed"))).toBe("failed");
		expect(hostOutcome(entry("installed", "runtime_present_not_installed"))).toBe("failed");
	});
});

describe("verify and status", () => {
	it("passes the canary through a registered hook and reports in-process tools as skip", async () => {
		quiet();
		opencodePresent();
		mkdirSync(join(home, ".claude"), { recursive: true });
		writeFileSync(
			join(home, ".claude", "settings.json"),
			JSON.stringify({
				hooks: {
					PreToolUse: [
						{ hooks: [{ type: "command", command: "/opt/aidr/bin/aidr hook pre-tool-use" }] },
					],
				},
			}),
		);
		const ops = createLocalOps({ home, env: env(), standaloneRoot: null, commercial: false });
		await ops.setup(["opencode"], () => {});
		const run = vi.fn((_command: string, payload: Record<string, unknown>) => {
			const command = (payload.tool_input as { command: string }).command;
			return command === "ls"
				? { decision: "allow" as const, detail: "allowed" }
				: { decision: "deny" as const, detail: "denied" };
		});
		const fakeOps = createLocalOps({ home, env: env(), verifyRun: run as never });
		const report = await fakeOps.verify();
		const byId = Object.fromEntries(report.hosts.map((host) => [host.id, host.outcome]));
		expect(byId["claude-code"]).toBe("pass");
		expect(byId.opencode).toBe("skip");
		expect(byId.codex).toBe("not_registered");
		expect(run).toHaveBeenCalledTimes(2);

		const status = await fakeOps.status();
		expect(status.detection.ok).toBe(true);
		expect(status.restart).toContain("OpenCode");
		expect(status.protected).toContain("Claude Code");
	});

	it("reports a hook that lets the canary through as fail", async () => {
		mkdirSync(join(home, ".claude"), { recursive: true });
		writeFileSync(
			join(home, ".claude", "settings.json"),
			JSON.stringify({
				hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "aidr-hook" }] }] },
			}),
		);
		const run = () => ({ decision: "allow" as const, detail: "allowed" });
		const report = await createLocalOps({ home, env: env(), verifyRun: run as never }).verify();
		expect(report.hosts.find((host) => host.id === "claude-code")?.outcome).toBe("fail");
	});
});

// ── Enrollment ─────────────────────────────────────────────────────────

interface FakePlane {
	start: Record<string, unknown>;
	polls: Array<{ ok: boolean; status?: number; error?: string; body?: Record<string, unknown> }>;
	calls: string[];
}

function plane(overrides: Partial<FakePlane> = {}): FakePlane {
	return {
		start: {
			ok: true,
			body: {
				device_code: "dev-code",
				user_code: "ABCD-EFGH",
				verification_url: "https://aidr.example.com/verify?code=ABCD-EFGH",
				expires_at: new Date(Date.UTC(2026, 9, 13, 12, 10)).toISOString(),
				interval_seconds: 2,
			},
		},
		polls: [],
		calls: [],
		...overrides,
	};
}

function enrollOps(fake: FakePlane, clock: { now: number }, enrollOutcome = "enrolled") {
	const enroll = vi.fn(async () => ({ outcome: enrollOutcome }) as never);
	const ops = createLocalOps({
		home,
		env: env(),
		enrollment: {
			now: () => clock.now,
			installationId: async () => "iid-test",
			enroll,
			client: (config) => {
				fake.calls.push(`client ${config.endpoint} enabled=${config.enabled}`);
				return {
					deviceStart: async (payload) => {
						fake.calls.push(`start ${JSON.stringify(payload?.iid)}`);
						return fake.start as never;
					},
					devicePoll: async ({ device_code }) => {
						fake.calls.push(`poll ${device_code}`);
						return (fake.polls.shift() ?? {
							ok: true,
							body: { error: "authorization_pending" },
						}) as never;
					},
				};
			},
		},
	});
	return { ops, enroll };
}

describe("device-code enrollment", () => {
	it("shows the code, waits, then exchanges the token and records managed mode", async () => {
		quiet();
		const clock = { now: t0 };
		const fake = plane({
			polls: [
				{
					ok: true,
					body: { status: "pending", error: "authorization_pending", interval_seconds: 2 },
				},
				{ ok: true, body: { status: "approved", enrollment_token: "enroll-token-1" } },
			],
		});
		const { ops, enroll } = enrollOps(fake, clock);
		const waiting = await ops.enrollStart({
			endpoint: "https://aidr.example.com/",
			useInstallerToken: false,
		});
		expect(waiting).toMatchObject({
			phase: "waiting",
			endpoint: "https://aidr.example.com",
			userCode: "ABCD-EFGH",
			verificationUrl: "https://aidr.example.com/verify?code=ABCD-EFGH",
			interval: 2,
		});
		expect(fake.calls[0]).toBe("client https://aidr.example.com enabled=true");
		// Polling faster than the control plane asked does not reach it.
		clock.now += 500;
		expect((await ops.enrollPoll()).phase).toBe("waiting");
		expect(fake.calls.filter((call) => call.startsWith("poll"))).toHaveLength(0);
		clock.now += 2_000;
		expect((await ops.enrollPoll()).phase).toBe("waiting");
		clock.now += 2_000;
		const done = await ops.enrollPoll();
		expect(done).toEqual({ phase: "enrolled", endpoint: "https://aidr.example.com" });
		expect(enroll).toHaveBeenCalledTimes(1);
		const args = enroll.mock.calls[0] as unknown as [Record<string, unknown>];
		expect(args[0]).toMatchObject({ enrollmentToken: "enroll-token-1", iid: "iid-test" });
		expect((args[0].config as { mode: string }).mode).toBe("managed");
		const config = getConfig() as unknown as {
			mode: string;
			control_plane: { endpoint: string; enabled: boolean };
		};
		expect(config.mode).toBe("managed");
		expect(config.control_plane).toMatchObject({
			endpoint: "https://aidr.example.com",
			enabled: true,
		});
	});

	it("refuses an address that is not https, has credentials or a query", async () => {
		const { ops } = enrollOps(plane(), { now: t0 });
		for (const endpoint of [
			"http://aidr.example.com",
			"https://user:pw@aidr.example.com",
			"https://aidr.example.com/?x=1",
			"javascript:alert(1)",
			"",
		]) {
			const view = await ops.enrollStart({ endpoint, useInstallerToken: false });
			expect(view, endpoint).toMatchObject({ phase: "error", message: "company.urlInvalid" });
		}
		expect(normalizeEndpoint("http://127.0.0.1:9", false)).toBeNull();
		expect(normalizeEndpoint("http://127.0.0.1:9", true)).toBe("http://127.0.0.1:9");
	});

	it("explains unreachable, wrong and refusing servers, and never links an insecure page", async () => {
		const unreachable = enrollOps(plane({ start: { ok: false, error: "request_failed" } }), {
			now: t0,
		});
		expect(
			await unreachable.ops.enrollStart({
				endpoint: "https://a.example",
				useInstallerToken: false,
			}),
		).toMatchObject({
			phase: "error",
			message: "company.unreachable",
		});
		const notAidr = enrollOps(plane({ start: { ok: false, status: 404, error: "http_error" } }), {
			now: t0,
		});
		expect(
			await notAidr.ops.enrollStart({ endpoint: "https://a.example", useInstallerToken: false }),
		).toMatchObject({
			message: "company.notAidr",
		});
		const insecure = plane();
		(insecure.start.body as Record<string, unknown>).verification_url =
			"http://phish.example/verify";
		expect(
			await enrollOps(insecure, { now: t0 }).ops.enrollStart({
				endpoint: "https://a.example",
				useInstallerToken: false,
			}),
		).toMatchObject({ phase: "error", code: "insecure_verification_url" });
	});

	it("handles slow_down, denial, expiry and a consumed code", async () => {
		const clock = { now: t0 };
		const fake = plane({
			polls: [
				{ ok: false, status: 400, error: "slow_down", body: { interval_seconds: 7 } },
				{ ok: false, status: 401, error: "device_code_invalid" },
			],
		});
		const { ops } = enrollOps(fake, clock);
		await ops.enrollStart({ endpoint: "https://a.example", useInstallerToken: false });
		clock.now += 3_000;
		expect(await ops.enrollPoll()).toMatchObject({ phase: "waiting", interval: 7 });
		clock.now += 7_000;
		expect(await ops.enrollPoll()).toMatchObject({ phase: "denied", message: "company.denied" });

		const late = enrollOps(plane(), clock);
		await late.ops.enrollStart({ endpoint: "https://a.example", useInstallerToken: false });
		clock.now = t0 + 11 * 60_000;
		expect(await late.ops.enrollPoll()).toMatchObject({ phase: "expired" });

		const consumedClock = { now: t0 };
		const consumed = enrollOps(
			plane({ polls: [{ ok: false, status: 409, error: "already_exchanged" }] }),
			consumedClock,
		);
		await consumed.ops.enrollStart({ endpoint: "https://a.example", useInstallerToken: false });
		consumedClock.now += 3_000;
		expect(await consumed.ops.enrollPoll()).toMatchObject({
			phase: "repair",
			message: "company.repair",
		});
		expect(await consumed.ops.enrollCancel()).toEqual({ phase: "idle" });
	});

	it("does not start while an earlier issuance is unsettled, and reports a repair after the exchange", async () => {
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		writeFileSync(join(home, ".singularity-aidr", "managed.json.enrollment-pending"), "{}");
		const fake = plane();
		const blocked = enrollOps(fake, { now: t0 });
		expect(
			await blocked.ops.enrollStart({ endpoint: "https://a.example", useInstallerToken: false }),
		).toMatchObject({
			phase: "repair",
		});
		expect(fake.calls.some((call) => call.startsWith("start"))).toBe(false);
		rmSync(join(home, ".singularity-aidr", "managed.json.enrollment-pending"));

		const clock = { now: t0 };
		const repair = enrollOps(
			plane({ polls: [{ ok: true, body: { enrollment_token: "tok-12345678" } }] }),
			clock,
			"repair",
		);
		await repair.ops.enrollStart({ endpoint: "https://a.example", useInstallerToken: false });
		clock.now += 3_000;
		expect(await repair.ops.enrollPoll()).toMatchObject({ phase: "repair" });
		expect(getConfig()).toBeNull();
	});
});

describe("enrollment bookkeeping", () => {
	it("says so when the credential was saved but the configuration could not be written", async () => {
		const clock = { now: t0 };
		const enrollment = createEnrollment({
			home,
			now: () => clock.now,
			installationId: async () => "iid-test",
			enroll: (async () => ({ outcome: "enrolled" })) as never,
			persist: async () => {
				throw new Error("disk full");
			},
			client: () => ({
				deviceStart: async () => plane().start as never,
				devicePoll: async () => ({ ok: true, body: { enrollment_token: "tok-12345678" } }) as never,
			}),
		});
		await enrollment.start({ endpoint: "https://a.example", useInstallerToken: false });
		clock.now += 3_000;
		expect(await enrollment.poll()).toMatchObject({ phase: "error", code: "config_write_failed" });
	});
});

describe("the installer's pending enrollment file", () => {
	// The Windows installer's handoff (utils/installer-enrollment.ts); assembled at
	// runtime so no credential-shaped literal sits in the source.
	const PENDING_ENROLLMENT_FILE = "installer-enrollment.json";
	const CODE = ["aidr", "enroll", "A".repeat(43)].join("_");
	function installerDocument(content: {
		control_plane_url?: string;
		enrollment_token?: string;
	}): Record<string, string> {
		return {
			format: "aidr-installer-enrollment/1",
			control_plane_url: content.control_plane_url ?? "",
			enrollment_code:
				content.enrollment_token === "installer-token-123"
					? CODE
					: (content.enrollment_token ?? ""),
			created_at: new Date().toISOString(),
		};
	}
	function writePending(content: unknown, mode = 0o600): string {
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		const path = join(home, ".singularity-aidr", PENDING_ENROLLMENT_FILE);
		const document =
			typeof content === "string" ? content : JSON.stringify(installerDocument(content as never));
		writeFileSync(path, document, { mode });
		chmodSync(path, mode);
		return path;
	}

	it("pre-fills the company address from a private, valid file", async () => {
		writePending({ schema_version: 1, control_plane_url: "https://aidr.corp.example/" });
		expect(readPendingEnrollment(home)).toMatchObject({
			pending: { endpoint: "https://aidr.corp.example", hasToken: false },
			ignored: false,
		});
		const state = await createLocalOps({ home, env: env() }).state();
		expect(state.pending).toEqual({ endpoint: "https://aidr.corp.example", hasToken: false });
		expect(JSON.stringify(state)).not.toContain(home);
		expect(state.dashboard).toBe("https://aidr.corp.example");
	});

	// AIDR-SKIP: AIDR-063 qa-owner - group/world-readable mode bits and file symlinks are POSIX semantics; Windows ACLs are covered by the private-file helper tests
	it.skipIf(!POSIX)(
		"ignores a file other users can read, a link, bad JSON or an insecure address",
		() => {
			writePending({ schema_version: 1, control_plane_url: "https://aidr.corp.example" }, 0o644);
			expect(readPendingEnrollment(home)).toEqual({ pending: null, ignored: true });
			const target = mkdtempSync(join(tmpdir(), "aidr-pending-"));
			const real = join(target, "p.json");
			writeFileSync(
				real,
				JSON.stringify(installerDocument({ control_plane_url: "https://x.example" })),
				{ mode: 0o600 },
			);
			rmSync(join(home, ".singularity-aidr", PENDING_ENROLLMENT_FILE));
			symlinkSync(real, join(home, ".singularity-aidr", PENDING_ENROLLMENT_FILE));
			expect(readPendingEnrollment(home).ignored).toBe(true);
			rmSync(join(home, ".singularity-aidr", PENDING_ENROLLMENT_FILE));
			writePending("{not json");
			expect(readPendingEnrollment(home).ignored).toBe(true);
			writePending({ schema_version: 1, control_plane_url: "http://aidr.corp.example" });
			expect(readPendingEnrollment(home).ignored).toBe(true);
			writePending({
				schema_version: 1,
				control_plane_url: "https://aidr.corp.example",
				enrollment_token: "x y",
			});
			expect(readPendingEnrollment(home).ignored).toBe(true);
			rmSync(target, { recursive: true, force: true });
		},
	);

	it("exchanges the installer's token directly and consumes the file", async () => {
		quiet();
		const path = writePending({
			schema_version: 1,
			control_plane_url: "https://aidr.corp.example",
			enrollment_token: "installer-token-123",
		});
		const fake = plane();
		const { ops, enroll } = enrollOps(fake, { now: t0 });
		const state = await ops.state();
		expect(state.pending).toEqual({ endpoint: "https://aidr.corp.example", hasToken: true });
		expect(JSON.stringify(state)).not.toContain(CODE);
		const view = await ops.enrollStart({
			endpoint: "https://aidr.corp.example",
			useInstallerToken: true,
		});
		expect(view).toEqual({ phase: "enrolled", endpoint: "https://aidr.corp.example" });
		expect(
			(enroll.mock.calls[0] as unknown as [{ enrollmentToken: string }])[0].enrollmentToken,
		).toBe(CODE);
		expect(fake.calls.some((call) => call.startsWith("start"))).toBe(false);
		expect(existsSync(path)).toBe(false);
	});

	it("will not use the installer token for a different address", async () => {
		writePending({
			schema_version: 1,
			control_plane_url: "https://aidr.corp.example",
			enrollment_token: "installer-token-123",
		});
		const { ops, enroll } = enrollOps(plane(), { now: t0 });
		expect(
			await ops.enrollStart({ endpoint: "https://evil.example", useInstallerToken: true }),
		).toMatchObject({
			phase: "error",
			code: "no_installer_token",
		});
		expect(enroll).not.toHaveBeenCalled();
	});
});

describe("Browser Guard links and dashboard", () => {
	it("uses the dashboard's store variables, https only, else the Download page", () => {
		const links = browserGuardLinks(
			{
				VITE_BROWSER_GUARD_CHROME_URL: "https://chromewebstore.google.com/detail/x",
				VITE_BROWSER_GUARD_EDGE_URL: "http://insecure.example",
				VITE_BROWSER_GUARD_FIREFOX_URL: "javascript:alert(1)",
			},
			"https://aidr.corp.example",
		);
		expect(links).toEqual({
			chrome: "https://chromewebstore.google.com/detail/x",
			edge: null,
			firefox: null,
			downloads: "https://aidr.corp.example/downloads",
		});
		expect(safeHttpsUrl("https://u:p@x.example")).toBeNull();
		expect(dashboardFor(undefined)).toBe("https://aidr.singularityrd.com");
		expect(dashboardFor("https://abc.supabase.co/functions/v1")).toBe(
			"https://aidr.singularityrd.com",
		);
		expect(dashboardFor("https://aidr.corp.example/v1")).toBe("https://aidr.corp.example");
	});

	it("serves the CLI locale in the state", async () => {
		const state = await createLocalOps({ home, env: env() }).state();
		expect(state.locale).toBe("en");
		expect(state.company).toBeNull();
		expect(state.browserGuard.downloads).toBe("https://aidr.singularityrd.com/downloads");
		expect(ControlPlaneConfigSchema).toBeDefined();
	});
});

describe("browser launcher", () => {
	const url = `http://127.0.0.1:43210/#t=${"a".repeat(64)}`;

	it("uses xdg-open on Linux and explorer.exe on Windows, as an argument vector", () => {
		expect(browserLauncher(url, "linux")).toEqual({ command: "xdg-open", args: [url] });
		const windows = browserLauncher(url, "win32", { SystemRoot: "C:\\Windows" });
		expect(windows?.command).toMatch(/explorer\.exe$/u);
		expect(windows?.args).toEqual([url]);
		expect(browserLauncher(url, "darwin")).toBeNull();
	});

	it("refuses anything but its own loopback address", () => {
		for (const bad of [
			"http://127.0.0.1:1/ & calc.exe",
			"http://127.0.0.1:1/#t=abc;rm -rf ~",
			"https://evil.example/",
			"file:///etc/passwd",
			"http://localhost:1/",
		]) {
			expect(browserLauncher(bad, "linux"), bad).toBeNull();
		}
	});

	it("spawns detached without a shell and reports a missing launcher", async () => {
		const seen: Array<{ command: string; args: string[]; options: Record<string, unknown> }> = [];
		const spawner = (command: string, args: string[], options: Record<string, unknown>) => {
			seen.push({ command, args, options });
			const child = new EventEmitter() as EventEmitter & { unref: () => void };
			child.unref = () => {};
			setImmediate(() => child.emit("spawn"));
			return child as never;
		};
		expect(await openInBrowser(url, { platform: "linux", spawner: spawner as never })).toBeNull();
		expect(seen[0]).toMatchObject({ command: "xdg-open", args: [url] });
		expect(seen[0].options).toMatchObject({ shell: false, detached: true, stdio: "ignore" });
		const failing = (_c: string, _a: string[], _o: unknown) => {
			const child = new EventEmitter() as EventEmitter & { unref: () => void };
			child.unref = () => {};
			setImmediate(() => child.emit("error", new Error("spawn xdg-open ENOENT")));
			return child as never;
		};
		expect(await openInBrowser(url, { platform: "linux", spawner: failing as never })).toMatch(
			/ENOENT/,
		);
	});
});

describe("the customer packet's company address", () => {
	const packet = {
		customerId: "bilgem",
		packetId: "PKT-BILGEM-1",
		controlPlaneUrl: "https://aidr.bilgem.example.tr",
	} as unknown as VerifiedCustomerPacket;

	it("pre-fills the address (no code) when the installer left no file", async () => {
		const ops = createLocalOps({ home, env: env(), enrollment: { customerPacket: () => packet } });
		const state = await ops.state();
		expect(state.pending).toEqual({ endpoint: "https://aidr.bilgem.example.tr", hasToken: false });
		expect(
			await ops.enrollStart({
				endpoint: "https://aidr.bilgem.example.tr",
				useInstallerToken: true,
			}),
		).toMatchObject({ phase: "error", code: "no_installer_token" });
	});

	it("loses to the installer's own file", async () => {
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		const path = join(home, ".singularity-aidr", "installer-enrollment.json");
		writeFileSync(
			path,
			JSON.stringify({
				format: "aidr-installer-enrollment/1",
				control_plane_url: "https://aidr.corp.example",
				enrollment_code: "",
				created_at: new Date().toISOString(),
			}),
			{ mode: 0o600 },
		);
		chmodSync(path, 0o600);
		const ops = createLocalOps({ home, env: env(), enrollment: { customerPacket: () => packet } });
		expect((await ops.state()).pending?.endpoint).toBe("https://aidr.corp.example");
	});

	it("shows nothing for a refused or absent packet", async () => {
		const ops = createLocalOps({ home, env: env(), enrollment: { customerPacket: () => null } });
		expect((await ops.state()).pending).toBeNull();
	});
});
