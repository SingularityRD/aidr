import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AmsiClient } from "../clients/amsi.js";
import { DetectionLegUnavailableError } from "../detection-leg.js";
import { evaluateToolCall } from "../evaluator.js";
import { extractFromBash } from "../extractors.js";
import { PackageChecker } from "../package-checker.js";
import type { PackageCheckResult } from "../types.js";

// The AMSI leg only runs on a Windows/WSL host. The cases below are about what
// the evaluator does when the leg is enabled and cannot run, so it is forced on
// regardless of the host executing the suite. The real AmsiClient is kept (by
// spreading the original module) so those failures exercise the real client.
vi.mock("../clients/amsi.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../clients/amsi.js")>()),
	isAmsiSupported: () => true,
}));

let root: string;
let configPath: string;
let previousHome: string | undefined;
let previousUserProfile: string | undefined;

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-package-unavailable-"));
	configPath = join(root, "config.json");
	previousHome = process.env.HOME;
	previousUserProfile = process.env.USERPROFILE;
	process.env.HOME = root;
	process.env.USERPROFILE = root;
	await writeConfig(true);
});

afterEach(async () => {
	vi.restoreAllMocks();
	if (previousHome === undefined) delete process.env.HOME;
	else process.env.HOME = previousHome;
	if (previousUserProfile === undefined) delete process.env.USERPROFILE;
	else process.env.USERPROFILE = previousUserProfile;
	await rm(root, { recursive: true, force: true });
});

async function writeConfig(
	packageCheckEnabled: boolean,
	mode = "local",
	amsiCheckEnabled = false,
): Promise<void> {
	await writeFile(
		configPath,
		JSON.stringify({
			mode,
			heuristics_enabled: false,
			package_check: { enabled: packageCheckEnabled, timeout_seconds: 0.1 },
			file_check: { enabled: false },
			url_check: { enabled: false },
			amsi_check: { enabled: amsiCheckEnabled },
			cache: { enabled: false },
			logging: { enabled: false },
		}),
		"utf8",
	);
}

function request(command: string) {
	return {
		sessionId: "package-check-unavailable",
		toolName: "Bash",
		toolInput: { command },
		artifacts: extractFromBash(command),
	};
}

/** A request whose only artifact is a URL, so the URL reputation leg decides. */
function urlRequest(url = "https://unlisted.example/payload.sh") {
	return {
		sessionId: "url-leg-unavailable",
		toolName: "WebFetch",
		toolInput: { url },
		artifacts: [{ type: "url" as const, value: url }],
	};
}

/** The shared config, with the URL reputation leg enabled instead of disabled. */
async function writeUrlCheckConfig(): Promise<void> {
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			heuristics_enabled: false,
			package_check: { enabled: false },
			file_check: { enabled: false },
			url_check: { enabled: true, timeout_seconds: 0.1 },
			amsi_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
		}),
		"utf8",
	);
}

describe("package check availability is fail-closed", () => {
	it("turns an unexpected checker exception into an explicit blocking review", async () => {
		vi.spyOn(PackageChecker.prototype, "checkPackages").mockRejectedValueOnce(
			new Error("simulated checker outage"),
		);

		const verdict = await evaluateToolCall(request("npm install left-pad"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "supply_chain",
			source: "package_check",
			severity: "warning",
		});
		expect(verdict.artifacts).toContain("left-pad");
		expect(verdict.reasons.join(" ")).toContain("unavailable");
		expect(verdict.reasons.join(" ")).toContain("NOT verified clean");
	});

	it("keeps a managed but unenrolled endpoint blocked pending review on checker outage", async () => {
		await writeConfig(true, "managed");
		vi.spyOn(PackageChecker.prototype, "checkPackages").mockRejectedValueOnce(
			new Error("simulated checker outage"),
		);

		const verdict = await evaluateToolCall(request("npm install managed-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "supply_chain",
			source: "package_check",
		});
		expect(verdict.reasons.join(" ")).toContain("NOT verified clean");
	});

	it("marks only packages omitted by a partial checker result as unavailable", async () => {
		const clean: PackageCheckResult = {
			packageName: "known-good",
			registry: "npm",
			verdict: "clean",
			confidence: 1,
			details: "verified",
		};
		vi.spyOn(PackageChecker.prototype, "checkPackages").mockResolvedValueOnce([clean]);

		const verdict = await evaluateToolCall(request("npm install known-good unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict.decision).toBe("ask");
		expect(verdict.artifacts).toEqual(["unchecked-package"]);
		expect(verdict.reasons.join(" ")).toContain("unchecked-package");
		expect(verdict.reasons.join(" ")).not.toContain("known-good");
	});

	it("keeps a completed clean local check as allow", async () => {
		vi.spyOn(PackageChecker.prototype, "checkPackages").mockResolvedValueOnce([
			{
				packageName: "known-good",
				registry: "npm",
				verdict: "clean",
				confidence: 1,
				details: "verified",
			},
		]);

		const verdict = await evaluateToolCall(request("npm install known-good"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict.decision).toBe("allow");
		expect(verdict.source).toBe("none");
	});

	it("does not invoke or degrade a package leg disabled by the operator", async () => {
		await writeConfig(false);
		const checker = vi.spyOn(PackageChecker.prototype, "checkPackages");

		const verdict = await evaluateToolCall(request("npm install unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(checker).not.toHaveBeenCalled();
		expect(verdict.decision).toBe("allow");
	});

	it("turns a URL reputation outage into an explicit blocking review when no signed feed is configured", async () => {
		await writeUrlCheckConfig();
		// No signed feed is configured and the first-party endpoint is
		// unreachable. That failure used to be discarded unless a feed was
		// present, so a reputation outage produced a clean `allow` for URLs
		// nobody had checked.
		vi.spyOn(globalThis, "fetch").mockRejectedValue(
			new Error("simulated URL reputation endpoint outage"),
		);

		const verdict = await evaluateToolCall(urlRequest(), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "url_reputation_unavailable",
			source: "url_check",
			severity: "warning",
		});
		// Not a clean result, and the operator is told why.
		expect(verdict.reasons.join(" ")).toContain("NOT verified clean");
		expect(verdict.reasons.join(" ")).toContain("simulated URL reputation endpoint outage");
	});

	it("keeps a URL leg the operator disabled from degrading the verdict", async () => {
		// The shared config leaves `url_check` disabled. The leg must not run, and
		// a no-coverage answer - which would be a blocking review if the leg were
		// enabled - must not change the verdict of a switched-off leg.
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
			new Response(
				JSON.stringify({
					coverage: "none",
					answers: [
						{
							key: "https://unlisted.example/payload.sh",
							coverage: "no_data",
							result: {
								success: {
									classification: { result: { unknown: { reason: "no_reputation_row" } } },
									flags: [],
									coverage: "no_data",
								},
							},
						},
					],
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			),
		);

		const verdict = await evaluateToolCall(urlRequest(), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(fetchSpy.mock.calls.some(([input]) => String(input).includes("url-check"))).toBe(false);
		expect(verdict.decision).toBe("allow");
		expect(verdict.category).not.toBe("url_reputation_unavailable");
		expect(verdict.source).not.toBe("url_check");
	});
});

describe("AMSI leg availability is fail-closed", () => {
	it("turns an AMSI backend exception into an explicit blocking review", async () => {
		await writeConfig(false, "local", true);
		// The shape a dead Windows AMSI backend takes: the client cannot run and
		// reports a typed unavailable-leg failure instead of answering null.
		vi.spyOn(AmsiClient.prototype, "init").mockRejectedValueOnce(
			new DetectionLegUnavailableError("amsi", "simulated AMSI backend outage"),
		);

		const verdict = await evaluateToolCall(request("npm install left-pad"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "amsi_unavailable",
			source: "amsi",
			severity: "warning",
		});
		expect(verdict.decision).not.toBe("allow");
		expect(verdict.reasons.join(" ")).toContain("NOT scanned");
	});

	it("turns a host with no usable AMSI backend into an explicit blocking review", async () => {
		await writeConfig(false, "local", true);
		// init() completes but establishes no backend: koffi and the PowerShell
		// fallback both failed. Before this guard the call was allowed anyway.
		vi.spyOn(AmsiClient.prototype, "init").mockResolvedValue(undefined);

		const verdict = await evaluateToolCall(request("npm install left-pad"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "amsi_unavailable",
			source: "amsi",
		});
	});

	it("turns an AMSI scan that produced no result into an explicit blocking review", async () => {
		await writeConfig(false, "local", true);
		vi.spyOn(AmsiClient.prototype, "init").mockResolvedValue(undefined);
		vi.spyOn(AmsiClient.prototype, "isAvailable", "get").mockReturnValue(true);
		vi.spyOn(AmsiClient.prototype, "scanString").mockResolvedValue(null);

		const verdict = await evaluateToolCall(request("npm install left-pad"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "amsi_unavailable",
			source: "amsi",
		});
		expect(verdict.decision).not.toBe("allow");
	});

	it("keeps an AMSI leg the operator disabled from degrading the verdict", async () => {
		await writeConfig(false, "local", false);
		const init = vi.spyOn(AmsiClient.prototype, "init");
		const scan = vi.spyOn(AmsiClient.prototype, "scanString");

		const verdict = await evaluateToolCall(request("npm install left-pad"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		// An explicit operator choice is not a degradation: the leg must not even
		// be attempted, and the verdict must stay clean.
		expect(init).not.toHaveBeenCalled();
		expect(scan).not.toHaveBeenCalled();
		expect(verdict).toMatchObject({ decision: "allow", source: "none" });
	});

	it("does not degrade a verdict when the enabled AMSI leg actually ran", async () => {
		await writeConfig(false, "local", true);
		vi.spyOn(AmsiClient.prototype, "init").mockResolvedValue(undefined);
		vi.spyOn(AmsiClient.prototype, "isAvailable", "get").mockReturnValue(true);
		vi.spyOn(AmsiClient.prototype, "scanString").mockResolvedValue({
			content: "npm install left-pad",
			contentName: "Bash:command",
			amsiResult: 0,
			isDetected: false,
			isBlockedByAdmin: false,
		});

		const verdict = await evaluateToolCall(request("npm install left-pad"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		// AMSI scanned the content and found nothing: that is a clean result, and
		// the guard must not fire on it.
		expect(verdict).toMatchObject({ decision: "allow", source: "none" });
	});
});
