import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VerdictCache } from "../cache.js";
import { AmsiClient } from "../clients/amsi.js";
import { DetectionLegUnavailableError } from "../detection-leg.js";
import { evaluateToolCall } from "../evaluator.js";
import { extractFromBash } from "../extractors.js";
import { PackageChecker } from "../package-checker.js";
import type { PackageCheckResult } from "../types.js";
import { VERSION } from "../version.js";

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
	uncheckedAction: "allow" | "ask" = "allow",
): Promise<void> {
	await writeFile(
		configPath,
		JSON.stringify({
			mode,
			heuristics_enabled: false,
			package_check: {
				enabled: packageCheckEnabled,
				timeout_seconds: 0.1,
				unchecked_action: uncheckedAction,
			},
			file_check: { enabled: false },
			url_check: { enabled: false, unchecked_action: uncheckedAction },
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

function manifestRequest(filePath: string, content: string) {
	return {
		sessionId: "unsupported-package-manifest",
		toolName: "Write",
		toolInput: { file_path: filePath, content },
		artifacts: [
			{ type: "file_path" as const, value: filePath },
			{ type: "content" as const, value: content, context: "write" },
		],
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
	it.each([
		"uv add requests",
		"uv sync",
		"poetry add requests",
		"pipenv install requests",
		"go get example.com/module",
	])(
		"requires review without registry calls for unsupported manager command %s",
		async (command) => {
			const fetch = vi.spyOn(globalThis, "fetch");

			const verdict = await evaluateToolCall(request(command), {
				configPath,
				threatsDir: root,
				allowlistsDir: root,
			});

			expect(fetch).not.toHaveBeenCalled();
			expect(verdict).toMatchObject({
				decision: "ask",
				category: "supply_chain",
				source: "package_check",
			});
			expect(verdict.reasons.join(" ")).toContain("NOT verified clean");
		},
	);

	it("requires review when an unsupported ecosystem manifest is written", async () => {
		const fetch = vi.spyOn(globalThis, "fetch");

		const verdict = await evaluateToolCall(
			manifestRequest("services/api/pyproject.toml", "[project]\ndependencies = ['requests']"),
			{ configPath, threatsDir: root, allowlistsDir: root },
		);

		expect(fetch).not.toHaveBeenCalled();
		expect(verdict).toMatchObject({
			decision: "ask",
			category: "supply_chain",
			source: "package_check",
		});
		expect(verdict.artifacts.join(" ")).toContain("pyproject.toml");
		expect(verdict.reasons.join(" ")).toContain("unsupported dependency manifest");
	});

	it.each([
		["registry timeout", () => Promise.reject(new Error("simulated timeout"))],
		[
			"malformed registry HTTP 200",
			() =>
				Promise.resolve(
					new Response(JSON.stringify({ "dist-tags": { latest: "1.0.0" }, versions: {} }), {
						status: 200,
					}),
				),
		],
	])("requires review after %s through the real checker", async (_case, response) => {
		vi.spyOn(globalThis, "fetch").mockImplementation(response);

		const verdict = await evaluateToolCall(request("npm install unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "supply_chain",
			source: "package_check",
		});
		expect(verdict.artifacts).toContain("unchecked-package");
		expect(verdict.reasons.join(" ")).toContain("unavailable");
	});

	it("rechecks when the package cache read fails instead of treating it as clean", async () => {
		vi.spyOn(VerdictCache.prototype, "getPackage").mockImplementation(() => {
			throw new Error("simulated cache failure");
		});
		const checker = vi.spyOn(PackageChecker.prototype, "checkPackages").mockResolvedValueOnce([
			{
				packageName: "unchecked-package",
				registry: "npm",
				verdict: "unknown",
				confidence: 0,
				details: "package was not verified clean",
			},
		]);

		const verdict = await evaluateToolCall(request("npm install unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(checker).toHaveBeenCalledOnce();
		expect(verdict).toMatchObject({ decision: "ask", source: "package_check" });
	});

	it("rechecks a malformed cached package row instead of throwing or trusting it", async () => {
		const cachePath = join(root, "malformed-package-cache.json");
		await writeFile(
			cachePath,
			JSON.stringify({
				urls: {},
				commands: {},
				packages: {
					"npm:unchecked-package": {
						verdict: "deny",
						severity: "critical",
						reasons: null,
						source: "package_check",
						checkedAt: new Date().toISOString(),
						expiresAt: "9999-12-31T23:59:59+00:00",
						aidrVersion: VERSION,
					},
				},
			}),
			"utf8",
		);
		await writeFile(
			configPath,
			JSON.stringify({
				mode: "local",
				heuristics_enabled: false,
				package_check: { enabled: true, timeout_seconds: 0.1 },
				file_check: { enabled: false },
				url_check: { enabled: false },
				amsi_check: { enabled: false },
				cache: { enabled: true, path: cachePath },
				logging: { enabled: false },
			}),
			"utf8",
		);
		vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("simulated registry outage"));

		const verdict = await evaluateToolCall(request("npm install unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "supply_chain",
			source: "package_check",
		});
		expect(verdict.reasons.join(" ")).toContain("unavailable");
	});

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

	it("marks malformed checker result rows unavailable instead of throwing", async () => {
		vi.spyOn(PackageChecker.prototype, "checkPackages").mockResolvedValueOnce([
			null,
		] as unknown as PackageCheckResult[]);

		const verdict = await evaluateToolCall(request("npm install unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "ask",
			category: "supply_chain",
			source: "package_check",
		});
		expect(verdict.artifacts).toContain("unchecked-package");
		expect(verdict.reasons.join(" ")).toContain("NOT verified clean");
	});

	it.each([
		["clean then malicious", false],
		["malicious then clean", true],
	])("preserves a malicious duplicate when rows are %s", async (_order, maliciousFirst) => {
		const clean: PackageCheckResult = {
			packageName: "unchecked-package",
			registry: "npm",
			verdict: "clean",
			confidence: 1,
			details: "verified clean",
		};
		const malicious: PackageCheckResult = {
			packageName: "unchecked-package",
			registry: "npm",
			verdict: "malicious",
			confidence: 1,
			details: "malicious duplicate",
		};
		vi.spyOn(PackageChecker.prototype, "checkPackages").mockResolvedValueOnce(
			maliciousFirst ? [malicious, clean] : [clean, malicious],
		);

		const verdict = await evaluateToolCall(request("npm install unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(verdict).toMatchObject({
			decision: "deny",
			category: "supply_chain",
			source: "package_check",
		});
		expect(verdict.artifacts).toContain("unchecked-package");
		expect(verdict.reasons.join(" ")).toContain("malicious duplicate");
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

	it("propagates the explicit loopback HTTP opt-in to package file checks", async () => {
		await writeFile(
			configPath,
			JSON.stringify({
				mode: "local",
				heuristics_enabled: false,
				package_check: { enabled: true, timeout_seconds: 0.1 },
				file_check: {
					enabled: true,
					endpoint: "http://127.0.0.1:3000/file-check",
					allow_insecure_loopback: true,
				},
				url_check: { enabled: false },
				amsi_check: { enabled: false },
				cache: { enabled: false },
				logging: { enabled: false },
			}),
			"utf8",
		);
		const checker = vi.spyOn(PackageChecker.prototype, "checkPackages").mockResolvedValueOnce([
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

		expect(checker).toHaveBeenCalledOnce();
		expect(verdict.decision).toBe("allow");
	});

	it("does not send package names when disabled and records them as not checked, never clean", async () => {
		await writeConfig(false);
		const checker = vi.spyOn(PackageChecker.prototype, "checkPackages");
		const fetch = vi.spyOn(globalThis, "fetch");

		const verdict = await evaluateToolCall(request("npm install unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(checker).not.toHaveBeenCalled();
		expect(fetch).not.toHaveBeenCalled();
		// The default `unchecked_action: allow` (GA audit PRD-2/CON-8): a disabled
		// leg is coverage information, not a block, and it is never labelled clean.
		expect(verdict).toMatchObject({
			decision: "allow",
			category: "reputation_not_checked",
			source: "local_only",
		});
		expect(verdict.reasons.join(" ")).toContain("Not checked by a reputation service");
		expect(verdict.reasons.join(" ")).toContain("not a clean reputation result");
	});

	it("does not send package names when disabled and requires review with unchecked_action ask", async () => {
		await writeConfig(false, "local", false, "ask");
		const checker = vi.spyOn(PackageChecker.prototype, "checkPackages");
		const fetch = vi.spyOn(globalThis, "fetch");

		const verdict = await evaluateToolCall(request("npm install unchecked-package"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(checker).not.toHaveBeenCalled();
		expect(fetch).not.toHaveBeenCalled();
		expect(verdict).toMatchObject({
			decision: "ask",
			category: "supply_chain",
			source: "package_check",
		});
		expect(verdict.reasons.join(" ")).toContain("disabled to avoid sharing package names");
		expect(verdict.reasons.join(" ")).toContain("NOT verified clean");
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

	it("records a URL as not checked when URL reputation is disabled, without sending it", async () => {
		await writeConfig(false);
		const fetchSpy = vi.spyOn(globalThis, "fetch");

		const verdict = await evaluateToolCall(urlRequest(), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		expect(fetchSpy).not.toHaveBeenCalled();
		expect(verdict).toMatchObject({
			decision: "allow",
			category: "reputation_not_checked",
			source: "local_only",
			artifacts: ["https://unlisted.example/payload.sh"],
		});
		expect(verdict.reasons.join(" ")).toContain("url_check is not enabled");
		expect(verdict.reasons.join(" ")).toContain("not a clean reputation result");
	});

	it("reports disabled URL reputation as unavailable with unchecked_action ask, without sending the URL", async () => {
		// `url_check.unchecked_action: ask` restores the strict behaviour: local
		// rules still run, and an unverified URL is held for review.
		await writeConfig(false, "local", false, "ask");
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
		expect(verdict).toMatchObject({
			decision: "ask",
			category: "url_reputation_unavailable",
			source: "url_check",
		});
		expect(verdict.reasons.join(" ")).toContain("NOT verified clean");
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

		const verdict = await evaluateToolCall(request("echo harmless"), {
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

		const verdict = await evaluateToolCall(request("echo harmless"), {
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

		const verdict = await evaluateToolCall(request("echo harmless"), {
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

		const verdict = await evaluateToolCall(request("echo harmless"), {
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
			content: "echo harmless",
			contentName: "Bash:command",
			amsiResult: 0,
			isDetected: false,
			isBlockedByAdmin: false,
		});

		const verdict = await evaluateToolCall(request("echo harmless"), {
			configPath,
			threatsDir: root,
			allowlistsDir: root,
		});

		// AMSI scanned the content and found nothing: that is a clean result, and
		// the guard must not fire on it.
		expect(verdict).toMatchObject({ decision: "allow", source: "none" });
	});
});
