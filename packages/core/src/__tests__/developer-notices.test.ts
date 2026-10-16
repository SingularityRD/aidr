/**
 * What the developer is told (D4, D6, D9, D10, D14): the first-run privacy
 * notice, AI tools AIDR does not protect, the false-positive report line and
 * support contact in block messages, and the OS-locale fallback.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { inspectAgentEnvironment } from "../agent-environment-posture.js";
import { buildRuntimeVerdictEntry } from "../audit-log.js";
import { formatBlockMessage } from "../block-message.js";
import {
	configuredSupportContact,
	safeDisplayUrl,
	setConfiguredSupportContact,
} from "../display-settings.js";
import { formatSessionStartMessage } from "../format.js";
import { resolveLocale } from "../i18n/index.js";
import { buildAgentPostureFindingEvents } from "../posture-events.js";
import {
	formatPrivacyNotice,
	privacyNoticeDigest,
	takeFirstRunPrivacyNotice,
} from "../privacy-notice.js";
import { type Config, ConfigSchema, type Verdict } from "../types.js";
import { detectUnprotectedAiTools } from "../unprotected-agents.js";

const deny: Verdict = {
	decision: "deny",
	category: "tool",
	confidence: 0.95,
	severity: "critical",
	source: "heuristic",
	artifacts: ["x"],
	matchedThreatId: "CLT-CMD-006",
	reasons: ["Recursive forced deletion from root"],
	ruleSeverity: "critical",
};
const ACTION_ID = "a1b2c3d4".repeat(8);

function config(extra: Record<string, unknown> = {}): Config {
	return ConfigSchema.parse(extra) as Config;
}

let dir: string;
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-notices-"));
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
	vi.unstubAllEnvs();
	setConfiguredSupportContact(undefined);
});

describe("first-run privacy notice (D4, D14)", () => {
	it("local mode: what is guarded, what is not, what is recorded, nothing sent", () => {
		const text = formatPrivacyNotice(config(), { locale: "en" });
		expect(text).toContain("What it guards");
		expect(text).toContain("What it does not guard");
		expect(text).toContain("`kubectl delete`, `git push --force` or `docker system prune`");
		expect(text).toContain("~/.singularity-aidr/audit.jsonl");
		expect(text).toContain("What leaves this computer: nothing about your work.");
		expect(text).toContain("The update check is turned off.");
		expect(text).toContain("ask your IT or security team");
		expect(text).toContain("aidr privacy notice");
	});

	it("managed mode names the console, the redaction and clean-verdict upload", () => {
		const text = formatPrivacyNotice(
			config({
				mode: "managed",
				control_plane: {
					endpoint: "https://aidr.corp.example",
					send_clean_verdicts: true,
					redact_mode: "full",
				},
				organization: {
					privacy_notice_url: "https://intranet.example/kvkk/aidr",
					support_contact_url: "https://help.example/aidr",
				},
			}),
			{ locale: "en", unprotectedTools: ["Windsurf"] },
		);
		expect(text).toContain("console (aidr.corp.example)");
		expect(text).toContain("(and allowed actions)");
		expect(text).toContain("summaries of commands, files and addresses are left out");
		expect(text).toContain("https://intranet.example/kvkk/aidr");
		expect(text).toContain("https://help.example/aidr");
		expect(text).toContain("without protection: Windsurf");
	});

	it("is Turkish in a Turkish locale", () => {
		const text = formatPrivacyNotice(config(), { locale: "tr" });
		expect(text).toContain("Neyi korur");
		expect(text).toContain("Neyi korumaz");
		expect(text).toContain("aydınlatma metni");
	});

	it("never prints a link that is not plain http(s)", () => {
		for (const bad of [
			"javascript:alert(1)",
			"https://user:pw@example.test",
			"https://example.test/\u202egnp.exe",
			"https://example.test/a b",
		]) {
			expect(safeDisplayUrl(bad)).toBeNull();
			expect(
				formatPrivacyNotice(config({ organization: { privacy_notice_url: bad } }), {
					locale: "en",
				}),
			).not.toContain(bad);
		}
	});

	it("is shown once per connector and again when what is sent changes", async () => {
		const local = config();
		expect(await takeFirstRunPrivacyNotice(local, "claude-code", { aidrDir: dir })).toContain(
			"What it guards",
		);
		expect(await takeFirstRunPrivacyNotice(local, "claude-code", { aidrDir: dir })).toBeNull();
		// Another connector shows it too.
		expect(await takeFirstRunPrivacyNotice(local, "cursor", { aidrDir: dir })).not.toBeNull();
		// Enrolment changes what leaves the computer: shown again.
		const managed = config({ mode: "managed", control_plane: { endpoint: "https://cp.example" } });
		expect(privacyNoticeDigest(managed)).not.toBe(privacyNoticeDigest(local));
		expect(await takeFirstRunPrivacyNotice(managed, "claude-code", { aidrDir: dir })).toContain(
			"cp.example",
		);
		const state = JSON.parse(readFileSync(join(dir, "privacy-notice-state.json"), "utf8"));
		expect(Object.keys(state.shown).sort()).toEqual(["claude-code", "cursor"]);
	});

	it("an unreadable state file means the notice is shown, never an error", async () => {
		writeFileSync(join(dir, "privacy-notice-state.json"), "{not json");
		expect(await takeFirstRunPrivacyNotice(config(), "codex", { aidrDir: dir })).not.toBeNull();
	});

	it("is part of the session banner, also when managed features are unavailable", () => {
		const message = formatSessionStartMessage("1.0.0", {
			enabled: false,
			disabled_reason: "not_enrolled",
			scanResults: [],
			versionCheck: null,
			privacyNotice: "NOTICE-TEXT",
			unprotectedTools: [{ id: "zed", label: "Zed", evidence: [] }],
		});
		expect(message).toContain("NOTICE-TEXT");
		expect(message).toContain("found on this computer: Zed");
	});
});

describe("unprotected AI tools (D6)", () => {
	const home = "/home/dev";
	const files = new Set([
		join(home, ".codeium", "windsurf"),
		join(home, ".gemini"),
		join("/usr/local/bin", "aider"),
	]);
	const dirs: Record<string, string[]> = {
		[join(home, ".vscode", "extensions")]: ["saoudrizwan.claude-dev-3.1.0", "ms-python.python-1"],
		[join(home, ".local", "share", "JetBrains")]: ["IntelliJIdea2025.2"],
		[join(home, ".local", "share", "JetBrains", "IntelliJIdea2025.2")]: ["ml-llm"],
	};
	const fake = {
		home,
		env: { PATH: "/usr/local/bin:/usr/bin" },
		platform: "linux" as const,
		exists: (path: string) => files.has(path),
		listDir: (path: string) => {
			const entries = dirs[path];
			if (!entries) throw new Error("ENOENT");
			return entries;
		},
	};

	it("finds tools by their directories, editor extensions, plugins and PATH", () => {
		const ids = detectUnprotectedAiTools(fake).map((tool) => tool.id);
		expect(ids).toEqual(["windsurf", "jetbrains-ai", "cline", "gemini-cli", "aider"]);
	});

	it("uses PATHEXT on Windows and %APPDATA% locations", () => {
		const win = detectUnprotectedAiTools({
			home: "C:\\Users\\dev",
			env: { Path: "C:\\tools", PATHEXT: ".EXE;.CMD", APPDATA: "C:\\Users\\dev\\AppData\\Roaming" },
			platform: "win32",
			exists: (path) =>
				path === join("C:\\tools", "kiro.cmd") ||
				path === join("C:\\Users\\dev\\AppData\\Roaming", "Zed"),
			listDir: () => [],
		});
		expect(win.map((tool) => tool.id)).toEqual(["kiro", "zed"]);
	});

	it("reports nothing on a clean machine", () => {
		expect(detectUnprotectedAiTools({ ...fake, exists: () => false, listDir: () => [] })).toEqual(
			[],
		);
	});

	it("become no_aidr_connector posture findings the ingest accepts", () => {
		const report = inspectAgentEnvironment({
			home: dir,
			env: {},
			unprotectedTools: [
				{ id: "windsurf", label: "Windsurf", evidence: ["/x"] },
				{ id: "copilot-cli", label: "GitHub Copilot CLI", evidence: ["PATH:copilot"] },
			],
		});
		const unprotected = report.findings.filter((f) => f.id === "no_aidr_connector");
		expect(unprotected.map((f) => f.host).sort()).toEqual(["copilot-cli", "windsurf"]);
		const events = buildAgentPostureFindingEvents(report, "scan-1");
		expect(
			events
				.filter((e) => e.check_id === "no_aidr_connector")
				.map((e) => e.agent_host)
				.sort(),
		).toEqual(["copilot-cli", "windsurf"]);
		// Evidence (paths) never leaves the machine.
		expect(JSON.stringify(events)).not.toContain("PATH:copilot");
	});
});

describe("false-positive report line and support contact (D9)", () => {
	it("a deny names the short id for `aidr report-fp`", () => {
		const message = formatBlockMessage(deny, { actionId: ACTION_ID });
		expect(message).toContain("aidr report-fp a1b2c3d4");
		expect(message).not.toContain(ACTION_ID);
	});

	it("shows the organisation's support contact once configured", () => {
		setConfiguredSupportContact("https://help.example/aidr");
		expect(configuredSupportContact()).toBe("https://help.example/aidr");
		expect(formatBlockMessage(deny, {})).toContain(
			"Help from your IT or security team: https://help.example/aidr",
		);
		setConfiguredSupportContact("javascript:alert(1)");
		expect(formatBlockMessage(deny, {})).not.toContain("Help from your IT");
	});

	it("records the action id in the local audit record", () => {
		const entry = buildRuntimeVerdictEntry(
			"s",
			"Bash",
			{ command: "x" },
			deny,
			false,
			1,
			ACTION_ID,
		);
		expect(entry.action_id).toBe(ACTION_ID);
		expect(
			buildRuntimeVerdictEntry("s", "Bash", {}, deny, false, 1, "../etc").action_id,
		).toBeUndefined();
	});
});

describe("display language fallback (D10)", () => {
	it("uses the OS locale Intl reports when no POSIX variable is set (Windows)", () => {
		expect(resolveLocale({}, undefined, "tr-TR")).toBe("tr");
		expect(resolveLocale({}, undefined, "en-US")).toBe("en");
		expect(resolveLocale({}, undefined, null)).toBe("en");
		// An explicit POSIX value still wins over Intl.
		expect(resolveLocale({ LANG: "en_US.UTF-8" }, undefined, "tr-TR")).toBe("en");
		// AIDR_LOCALE (what the editor launcher sets) wins over everything.
		expect(resolveLocale({ AIDR_LOCALE: "tr", LANG: "en_US" }, "en", "en-US")).toBe("tr");
	});
});
