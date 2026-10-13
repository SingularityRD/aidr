/**
 * PRD-15: the user-facing message catalog. English is the reference and the
 * default; Turkish must cover exactly the same keys with the same parameters,
 * and every key must be used by a connector, the CLI or the core formatters.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { isInvalidConfig, loadConfig } from "../config.js";
import { formatAskMessage, formatDashboardApprovalNotice, formatDenyMessage } from "../guard.js";
import { en } from "../i18n/en.js";
import {
	currentLocale,
	MESSAGE_CATALOGS,
	normalizeLocale,
	resolveLocale,
	setConfiguredLocale,
	severityLabel,
	t,
} from "../i18n/index.js";
import { tr } from "../i18n/tr.js";
import type { Artifact, Verdict } from "../types.js";

const REPO_ROOT = resolve(__dirname, "..", "..", "..", "..");

function placeholders(text: string): string[] {
	return [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1] as string).sort();
}

function sourceFiles(dir: string, out: string[] = []): string[] {
	for (const entry of readdirSync(dir)) {
		if (entry === "node_modules" || entry === "dist" || entry === "__tests__") continue;
		const path = join(dir, entry);
		if (statSync(path).isDirectory()) sourceFiles(path, out);
		else if (/\.(ts|tsx)$/.test(entry) && !entry.endsWith(".d.ts")) out.push(path);
	}
	return out;
}

const verdict: Verdict = {
	decision: "deny",
	confidence: 0.95,
	category: "dangerous_command",
	severity: "critical",
	ruleSeverity: "high",
	matchedThreatId: "CLT-CMD-001",
	reasons: ["Recursive delete of the filesystem root"],
	artifacts: ["rm -rf /"],
	source: "heuristic",
} as Verdict;

const artifacts: Artifact[] = [{ type: "command", value: "rm -rf /" } as Artifact];

afterEach(() => {
	vi.unstubAllEnvs();
	setConfiguredLocale(undefined);
});

describe("message catalog parity", () => {
	it("has exactly the same keys in en and tr", () => {
		const enKeys = Object.keys(en).sort();
		const trKeys = Object.keys(tr).sort();
		expect(trKeys).toEqual(enKeys);
		expect(enKeys.length).toBeGreaterThan(100);
	});

	it("uses only parameters the English message defines, and no empty or untranslated text", () => {
		const problems: string[] = [];
		for (const [key, english] of Object.entries(en)) {
			const turkish = tr[key as keyof typeof en];
			if (!turkish || turkish.trim() === "") problems.push(`${key}: empty`);
			const extra = placeholders(turkish).filter((p) => !placeholders(english).includes(p));
			if (extra.length > 0) problems.push(`${key}: unknown parameter(s) ${extra.join(", ")}`);
			// A sentence copied over unchanged is a missed translation. Short
			// labels and pure templates may legitimately read the same.
			if (
				turkish === english &&
				/[a-z]{4,} [a-z]{4,}/i.test(english.replace(/\{\w+\}|Singularity AIDR/g, ""))
			) {
				problems.push(`${key}: identical to English`);
			}
		}
		expect(problems).toEqual([]);
	});

	it("keeps product, command and token names untranslated", () => {
		for (const [key, english] of Object.entries(en)) {
			const turkish = tr[key as keyof typeof en];
			for (const token of ["Singularity AIDR", "aidr approve", "aidr pending", "actionId"]) {
				if (english.includes(token)) expect(turkish, `${key} keeps ${token}`).toContain(token);
			}
		}
	});

	it("has no unused keys: every key is referenced from package source", () => {
		const roots = ["core", "claude-code", "cli", "codex", "opencode", "openclaw", "extension"]
			.map((name) => join(REPO_ROOT, "packages", name, "src"))
			.filter((dir) => {
				try {
					return statSync(dir).isDirectory();
				} catch {
					return false;
				}
			});
		const corpus = roots
			.flatMap((dir) => sourceFiles(dir))
			.filter((file) => !/[\\/]i18n[\\/](en|tr)\.ts$/.test(file))
			.map((file) => readFileSync(file, "utf8"))
			.join("\n");
		const unused = Object.keys(en).filter((key) => !corpus.includes(`"${key}"`));
		expect(unused).toEqual([]);
	});

	it("exposes both catalogs", () => {
		expect(Object.keys(MESSAGE_CATALOGS).sort()).toEqual(["en", "tr"]);
	});
});

describe("locale resolution", () => {
	it("normalizes POSIX and BCP 47 tags", () => {
		expect(normalizeLocale("tr_TR.UTF-8")).toBe("tr");
		expect(normalizeLocale("tr-TR")).toBe("tr");
		expect(normalizeLocale("TR")).toBe("tr");
		expect(normalizeLocale("en_US.UTF-8")).toBe("en");
		expect(normalizeLocale("C")).toBeUndefined();
		expect(normalizeLocale("de_DE")).toBeUndefined();
		expect(normalizeLocale(42)).toBeUndefined();
	});

	it("defaults to English", () => {
		expect(resolveLocale({})).toBe("en");
		expect(resolveLocale({ LANG: "de_DE.UTF-8" })).toBe("en");
		expect(resolveLocale({ LANG: "C" })).toBe("en");
	});

	it("follows AIDR_LOCALE, then config, then LC_ALL / LC_MESSAGES / LANG", () => {
		expect(resolveLocale({ AIDR_LOCALE: "tr", LANG: "en_US" }, "en")).toBe("tr");
		expect(resolveLocale({ AIDR_LOCALE: "en", LANG: "tr_TR" }, "tr")).toBe("en");
		expect(resolveLocale({ LANG: "en_US" }, "tr")).toBe("tr");
		expect(resolveLocale({ AIDR_LOCALE: "xx", LANG: "tr_TR.UTF-8" })).toBe("tr");
		expect(resolveLocale({ LANG: "tr_TR.UTF-8" })).toBe("tr");
		expect(resolveLocale({ LC_MESSAGES: "tr_TR", LANG: "en_US" })).toBe("tr");
		// LC_ALL overrides LANG even when it names a locale we do not ship.
		expect(resolveLocale({ LC_ALL: "C", LANG: "tr_TR.UTF-8" })).toBe("en");
		expect(resolveLocale({ LC_ALL: "tr_TR.UTF-8", LANG: "en_US" })).toBe("tr");
	});

	it("applies the configured locale set by loadConfig", () => {
		vi.stubEnv("AIDR_LOCALE", "");
		vi.stubEnv("LC_ALL", "");
		vi.stubEnv("LC_MESSAGES", "");
		vi.stubEnv("LANG", "");
		setConfiguredLocale("tr");
		expect(currentLocale()).toBe("tr");
		setConfiguredLocale("klingon");
		expect(currentLocale()).toBe("en");
	});

	it("reads `locale` from the configuration without ever invalidating it", async () => {
		vi.stubEnv("AIDR_LOCALE", "");
		vi.stubEnv("LC_ALL", "");
		vi.stubEnv("LC_MESSAGES", "");
		vi.stubEnv("LANG", "");
		const turkish = await loadConfig(undefined, undefined, undefined, { raw: '{"locale":"tr"}' });
		expect(turkish.locale).toBe("tr");
		expect(isInvalidConfig(turkish)).toBe(false);
		expect(currentLocale()).toBe("tr");
		const unsupported = await loadConfig(undefined, undefined, undefined, {
			raw: '{"locale":"de","sensitivity":"paranoid"}',
		});
		expect(isInvalidConfig(unsupported)).toBe(false);
		expect(unsupported.locale).toBeUndefined();
		expect(unsupported.sensitivity).toBe("paranoid");
		expect(currentLocale()).toBe("en");
	});

	it("interpolates parameters and never throws on a missing one", () => {
		expect(t("block.line.rule", { rule: "CLT-1" }, "en")).toBe("Rule: CLT-1");
		expect(t("block.line.rule", { rule: "CLT-1" }, "tr")).toBe("Kural: CLT-1");
		expect(t("block.line.rule", {}, "tr")).toBe("Kural: {rule}");
		expect(severityLabel("high", "tr")).toBe("yüksek");
		expect(severityLabel("HIGH", "en")).toBe("HIGH");
		expect(severityLabel("custom", "tr")).toBe("custom");
	});
});

describe("block messages", () => {
	it("renders the deny message in English by default (unchanged text)", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		expect(formatDenyMessage(verdict)).toMatchInlineSnapshot(`
			"Singularity AIDR blocked this action.
			Severity: high
			Rule: CLT-CMD-001
			Category: dangerous_command
			Reason: Recursive delete of the filesystem root"
		`);
	});

	it("renders the deny message in Turkish", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		expect(formatDenyMessage(verdict)).toMatchInlineSnapshot(`
			"Singularity AIDR bu eylemi engelledi.
			Önem: yüksek
			Kural: CLT-CMD-001
			Kategori: dangerous_command
			Neden: Recursive delete of the filesystem root"
		`);
	});

	it("renders the ask message in English with the actionId token intact", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		const message = formatAskMessage("act_123", { ...verdict, decision: "ask" }, artifacts);
		expect(message).toMatchInlineSnapshot(`
			"Singularity AIDR flagged this action and blocked it pending explicit user approval.
			Severity: high
			Rule: CLT-CMD-001
			Category: dangerous_command
			Reason: Recursive delete of the filesystem root
			Artifacts: command 'rm -rf /'

			Approval reference: actionId: "act_123"
			You cannot approve this action yourself and no tool available to you can approve it.
			Approval is an out-of-band, human-only action. Report the reference above to the user and
			stop here: do NOT retry this tool call and do NOT try to work around the block. The action
			stays blocked until the user approves it out of band or permanently allowlists the artifact.
			(For the user: review it with \`aidr pending\` and approve it with \`aidr approve <actionId>\`
			in your own terminal; the approval covers one retry of this exact call for 15 minutes.)"
		`);
	});

	it("renders the ask message in Turkish with the actionId token intact", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		const message = formatAskMessage("act_123", { ...verdict, decision: "ask" }, artifacts);
		expect(message).toContain('actionId: "act_123"');
		expect(message).toContain("aidr approve <actionId>");
		expect(message).toMatchInlineSnapshot(`
			"Singularity AIDR bu eylemi şüpheli buldu ve kullanıcı açıkça onaylayana kadar engelledi.
			Önem: yüksek
			Kural: CLT-CMD-001
			Kategori: dangerous_command
			Neden: Recursive delete of the filesystem root
			Öğeler: command 'rm -rf /'

			Onay referansı: actionId: "act_123"
			Bu eylemi kendin onaylayamazsın ve erişebildiğin hiçbir araç da onaylayamaz.
			Onay, bant dışı ve yalnızca bir insanın verebileceği bir işlemdir. Yukarıdaki referansı kullanıcıya bildir ve
			burada dur: bu araç çağrısını yeniden DENEME ve engeli aşmaya ÇALIŞMA. Eylem, kullanıcı
			bant dışında onaylayana ya da öğeyi kalıcı olarak izin listesine ekleyene kadar engelli kalır.
			(Kullanıcı için: kendi terminalinizde \`aidr pending\` ile inceleyip \`aidr approve <actionId>\` ile
			onaylayın; onay, bu çağrının birebir aynısının 15 dakika içinde bir kez yeniden denenmesini kapsar.)"
		`);
	});

	it("localizes dashboard approval notices", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		expect(
			formatDashboardApprovalNotice({ status: "denied", requestId: "req_9" } as never),
		).toMatchInlineSnapshot(
			`"req_9 numaralı AIDR paneli onay isteği reddedildi; eylem engelli kalıyor."`,
		);
	});
});
