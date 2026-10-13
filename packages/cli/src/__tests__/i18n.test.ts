/**
 * PRD-15: `aidr` help and incident-command output in English (default,
 * unchanged) and Turkish. The real command tree from src/index.ts is captured
 * by stubbing parseAsync, so the parity check sees exactly what ships.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Command } from "commander";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
	BUILTIN_HELP_TEXTS,
	CLI_EN,
	CLI_TR,
	collectHelpTexts,
	ct,
	HELP_TR,
	localizeHelp,
} from "../i18n/index.js";

const captured: { program?: Command } = {};

vi.mock("commander", async (importOriginal) => {
	const actual = await importOriginal<typeof import("commander")>();
	class CapturingCommand extends actual.Command {
		override async parseAsync(): Promise<this> {
			captured.program = this as unknown as Command;
			return this;
		}
	}
	return { ...actual, Command: CapturingCommand };
});

let program: Command;

beforeAll(async () => {
	vi.stubEnv("AIDR_LOCALE", "en");
	await import("../index.js");
	if (!captured.program) throw new Error("the CLI program was not captured");
	program = captured.program;
	vi.unstubAllEnvs();
}, 60_000);

afterEach(() => {
	vi.unstubAllEnvs();
});

function helpOf(command: Command): string {
	return command.helpInformation();
}

/** Help text with the column wrapping folded away. */
function flat(text: string): string {
	return text.replace(/\s+/g, " ");
}

function find(path: string[]): Command {
	let command = program;
	for (const name of path) {
		const next = command.commands.find((sub) => sub.name() === name);
		if (!next) throw new Error(`no command ${path.join(" ")}`);
		command = next;
	}
	return command;
}

describe("help translation parity", () => {
	it("has a Turkish entry for every description in the command tree", () => {
		const missing = [...collectHelpTexts(program)].filter((text) => !(text in HELP_TR));
		expect(missing).toEqual([]);
	});

	it("has no unused Turkish help entries", () => {
		const used = new Set<string>([...collectHelpTexts(program), ...BUILTIN_HELP_TEXTS]);
		const unused = Object.keys(HELP_TR).filter((text) => !used.has(text));
		expect(unused).toEqual([]);
	});

	it("keeps the flags and command names of every translation", () => {
		const problems: string[] = [];
		for (const [english, turkish] of Object.entries(HELP_TR)) {
			if (turkish.trim() === "" || turkish === english) problems.push(english);
			for (const token of english.match(/--[a-z-]+|`[^`]+`|[A-Z][A-Z0-9_]{3,}=[\w-]+/g) ?? []) {
				if (!turkish.includes(token)) problems.push(`${english} -> lost ${token}`);
			}
		}
		expect(problems).toEqual([]);
	});
});

describe("CLI message catalog parity", () => {
	it("has the same keys and parameters in en and tr", () => {
		expect(Object.keys(CLI_TR).sort()).toEqual(Object.keys(CLI_EN).sort());
		const params = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
		for (const [key, english] of Object.entries(CLI_EN)) {
			const turkish = CLI_TR[key as keyof typeof CLI_EN];
			expect(params(turkish), key).toEqual(params(english));
		}
	});

	it("has no unused keys", () => {
		const dir = resolve(__dirname, "..");
		const files: string[] = [];
		const walk = (d: string) => {
			for (const entry of readdirSync(d, { withFileTypes: true })) {
				if (entry.name === "__tests__" || entry.name === "i18n") continue;
				const path = join(d, entry.name);
				if (entry.isDirectory()) walk(path);
				else if (entry.name.endsWith(".ts")) files.push(path);
			}
		};
		walk(dir);
		const corpus = files.map((file) => readFileSync(file, "utf8")).join("\n");
		const unused = Object.keys(CLI_EN).filter((key) => !corpus.includes(`"${key}"`));
		expect(unused).toEqual([]);
	});
});

describe("help output", () => {
	it("is unchanged English by default", () => {
		localizeHelp(program, "en");
		const help = flat(helpOf(find(["approve"])));
		expect(help).toContain("Usage: aidr approve");
		expect(help).toContain(
			"Operator only: approve ONE retry of a blocked call (interactive confirmation; 15-minute default)",
		);
		expect(help).toContain("display help for command");
	});

	it("renders Turkish help with flags and command names intact", () => {
		localizeHelp(program, "tr");
		const root = helpOf(program);
		expect(root).toContain("Kullanım: aidr");
		expect(root).toContain("Komutlar:");
		expect(root).toContain("Singularity AIDR komut satırı kurulum ve tanılama aracı");
		const approve = helpOf(find(["approve"]));
		expect(approve).toMatchInlineSnapshot(`
			"Kullanım: aidr approve [options] <actionId>

			Yalnızca operatör: engellenmiş bir çağrının TEK bir yeniden denemesini onayla
			(etkileşimli onay; varsayılan 15 dakika)

			Seçenekler:
			  --ttl <minutes>     Onayın geçerli kalacağı dakika sayısı (1-1440)
			                      (varsayılan: "15")
			  --permit-allowlist  Ajanın bu öğeleri izin listesine bir kez eklemesine de
			                      izin ver
			  -y, --yes           İstemi atla; yalnızca AIDR_OPERATOR_NONINTERACTIVE=1 ile
			                      dikkate alınır
			  --json              Makinece okunabilir bir makbuz üret
			  -h, --help          komutun yardımını göster
			"
		`);
		const privacyScan = helpOf(find(["privacy", "scan"]));
		expect(privacyScan).toContain('(varsayılan: "any")');
		expect(privacyScan).toContain("--fail-on <mode>");
	});
});

describe("incident command output", () => {
	it("renders the same approval line in both languages", () => {
		expect(
			ct("approvals.approved", { actionId: "act_1", expiresAt: "2026-10-13T10:00:00Z" }, "en"),
		).toBe("Approved act_1… until 2026-10-13T10:00:00Z.");
		expect(
			ct("approvals.approved", { actionId: "act_1", expiresAt: "2026-10-13T10:00:00Z" }, "tr"),
		).toBe("act_1… onaylandı, geçerlilik bitişi: 2026-10-13T10:00:00Z.");
	});

	it("follows AIDR_LOCALE", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		expect(ct("approvals.none")).toBe("Onay bekleyen bir Singularity AIDR isteği yok.");
		vi.stubEnv("AIDR_LOCALE", "en");
		expect(ct("approvals.none")).toBe("No Singularity AIDR asks are waiting for approval.");
	});
});
