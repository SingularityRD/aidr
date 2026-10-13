/**
 * PRD-15: Claude Code block messages in English (default, unchanged) and
 * Turkish, and proof that the locale changes only human-readable text: the
 * hook JSON the host parses keeps the same fields and decision values.
 */
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Verdict } from "@singularityrd/aidr-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { formatBlockReason } from "../format.js";

const PRE_TOOL_USE = resolve(__dirname, "..", "..", "dist", "pre-tool-use.cjs");

const verdict: Verdict = {
	decision: "deny",
	category: "dangerous_command",
	confidence: 0.97,
	severity: "critical",
	ruleSeverity: "critical",
	source: "heuristic",
	artifacts: ["rm -rf /"],
	matchedThreatId: "CLT-CMD-001",
	reasons: ["Recursive delete of the filesystem root"],
};

afterEach(() => {
	vi.unstubAllEnvs();
});

describe("formatBlockReason locales", () => {
	it("keeps the English deny banner unchanged by default", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		expect(formatBlockReason(verdict)).toMatchInlineSnapshot(`
			" 
			🚨 Threat      Recursive delete of the filesystem root
			   Severity    CRITICAL
			   Rule        CLT-CMD-001
			   Artifact    rm -rf /
			   Source      heuristic
			   Action      Blocked"
		`);
	});

	it("renders the deny banner in Turkish", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		expect(formatBlockReason(verdict)).toMatchInlineSnapshot(`
			" 
			🚨 Tehdit      Recursive delete of the filesystem root
			   Önem        KRİTİK
			   Kural       CLT-CMD-001
			   Öğe         rm -rf /
			   Kaynak      heuristic
			   Eylem       Engellendi"
		`);
	});

	it("renders the ask banner in Turkish with locale-aware upper case", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		expect(formatBlockReason({ ...verdict, decision: "ask" })).toMatchInlineSnapshot(`
			"🛡️ Singularity AIDR: Şüpheli Etkinlik Algılandı
			━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
			🚨 Tehdit      Recursive delete of the filesystem root
			   Önem        KRİTİK
			   Kural       CLT-CMD-001
			   Öğe         rm -rf /
			   Kaynak      heuristic
			   Eylem       Onay gerekiyor"
		`);
	});
});

async function runHook(
	input: Record<string, unknown>,
	env: Record<string, string>,
): Promise<Record<string, unknown>> {
	const home = mkdtempSync(join(tmpdir(), "aidr-i18n-hook-home-"));
	try {
		const childEnv: Record<string, string | undefined> = {
			...process.env,
			HOME: home,
			USERPROFILE: home,
			XDG_CONFIG_HOME: join(home, ".config"),
			XDG_STATE_HOME: join(home, ".local", "state"),
			XDG_CACHE_HOME: join(home, ".cache"),
		};
		for (const key of Object.keys(childEnv)) {
			if (key.startsWith("AIDR_") || key.startsWith("LC_") || key === "LANG") delete childEnv[key];
		}
		const stdout = await new Promise<string>((done, fail) => {
			const child = execFile(
				"node",
				[PRE_TOOL_USE],
				{ timeout: 30_000, env: { ...childEnv, ...env } },
				(error, out) => (error && !out ? fail(error) : done(out)),
			);
			child.stdin?.end(JSON.stringify(input));
		});
		return JSON.parse(stdout.trim()) as Record<string, unknown>;
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
}

function shape(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(shape);
	if (value && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, shape(v)]),
		);
	}
	return typeof value;
}

describe("pre-tool-use hook output across locales", () => {
	const call = { tool_name: "Bash", tool_input: { command: "rm -rf /" }, session_id: "s1" };

	it("keeps the JSON fields and decision identical; only the text is Turkish", async () => {
		const english = await runHook(call, {});
		const turkish = await runHook(call, { LANG: "tr_TR.UTF-8" });
		const explicit = await runHook(call, { AIDR_LOCALE: "tr", LANG: "en_US.UTF-8" });

		expect(shape(turkish)).toEqual(shape(english));
		expect(explicit).toEqual(turkish);
		const decision = (r: Record<string, unknown>) =>
			(r.hookSpecificOutput as Record<string, unknown>).permissionDecision;
		expect(decision(turkish)).toBe(decision(english));
		expect(["deny", "ask"]).toContain(decision(english));

		expect(JSON.stringify(english)).toContain("Singularity AIDR");
		expect(JSON.stringify(english)).not.toMatch(/Tehdit|Eylem/);
		expect(JSON.stringify(turkish)).toMatch(/Tehdit|Eylem/);
	}, 60_000);

	it("localizes the fixed fail-closed deny for unreadable input", async () => {
		const english = await runHook({ not: "a tool call" }, {});
		const turkish = await runHook({ not: "a tool call" }, { AIDR_LOCALE: "tr" });
		expect(shape(turkish)).toEqual(shape(english));
		expect((turkish.hookSpecificOutput as Record<string, unknown>).permissionDecision).toBe("deny");
		expect(turkish.systemMessage).toBe(
			"Singularity AIDR bu araç çağrısını inceleyemedi. Eylem engellendi.",
		);
		expect(english.systemMessage).toBe(
			"Singularity AIDR could not inspect this tool call. The action was blocked.",
		);
	}, 60_000);
});
