/**
 * Setup Assistant texts: EN/TR parity, plain words, the brand's casing, every
 * key used, and the bundled page in sync with its sources and free of inline
 * script or style (CSP `default-src 'self'`).
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { ASSISTANT_UI } from "../generated/assistant-ui.js";
import { ASSISTANT_EN, ASSISTANT_TR, at } from "../i18n/index.js";

const PACKAGE = resolve(__dirname, "..", "..");
const params = (text: string) => [...text.matchAll(/\{(\w+)\}/gu)].map((match) => match[1]).sort();

describe("assistant catalog parity", () => {
	it("has the same keys and parameters in English and Turkish, none empty", () => {
		expect(Object.keys(ASSISTANT_TR).sort()).toEqual(Object.keys(ASSISTANT_EN).sort());
		for (const [key, english] of Object.entries(ASSISTANT_EN)) {
			const turkish = ASSISTANT_TR[key as keyof typeof ASSISTANT_EN];
			expect(params(turkish), key).toEqual(params(english));
			expect(english.trim(), key).not.toBe("");
			expect(turkish.trim(), key).not.toBe("");
		}
	});

	it("uses plain words and keeps commands and the brand as they are", () => {
		for (const [key, turkish] of Object.entries(ASSISTANT_TR)) {
			expect(turkish, key).not.toMatch(
				/heuristic|toxic_flow|actionId|bant dışı|ajan ana makinesi|SİNGULARİTY/iu,
			);
			const english = ASSISTANT_EN[key as keyof typeof ASSISTANT_EN];
			for (const command of english.match(/'aidr [^']+'/gu) ?? []) {
				expect(turkish, `${key} keeps ${command}`).toContain(command);
			}
			if (english.includes("Singularity AIDR")) expect(turkish, key).toContain("Singularity AIDR");
		}
		for (const [key, english] of Object.entries(ASSISTANT_EN)) {
			expect(english, key).not.toMatch(/heuristic|toxic_flow|actionId/u);
		}
	});

	it("uses every key from the page or the command", () => {
		const sources = [
			readFileSync(join(PACKAGE, "src", "assistant", "ui", "app.ts"), "utf8"),
			readFileSync(join(PACKAGE, "src", "commands", "assistant.ts"), "utf8"),
			...readdirSync(join(PACKAGE, "src", "assistant"))
				.filter((name) => name.endsWith(".ts"))
				.map((name) => readFileSync(join(PACKAGE, "src", "assistant", name), "utf8")),
		].join("\n");
		// Keys built from a prefix at run time (badge.<state>, step.<name>, outcome.<outcome>).
		const dynamic = ["badge.", "step.", "outcome."];
		const unused = Object.keys(ASSISTANT_EN).filter(
			(key) => !sources.includes(`"${key}"`) && !dynamic.some((prefix) => key.startsWith(prefix)),
		);
		expect(unused).toEqual([]);
	});

	it("prints the terminal lines in the CLI locale", () => {
		expect(at("assistant.cli.noOpen", {}, "tr")).toBe(ASSISTANT_TR["assistant.cli.noOpen"]);
		expect(at("assistant.cli.noOpen", {}, "en")).toBe(ASSISTANT_EN["assistant.cli.noOpen"]);
	});
});

describe("bundled page", () => {
	it("is in sync with src/assistant/ui (run build:assistant-ui after editing it)", () => {
		const output = execFileSync(
			process.execPath,
			[join(PACKAGE, "scripts", "build-assistant-ui.mjs"), "--check"],
			{
				encoding: "utf8",
			},
		);
		expect(output).toContain("up to date");
	}, 60_000);

	it("has no inline script, inline style or external resource", () => {
		const { html, js, css } = ASSISTANT_UI;
		expect(
			[...html.matchAll(/<script\b([^>]*)>/gu)].every((match) =>
				/\bsrc="\/app\.js"/u.test(match[1]),
			),
		).toBe(true);
		expect(html).not.toMatch(/\sstyle=|<style\b|\son[a-z]+=/iu);
		expect(html).not.toMatch(/(?:src|href)="(?:https?:)?\/\//iu);
		expect(css).not.toMatch(/@import|url\(\s*["']?(?:https?:)?\/\//iu);
		expect(css).not.toMatch(/text-transform/iu);
		expect(js).not.toMatch(
			/\.innerHTML\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function\(/u,
		);
		// The page carries both catalogs.
		expect(js).toContain(ASSISTANT_TR["welcome.heading"]);
		expect(js).toContain(ASSISTANT_EN["welcome.heading"]);
	});
});
