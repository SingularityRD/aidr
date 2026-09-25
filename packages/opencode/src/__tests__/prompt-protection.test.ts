/**
 * Prompt protection through the built plugin (dist/index.js): `chat.message`
 * receives the parts OpenCode is about to store and send, by reference, the way
 * `@opencode-ai/plugin` 1.2.x declares the hook.
 */

import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const PLUGIN_DIST = resolve(__dirname, "..", "..", "dist", "index.js");

// Synthetic values built at runtime so no literal credential sits in the source.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5".repeat(4)}`;
// Checksum-valid synthetic identifiers (TC Kimlik check digits, IBAN mod-97).
const TC_KIMLIK = "10000000146";
const IBAN = "TR33 0006 1005 1978 6457 8413 26";

interface TextPart {
	id: string;
	sessionID: string;
	messageID: string;
	type: "text";
	text: string;
	synthetic?: boolean;
}

interface Hooks {
	"chat.message"?: (
		input: { sessionID: string; messageID?: string },
		output: { message: { id: string; sessionID: string; role: "user" }; parts: unknown[] },
	) => Promise<void>;
	"experimental.chat.messages.transform"?: (
		input: Record<string, never>,
		output: { messages: Array<{ info: Record<string, unknown>; parts: unknown[] }> },
	) => Promise<void>;
}

const saved: Record<string, string | undefined> = {};
const toasts: Array<{ message: string; variant: string }> = [];
let home: string;
let aidrDir: string;
let hooks: Hooks;

function textPart(text: string, extra: Partial<TextPart> = {}): TextPart {
	return { id: "prt_1", sessionID: "ses_1", messageID: "msg_1", type: "text", text, ...extra };
}

function message(id = "msg_1") {
	return { id, sessionID: "ses_1", role: "user" as const };
}

async function writeConfig(overrides: Record<string, unknown> = {}): Promise<void> {
	await writeFile(
		join(aidrDir, "config.json"),
		JSON.stringify({
			mode: "local",
			logging: { enabled: true, path: join(aidrDir, "audit.jsonl") },
			...overrides,
		}),
	);
}

async function auditLog(): Promise<string> {
	const path = join(aidrDir, "audit.jsonl");
	return existsSync(path) ? readFile(path, "utf8") : "";
}

beforeAll(async () => {
	for (const key of ["HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"]) {
		saved[key] = process.env[key];
	}
	home = await mkdtemp(join(tmpdir(), "aidr-opencode-prompt-"));
	process.env.HOME = home;
	process.env.USERPROFILE = home;
	process.env.XDG_CONFIG_HOME = join(home, ".config");
	process.env.XDG_CACHE_HOME = join(home, ".cache");
	aidrDir = join(home, ".singularity-aidr");
	await mkdir(aidrDir, { recursive: true });
	await writeConfig();

	const mod = (await import(PLUGIN_DIST)) as {
		default: (input: Record<string, unknown>) => Promise<Hooks>;
	};
	hooks = await mod.default({
		client: {
			app: { log: async () => undefined },
			tui: {
				showToast: async (options: { body: { message: string; variant: string } }) => {
					toasts.push({ message: options.body.message, variant: options.body.variant });
					return true;
				},
			},
		},
		project: { id: "test-project" },
		directory: home,
		worktree: home,
		$: {},
	});
}, 30_000);

beforeEach(async () => {
	toasts.length = 0;
	await writeConfig();
	await rm(join(aidrDir, "audit.jsonl"), { force: true });
});

afterAll(async () => {
	for (const [key, value] of Object.entries(saved)) {
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
	await rm(home, { recursive: true, force: true });
});

describe("OpenCode chat.message prompt protection", () => {
	it("registers the prompt hook", () => {
		expect(hooks["chat.message"]).toBeTypeOf("function");
	});

	it("leaves a clean prompt untouched", async () => {
		const parts = [textPart("rename the helper function")];
		await hooks["chat.message"]?.({ sessionID: "ses_1" }, { message: message(), parts });
		expect(parts[0]?.text).toBe("rename the helper function");
		expect(toasts).toEqual([]);
		expect(await auditLog()).toBe("");
	});

	it("blocks a secret: throws, replaces the text and never echoes the value", async () => {
		const parts = [textPart(`token ${GITHUB_TOKEN}`), textPart("second part", { id: "prt_2" })];
		const submit = hooks["chat.message"]?.({ sessionID: "ses_1" }, { message: message(), parts });
		await expect(submit).rejects.toThrow(/GitHub token/);
		await expect(submit).rejects.toMatchObject({ name: "AidrVerdictBlockError" });
		for (const part of parts) {
			expect(part.text).toContain("Singularity AIDR blocked this prompt");
			expect(part.text).not.toContain(GITHUB_TOKEN);
		}
		expect(toasts).toEqual([
			{ message: expect.stringContaining("GitHub token"), variant: "error" },
		]);
		const log = await auditLog();
		expect(log).toContain('"tool_name":"chat.message"');
		expect(log).not.toContain(GITHUB_TOKEN);
	});

	it("does not inspect synthetic parts OpenCode generated", async () => {
		const parts = [
			textPart("summarise the attached file"),
			textPart(`GITHUB=${GITHUB_TOKEN}`, { id: "prt_file", synthetic: true }),
		];
		await hooks["chat.message"]?.({ sessionID: "ses_1" }, { message: message(), parts });
		expect(parts[1]?.text).toContain(GITHUB_TOKEN);
	});

	it("warns on Turkish personal data: sends it, toasts, and gives the model a notice on that message", async () => {
		const parts = [textPart(`TCKN ${TC_KIMLIK}, IBAN ${IBAN}`)];
		await hooks["chat.message"]?.(
			{ sessionID: "ses_1", messageID: "msg_warn" },
			{ message: message("msg_warn"), parts },
		);
		expect(parts[0]?.text).toContain(TC_KIMLIK);
		expect(toasts).toEqual([
			{ message: expect.stringContaining("Turkish ID number (TC Kimlik)"), variant: "warning" },
		]);

		const history = [
			{ info: { id: "msg_other", role: "user", sessionID: "ses_1" }, parts: [textPart("hi")] },
			{ info: { id: "msg_warn", role: "user", sessionID: "ses_1" }, parts: [...parts] },
		];
		await hooks["experimental.chat.messages.transform"]?.({}, { messages: history });
		expect(history[0]?.parts).toHaveLength(1);
		const notice = history[1]?.parts.at(-1) as TextPart;
		expect(notice.synthetic).toBe(true);
		expect(notice.text).toContain("aidr-prompt-protection");
		expect(notice.text).toContain("Do not repeat it");
		expect(notice.text).not.toContain(TC_KIMLIK);
		expect(await auditLog()).toContain("prompt_protection_warning");
	});

	it("follows prompt_protection from config", async () => {
		await writeConfig({ prompt_protection: { secrets: "off", pii: "block" } });
		const token = [textPart(`token ${GITHUB_TOKEN}`)];
		await hooks["chat.message"]?.({ sessionID: "ses_1" }, { message: message(), parts: token });
		expect(token[0]?.text).toContain(GITHUB_TOKEN);

		const iban = [textPart(`IBAN ${IBAN}`)];
		await expect(
			hooks["chat.message"]?.({ sessionID: "ses_1" }, { message: message(), parts: iban }),
		).rejects.toThrow(/IBAN/);
		expect(iban[0]?.text).not.toContain(IBAN);
	});
});
