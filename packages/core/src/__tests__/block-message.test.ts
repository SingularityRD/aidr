import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { parse as parseYaml } from "yaml";
import { approveCommand, formatAgentBlockReason, formatBlockMessage } from "../block-message.js";
import { formatAskMessage, formatDenyMessage } from "../guard.js";
import {
	categoryLabel,
	displayReason,
	registerReasonDisplay,
	resetDisplayRegistryForTests,
	sourceLabel,
} from "../i18n/display.js";
import { formatInitFailureMessage, integrityFailureMessage } from "../init-failure.js";
import { ArtifactIntegrityError } from "../integrity/runtime.js";
import { loadThreats } from "../threat-loader.js";
import { plainToxicFlowReason } from "../toxic-flow-plain.js";
import type { Verdict } from "../types.js";

const THREATS_DIR = resolve(__dirname, "../../../../threats");

const rmVerdict: Verdict = {
	decision: "deny",
	category: "tool",
	confidence: 0.95,
	severity: "critical",
	source: "heuristic",
	artifacts: ["rm -rf /", "rm -rf /", ";", "~/.singularity-aidr"],
	matchedThreatId: "CLT-CMD-006",
	reasons: ["Recursive forced deletion from root"],
	ruleSeverity: "critical",
};

const INTERNAL_LABELS =
	/\b(heuristic|toxic_flow|package_check|actionId|url_check)\b|bant dışı|out-of-band/;

afterEach(() => {
	vi.unstubAllEnvs();
	resetDisplayRegistryForTests();
});

describe("one block-message shape", () => {
	it("deny: what was stopped, why, what to do, and the agent line, with no internal labels", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		const message = formatDenyMessage(rmVerdict, undefined, [
			{ type: "command", value: "rm -rf /" },
			{ type: "content", value: "rm -rf /" },
		]);
		expect(message).toMatchInlineSnapshot(`
			"🛡️ Singularity AIDR blocked this action.
			Stopped: command 'rm -rf /'
			Why: Recursive forced deletion from root (critical, rule CLT-CMD-006).
			What you can do: if you think this is a false positive, report rule CLT-CMD-006 to your IT or security team; they can allow it with a time-limited exception. Details: \`aidr audit tail\`.
			For the AI agent: do not retry this call or try to work around the block."
		`);
		expect(message).not.toMatch(INTERNAL_LABELS);
		// The rm -rf / banner no longer repeats the artifact or prints a stray ";".
		expect(message).not.toMatch(/^;$/m);
		expect(message.match(/rm -rf \//g)).toHaveLength(1);
	});

	it("ask: the user's approval step comes first and the agent cannot approve", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		const actionId = "a".repeat(64);
		const message = formatAskMessage(actionId, { ...rmVerdict, decision: "ask" }, [
			{ type: "command", value: "rm -rf /" },
		]);
		const lines = message.split("\n");
		expect(lines[0]).toBe("🛡️ Singularity AIDR stopped this action until you approve it.");
		expect(lines[1]).toContain("To allow it once, run this in your own terminal");
		expect(lines[2]).toBe(`  ${approveCommand(actionId)}`);
		// The user types the 8-character prefix; the full id stays in the reference line.
		expect(approveCommand(actionId)).toBe("aidr approve aaaaaaaa");
		expect(message).toContain(`Approval reference: ${actionId}`);
		expect(message).toContain("Stopped: command 'rm -rf /'");
		expect(message).not.toMatch(INTERNAL_LABELS);
		const agentLine = lines.at(-1) ?? "";
		expect(agentLine).toMatch(/^For the AI agent: you cannot approve this action/);
		expect(agentLine).not.toContain("aidr approve");
	});

	it("ask that could not be recorded points at aidr doctor, never at aidr approve", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		const message = formatAskMessage(
			"b".repeat(64),
			{ ...rmVerdict, decision: "ask" },
			[],
			undefined,
			false,
		);
		expect(message).toContain("Run `aidr doctor`");
		expect(message).not.toContain("aidr approve");
	});

	it("never names the matched value of a secret, DLP or canary finding", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		const secret = ["sk", "live", "0123456789abcdef"].join("-");
		for (const marks of [
			{ category: "secrets", source: "heuristic" },
			{ category: "dlp_redact", source: "dlp" },
			{ category: "canary", source: "canary" },
		]) {
			const message = formatDenyMessage(
				{ ...rmVerdict, ...marks, artifacts: [`echo ${secret}`] },
				undefined,
				[{ type: "command", value: `echo ${secret}` }],
			);
			expect(message).not.toContain(secret);
			expect(message).not.toContain("Stopped:");
		}
	});

	it("names no inline content and nothing when the connector passed no typed artifacts", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		expect(formatDenyMessage(rmVerdict)).not.toContain("Stopped:");
		expect(
			formatDenyMessage(rmVerdict, undefined, [{ type: "content", value: "rm -rf /" }]),
		).not.toContain("Stopped:");
	});

	it("names other findings on their own line, the deciding rule first", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		const message = formatBlockMessage({
			...rmVerdict,
			reasons: ["Second finding", "Recursive forced deletion from root"],
		});
		expect(message).toContain("Why: Second finding (critical, rule CLT-CMD-006).");
		expect(message).toContain("Also found: Recursive forced deletion from root.");
	});

	it("shows a plain source label instead of an internal one when no rule decided", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		const message = formatBlockMessage({
			...rmVerdict,
			matchedThreatId: null,
			ruleSeverity: undefined,
			source: "package_check",
			severity: "critical",
			reasons: [],
			category: "supply_chain",
		});
		expect(message).toContain("Neden: yazılım tedarik zinciri (kritik, paket denetimi).");
		expect(message).not.toMatch(INTERNAL_LABELS);
	});

	it("gives the agent one short line on a deny and on a held ask", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		expect(formatAgentBlockReason(rmVerdict)).toBe(
			"🛡️ Singularity AIDR blocked this action: Recursive forced deletion from root (rule CLT-CMD-006). Do not retry it or try to work around the block; the user has been shown the details.",
		);
		expect(formatAgentBlockReason(rmVerdict, true)).toContain("You cannot approve it");
	});
});

describe("Turkish display text", () => {
	it("uses the rule's title_tr once the rule set is loaded, English otherwise", async () => {
		await loadThreats(THREATS_DIR);
		vi.stubEnv("AIDR_LOCALE", "tr");
		const message = formatDenyMessage(rmVerdict);
		expect(message).toContain(
			"Neden: Kök dizinden (/) başlayarak zorla ve özyinelemeli silme (kritik, kural CLT-CMD-006).",
		);
		expect(message).toContain("Yapay zekâ aracı için:");
		vi.stubEnv("AIDR_LOCALE", "en");
		expect(formatDenyMessage(rmVerdict)).toContain("Why: Recursive forced deletion from root");
	});

	it("keeps the English reason when a rule has no title_tr", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		expect(displayReason("Some untranslated rule title")).toBe("Some untranslated rule title");
	});

	it("shows registered plain wording but keeps the raw reason as the key", () => {
		registerReasonDisplay("raw technical reason", { en: "plain", tr: "sade" });
		expect(displayReason("raw technical reason", "en")).toBe("plain");
		expect(displayReason("raw technical reason", "tr")).toBe("sade");
	});

	it("bounds the dynamic reason table", () => {
		for (let i = 0; i < 300; i++) registerReasonDisplay(`r${i}`, { en: `e${i}`, tr: `t${i}` });
		expect(displayReason("r0", "en")).toBe("r0");
		expect(displayReason("r299", "en")).toBe("e299");
	});

	it("maps categories and sources to plain words in both locales", () => {
		expect(categoryLabel("tool", "en")).toBe("dangerous command or tool use");
		expect(categoryLabel("toxic_flow_exfil_chain", "tr")).toBe("bu oturumda riskli birleşim");
		expect(categoryLabel("brand_new_category", "en")).toBe("brand new category");
		expect(sourceLabel("heuristic", "tr")).toBe("tehdit kuralı");
		expect(sourceLabel("cache(url_check)", "en")).toBe("URL reputation check");
		expect(sourceLabel("fallback", "en")).toBeNull();
	});

	it("ships Turkish titles for at least 80 of the rules most likely to fire", () => {
		let translated = 0;
		for (const file of readdirSync(THREATS_DIR).filter((name) => name.endsWith(".yaml"))) {
			const rules = parseYaml(readFileSync(join(THREATS_DIR, file), "utf8")) as Array<{
				title_tr?: unknown;
			}>;
			for (const rule of rules ?? []) {
				if (rule.title_tr === undefined) continue;
				expect(typeof rule.title_tr).toBe("string");
				expect(String(rule.title_tr).trim()).not.toBe("");
				translated += 1;
			}
		}
		expect(translated).toBeGreaterThanOrEqual(80);
	});

	it("loads title_tr onto the threat without touching matching fields", async () => {
		const threats = await loadThreats(THREATS_DIR);
		const rule = threats.find((threat) => threat.id === "CLT-CRED-004");
		expect(rule?.titleTr).toBe("Kimlik bilgisi ya da gizli bilgi içeren dosyayı okuma");
		expect(rule?.title).toBe("Reading credential or secret file");
	});
});

describe("integrity failure messages", () => {
	it("explains a missing release key with the administrator's fix", () => {
		vi.stubEnv("AIDR_LOCALE", "en");
		const error = new ArtifactIntegrityError("claude-code/dist", { status: "no_public_keys" });
		const result = integrityFailureMessage(error);
		expect(result?.message).toContain(
			"Singularity AIDR blocked this action because it cannot verify its own installation (release verification key missing). Nothing runs until this is fixed. Ask your IT admin to run: aidr setup --release-key <key.pem> (details: aidr doctor)",
		);
		expect(result?.sessionStart).toContain("every tool call in this session is blocked");
		expect(result?.sessionStart).not.toContain("not protected");
		expect(formatInitFailureMessage("integrity_no_public_keys", error)).toBe(result?.message);
	});

	it("names the cause of other integrity failures, in Turkish too", () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		const error = Object.assign(new Error("x"), {
			name: "ArtifactIntegrityError",
			result: { status: "hash_mismatch" },
		});
		expect(integrityFailureMessage(error)?.message).toContain(
			"kendi kurulumunu doğrulayamadığı için bu işlemi engelledi (dosyaları değiştirilmiş ya da eksik)",
		);
		expect(integrityFailureMessage(new Error("other"))).toBeNull();
	});
});

describe("toxic-flow plain wording", () => {
	it("describes the lethal trifecta without chain names or capability tags", () => {
		const plain = plainToxicFlowReason({
			chain: "lethal_trifecta",
			earlier: [
				{ cap: "untrusted_content", kind: "web_content", summary: "WebFetch ← evil.example" },
				{ cap: "external_comm", kind: "network_egress", summary: "curl → paste.example" },
			],
			current: [
				{
					cap: "private_data",
					kind: "sensitive_file",
					summary: "reads ~/.ssh/id_rsa (SSH private key)",
				},
			],
			integrityLost: false,
		});
		expect(plain.en).toBe(
			"Risky combination in this session: the agent read content from evil.example, can send data out and is now reading sensitive data (SSH private key). Together these could leak your data.",
		);
		expect(plain.tr).toBe(
			"Bu oturumda riskli birleşim: yapay zekâ aracı evil.example adresinden içerik aldı, dışarı veri gönderebiliyor ve şimdi hassas bir veriye erişiyor (SSH özel anahtarı). Bunlar birlikte verilerinizin sızmasına yol açabilir.",
		);
		expect(`${plain.en} ${plain.tr}`).not.toMatch(/lethal_trifecta|\[private data\]|Toxic flow/);
	});
});
