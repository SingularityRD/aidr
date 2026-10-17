import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
	PRIVACY_EXIT,
	PRIVACY_SCAN_MAX_BYTES,
	type PrivacyScanDependencies,
	type PrivacyScanOptions,
	runPrivacyScan,
} from "../commands/privacy.js";

/**
 * `aidr privacy scan`: local TR/EN personal-data and secret scan. The product properties
 * pinned here: every supported type is found, no matched value is ever printed, masking
 * replaces whole values, and an input that was not fully inspected is never clean.
 */

const VALUES = {
	tckn: "10000000146",
	iban: "TR33 0006 1005 1978 6457 8413 26",
	phone: "0532 123 45 67",
	email: "ahmet.yilmaz@example.com.tr",
	card: "4111 1111 1111 1111",
	token: "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12",
} as const;

const SAMPLE = [
	`Müşteri TCKN: ${VALUES.tckn}`,
	`IBAN: ${VALUES.iban}`,
	`Telefon: ${VALUES.phone}`,
	`e-posta ${VALUES.email}`,
	`Kart ${VALUES.card}`,
	`token ${VALUES.token}`,
	"Bu satırda kişisel veri yok.",
	"",
].join("\n");

const MASKED_SAMPLE = [
	"Müşteri TCKN: [TC_KIMLIK]",
	"IBAN: [IBAN]",
	"Telefon: [PHONE]",
	"e-posta [EMAIL]",
	"Kart [CREDIT_CARD]",
	"token [SECRET]",
	"Bu satırda kişisel veri yok.",
	"",
].join("\n");

const KEY_BODY =
	"MIIEowIBAAKCAQEA7Qx3Fv0rX9yJ2cZkqLpM4nB8sT1uV6wH0aR5eD2gK9jF3lN7oP1qW4xY8zA2bC5dE6fG7";

interface Run {
	code: number;
	stdout: string;
	stderr: string;
}

let directory: string;

beforeAll(async () => {
	directory = await mkdtemp(join(tmpdir(), "aidr-privacy-scan-"));
});

afterAll(async () => {
	await rm(directory, { recursive: true, force: true });
});

async function writeInput(name: string, content: string | Buffer): Promise<string> {
	const path = join(directory, name);
	await writeFile(path, content);
	return path;
}

async function run(
	file: string | undefined,
	options: PrivacyScanOptions = {},
	dependencies: PrivacyScanDependencies = {},
): Promise<Run> {
	let stdout = "";
	let stderr = "";
	const code = await runPrivacyScan(file, options, {
		stdout: (text) => {
			stdout += text;
		},
		stderr: (text) => {
			stderr += text;
		},
		...dependencies,
	});
	return { code, stdout, stderr };
}

function stdinOf(content: string | Buffer): PrivacyScanDependencies["stdin"] {
	return Readable.from([typeof content === "string" ? Buffer.from(content) : content]);
}

function expectNoRawValues(text: string): void {
	for (const value of Object.values(VALUES)) expect(text).not.toContain(value);
	expect(text).not.toContain(KEY_BODY);
}

describe("aidr privacy scan - detection", () => {
	it("finds TCKN, IBAN, phone, e-mail, card and secret with their line numbers", async () => {
		const path = await writeInput("sample.txt", SAMPLE);
		const result = await run(path, { json: true });
		const report = JSON.parse(result.stdout);
		expect(result.code).toBe(PRIVACY_EXIT.findings);
		expect(report.counts).toEqual({
			CREDIT_CARD: 1,
			EMAIL: 1,
			IBAN: 1,
			PHONE: 1,
			SECRET: 1,
			TC_KIMLIK: 1,
		});
		const lines = Object.fromEntries(
			report.findings.map((finding: { type: string; line: number }) => [
				finding.type,
				finding.line,
			]),
		);
		expect(lines).toEqual({
			TC_KIMLIK: 1,
			IBAN: 2,
			PHONE: 3,
			EMAIL: 4,
			CREDIT_CARD: 5,
			SECRET: 6,
		});
		expect(report.incomplete).toBe(false);
	});

	it("reports offsets that cover each whole value in the decoded text", async () => {
		const result = await run(undefined, { json: true }, { stdin: stdinOf(SAMPLE) });
		const covered = JSON.parse(result.stdout).findings.map(
			(finding: { start: number; end: number }) => SAMPLE.slice(finding.start, finding.end),
		);
		for (const value of Object.values(VALUES)) {
			expect(covered.some((slice: string) => slice.includes(value))).toBe(true);
		}
	});

	it("adds credentials only the output-quarantine detector names, such as a Slack webhook", async () => {
		const webhook = "https://hooks.slack.com/services/T0ABCDEF1/B0ABCDEF2/abcdefghijklmnop1234";
		const result = await run(undefined, { mask: true }, { stdin: stdinOf(`hook ${webhook}\n`) });
		expect(result.code).toBe(PRIVACY_EXIT.findings);
		expect(result.stdout).toBe("hook [SECRET]\n");
		expect(result.stderr).not.toContain(webhook);
	});

	it("exits 0 with no findings on ordinary text", async () => {
		const result = await run(undefined, {}, { stdin: stdinOf("merhaba dünya\nhello world\n") });
		expect(result.code).toBe(PRIVACY_EXIT.clean);
		expect(result.stdout).toContain("No findings for the selected detectors.");
	});
});

describe("aidr privacy scan - output never contains a matched value", () => {
	it("prints a type/count/line table without values", async () => {
		const path = await writeInput("table.txt", SAMPLE);
		const result = await run(path);
		expect(result.code).toBe(PRIVACY_EXIT.findings);
		expect(result.stdout).toMatch(/TYPE\s+COUNT\s+LINES/);
		expect(result.stdout).toMatch(/TC_KIMLIK\s+1\s+1\b/);
		expect(result.stdout).toMatch(/SECRET\s+1\s+6\b/);
		expectNoRawValues(result.stdout + result.stderr);
	});

	it("emits exactly {findings:[{type,start,end,line}], counts, incomplete, reasons} as JSON", async () => {
		const result = await run(undefined, { json: true }, { stdin: stdinOf(SAMPLE) });
		const report = JSON.parse(result.stdout);
		expect(Object.keys(report).sort()).toEqual(["counts", "findings", "incomplete", "reasons"]);
		for (const finding of report.findings) {
			expect(Object.keys(finding).sort()).toEqual(["end", "line", "start", "type"]);
		}
		expectNoRawValues(result.stdout + result.stderr);
	});
});

describe("aidr privacy scan - masking", () => {
	it("prints the text with each value replaced by its [TYPE] placeholder", async () => {
		const path = await writeInput("mask.txt", SAMPLE);
		const result = await run(path, { mask: true });
		expect(result.code).toBe(PRIVACY_EXIT.findings);
		expect(result.stdout).toBe(MASKED_SAMPLE);
		// The summary goes to stderr so stdout can be redirected into a clean copy.
		expect(result.stderr).toContain("TC_KIMLIK");
		expectNoRawValues(result.stdout + result.stderr);
	});

	it("masks a whole PEM private key, not just its header", async () => {
		const key = `-----BEGIN RSA PRIVATE KEY-----\n${KEY_BODY}\n${KEY_BODY}\n-----END RSA PRIVATE KEY-----`;
		const result = await run(
			undefined,
			{ mask: true },
			{ stdin: stdinOf(`key:\n${key}\nafter\n`) },
		);
		expect(result.code).toBe(PRIVACY_EXIT.findings);
		expect(result.stdout).toBe("key:\n[PRIVATE_KEY]\nafter\n");
	});

	it("includes the masked text in JSON when both flags are given", async () => {
		const result = await run(undefined, { json: true, mask: true }, { stdin: stdinOf(SAMPLE) });
		expect(JSON.parse(result.stdout).masked).toBe(MASKED_SAMPLE);
	});

	it("masks only the selected --types", async () => {
		const result = await run(
			undefined,
			{ mask: true, types: "tckn,email" },
			{ stdin: stdinOf(SAMPLE) },
		);
		expect(result.stdout).toContain("Müşteri TCKN: [TC_KIMLIK]");
		expect(result.stdout).toContain("e-posta [EMAIL]");
		expect(result.stdout).toContain(VALUES.iban);
	});
});

describe("aidr privacy scan - input handling", () => {
	it("reads standard input when no file, or '-', is given", async () => {
		for (const file of [undefined, "-"]) {
			const result = await run(file, { json: true }, { stdin: stdinOf(SAMPLE) });
			expect(result.code).toBe(PRIVACY_EXIT.findings);
			expect(JSON.parse(result.stdout).counts.TC_KIMLIK).toBe(1);
		}
	});

	it("refuses to wait on an interactive terminal", async () => {
		const stdin = Object.assign(Readable.from([]), { isTTY: true });
		const result = await run(undefined, {}, { stdin });
		expect(result.code).toBe(PRIVACY_EXIT.error);
		expect(result.stderr).toContain("No input");
	});

	it("rejects an oversize file before reading it", async () => {
		const path = await writeInput("big.txt", Buffer.alloc(PRIVACY_SCAN_MAX_BYTES + 1, 0x61));
		const result = await run(path);
		expect(result.code).toBe(PRIVACY_EXIT.error);
		expect(result.stderr).toMatch(/reads at most 4\.0 MiB/);
		expect(result.stdout).toBe("");
	});

	it("rejects oversize standard input", async () => {
		const result = await run(undefined, {}, { stdin: stdinOf("a".repeat(2048)), maxBytes: 1024 });
		expect(result.code).toBe(PRIVACY_EXIT.error);
		expect(result.stderr).toContain("Standard input exceeds");
	});

	it("rejects binary and non-UTF-8 input with a clear error", async () => {
		const binary = await writeInput("image.bin", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
		const nul = await run(binary);
		expect(nul.code).toBe(PRIVACY_EXIT.error);
		expect(nul.stderr).toContain("binary");

		const latin1 = await run(
			undefined,
			{},
			{ stdin: stdinOf(Buffer.from([0x63, 0x61, 0x66, 0xe9])) },
		);
		expect(latin1.code).toBe(PRIVACY_EXIT.error);
		expect(latin1.stderr).toContain("not valid UTF-8");
	});

	it("reports a missing file or a directory as an error", async () => {
		expect((await run(join(directory, "missing.txt"))).code).toBe(PRIVACY_EXIT.error);
		expect((await run(directory)).code).toBe(PRIVACY_EXIT.error);
	});

	it("rejects an unknown --types entry and an unknown --fail-on mode", async () => {
		const types = await run(undefined, { types: "tckn,bogus" }, { stdin: stdinOf(SAMPLE) });
		expect(types.code).toBe(PRIVACY_EXIT.error);
		expect(types.stderr).toContain('Unknown type "bogus"');
		const failOn = await run(undefined, { failOn: "sometimes" }, { stdin: stdinOf(SAMPLE) });
		expect(failOn.code).toBe(PRIVACY_EXIT.error);
	});

	it("reports in Turkish under AIDR_LOCALE=tr", async () => {
		vi.stubEnv("AIDR_LOCALE", "tr");
		try {
			const missing = await run(join(directory, "missing.txt"));
			expect(missing.stderr).toContain("Dosya bulunamadı");
			const report = await run(undefined, {}, { stdin: stdinOf(SAMPLE) });
			expect(report.stdout).toContain("AIDR gizlilik taraması: standart girdi");
			expect(report.stdout).toContain("Değerler hiçbir zaman yazdırılmaz");
			expect(report.stdout).not.toMatch(/finding\(s\)|local only/);
		} finally {
			vi.unstubAllEnvs();
		}
	});
});

describe("aidr privacy scan - exit codes", () => {
	it("--fail-on secret ignores personal data but fails on a secret", async () => {
		const piiOnly = SAMPLE.replace(`token ${VALUES.token}`, "token yok");
		const pii = await run(undefined, { failOn: "secret" }, { stdin: stdinOf(piiOnly) });
		expect(pii.code).toBe(PRIVACY_EXIT.clean);
		const secret = await run(undefined, { failOn: "secret" }, { stdin: stdinOf(SAMPLE) });
		expect(secret.code).toBe(PRIVACY_EXIT.findings);
	});

	it("--fail-on none reports findings but exits 0", async () => {
		const result = await run(undefined, { failOn: "none" }, { stdin: stdinOf(SAMPLE) });
		expect(result.code).toBe(PRIVACY_EXIT.clean);
		expect(result.stdout).toContain("6 finding(s)");
	});

	it("exits 3 when the input exceeds the privacy rules' working limit", async () => {
		const text = `${"lorem ipsum dolor\n".repeat(60_000)}TCKN: ${VALUES.tckn}\n`;
		expect(text.length).toBeGreaterThan(1024 * 1024);
		const result = await run(undefined, { json: true }, { stdin: stdinOf(text) });
		const report = JSON.parse(result.stdout);
		expect(result.code).toBe(PRIVACY_EXIT.incomplete);
		expect(report.incomplete).toBe(true);
		expect(report.reasons).toContain("INPUT_LIMIT");
	});

	it("exits 3 for a truncated private key when findings do not fail, and never prints a partial mask", async () => {
		const truncated = `-----BEGIN RSA PRIVATE KEY-----\n${KEY_BODY}\n`;
		const human = await run(undefined, { failOn: "none" }, { stdin: stdinOf(truncated) });
		expect(human.code).toBe(PRIVACY_EXIT.incomplete);
		expect(human.stdout).toContain("INCOMPLETE");
		expect(human.stdout).toContain("This is not a clean result");

		const masked = await run(
			undefined,
			{ mask: true, failOn: "none" },
			{ stdin: stdinOf(truncated) },
		);
		expect(masked.code).toBe(PRIVACY_EXIT.incomplete);
		expect(masked.stdout).toBe("");
		expect(masked.stderr).toContain("Refusing to print a masked copy");

		const json = await run(undefined, { json: true, mask: true }, { stdin: stdinOf(truncated) });
		expect(JSON.parse(json.stdout).masked).toBeNull();
		expectNoRawValues(human.stdout + masked.stdout + masked.stderr + json.stdout);
	});

	it("exits 3 on an incomplete scan with no findings instead of reporting it clean", async () => {
		const result = await run(
			undefined,
			{},
			{ stdin: stdinOf("nothing sensitive here\n"), maxScanChars: 8 },
		);
		expect(result.code).toBe(PRIVACY_EXIT.incomplete);
		expect(result.stdout).toContain("No findings in the inspected part of the input.");
		expect(result.stdout).not.toContain("No findings for the selected detectors.");
	});
});

const CLI_ENTRY = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "dist", "index.js");

describe("aidr privacy scan - built binary", () => {
	it("scans piped standard input and sets the process exit code", () => {
		const result = spawnSync(process.execPath, [CLI_ENTRY, "privacy", "scan", "--json"], {
			input: SAMPLE,
			encoding: "utf8",
		});
		expect(result.status).toBe(PRIVACY_EXIT.findings);
		expect(JSON.parse(result.stdout).counts.IBAN).toBe(1);
		expectNoRawValues(result.stdout + result.stderr);
	});

	it("exits 0 on clean piped input", () => {
		const result = spawnSync(process.execPath, [CLI_ENTRY, "privacy", "scan"], {
			input: "hello\n",
			encoding: "utf8",
		});
		expect(result.status).toBe(PRIVACY_EXIT.clean);
	});
});
