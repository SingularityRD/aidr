/**
 * `aidr exception add|list|remove`: operator-only, time-limited detection
 * exceptions. Adding one requires a human confirmation (TTY, or --yes with the
 * operator variable), a bounded expiry, a reason and exactly one subject, and
 * never accepts a self-defense rule.
 */

import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import {
	clearOperatorApprovalKeyCache,
	type DetectionExceptionStoreOptions,
	listDetectionExceptions,
	loadUsableLocalExceptions,
} from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	exceptionAddCommand,
	exceptionListCommand,
	exceptionRemoveCommand,
	parseExceptionDuration,
} from "../commands/exceptions.js";
import { OPERATOR_NONINTERACTIVE_ENV } from "../utils/operator-confirm.js";

let dir: string;
let store: DetectionExceptionStoreOptions;
let out: string[];
let err: string[];

function ttyStreams(answer: string) {
	const input = Object.assign(new PassThrough(), { isTTY: true });
	const output = Object.assign(new PassThrough(), { isTTY: true });
	output.resume();
	setTimeout(() => input.write(`${answer}\n`), 10);
	return { input, output };
}

function nonTtyStreams() {
	const output = new PassThrough();
	output.resume();
	return { input: new PassThrough(), output };
}

const VALID = { agent: "claude-code", expires: "7d", reason: "deploy script needs chmod" };

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-exception-cli-"));
	clearOperatorApprovalKeyCache();
	const key = randomBytes(32);
	let ledger: string | null = null;
	store = {
		path: join(dir, "detection-exceptions.json"),
		approvals: {
			path: join(dir, "approvals.json"),
			keyProvider: {
				load: () => ({ key, location: "os-vault", store: "macos-keychain" }),
				anchor: () => ({
					location: "os-vault",
					read: () => ledger,
					write: (value) => {
						ledger = value;
					},
				}),
			},
		},
	};
	out = [];
	err = [];
	vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		out.push(args.map(String).join(" "));
	});
	vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
		err.push(args.map(String).join(" "));
	});
	process.exitCode = undefined;
});

afterEach(() => {
	vi.restoreAllMocks();
	clearOperatorApprovalKeyCache();
	rmSync(dir, { recursive: true, force: true });
	process.exitCode = undefined;
});

describe("parseExceptionDuration", () => {
	it("accepts 5 minutes to 30 days only", () => {
		expect(parseExceptionDuration("30m")).toBe(30 * 60_000);
		expect(parseExceptionDuration("30d")).toBe(30 * 86_400_000);
		expect(parseExceptionDuration("31d")).toBeNull();
		expect(parseExceptionDuration("4m")).toBeNull();
		expect(parseExceptionDuration(undefined)).toBeNull();
		expect(parseExceptionDuration("forever")).toBeNull();
	});
});

describe("aidr exception add", () => {
	it("refuses without an interactive terminal (an agent tool call) and records nothing", async () => {
		await exceptionAddCommand("CLT-CMD-011", VALID, { store, streams: nonTtyStreams() });
		expect(process.exitCode).toBe(1);
		expect(err.join("\n")).toContain("interactive terminal");
		expect(await listDetectionExceptions(store)).toEqual([]);
	});

	it("ignores --yes unless the operator variable is set", async () => {
		await exceptionAddCommand(
			"CLT-CMD-011",
			{ ...VALID, yes: true },
			{ store, env: {}, streams: nonTtyStreams() },
		);
		expect(process.exitCode).toBe(1);
		expect(await listDetectionExceptions(store)).toEqual([]);
	});

	it("is refused before any prompt when machine policy locks protection", async () => {
		const { confirmOperatorAction } = await import("../utils/operator-confirm.js");
		await expect(
			confirmOperatorAction({
				prompt: "add an exception",
				word: "except",
				streams: ttyStreams("except"),
				relaxesProtection: true,
				protectionLocked: () => true,
			}),
		).rejects.toThrow(/protection_locked/);
		await expect(
			confirmOperatorAction({
				prompt: "add an exception",
				word: "except",
				streams: ttyStreams("except"),
				relaxesProtection: true,
				protectionLocked: () => false,
			}),
		).resolves.toBe("interactive");
	});

	it("refuses a rule ID this installation does not load (a typo would match nothing)", async () => {
		await exceptionAddCommand("CLT-CMD-9999", VALID, {
			store,
			streams: ttyStreams("except"),
			knownRuleIds: async () => new Set(["CLT-CMD-011"]),
		});
		expect(process.exitCode).toBe(1);
		expect(err.join("\n")).toContain("not a rule this installation loads");
		expect(await listDetectionExceptions(store)).toEqual([]);
	});

	it("adds a signed exception when the operator types the confirmation word", async () => {
		await exceptionAddCommand("CLT-CMD-011", VALID, { store, streams: ttyStreams("except") });
		expect(process.exitCode).toBeUndefined();
		const listed = await listDetectionExceptions(store);
		expect(listed).toHaveLength(1);
		expect(listed[0]).toMatchObject({
			ruleId: "CLT-CMD-011",
			subject: { kind: "agent", value: "claude-code" },
			verified: true,
		});
		expect(listed[0]?.createdBy).toContain("(interactive)");
		expect(await loadUsableLocalExceptions(new Set(["CLT-CMD-011"]), store)).toHaveLength(1);
	});

	it("does nothing when the operator declines", async () => {
		await exceptionAddCommand("CLT-CMD-011", VALID, { store, streams: ttyStreams("no") });
		expect(process.exitCode).toBe(1);
		expect(await listDetectionExceptions(store)).toEqual([]);
	});

	it("accepts --yes with the operator variable (automation)", async () => {
		await exceptionAddCommand(
			"CLT-CMD-011",
			{ ...VALID, yes: true },
			{ store, env: { [OPERATOR_NONINTERACTIVE_ENV]: "1" }, streams: nonTtyStreams() },
		);
		expect(process.exitCode).toBeUndefined();
		expect(await listDetectionExceptions(store)).toHaveLength(1);
	});

	it("validates subject, expiry, reason and refuses self-defense rules before prompting", async () => {
		const cases: Array<[string, Record<string, unknown>, string]> = [
			["CLT-CMD-011", { ...VALID, agent: undefined }, "exactly one subject"],
			["CLT-CMD-011", { ...VALID, user: "bob" }, "exactly one subject"],
			["CLT-CMD-011", { ...VALID, expires: undefined }, "--expires is required"],
			["CLT-CMD-011", { ...VALID, expires: "90d" }, "--expires is required"],
			["CLT-CMD-011", { ...VALID, reason: " " }, "--reason is required"],
			["CLT-SELF-007", VALID, "self-defense rule"],
			["CLT-SELF-001", VALID, "self-defense rule"],
		];
		for (const [rule, options, message] of cases) {
			err.length = 0;
			process.exitCode = undefined;
			await exceptionAddCommand(rule, options, { store, streams: ttyStreams("except") });
			expect(process.exitCode, `${rule} ${JSON.stringify(options)}`).toBe(1);
			expect(err.join("\n")).toContain(message);
		}
		expect(await listDetectionExceptions(store)).toEqual([]);
	});
});

describe("aidr exception list / remove", () => {
	it("lists, then revokes an exception for good", async () => {
		await exceptionAddCommand("CLT-CMD-011", VALID, { store, streams: ttyStreams("except") });
		out.length = 0;
		await exceptionListCommand({ json: true }, { store });
		const report = JSON.parse(out.join("\n")) as { exceptions: Array<{ id: string }> };
		expect(report.exceptions).toHaveLength(1);
		const id = report.exceptions[0]?.id as string;

		await exceptionRemoveCommand(id, {}, { store });
		expect(process.exitCode).toBeUndefined();
		expect(await listDetectionExceptions(store)).toEqual([]);

		out.length = 0;
		await exceptionListCommand({}, { store });
		expect(out.join("\n")).toContain("No local Singularity AIDR detection exceptions");
	});

	it("reports an unknown id", async () => {
		await exceptionRemoveCommand("does-not-exist", {}, { store });
		expect(process.exitCode).toBe(1);
		expect(err.join("\n")).toContain("not_found");
	});
});
