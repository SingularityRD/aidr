// @vitest-environment jsdom
/**
 * Personal vs company AI accounts (managed `workAccounts`): account detection from the
 * hermetic e2e fixtures, classification under a site rule, policy validation, telemetry
 * (enum only) and the content guard's warn / block / mask-only behaviour.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluatePolicy } from "../background/policy";
import { buildEvent, sanitizeEvent } from "../background/telemetry";
import { STRINGS } from "../content/strings";
import {
	type AccountProbe,
	accountVerdict,
	classifyAccount,
	cookieValue,
	detectAccount,
	emailDomainIn,
} from "../sites/accounts";
import type { GuardMessage, GuardPolicy, WorkAccountPolicy } from "../types";
import {
	EMAIL,
	FakeDataTransfer,
	type Harness,
	makeFilesWritable,
	setupGuard,
} from "./content-helpers";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "e2e", "fixtures");

function fixtureRoot(name: string): Document {
	return new DOMParser().parseFromString(readFileSync(join(FIXTURES, name), "utf8"), "text/html");
}

const emptyDoc = (): Document => new DOMParser().parseFromString("<p></p>", "text/html");

const probe = (url: string, cookie = "", root: ParentNode = emptyDoc()): AccountProbe => ({
	url,
	cookie,
	root,
});

const RULE = (workspaceIds: string[] = [], emailDomains: string[] = []) => ({
	workspaceIds,
	emailDomains,
});

describe("account detection (fixture pages)", () => {
	it("Gemini: reads only the email domain from the Google bar account button, in any UI language", () => {
		const work = detectAccount(
			"gemini",
			probe("https://gemini.google.com/u/1/app", "", fixtureRoot("gemini-account-workspace.html")),
		);
		expect(work).toEqual({
			kind: "work",
			workspaceId: null,
			emailDomain: "acme.example",
			signals: ["google.account-button"],
		});
		const personal = detectAccount(
			"gemini",
			probe("https://gemini.google.com/u/2/app", "", fixtureRoot("gemini-account-personal.html")),
		);
		expect(personal).toMatchObject({ kind: "personal", emailDomain: "gmail.com" });
		// No local part anywhere in the result.
		expect(JSON.stringify(work)).not.toContain("ada.yilmaz");
		expect(JSON.stringify(personal)).not.toContain("ada.yilmaz");
	});

	it("Gemini without the account button is unknown", () => {
		const ctx = detectAccount(
			"gemini",
			probe("https://gemini.google.com/app", "", fixtureRoot("gemini.html")),
		);
		expect(ctx.kind).toBe("unknown");
		expect(ctx.emailDomain).toBeNull();
	});

	it("Copilot: the Microsoft 365 host is a work account, the consumer host a personal one", () => {
		const m365 = detectAccount(
			"copilot",
			probe("https://copilot.cloud.microsoft/chat", "", fixtureRoot("m365-copilot-chat.html")),
		);
		expect(m365).toEqual({
			kind: "work",
			workspaceId: null,
			emailDomain: "acme.example",
			signals: ["copilot.host", "m365.me-control"],
		});
		const consumer = detectAccount(
			"copilot",
			probe("https://copilot.microsoft.com/", "", fixtureRoot("copilot.html")),
		);
		expect(consumer).toMatchObject({ kind: "personal", emailDomain: null });
		const consumerDomain = detectAccount(
			"copilot",
			probe("https://m365.cloud.microsoft/chat", "", fixtureFromHtml("someone@outlook.com")),
		);
		expect(consumerDomain.kind).toBe("personal");
	});

	it("ChatGPT: the _account workspace cookie; `personal` is the personal account", () => {
		expect(
			detectAccount("chatgpt", probe("https://chatgpt.com/", "a=1; _account=WS-Acme-1")),
		).toEqual({
			kind: "work",
			workspaceId: "ws-acme-1",
			emailDomain: null,
			signals: ["chatgpt.cookie-account"],
		});
		expect(detectAccount("chatgpt", probe("https://chatgpt.com/", "_account=personal")).kind).toBe(
			"personal",
		);
		expect(detectAccount("chatgpt", probe("https://chatgpt.com/", "")).kind).toBe("unknown");
		expect(
			detectAccount("chatgpt", probe("https://chatgpt.com/", "_account=%3Cscript%3E")).kind,
		).toBe("unknown");
	});

	it("Claude: the lastActiveOrg cookie gives an organisation id but never a kind", () => {
		const ctx = detectAccount(
			"claude",
			probe("https://claude.ai/new", "lastActiveOrg=0B9E5C5A-1111-4222-8333-444455556666"),
		);
		expect(ctx).toEqual({
			kind: "unknown",
			workspaceId: "0b9e5c5a-1111-4222-8333-444455556666",
			emailDomain: null,
			signals: ["claude.cookie-org"],
		});
	});

	it("sites without a detector are unknown; a throwing probe root is unknown", () => {
		expect(detectAccount("perplexity", probe("https://www.perplexity.ai/")).kind).toBe("unknown");
		const throwing = {
			querySelector: () => {
				throw new Error("boom");
			},
		} as unknown as ParentNode;
		expect(detectAccount("gemini", probe("https://gemini.google.com/app", "", throwing)).kind).toBe(
			"unknown",
		);
	});

	it("helpers: cookie lookup and email domain extraction", () => {
		expect(cookieValue(" x=1;  _account=%22ws-1%22 ", "_account")).toBe("ws-1");
		expect(cookieValue("my_account=ws-1", "_account")).toBeNull();
		expect(emailDomainIn("Google Account: A (a.b+c@Sub.Acme.Example)")).toBe("sub.acme.example");
		expect(emailDomainIn("no email here")).toBeNull();
	});
});

function fixtureFromHtml(upn: string): Document {
	return new DOMParser().parseFromString(
		`<div id="mectrl_currentAccount_secondary">${upn}</div>`,
		"text/html",
	);
}

describe("account classification", () => {
	const work = {
		kind: "work",
		workspaceId: null,
		emailDomain: "acme.example",
		signals: [],
	} as const;
	it("an allowed id or domain (or a subdomain of it) is the company account", () => {
		expect(classifyAccount(RULE([], ["acme.example"]), work)).toBe("company");
		expect(
			classifyAccount(RULE([], ["acme.example"]), { ...work, emailDomain: "tr.acme.example" }),
		).toBe("company");
		expect(
			classifyAccount(RULE(["WS-1"]), { ...work, emailDomain: null, workspaceId: "ws-1" }),
		).toBe("company");
	});
	it("a look-alike domain or another organisation is `other`", () => {
		expect(
			classifyAccount(RULE([], ["acme.example"]), { ...work, emailDomain: "evilacme.example" }),
		).toBe("other");
		expect(
			classifyAccount(RULE(["ws-1"]), {
				kind: "unknown",
				workspaceId: "ws-2",
				emailDomain: null,
				signals: [],
			}),
		).toBe("other");
	});
	it("a personal account stays personal even with an allowed domain", () => {
		expect(classifyAccount(RULE([], ["acme.example"]), { ...work, kind: "personal" })).toBe(
			"personal",
		);
	});
	it("empty lists accept any recognised work account; nothing recognised is unverified", () => {
		expect(classifyAccount(RULE(), work)).toBe("company");
		expect(
			classifyAccount(RULE(), {
				kind: "unknown",
				workspaceId: null,
				emailDomain: null,
				signals: [],
			}),
		).toBe("unverified");
	});
	it("verdicts: unverified is enforced by default and can be allowed", () => {
		const policy: WorkAccountPolicy = {
			action: "warn",
			unverified: "enforce",
			sites: { chatgpt: RULE(["ws-1"]) },
		};
		const none = probe("https://chatgpt.com/");
		expect(accountVerdict(policy, "chatgpt", none)).toMatchObject({
			type: "unverified",
			enforce: true,
		});
		expect(accountVerdict({ ...policy, unverified: "allow" }, "chatgpt", none)).toMatchObject({
			type: "unverified",
			enforce: false,
		});
		expect(
			accountVerdict(policy, "chatgpt", probe("https://chatgpt.com/", "_account=ws-1")),
		).toMatchObject({ type: "company", enforce: false });
		expect(accountVerdict(policy, "gemini", none)).toBeNull();
		expect(accountVerdict(null, "chatgpt", none)).toBeNull();
	});
});

describe("managed policy: workAccounts", () => {
	it("is off by default", () => {
		expect(evaluatePolicy(undefined, undefined).policy.workAccounts).toBeNull();
	});

	it("accepts a valid value, lowercases ids/domains and locks the key", () => {
		const { policy } = evaluatePolicy(
			{
				workAccounts: {
					action: "mask-only",
					sites: {
						chatgpt: { workspaceIds: ["WS-Acme"] },
						gemini: { emailDomains: ["@Acme.Example"] },
					},
				},
			},
			undefined,
		);
		expect(policy.workAccounts).toEqual({
			action: "mask-only",
			unverified: "enforce",
			sites: {
				chatgpt: { workspaceIds: ["ws-acme"], emailDomains: [] },
				gemini: { workspaceIds: [], emailDomains: ["acme.example"] },
			},
		});
		expect(policy.managedKeys).toContain("workAccounts");
		expect(policy.policyErrors).toEqual([]);
	});

	it.each([
		["unknown action", { action: "ignore", sites: { chatgpt: {} } }],
		["unknown site", { action: "warn", sites: { poe: {} } }],
		["no site", { action: "warn", sites: {} }],
		["bad domain", { action: "warn", sites: { gemini: { emailDomains: ["*.acme.example"] } } }],
		["bad unverified", { action: "warn", unverified: "maybe", sites: { gemini: {} } }],
		["unknown key", { action: "warn", sites: { gemini: {} }, extra: 1 }],
	])(
		"an invalid value (%s) fails safe: block, unverified enforced, valid entries kept",
		(_name, raw) => {
			const { policy } = evaluatePolicy({ workAccounts: raw }, undefined);
			expect(policy.policyErrors).toContain("workAccounts");
			const sites = (raw as { sites: Record<string, unknown> }).sites;
			if (Object.keys(sites).some((s) => ["chatgpt", "claude", "gemini", "copilot"].includes(s))) {
				expect(policy.workAccounts).toMatchObject({ action: "block", unverified: "enforce" });
			} else {
				expect(policy.workAccounts).toBeNull();
			}
		},
	);

	it("a bad domain is dropped in the fail-safe value, the good one kept", () => {
		const { policy } = evaluatePolicy(
			{
				workAccounts: {
					action: "warn",
					sites: { gemini: { emailDomains: ["acme.example", "not a domain"] } },
				},
			},
			undefined,
		);
		expect(policy.workAccounts).toEqual({
			action: "block",
			unverified: "enforce",
			sites: { gemini: { workspaceIds: [], emailDomains: ["acme.example"] } },
		});
	});
});

describe("telemetry: account_type", () => {
	const input = { site: "chatgpt", action: "blocked", channel: "prompt", counts: {} } as const;
	it("carries the account type enum only", () => {
		const event = buildEvent({ ...input, accountType: "personal" }, Date.UTC(2026, 9, 14));
		expect(event?.account_type).toBe("personal");
		expect(Object.keys(event ?? {})).not.toContain("workspace");
		expect(buildEvent(input, 0)?.account_type).toBeUndefined();
	});
	it("refuses any other value", () => {
		const event = buildEvent({ ...input, accountType: "company" }, 0);
		expect(sanitizeEvent({ ...event, account_type: "acme.example" })).toBeNull();
		expect(sanitizeEvent({ ...event, account_type: "other" })?.account_type).toBe("other");
	});
});

// ---- content guard ------------------------------------------------------------------------

let h: Harness | undefined;
const scope = window as unknown as Record<string, unknown>;
beforeEach(() => {
	scope.DataTransfer = FakeDataTransfer;
});
afterEach(() => {
	h?.guard.stop();
	h = undefined;
	document.body.innerHTML = "";
	delete scope.DataTransfer;
});

/** The harness adapter is ChatGPT; the cookie decides the account. */
function start(
	action: WorkAccountPolicy["action"],
	cookie: string,
	policy: Partial<GuardPolicy> = {},
): Harness {
	h = setupGuard({
		policy: {
			...policy,
			workAccounts: { action, unverified: "enforce", sites: { chatgpt: RULE(["ws-acme"]) } },
		},
		accountProbe: () => probe("https://chatgpt.com/", cookie),
	});
	return h;
}

const records = (g: Harness) => g.records() as Extract<GuardMessage, { type: "RECORD" }>[];

describe("content guard: workAccounts", () => {
	it("company workspace: sends are masked as usual and recorded as company", async () => {
		const g = start("block", "_account=ws-acme");
		g.editor.value = `Mail ${EMAIL}`;
		g.enter();
		await expect.poll(() => g.sent.length).toBe(1);
		expect(g.sent[0]).not.toContain(EMAIL);
		expect(records(g).at(-1)).toMatchObject({ action: "masked", account: "company" });
	});

	it("block: a personal account cannot send, and the bubble says why (EN)", async () => {
		const g = start("block", "_account=personal");
		g.editor.value = `Mail ${EMAIL}`;
		const event = g.enter();
		expect(event.defaultPrevented).toBe(true);
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("personal account");
		expect(g.bubble()?.textContent).toContain(STRINGS.en.accountBlocked("ChatGPT"));
		expect(g.sent).toEqual([]);
		expect(g.engine.scan).not.toHaveBeenCalled();
		expect(records(g).at(-1)).toMatchObject({ action: "blocked", account: "personal" });
	});

	it("block: an unverified account is blocked too (fail closed), in Turkish when asked", async () => {
		h = setupGuard({
			policy: {
				language: "tr",
				workAccounts: {
					action: "block",
					unverified: "enforce",
					sites: { chatgpt: RULE(["ws-acme"]) },
				},
			},
			accountProbe: () => probe("https://chatgpt.com/", ""),
		});
		h.editor.value = "hello";
		h.enter();
		await expect.poll(() => h?.bubble()?.textContent ?? "").toContain("doğrulayamadı");
		expect(h.sent).toEqual([]);
	});

	it("block: also applies in monitor mode, and to uploads", async () => {
		const g = start("block", "_account=personal", { mode: "monitor" });
		g.editor.value = "hello";
		g.enter();
		expect(g.sent).toEqual([]);
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["hi"], "a.txt", { type: "text/plain" })]);
		input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("The file was not uploaded");
		expect(g.sanitizeFile).not.toHaveBeenCalled();
		expect(records(g).at(-1)).toMatchObject({
			action: "blocked",
			channel: "file",
			account: "personal",
		});
	});

	it("warn: the first send waits for Continue, then the next send goes through masked", async () => {
		const g = start("warn", "_account=ws-other");
		g.editor.value = `Mail ${EMAIL}`;
		g.enter();
		await expect
			.poll(() => g.bubble()?.textContent ?? "")
			.toContain("not one of your organisation");
		expect(g.sent).toEqual([]);
		expect(records(g).at(-1)).toMatchObject({ action: "warned", account: "other" });
		g.bubbleButton("account-continue")?.click();
		await expect.poll(() => g.toastText()).toContain("Press send again");
		g.enter();
		await expect.poll(() => g.sent.length).toBe(1);
		expect(g.sent[0]).not.toContain(EMAIL);
	});

	it("warn: Cancel keeps holding sends", async () => {
		const g = start("warn", "_account=personal");
		g.editor.value = "hello";
		g.enter();
		await expect.poll(() => g.bubbleButton("account-cancel")).not.toBeNull();
		g.bubbleButton("account-cancel")?.click();
		await expect.poll(() => g.bubble()).toBeNull();
		g.enter();
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("personal account");
		expect(g.sent).toEqual([]);
	});

	it("mask-only: monitor mode and send-original do not apply to a personal account", async () => {
		const g = start("mask-only", "_account=personal", { mode: "monitor", allowSendAnyway: true });
		g.editor.value = `Mail ${EMAIL}`;
		g.enter();
		await expect.poll(() => g.sent.length).toBe(1);
		expect(g.sent[0]).not.toContain(EMAIL);
		expect(g.toastText()).toContain(STRINGS.en.accountMaskOnly);
		expect(records(g).at(-1)).toMatchObject({ action: "masked", account: "personal" });
	});

	it("mask-only: confirm mode offers no Send original", async () => {
		const g = start("mask-only", "_account=personal", { mode: "confirm", allowSendAnyway: true });
		g.editor.value = `Mail ${EMAIL}`;
		g.enter();
		await expect.poll(() => g.bubbleButton("send-masked")).not.toBeNull();
		expect(g.bubbleButton("send-original")).toBeNull();
	});

	it("mask-only: the company account keeps monitor mode", async () => {
		const g = start("mask-only", "_account=ws-acme", { mode: "monitor" });
		g.editor.value = `Mail ${EMAIL}`;
		g.enter();
		expect(g.sent).toEqual([`Mail ${EMAIL}`]);
	});

	it("no workAccounts: no account field is recorded", async () => {
		h = setupGuard({ accountProbe: () => probe("https://chatgpt.com/", "_account=personal") });
		h.editor.value = `Mail ${EMAIL}`;
		h.enter();
		await expect.poll(() => h?.sent.length).toBe(1);
		expect(records(h).at(-1)?.account).toBeUndefined();
	});
});
