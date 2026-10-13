// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import type { GuardMessage, GuardPolicy, GuardStats } from "../types";
import type { ActiveTab, LocaleMessages, StorageAreaName, UiEnv } from "../ui/env";
import { applyI18n, formatClock, formatMessage } from "../ui/i18n";
import { startOptions } from "../ui/options-app";
import { RESTORE_VISIBLE_KEY, startPopup } from "../ui/popup-app";
import { blockedSiteFromUrl, renderBlocked } from "../ui/render-blocked";

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const LOCALES: Record<"en" | "tr", LocaleMessages> = {
	en: JSON.parse(readFileSync(join(PACKAGE_ROOT, "_locales/en/messages.json"), "utf8")),
	tr: JSON.parse(readFileSync(join(PACKAGE_ROOT, "_locales/tr/messages.json"), "utf8")),
};
const NOW = Date.UTC(2026, 8, 24, 12, 0, 0);

const BASE_POLICY: GuardPolicy = {
	version: 1,
	mode: "auto",
	enabledEntities: ["PERSON", "EMAIL", "PHONE", "IBAN", "SECRET"],
	neverRestore: ["SECRET", "PRIVATE_KEY"],
	literals: [{ value: "Project Falcon", type: "INTERNAL" }],
	exactData: [],
	detectSignals: true,
	signalAction: "warn",
	blockedSites: [],
	disabledSites: [],
	allowUserPause: true,
	allowSendAnyway: true,
	maskPaste: true,
	fileHandling: "scan",
	maxFileBytes: 5 * 1024 * 1024,
	restoreResponses: true,
	useNativeHost: false,
	telemetry: null,
	language: "auto",
	managedKeys: [],
	policyId: "aidr-browser-guard-default",
};

const BASE_STATS: GuardStats = {
	site: "chatgpt",
	protectedPrompts: 4,
	maskedItems: 9,
	blockedSends: 1,
	byType: { EMAIL: 5, IBAN: 3, SECRET: 1 },
	pausedUntil: null,
	nativeHost: "disabled",
	contentActive: true,
};

type Reply = unknown | ((message: GuardMessage) => unknown);

interface FakeEnv extends UiEnv {
	readonly sent: GuardMessage[];
	readonly session: Map<string, unknown>;
	policy: GuardPolicy;
	stats: GuardStats;
	tab: ActiveTab | null;
	/** Per-message-type override of the worker reply. */
	readonly replies: Partial<Record<GuardMessage["type"], Reply>>;
	optionsOpened: number;
	/** nativeMessaging granted? null: the permissions API is unavailable. */
	permission: boolean | null;
	/** Answer the user gives to the next permission prompt. */
	grant: boolean;
	permissionRequests: number;
	invalidate(area: StorageAreaName): void;
}

/** Default replies of the fake background worker (mirrors src/background/index.ts). */
function workerReply(env: FakeEnv, message: GuardMessage): unknown {
	switch (message.type) {
		case "GET_POLICY":
			return { ok: true, policy: env.policy };
		case "GET_STATS":
			return { ok: true, stats: env.stats };
		case "SET_USER_SETTINGS": {
			const locked = Object.keys(message.settings).filter((key) =>
				env.policy.managedKeys.includes(key),
			);
			if (locked.length > 0) return { ok: false, error: "LOCKED_KEYS", keys: locked };
			env.policy = { ...env.policy, ...message.settings } as GuardPolicy;
			return { ok: true, policy: env.policy };
		}
		case "PAUSE": {
			if (message.minutes > 0 && !env.policy.allowUserPause) {
				return { ok: false, error: "PAUSE_DISABLED" };
			}
			const pausedUntil = message.minutes === 0 ? null : NOW + message.minutes * 60_000;
			env.stats = { ...env.stats, pausedUntil };
			return { ok: true, pausedUntil };
		}
		case "SET_RESTORE_VISIBLE":
			return { ok: true };
		default:
			return { ok: false, error: "BAD_MESSAGE" };
	}
}

/** In-memory stand-in for the background worker and extension APIs. */
function fakeEnv(
	overrides: { policy?: Partial<GuardPolicy>; stats?: Partial<GuardStats> } = {},
): FakeEnv {
	const listeners: Array<{ areas: readonly StorageAreaName[]; listener: () => void }> = [];
	const env: FakeEnv = {
		sent: [],
		session: new Map(),
		policy: { ...BASE_POLICY, ...overrides.policy },
		stats: { ...BASE_STATS, ...overrides.stats },
		tab: { id: 7, url: "https://chatgpt.com/c/abc" },
		replies: {},
		optionsOpened: 0,
		async send(message) {
			env.sent.push(message);
			const override = env.replies[message.type];
			if (override !== undefined) {
				return typeof override === "function"
					? (override as (m: GuardMessage) => unknown)(message)
					: override;
			}
			return workerReply(env, message);
		},
		async getActiveTab() {
			return env.tab;
		},
		openOptionsPage() {
			env.optionsOpened++;
		},
		getVersion: () => "1.0.0",
		uiLanguage: () => "en-US",
		getMessage: (key, substitutions) => formatMessage(LOCALES.en, key, substitutions),
		async loadLocaleMessages(lang) {
			return LOCALES[lang];
		},
		async sessionGet(key) {
			return env.session.get(key);
		},
		async sessionSet(key, value) {
			env.session.set(key, value);
		},
		onInvalidate(areas, listener) {
			listeners.push({ areas, listener });
		},
		now: () => NOW,
		permission: false,
		grant: true,
		permissionRequests: 0,
		async hasPermission() {
			return env.permission;
		},
		requestPermission() {
			// Counted synchronously: the real API only prompts inside the user gesture.
			env.permissionRequests++;
			if (env.grant) env.permission = true;
			return Promise.resolve(env.grant);
		},
		invalidate(area) {
			for (const entry of listeners) if (entry.areas.includes(area)) entry.listener();
		},
	};
	return env;
}

async function settle(): Promise<void> {
	for (let i = 0; i < 5; i++) await new Promise((resolve) => setTimeout(resolve, 0));
}

function mountShell(): { app: HTMLElement; live: HTMLElement } {
	document.documentElement.lang = "en";
	document.body.innerHTML = '<main id="app"></main><div id="live" role="status"></div>';
	return {
		app: document.getElementById("app") as HTMLElement,
		live: document.getElementById("live") as HTMLElement,
	};
}

function text(selector: string): string {
	return document.querySelector(selector)?.textContent?.trim() ?? "";
}

function input(selector: string): HTMLInputElement {
	const element = document.querySelector(selector);
	if (!(element instanceof HTMLInputElement)) throw new Error(`no input ${selector}`);
	return element;
}

function change(element: HTMLInputElement | HTMLSelectElement, value?: string | boolean): void {
	if (typeof value === "boolean" && element instanceof HTMLInputElement) element.checked = value;
	else if (typeof value === "string") element.value = value;
	element.dispatchEvent(new Event("change", { bubbles: true }));
}

function type(element: HTMLInputElement, value: string): void {
	element.value = value;
	element.dispatchEvent(new Event("input", { bubbles: true }));
}

function click(selector: string): void {
	const element = document.querySelector(selector);
	if (!(element instanceof HTMLElement)) throw new Error(`no element ${selector}`);
	element.click();
}

function submit(selector: string): void {
	const form = document.querySelector(selector);
	if (!(form instanceof HTMLFormElement)) throw new Error(`no form ${selector}`);
	form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

function mutations(env: FakeEnv): GuardMessage[] {
	return env.sent.filter(
		(message) => message.type !== "GET_POLICY" && message.type !== "GET_STATS",
	);
}

async function openPopup(env: FakeEnv) {
	const controller = startPopup(document, env, mountShell());
	await controller.ready;
	return controller;
}

async function openOptions(env: FakeEnv) {
	const controller = startOptions(document, env, mountShell());
	await controller.ready;
	return controller;
}

beforeEach(() => {
	document.body.innerHTML = "";
});

describe("popup", () => {
	it("shows a protected tab with stats, top entity types and the pause action", async () => {
		const env = fakeEnv();
		await openPopup(env);
		expect(env.sent).toEqual([{ type: "GET_POLICY" }, { type: "GET_STATS", tabId: 7 }]);
		expect(text(".status__title")).toBe("Protected");
		expect(text(".status__detail")).toContain("ChatGPT");
		expect(document.querySelector(".status")?.classList.contains("status--ok")).toBe(true);
		expect([...document.querySelectorAll(".stat__value")].map((node) => node.textContent)).toEqual([
			"4",
			"9",
			"1",
		]);
		expect(
			[...document.querySelectorAll(".bar")].map((node) => node.getAttribute("data-entity")),
		).toEqual(["EMAIL", "IBAN", "SECRET"]);
		expect(text(".bar__label")).toBe("Email address");
		expect(text("#pause")).toBe("Pause for 15 min");
		expect(input("#popup-mode-auto").checked).toBe(true);
		expect(input("#restore-visible").checked).toBe(true);
		expect(input("#restore-visible").disabled).toBe(false);
		// Without the helper app, the popup says plainly that names are not checked.
		expect(text(".native")).toBe(
			"Names and addresses are not checked: advanced detection is off. Built-in rules are active.",
		);
	});

	it("names the modes plainly: Ask me, Count only (no masking)", async () => {
		const env = fakeEnv();
		await openPopup(env);
		const labels = [...document.querySelectorAll('label[for^="popup-mode-"]')].map((node) =>
			node.textContent?.trim(),
		);
		expect(labels).toEqual(["Auto-mask", "Ask me", "Block", "Count only (no masking)"]);
	});

	it("says when the tab is not a supported AI site", async () => {
		const env = fakeEnv({ stats: { site: null, byType: {} } });
		env.tab = { id: 3, url: "https://example.com/" };
		await openPopup(env);
		expect(text(".status__title")).toBe("Not a supported AI site");
		expect(document.getElementById("pause")).toBeNull();
		expect(input("#restore-visible").disabled).toBe(true);
		expect(text(".stats__empty")).toBe("No sensitive data found yet.");
	});

	it("says 'Not protected — reload' for an AI tab without a live content script (BG-7)", async () => {
		const env = fakeEnv({ stats: { site: null, byType: {}, contentActive: false } });
		await openPopup(env);
		expect(text(".status__title")).toBe("Not protected — reload this tab");
		expect(text(".status__detail")).toContain("ChatGPT");
		expect(document.querySelector(".status")?.classList.contains("status--danger")).toBe(true);
		expect(document.getElementById("pause")).toBeNull();
		expect(input("#restore-visible").disabled).toBe(true);
	});

	it("shows a policy error when managed values were invalid (BG-4)", async () => {
		const env = fakeEnv({ policy: { policyErrors: ["mode", "blockedSites"] } });
		await openPopup(env);
		expect(text("#policy-error")).toContain("2 invalid setting");
		const clean = fakeEnv();
		document.body.innerHTML = "";
		await openPopup(clean);
		expect(document.getElementById("policy-error")).toBeNull();
	});

	it("shows 'Paused until hh:mm' and resumes with PAUSE 0", async () => {
		const until = NOW + 10 * 60_000;
		const env = fakeEnv({ stats: { pausedUntil: until } });
		await openPopup(env);
		expect(text(".status__title")).toBe(`Paused until ${formatClock("en-US", until)}`);
		expect(document.getElementById("pause")).toBeNull();
		click("#resume");
		await settle();
		expect(mutations(env)).toEqual([{ type: "PAUSE", minutes: 0 }]);
		expect(text(".status__title")).toBe("Protected");
		expect(text("#live")).toBe("Protection resumed");
	});

	it("shows 'Disabled by policy' for a site the organisation turned off", async () => {
		const env = fakeEnv({ policy: { disabledSites: ["chatgpt"], managedKeys: ["disabledSites"] } });
		await openPopup(env);
		expect(text(".status__title")).toBe("Disabled by policy");
		expect(document.getElementById("pause")).toBeNull();
		expect(input("#restore-visible").disabled).toBe(true);
	});

	it("shows a site blocked by the organisation", async () => {
		const env = fakeEnv({ policy: { blockedSites: ["chatgpt"], managedKeys: ["blockedSites"] } });
		await openPopup(env);
		expect(text(".status__title")).toBe("Blocked by your organization");
	});

	it("sends SET_USER_SETTINGS when the mode changes", async () => {
		const env = fakeEnv();
		await openPopup(env);
		change(input("#popup-mode-block"), true);
		await settle();
		expect(mutations(env)).toEqual([{ type: "SET_USER_SETTINGS", settings: { mode: "block" } }]);
		expect(input("#popup-mode-block").checked).toBe(true);
		expect(text("#live")).toBe("Saved");
	});

	it("locks the mode control when managed, with a lock icon and explanation", async () => {
		const env = fakeEnv({ policy: { mode: "block", managedKeys: ["mode"] } });
		await openPopup(env);
		const fieldset = document.querySelector("fieldset.segmented") as HTMLFieldSetElement;
		expect(fieldset.disabled).toBe(true);
		expect(fieldset.classList.contains("is-locked")).toBe(true);
		const badge = fieldset.querySelector(".managed-badge");
		expect(badge?.querySelector("svg.icon")).not.toBeNull();
		expect(badge?.getAttribute("title")).toBe("Managed by your organization");
		expect(badge?.textContent).toContain("Managed by your organization");
		// A forged change event on the locked control must not reach the worker.
		change(input("#popup-mode-auto"), true);
		await settle();
		expect(mutations(env)).toEqual([]);
	});

	it("pauses for 15 minutes only when allowed", async () => {
		const env = fakeEnv();
		await openPopup(env);
		click("#pause");
		await settle();
		expect(mutations(env)).toEqual([{ type: "PAUSE", minutes: 15 }]);
		expect(text(".status__title")).toBe(`Paused until ${formatClock("en-US", NOW + 15 * 60_000)}`);

		const locked = fakeEnv({ policy: { allowUserPause: false } });
		await openPopup(locked);
		expect(document.getElementById("pause")).toBeNull();
	});

	it("toggles 'Show original values' with SET_RESTORE_VISIBLE and remembers it for the session", async () => {
		const env = fakeEnv();
		await openPopup(env);
		change(input("#restore-visible"), false);
		await settle();
		expect(mutations(env)).toEqual([{ type: "SET_RESTORE_VISIBLE", visible: false }]);
		expect(env.session.get(RESTORE_VISIBLE_KEY)).toBe(false);
		expect(input("#restore-visible").checked).toBe(false);
		expect(text("#live")).toBe("Answers show labels such as [EMAIL_1]");

		await openPopup(env);
		expect(input("#restore-visible").checked).toBe(false);
	});

	it("reports a rejected change instead of claiming it was saved", async () => {
		const env = fakeEnv();
		env.replies.SET_USER_SETTINGS = { ok: false, error: "LOCKED_KEYS", keys: ["mode"] };
		await openPopup(env);
		change(input("#popup-mode-confirm"), true);
		await settle();
		expect(text("#live")).toBe("This setting is managed by your organization.");
		expect(document.getElementById("live")?.className).toContain("notice--error");
		expect(input("#popup-mode-auto").checked).toBe(true);
	});

	it("shows an error with retry when the worker does not answer", async () => {
		const env = fakeEnv();
		env.replies.GET_POLICY = () => undefined;
		const controller = await openPopup(env);
		expect(controller.getState().phase).toBe("error");
		expect(text(".status__title")).toBe("Browser Guard is not responding");
		delete env.replies.GET_POLICY;
		click("#retry");
		await settle();
		expect(controller.getState().phase).toBe("ready");
		expect(text(".status__title")).toBe("Protected");
	});

	it("refreshes stats when storage changes and opens the options page", async () => {
		const env = fakeEnv();
		await openPopup(env);
		env.stats = { ...env.stats, maskedItems: 12 };
		env.invalidate("session");
		await settle();
		expect(document.querySelectorAll(".stat__value")[1]?.textContent).toBe("12");
		click("#open-options");
		expect(env.optionsOpened).toBe(1);
	});

	it("follows an explicit Turkish language setting", async () => {
		const env = fakeEnv({ policy: { language: "tr" } });
		await openPopup(env);
		expect(document.documentElement.lang).toBe("tr");
		expect(text(".status__title")).toBe("Korunuyor");
		expect(text("#pause")).toBe("15 dk duraklat");
	});
});

describe("options page", () => {
	it("shows a policy error when managed values were invalid (BG-4)", async () => {
		await openOptions(fakeEnv({ policy: { policyErrors: ["*"], managedKeys: ["mode"] } }));
		expect(text("#policy-error")).toContain("1 invalid setting");
	});

	it("renders every section and groups all entity toggles", async () => {
		const env = fakeEnv();
		await openOptions(env);
		expect([...document.querySelectorAll("section.section")].map((node) => node.id)).toEqual([
			"protection",
			"terms",
			"sites",
			"organization",
			"language",
			"about",
		]);
		expect(
			[...document.querySelectorAll(".entity-group legend")].map((node) => node.textContent),
		).toEqual(["Identity", "Contact", "Financial", "Technical", "Organization", "Other"]);
		expect(document.querySelectorAll('[data-action="toggle-entity"]')).toHaveLength(23);
		expect(input("#entity-EMAIL").checked).toBe(true);
		expect(input("#entity-USERNAME").checked).toBe(false);
		expect(document.querySelectorAll('[data-action="toggle-site"]')).toHaveLength(8);
		expect(text(".terms__value")).toBe("Project Falcon");
		expect(text(".facts dd")).toBe("1.0.0");
		expect(document.querySelector(".banner")).toBeNull();
		expect(text("#about")).toContain("Detection runs entirely in your browser");
	});

	it("renders every managed key read-only and never sends it", async () => {
		const managedKeys = [
			"mode",
			"enabledEntities",
			"literals",
			"disabledSites",
			"maskPaste",
			"restoreResponses",
			"language",
			"telemetry",
		];
		const env = fakeEnv({
			policy: {
				managedKeys,
				telemetry: { controlPlaneUrl: "https://aidr.example.com", apiKey: "secret-key-123" },
			},
		});
		await openOptions(env);
		expect(text(".banner")).toContain("managed by your organization");
		expect(
			(document.querySelector("#protection fieldset.segmented") as HTMLFieldSetElement).disabled,
		).toBe(true);
		for (const group of document.querySelectorAll<HTMLFieldSetElement>(".entity-group")) {
			expect(group.disabled).toBe(true);
		}
		expect(input("#mask-paste").disabled).toBe(true);
		expect(input("#restore-responses").disabled).toBe(true);
		for (const site of document.querySelectorAll<HTMLInputElement>('[data-action="toggle-site"]')) {
			expect(site.disabled).toBe(true);
		}
		expect((document.getElementById("language-select") as HTMLSelectElement).disabled).toBe(true);
		// Organisation terms are confidential: only their count is shown, no add form.
		expect(document.querySelector(".term-form")).toBeNull();
		expect(document.querySelector(".terms")).toBeNull();
		expect(document.body.textContent).not.toContain("Project Falcon");
		expect(text("#terms .terms__count")).toContain("1");
		// The telemetry form is replaced by the status line; the key never appears.
		expect(document.getElementById("telemetry-url")).toBeNull();
		expect(text("#connection-status")).toBe("Connected to https://aidr.example.com");
		expect(document.body.innerHTML).not.toContain("secret-key-123");

		change(input("#mask-paste"), false);
		change(input("#entity-EMAIL"), false);
		change(input("#opt-mode-monitor"), true);
		await settle();
		expect(mutations(env)).toEqual([]);
		expect(text("#live")).toBe("This setting is managed by your organization.");
	});

	it("locks individual keys while leaving the rest editable", async () => {
		const env = fakeEnv({ policy: { managedKeys: ["maskPaste"] } });
		await openOptions(env);
		expect(input("#mask-paste").disabled).toBe(true);
		expect(input("#restore-responses").disabled).toBe(false);
		expect(document.querySelector("#protection .switch-row .managed-badge")).not.toBeNull();
		change(input("#restore-responses"), false);
		await settle();
		expect(mutations(env)).toEqual([
			{ type: "SET_USER_SETTINGS", settings: { restoreResponses: false } },
		]);
	});

	it("toggles entities, paste masking and sites", async () => {
		const env = fakeEnv();
		await openOptions(env);
		change(input("#entity-EMAIL"), false);
		await settle();
		change(input("#mask-paste"), false);
		await settle();
		change(input("#site-claude"), false);
		await settle();
		expect(mutations(env)).toEqual([
			{
				type: "SET_USER_SETTINGS",
				settings: { enabledEntities: ["PERSON", "PHONE", "IBAN", "SECRET"] },
			},
			{ type: "SET_USER_SETTINGS", settings: { maskPaste: false } },
			{ type: "SET_USER_SETTINGS", settings: { disabledSites: ["claude"] } },
		]);
		expect(input("#entity-EMAIL").checked).toBe(false);
		expect(input("#site-claude").checked).toBe(false);
		expect(document.activeElement?.id).toBe("site-claude");
	});

	it("explains the native host and asks for nativeMessaging before turning it on", async () => {
		const env = fakeEnv();
		await openOptions(env);
		expect(text("#native-host")).toContain("never leaves this computer");
		expect(text("#native-permission")).toBe(
			"Permission to talk to the helper app has not been granted yet.",
		);
		expect(text("#native-status")).toContain("Advanced detection is off");
		expect(input("#native-host-toggle").checked).toBe(false);

		// Declined: nothing is saved and the switch stays off.
		env.grant = false;
		change(input("#native-host-toggle"), true);
		expect(env.permissionRequests).toBe(1); // requested synchronously, inside the gesture
		await settle();
		expect(mutations(env)).toEqual([]);
		expect(input("#native-host-toggle").checked).toBe(false);
		expect(text("#live")).toContain("Permission was not granted");

		// Granted: the setting is saved and the host status is shown.
		env.grant = true;
		env.stats = { ...env.stats, nativeHost: "connected" };
		change(input("#native-host-toggle"), true);
		expect(env.permissionRequests).toBe(2);
		await settle();
		expect(mutations(env)).toEqual([
			{ type: "SET_USER_SETTINGS", settings: { useNativeHost: true } },
		]);
		expect(input("#native-host-toggle").checked).toBe(true);
		expect(text("#native-permission")).toBe("Permission to talk to the helper app is granted.");
		expect(document.getElementById("native-grant")).toBeNull();
		expect(text("#native-status")).toBe("Advanced detection is connected");

		// Turning it off needs no prompt.
		change(input("#native-host-toggle"), false);
		await settle();
		expect(env.permissionRequests).toBe(2);
		expect(mutations(env).at(-1)).toEqual({
			type: "SET_USER_SETTINGS",
			settings: { useNativeHost: false },
		});
	});

	it("shows when an administrator made native NER mandatory", async () => {
		const optional = fakeEnv({ policy: { useNativeHost: true, managedKeys: ["useNativeHost"] } });
		await openOptions(optional);
		expect(document.getElementById("native-required")).toBeNull();
		const env = fakeEnv({
			policy: {
				useNativeHost: true,
				requireNativeNer: true,
				managedKeys: ["requireNativeNer", "useNativeHost"],
			},
			stats: { nativeHost: "unavailable" },
		});
		await openOptions(env);
		expect(input("#native-host-toggle").disabled).toBe(true);
		expect(text("#native-required")).toContain("Required by your organisation");
		expect(text("#native-required")).toContain("it is blocked");
	});

	it("offers a grant button when an administrator enabled the native host", async () => {
		const env = fakeEnv({
			policy: { useNativeHost: true, managedKeys: ["useNativeHost"] },
			stats: { nativeHost: "unavailable" },
		});
		await openOptions(env);
		expect(input("#native-host-toggle").disabled).toBe(true);
		expect(text("#native-status")).toBe(
			"Names and addresses are not checked: the AIDR Privacy helper app is not available. Built-in rules are active.",
		);
		click("#native-grant");
		expect(env.permissionRequests).toBe(1);
		await settle();
		expect(text("#native-permission")).toBe("Permission to talk to the helper app is granted.");
		expect(text("#live")).toContain("Permission granted.");
		expect(mutations(env)).toEqual([]);
	});

	it("says when the browser cannot grant the permission from the page", async () => {
		const env = fakeEnv();
		env.permission = null;
		await openOptions(env);
		expect(text("#native-permission")).toBe(
			"This browser cannot grant the permission from this page.",
		);
		expect(document.getElementById("native-grant")).toBeNull();
	});

	it("validates custom terms before sending them", async () => {
		const env = fakeEnv();
		await openOptions(env);
		type(input("#literal-value"), "x");
		submit(".term-form");
		await settle();
		expect(text(".field__error")).toBe("A term needs at least 2 characters.");
		expect(input("#literal-value").getAttribute("aria-invalid")).toBe("true");

		type(input("#literal-value"), "project falcon");
		submit(".term-form");
		await settle();
		expect(text(".field__error")).toBe("This term is already in the list.");

		type(input("#literal-value"), "y".repeat(257));
		submit(".term-form");
		await settle();
		expect(text(".field__error")).toBe("A term can have at most 256 characters.");
		expect(mutations(env)).toEqual([]);

		type(input("#literal-value"), "  ACME-Internal  ");
		change(document.getElementById("literal-type") as HTMLSelectElement, "PERSON");
		submit(".term-form");
		await settle();
		expect(mutations(env)).toEqual([
			{
				type: "SET_USER_SETTINGS",
				settings: {
					literals: [
						{ value: "Project Falcon", type: "INTERNAL" },
						{ value: "ACME-Internal", type: "PERSON" },
					],
				},
			},
		]);
		expect(document.querySelector(".field__error")).toBeNull();
		expect(input("#literal-value").value).toBe("");
		expect([...document.querySelectorAll(".terms__value")].map((node) => node.textContent)).toEqual(
			["Project Falcon", "ACME-Internal"],
		);
		expect(text("#live")).toBe("Term added");
	});

	it("renders custom terms as text, never markup, and removes them", async () => {
		const env = fakeEnv({
			policy: { literals: [{ value: '<img src=x onerror="alert(1)">', type: "INTERNAL" }] },
		});
		await openOptions(env);
		expect(document.querySelector("#terms img")).toBeNull();
		expect(text(".terms__value")).toBe('<img src=x onerror="alert(1)">');
		expect(document.getElementById("literal-remove-0")?.getAttribute("aria-label")).toBe(
			'Remove term <img src=x onerror="alert(1)">',
		);
		click("#literal-remove-0");
		await settle();
		expect(mutations(env)).toEqual([{ type: "SET_USER_SETTINGS", settings: { literals: [] } }]);
		expect(text(".terms__empty")).toBe("No custom terms yet.");
	});

	it("saves and removes the organisation connection", async () => {
		const env = fakeEnv();
		await openOptions(env);
		expect(text("#connection-status")).toBe("Not connected. Nothing leaves this browser.");
		expect(text("#organization")).toContain("Never shared:");

		type(input("#telemetry-url"), "http://aidr.example.com");
		type(input("#telemetry-key"), "key-12345678");
		submit('form[data-action="save-telemetry"]');
		await settle();
		expect(text("#telemetry-error")).toContain("https://");
		expect(mutations(env)).toEqual([]);

		type(input("#telemetry-url"), "https://aidr.example.com/");
		submit('form[data-action="save-telemetry"]');
		await settle();
		expect(mutations(env)).toEqual([
			{
				type: "SET_USER_SETTINGS",
				settings: {
					telemetry: { controlPlaneUrl: "https://aidr.example.com", apiKey: "key-12345678" },
				},
			},
		]);
		expect(text("#connection-status")).toBe("Connected to https://aidr.example.com");
		expect(input("#telemetry-key").value).toBe("");
		expect(input("#telemetry-key").type).toBe("password");

		click("#telemetry-disconnect");
		await settle();
		expect(mutations(env).at(-1)).toEqual({
			type: "SET_USER_SETTINGS",
			settings: { telemetry: null },
		});
		expect(text("#connection-status")).toBe("Not connected. Nothing leaves this browser.");
	});

	it("switches the page language", async () => {
		const env = fakeEnv();
		document.title = "";
		await openOptions(env);
		change(document.getElementById("language-select") as HTMLSelectElement, "tr");
		await settle();
		expect(mutations(env)).toEqual([{ type: "SET_USER_SETTINGS", settings: { language: "tr" } }]);
		expect(document.documentElement.lang).toBe("tr");
		expect(text("#protection-title")).toBe("Koruma");
		expect(text("#live")).toBe("Kaydedildi");
	});

	it("reloads when an administrator pushes a managed policy", async () => {
		const env = fakeEnv();
		await openOptions(env);
		expect(input("#mask-paste").disabled).toBe(false);
		env.policy = { ...env.policy, managedKeys: ["maskPaste"] };
		env.invalidate("managed");
		await settle();
		expect(input("#mask-paste").disabled).toBe(true);
	});

	it("shows the worker's error and the enforced policy when a save is rejected", async () => {
		const env = fakeEnv();
		env.replies.SET_USER_SETTINGS = { ok: false, error: "INVALID_SETTINGS", keys: ["maskPaste"] };
		await openOptions(env);
		change(input("#mask-paste"), false);
		await settle();
		expect(text("#live")).toBe("That value is not allowed. Please check it and try again.");
		expect(input("#mask-paste").checked).toBe(true);
	});
});

describe("blocked page", () => {
	it("names the blocked site and localises the static text", () => {
		document.body.innerHTML = `
			<h1 id="blocked-title" data-i18n="blocked_title">x</h1>
			<p data-i18n="blocked_body">x</p>`;
		const t = (key: string, subs?: string | readonly string[]) =>
			formatMessage(LOCALES.tr, key, subs);
		applyI18n(document, t);
		renderBlocked(
			document,
			t,
			blockedSiteFromUrl("chrome-extension://id/blocked.html?site=gemini"),
		);
		expect(text("#blocked-title")).toBe("Gemini kuruluşunuz tarafından engellendi");
		expect(text("p")).toContain("Browser Guard sayfanın açılmasını durdurdu");
		expect(document.title).toBe("Kuruluşunuz tarafından engellendi");

		renderBlocked(document, t, null);
		expect(text("#blocked-title")).toBe("Bu yapay zekâ hizmeti kuruluşunuz tarafından engellendi");
	});
});
