/**
 * Singularity AIDR Setup Assistant — the page. Plain DOM, no framework; every
 * dynamic text goes through textContent (never innerHTML), and the only network
 * access is same-origin fetch to the local server (CSP `default-src 'self'`).
 * Bundled by packages/cli/scripts/build-assistant-ui.mjs into the CLI.
 */
import { ASSISTANT_EN, ASSISTANT_TR } from "../../i18n/assistant-messages.js";
import type {
	AssistantState,
	DetectedTool,
	EnrollView,
	HostSetupResult,
	Locale,
	SetupEvent,
	SetupSummary,
	StatusReport,
	VerifyReport,
} from "../types.js";

const STEPS = ["welcome", "tools", "company", "protect", "verify", "browser", "done"] as const;
type Step = (typeof STEPS)[number];

export interface BootOptions {
	fetch?: typeof fetch;
	location?: Pick<Location, "hash">;
	history?: Pick<History, "replaceState">;
	/** Poll interval for setup progress, ms (tests). */
	progressMs?: number;
	/** Seconds-to-ms factor for enrollment polling (tests). */
	pollScale?: number;
}

class ApiError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
	) {
		super(code);
	}
}

interface Model {
	state: AssistantState | null;
	locale: Locale;
	step: number;
	tools: DetectedTool[] | null;
	selected: Set<string>;
	companyChoice: "local" | "connect";
	endpoint: string;
	enroll: EnrollView;
	setupRunning: boolean;
	setupEvents: SetupEvent[];
	setupResult: SetupSummary | null;
	setupError: string | null;
	verify: VerifyReport | null;
	verifying: boolean;
	status: StatusReport | null;
	closed: boolean;
	fatal: "expired" | "lost" | null;
	error: string | null;
	busy: boolean;
}

type Child = Node | string | null | undefined | false;

function h(
	tag: string,
	attrs: Record<string, string | boolean | undefined> = {},
	...children: Child[]
) {
	const element = document.createElement(tag);
	for (const [name, value] of Object.entries(attrs)) {
		if (value === undefined || value === false) continue;
		element.setAttribute(name, value === true ? "" : value);
	}
	for (const child of children) {
		if (child === null || child === undefined || child === false) continue;
		element.append(typeof child === "string" ? document.createTextNode(child) : child);
	}
	return element;
}

/** "Singularity AIDR" always in English casing rules. */
function withBrand(text: string): Node {
	const fragment = document.createDocumentFragment();
	const parts = text.split("Singularity AIDR");
	parts.forEach((part, index) => {
		if (index > 0) fragment.append(h("span", { lang: "en" }, "Singularity AIDR"));
		if (part) fragment.append(document.createTextNode(part));
	});
	return fragment;
}

export function boot(root: HTMLElement, options: BootOptions = {}) {
	const fetcher = options.fetch ?? window.fetch.bind(window);
	const loc = options.location ?? window.location;
	const hist = options.history ?? window.history;
	const progressMs = options.progressMs ?? 700;
	const pollScale = options.pollScale ?? 1000;
	const timers = new Set<ReturnType<typeof setTimeout>>();

	const model: Model = {
		state: null,
		// Until the server answers, follow the browser; then the CLI locale.
		locale: /^tr\b/iu.test(navigator.language ?? "") ? "tr" : "en",
		step: 0,
		tools: null,
		selected: new Set(),
		companyChoice: "local",
		endpoint: "",
		enroll: { phase: "idle" },
		setupRunning: false,
		setupEvents: [],
		setupResult: null,
		setupError: null,
		verify: null,
		verifying: false,
		status: null,
		closed: false,
		fatal: null,
		error: null,
		busy: false,
	};

	function t(key: string, params: Record<string, string | number> = {}): string {
		const catalog: Record<string, string> = model.locale === "tr" ? ASSISTANT_TR : ASSISTANT_EN;
		const template = catalog[key] ?? (ASSISTANT_EN as Record<string, string>)[key] ?? key;
		return template.replace(/\{(\w+)\}/g, (match, name: string) =>
			params[name] === undefined ? match : String(params[name]),
		);
	}

	function later(fn: () => void, ms: number): void {
		const timer = setTimeout(() => {
			timers.delete(timer);
			fn();
		}, ms);
		timers.add(timer);
	}

	function stopTimers(): void {
		for (const timer of timers) clearTimeout(timer);
		timers.clear();
	}

	async function api<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
		let response: Response;
		try {
			response = await fetcher(path, {
				method,
				credentials: "same-origin",
				headers: method === "POST" ? { "Content-Type": "application/json" } : {},
				body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
			});
		} catch {
			throw new ApiError(0, "unreachable");
		}
		let parsed: unknown = null;
		try {
			parsed = await response.json();
		} catch {
			parsed = null;
		}
		if (!response.ok) {
			const code = (parsed as { error?: string } | null)?.error ?? `http_${response.status}`;
			throw new ApiError(response.status, code);
		}
		return parsed as T;
	}

	/** A lost session or server ends the wizard with a plain explanation. */
	function fail(error: unknown): void {
		if (error instanceof ApiError && error.status === 401) model.fatal = "expired";
		else if (error instanceof ApiError && error.status === 0) model.fatal = "lost";
		else model.error = error instanceof Error ? error.message : String(error);
		model.busy = false;
		render();
	}

	const live = h("div", { class: "sr-only", "aria-live": "polite", role: "status" });
	function announce(text: string): void {
		live.textContent = text;
	}

	// ── Steps ────────────────────────────────────────────────────────────

	function badgeTone(state: string): string {
		if (state === "installed") return "tone-ok";
		if (state === "runtime_present_not_installed") return "tone-info";
		if (state === "not_detected") return "tone-muted";
		return "tone-warn";
	}

	function welcome(): Node[] {
		return [
			h("p", {}, withBrand(t("welcome.body"))),
			h("p", { class: "muted" }, t("welcome.local")),
			h("p", { class: "muted" }, t("welcome.time")),
		];
	}

	function tools(): Node[] {
		if (!model.tools) return [h("p", { class: "muted" }, t("ui.working"))];
		const found = model.tools.filter((tool) => tool.state !== "not_detected");
		const list = h("ul", { class: "list" });
		for (const tool of model.tools) {
			const missing = tool.state === "not_detected";
			const id = `tool-${tool.id}`;
			const box = h("input", {
				type: "checkbox",
				id,
				name: "tools",
				value: tool.id,
				disabled: missing,
				checked: !missing && model.selected.has(tool.id),
				"aria-describedby": `${id}-state`,
			}) as HTMLInputElement;
			box.addEventListener("change", () => {
				if (box.checked) model.selected.add(tool.id);
				else model.selected.delete(tool.id);
				render();
			});
			list.append(
				h(
					"li",
					{ class: missing ? "item disabled" : "item" },
					h(
						"label",
						{ for: id },
						box,
						h("span", { class: "title" }, tool.label),
						tool.preview ? h("span", { class: "badge tone-muted" }, t("ui.preview")) : null,
					),
					h(
						"span",
						{ id: `${id}-state`, class: `badge ${badgeTone(tool.state)}` },
						t(`badge.${tool.state}`),
					),
				),
			);
		}
		const rescan = h(
			"button",
			{ type: "button", id: "tools-rescan", class: "button secondary" },
			t("tools.rescan"),
		);
		rescan.addEventListener("click", () => void detect());
		return [
			h("p", {}, withBrand(t("tools.body"))),
			list,
			found.length === 0 ? notice("tone-warn", t("tools.none")) : null,
			found.length > 0 && model.selected.size === 0
				? notice("tone-info", t("tools.noneSelected"))
				: null,
			h("div", { class: "row" }, rescan),
		].filter(Boolean) as Node[];
	}

	function notice(tone: string, text: string, role?: string): HTMLElement {
		return h("div", { class: `notice ${tone}`, role }, h("p", {}, withBrand(text)));
	}

	function radio(value: "local" | "connect", title: string, hint: string): HTMLElement {
		const id = `company-${value}`;
		const input = h("input", {
			type: "radio",
			name: "company",
			id,
			value,
			checked: model.companyChoice === value,
			"aria-describedby": `${id}-hint`,
		}) as HTMLInputElement;
		input.addEventListener("change", () => {
			if (input.checked) {
				model.companyChoice = value;
				render();
			}
		});
		return h(
			"div",
			{ class: "item" },
			h(
				"div",
				{ class: "body" },
				h("label", { for: id }, input, h("span", { class: "title" }, title)),
				h("p", { id: `${id}-hint`, class: "muted" }, hint),
			),
		);
	}

	function company(): Node[] {
		const state = model.state;
		const nodes: Node[] = [h("p", {}, withBrand(t("company.body")))];
		if (state?.company?.enrolled && model.enroll.phase !== "enrolled") {
			nodes.push(notice("tone-ok", t("company.already", { url: state.company.endpoint })));
			return nodes;
		}
		nodes.push(
			h(
				"fieldset",
				{ class: "choice" },
				h("legend", { class: "sr-only" }, t("company.heading")),
				radio("local", t("company.local"), t("company.localHint")),
				radio("connect", t("company.connect"), t("company.connectHint")),
			),
		);
		if (state?.pendingIgnored) nodes.push(notice("tone-warn", t("company.pendingIgnored")));
		if (model.companyChoice === "local") {
			nodes.push(h("p", { class: "muted" }, t("company.skipHint")));
			return nodes;
		}
		const enroll = model.enroll;
		if (enroll.phase === "enrolled") {
			nodes.push(
				notice("tone-ok", t("company.connected", { url: enroll.endpoint ?? "" }), "status"),
			);
			return nodes;
		}
		if (enroll.phase === "waiting") {
			nodes.push(...waiting(enroll));
			return nodes;
		}
		const pending = state?.pending;
		if (pending && model.endpoint === pending.endpoint) {
			nodes.push(
				notice(
					"tone-info",
					t(pending.hasToken ? "company.fromInstallerToken" : "company.fromInstaller", {
						url: pending.endpoint,
					}),
				),
			);
		}
		const input = h("input", {
			type: "url",
			id: "company-url",
			name: "company-url",
			inputmode: "url",
			autocomplete: "url",
			placeholder: "https://",
			value: model.endpoint,
			required: true,
		}) as HTMLInputElement;
		input.addEventListener("input", () => {
			model.endpoint = input.value;
		});
		nodes.push(
			h("div", { class: "field" }, h("label", { for: "company-url" }, t("company.url")), input),
		);
		if (enroll.phase === "error" || enroll.phase === "denied" || enroll.phase === "repair") {
			nodes.push(
				notice(
					enroll.phase === "repair" ? "tone-warn" : "tone-bad",
					t(enroll.message ?? "company.failed", {
						url: enroll.endpoint ?? model.endpoint,
						code: enroll.code ?? "",
					}),
					"alert",
				),
			);
		}
		if (enroll.phase === "expired") nodes.push(notice("tone-warn", t("company.expired"), "alert"));
		const useToken = Boolean(pending?.hasToken && model.endpoint.trim() === pending.endpoint);
		const start = h(
			"button",
			{
				type: "button",
				id: "company-start",
				class: "button",
				disabled: model.busy || enroll.phase === "repair",
			},
			model.busy
				? t("ui.working")
				: useToken
					? t("company.connectNow")
					: enroll.phase === "expired"
						? t("company.newCode")
						: t("company.getCode"),
		);
		start.addEventListener("click", () => void enrollStart(useToken));
		nodes.push(h("div", { class: "row" }, start));
		return nodes;
	}

	function waiting(enroll: EnrollView): Node[] {
		const link = h(
			"a",
			{
				class: "button",
				href: enroll.verificationUrl ?? "#",
				target: "_blank",
				rel: "noopener noreferrer",
			},
			t("company.openPage"),
		);
		const cancel = h(
			"button",
			{ type: "button", id: "company-cancel", class: "button secondary" },
			t("company.cancel"),
		);
		cancel.addEventListener("click", () => void enrollCancel());
		const expires = enroll.expiresAt ? new Date(enroll.expiresAt) : null;
		return [
			h("h2", {}, t("company.code")),
			h("div", { class: "code", "aria-label": t("company.code") }, enroll.userCode ?? ""),
			h("p", {}, t("company.codeHelp")),
			h("div", { class: "row" }, link, cancel),
			h("p", { class: "muted", role: "status" }, t("company.waiting")),
			expires
				? h(
						"p",
						{ class: "muted" },
						t("company.expiresAt", {
							time: expires.toLocaleTimeString(model.locale === "tr" ? "tr-TR" : "en-GB", {
								hour: "2-digit",
								minute: "2-digit",
							}),
						}),
					)
				: null,
		].filter(Boolean) as Node[];
	}

	/** Copies a manual step for the person's own terminal; hidden where the clipboard is unavailable. */
	function copyButton(text: string): HTMLElement | null {
		const clipboard = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
		if (!clipboard) return null;
		const copy = h("button", { type: "button", class: "button secondary" }, t("ui.copy"));
		copy.addEventListener("click", () => {
			clipboard.writeText(text).then(
				() => {
					copy.textContent = t("ui.copied");
					announce(t("ui.copied"));
				},
				() => {},
			);
		});
		return h("div", { class: "row" }, copy);
	}

	function hostResultNode(result: HostSetupResult): HTMLElement {
		const tone =
			result.outcome === "protected"
				? "tone-ok"
				: result.outcome === "restart"
					? "tone-info"
					: result.outcome === "manual"
						? "tone-warn"
						: "tone-bad";
		const text =
			result.outcome === "protected"
				? t("protect.protected")
				: result.outcome === "restart"
					? t("protect.restart", { tool: result.label })
					: result.outcome === "manual"
						? t("protect.manual")
						: result.outcome === "failed"
							? t("protect.failed", { tool: result.label })
							: t("protect.notSelected");
		return h(
			"li",
			{ class: "item" },
			h(
				"div",
				{ class: "body" },
				h("div", { class: "title" }, result.label),
				h("p", { class: "muted" }, text),
				// The exact commands of a manual step, to copy into the person's own terminal.
				result.outcome === "manual" && result.steps.length > 0
					? h("div", {}, h("pre", {}, result.steps.join("\n")), copyButton(result.steps.join("\n")))
					: null,
				h(
					"details",
					{},
					h("summary", {}, t("ui.details")),
					h(
						"pre",
						{},
						[result.detail, ...(result.outcome === "manual" ? [] : result.steps)].join("\n"),
					),
				),
			),
			h("span", { class: `badge ${tone}` }, t(`outcome.${result.outcome}`)),
		);
	}

	function protect(): Node[] {
		const nodes: Node[] = [h("p", {}, withBrand(t("protect.body")))];
		const done = new Map<string, HostSetupResult>();
		let running: string | null = null;
		let rules = 0;
		for (const event of model.setupEvents) {
			if (event.type === "rules") rules = event.rules;
			if (event.type === "host-start") running = event.id;
			if (event.type === "host-done") {
				done.set(event.result.id, event.result);
				if (running === event.result.id) running = null;
			}
		}
		if (rules > 0) nodes.push(h("p", { class: "muted" }, t("protect.rules", { rules })));
		else if (model.setupRunning) nodes.push(h("p", { class: "muted" }, t("protect.preparing")));
		const list = h("ul", { class: "list" });
		for (const tool of model.tools ?? []) {
			if (!model.selected.has(tool.id)) continue;
			const result = done.get(tool.id);
			if (result) {
				list.append(hostResultNode(result));
				continue;
			}
			const active = running === tool.id;
			list.append(
				h(
					"li",
					{ class: "item" },
					h("span", { class: "title" }, tool.label),
					h(
						"span",
						{ class: `badge ${active ? "tone-info" : "tone-muted"}` },
						active ? t("protect.running", { tool: tool.label }) : t("protect.waiting"),
					),
				),
			);
		}
		nodes.push(list);
		const failure = model.setupResult?.failure;
		if (failure)
			nodes.push(notice("tone-bad", t(failure.key, { detail: failure.detail }), "alert"));
		if (model.setupError) {
			nodes.push(
				notice("tone-bad", t("protect.setupFailed", { detail: model.setupError }), "alert"),
			);
		}
		if (!model.setupResult || failure || model.setupError) {
			const start = h(
				"button",
				{ type: "button", id: "protect-start", class: "button", disabled: model.setupRunning },
				model.setupRunning
					? t("ui.working")
					: model.setupResult
						? t("ui.retry")
						: t("protect.start"),
			);
			start.addEventListener("click", () => void runSetup());
			nodes.push(h("div", { class: "row" }, start));
		}
		return nodes;
	}

	function verify(): Node[] {
		const nodes: Node[] = [h("p", {}, withBrand(t("verify.body")))];
		const report = model.verify;
		if (report) {
			const list = h("ul", { class: "list" });
			for (const host of report.hosts) {
				if (host.outcome === "not_registered" && !model.selected.has(host.id)) continue;
				const tone =
					host.outcome === "pass" ? "tone-ok" : host.outcome === "fail" ? "tone-bad" : "tone-muted";
				const text =
					host.outcome === "pass"
						? t("verify.pass")
						: host.outcome === "fail"
							? t("verify.fail")
							: host.outcome === "skip"
								? t("verify.skip", { tool: host.label })
								: t("verify.notRegistered");
				list.append(
					h(
						"li",
						{ class: "item" },
						h(
							"div",
							{ class: "body" },
							h("div", { class: "title" }, host.label),
							h("p", {}, withBrand(text)),
							host.outcome === "fail"
								? h("p", { class: "muted" }, withBrand(t("verify.failHelp", { tool: host.label })))
								: null,
							h("details", {}, h("summary", {}, t("ui.details")), h("pre", {}, host.detail)),
						),
						h(
							"span",
							{ class: `badge ${tone}` },
							host.outcome === "not_registered"
								? t("verify.notRegistered")
								: host.outcome.toUpperCase(),
						),
					),
				);
			}
			nodes.push(list);
			const passed = report.hosts.filter((host) => host.outcome === "pass").length;
			const failed = report.hosts.filter((host) => host.outcome === "fail").length;
			nodes.push(
				failed > 0
					? notice("tone-bad", t("verify.summaryFail", { count: failed }), "status")
					: passed > 0
						? notice("tone-ok", t("verify.summaryPass", { count: passed }), "status")
						: notice("tone-muted", t("verify.summaryNone"), "status"),
			);
		}
		const run = h(
			"button",
			{
				type: "button",
				id: "verify-run",
				class: report ? "button secondary" : "button",
				disabled: model.verifying,
			},
			model.verifying ? t("ui.working") : report ? t("verify.again") : t("verify.start"),
		);
		run.addEventListener("click", () => void runVerify());
		nodes.push(h("div", { class: "row" }, run));
		return nodes;
	}

	function browser(): Node[] {
		const links = model.state?.browserGuard;
		const stores = [
			[links?.chrome, t("browser.chrome")],
			[links?.edge, t("browser.edge")],
			[links?.firefox, t("browser.firefox")],
		].filter((entry): entry is [string, string] => typeof entry[0] === "string");
		const external = (href: string, label: string, primary = true) =>
			h(
				"a",
				{
					class: primary ? "button" : "button secondary",
					href,
					target: "_blank",
					rel: "noopener noreferrer",
				},
				label,
			);
		return [
			h("p", {}, withBrand(t("browser.body"))),
			stores.length > 0
				? h("div", { class: "row" }, ...stores.map(([href, label]) => external(href, label)))
				: notice("tone-info", t("browser.noLinks")),
			links
				? h("div", { class: "row" }, external(links.downloads, t("browser.dashboard"), false))
				: null,
			h("p", { class: "muted" }, withBrand(t("browser.installed"))),
		].filter(Boolean) as Node[];
	}

	function doneStep(): Node[] {
		if (model.closed) return [notice("tone-ok", t("done.closed"), "status")];
		const status = model.status;
		const none = t("done.none");
		const close = h(
			"button",
			{ type: "button", id: "done-close", class: "button" },
			t("done.close"),
		);
		close.addEventListener("click", () => void finish());
		return [
			h("p", {}, withBrand(t("done.restart"))),
			status
				? h(
						"p",
						{ class: "muted" },
						t("done.summary", {
							protected: status.protected.join(", ") || none,
							restart: status.restart.join(", ") || none,
							manual:
								status.manual.map((entry) => `${entry.label} → ${entry.command}`).join("; ") ||
								none,
						}),
					)
				: null,
			h(
				"div",
				{ class: "row" },
				model.state
					? h(
							"a",
							{
								class: "button secondary",
								href: model.state.dashboard,
								target: "_blank",
								rel: "noopener noreferrer",
							},
							t("done.dashboard"),
						)
					: null,
			),
			h("h2", {}, t("done.quickstart")),
			h(
				"ol",
				{ class: "steps" },
				...["done.qs1", "done.qs2", "done.qs3", "done.qs4"].map((key) =>
					h("li", {}, withBrand(t(key))),
				),
			),
			h("p", { class: "muted" }, t("done.again")),
			h("div", { class: "row" }, close),
		].filter(Boolean) as Node[];
	}

	const STEP_VIEW: Record<Step, () => Node[]> = {
		welcome,
		tools,
		company,
		protect,
		verify,
		browser,
		done: doneStep,
	};

	const HEADINGS: Record<Step, string> = {
		welcome: "welcome.heading",
		tools: "tools.heading",
		company: "company.heading",
		protect: "protect.heading",
		verify: "verify.heading",
		browser: "browser.heading",
		done: "done.heading",
	};

	function canAdvance(step: Step): boolean {
		if (model.busy) return false;
		if (step === "tools") return model.selected.size > 0;
		if (step === "protect")
			return model.setupResult !== null && !model.setupRunning && !model.setupResult.failure;
		if (step === "verify") return !model.verifying;
		return true;
	}

	// ── Actions ──────────────────────────────────────────────────────────

	async function detect(): Promise<void> {
		try {
			const found = await api<DetectedTool[]>("POST", "/api/detect");
			const first = model.tools === null;
			model.tools = found;
			if (first) {
				for (const tool of found) if (tool.state !== "not_detected") model.selected.add(tool.id);
			}
			for (const id of [...model.selected]) {
				if (!found.some((tool) => tool.id === id && tool.state !== "not_detected"))
					model.selected.delete(id);
			}
			render();
		} catch (error) {
			fail(error);
		}
	}

	async function enrollStart(useInstallerToken: boolean): Promise<void> {
		model.busy = true;
		model.error = null;
		render();
		try {
			model.enroll = await api<EnrollView>("POST", "/api/enroll/start", {
				endpoint: model.endpoint,
				useInstallerToken,
			});
			model.busy = false;
			render();
			if (model.enroll.phase === "waiting") schedulePoll();
		} catch (error) {
			fail(error);
		}
	}

	function schedulePoll(): void {
		const interval = Math.max(1, model.enroll.interval ?? 5);
		later(async () => {
			if (model.enroll.phase !== "waiting") return;
			try {
				model.enroll = await api<EnrollView>("POST", "/api/enroll/poll");
				if (model.enroll.phase === "enrolled")
					announce(t("company.connected", { url: model.enroll.endpoint ?? "" }));
				render();
				if (model.enroll.phase === "waiting") schedulePoll();
			} catch (error) {
				fail(error);
			}
		}, interval * pollScale);
	}

	async function enrollCancel(): Promise<void> {
		stopTimers();
		try {
			model.enroll = await api<EnrollView>("POST", "/api/enroll/cancel");
		} catch (error) {
			fail(error);
			return;
		}
		render();
	}

	async function runSetup(): Promise<void> {
		model.setupRunning = true;
		model.setupEvents = [];
		model.setupResult = null;
		model.setupError = null;
		render();
		try {
			await api("POST", "/api/setup", { hosts: [...model.selected] });
		} catch (error) {
			model.setupRunning = false;
			if (error instanceof ApiError && (error.status === 401 || error.status === 0))
				return fail(error);
			model.setupError = error instanceof Error ? error.message : String(error);
			render();
			return;
		}
		const tick = async () => {
			try {
				const job = await api<{
					events: SetupEvent[];
					done: boolean;
					result: SetupSummary | null;
					error: string | null;
				}>("GET", "/api/setup");
				const before = model.setupEvents.length;
				model.setupEvents = job.events;
				for (const event of job.events.slice(before)) {
					if (event.type === "host-start") announce(t("protect.running", { tool: event.label }));
				}
				if (job.done) {
					model.setupRunning = false;
					model.setupResult = job.result;
					model.setupError = job.error;
				}
				render();
				if (!job.done) later(() => void tick(), progressMs);
			} catch (error) {
				model.setupRunning = false;
				fail(error);
			}
		};
		later(() => void tick(), progressMs);
	}

	async function runVerify(): Promise<void> {
		model.verifying = true;
		render();
		try {
			model.verify = await api<VerifyReport>("POST", "/api/verify");
			model.verifying = false;
			render();
		} catch (error) {
			model.verifying = false;
			fail(error);
		}
	}

	async function loadStatus(): Promise<void> {
		try {
			model.status = await api<StatusReport>("GET", "/api/status");
			render();
		} catch (error) {
			fail(error);
		}
	}

	async function finish(): Promise<void> {
		stopTimers();
		try {
			await api("POST", "/api/finish");
		} catch {
			// The server may already be gone; the page says it has stopped either way.
		}
		model.closed = true;
		render();
	}

	function go(step: number): void {
		const from = STEPS[model.step];
		if (from === "company" && model.enroll.phase === "waiting" && step > model.step) {
			void enrollCancel();
		}
		model.step = Math.max(0, Math.min(STEPS.length - 1, step));
		model.error = null;
		const name = STEPS[model.step];
		if (name === "tools" && model.tools === null) void detect();
		if (name === "verify" && model.verify === null && !model.verifying) void runVerify();
		if (name === "done") void loadStatus();
		render(true);
	}

	// ── Rendering ────────────────────────────────────────────────────────

	function header(): HTMLElement {
		const select = h(
			"select",
			{ id: "lang", name: "lang" },
			h("option", { value: "en", lang: "en", selected: model.locale === "en" }, "English"),
			h("option", { value: "tr", lang: "tr", selected: model.locale === "tr" }, "Türkçe"),
		) as HTMLSelectElement;
		select.addEventListener("change", () => {
			model.locale = select.value === "tr" ? "tr" : "en";
			try {
				window.sessionStorage.setItem("aidr-assistant-lang", model.locale);
			} catch {
				// Storage unavailable: the choice lasts for this page only.
			}
			render();
			(root.querySelector("#lang") as HTMLElement | null)?.focus();
		});
		return h(
			"header",
			{ class: "topbar" },
			h(
				"div",
				{ class: "brand" },
				h("img", { src: "/icon.svg", alt: "" }),
				h("div", {}, h("span", { lang: "en" }, "Singularity AIDR"), h("small", {}, t("ui.title"))),
			),
			h("div", { class: "lang" }, h("label", { for: "lang" }, t("ui.language")), select),
		);
	}

	function render(focusHeading = false): void {
		// Every render rebuilds the page; keyboard focus stays on the control it was on.
		const focused = root.contains(document.activeElement) ? document.activeElement?.id : undefined;
		document.documentElement.lang = model.locale;
		document.title = `Singularity AIDR — ${t("ui.title")}`;
		root.replaceChildren();
		root.append(header());
		if (model.fatal) {
			root.append(
				h(
					"main",
					{ class: "card" },
					h("h1", { tabindex: "-1" }, t("ui.title")),
					notice(
						"tone-bad",
						t(model.fatal === "expired" ? "ui.expired" : "ui.connectionLost"),
						"alert",
					),
				),
				live,
			);
			return;
		}
		if (!model.state) {
			root.append(h("main", { class: "card" }, h("p", { class: "muted" }, t("ui.working"))), live);
			return;
		}
		const step = STEPS[model.step];
		const stepper = h("ol", { class: "stepper", "aria-label": t("ui.steps") });
		STEPS.forEach((name, index) => {
			stepper.append(
				h(
					"li",
					{
						class: index < model.step ? "done" : undefined,
						"aria-current": index === model.step ? "step" : undefined,
					},
					t(`step.${name}`),
				),
			);
		});
		const heading = h("h1", { tabindex: "-1", id: "step-heading" }, t(HEADINGS[step]));
		const back = h(
			"button",
			{ type: "button", id: "nav-back", class: "button secondary" },
			t("ui.back"),
		);
		back.addEventListener("click", () => go(model.step - 1));
		const next = h(
			"button",
			{ type: "button", id: "nav-next", class: "button", disabled: !canAdvance(step) },
			step === "welcome" ? t("welcome.start") : t("ui.next"),
		);
		next.addEventListener("click", () => go(model.step + 1));
		const nav = h(
			"div",
			{ class: "nav" },
			model.step > 0 && !model.closed ? back : h("span", {}),
			step !== "done" ? next : h("span", {}),
		);
		root.append(
			stepper,
			h(
				"main",
				{ class: "card", "aria-labelledby": "step-heading" },
				h("p", { class: "muted" }, t("ui.step", { current: model.step + 1, total: STEPS.length })),
				heading,
				model.error ? notice("tone-bad", t("ui.error", { detail: model.error }), "alert") : null,
				...STEP_VIEW[step](),
				nav,
			),
			live,
		);
		const again = focused ? document.getElementById(focused) : null;
		if (focusHeading || (focused && !again)) heading.focus();
		else again?.focus();
	}

	async function start(): Promise<void> {
		render();
		const match = /(?:^#|&)t=([0-9a-f]{64})(?:&|$)/u.exec(loc.hash ?? "");
		// Drop the one-time token from the address bar and history at once.
		if (loc.hash) hist.replaceState(null, "", "/");
		if (match) {
			try {
				await api("POST", "/api/session", { token: match[1] });
			} catch (error) {
				// A reload after a successful exchange keeps its cookie; /api/state decides.
				if (!(error instanceof ApiError && error.status === 403)) return fail(error);
			}
		}
		try {
			model.state = await api<AssistantState>("GET", "/api/state");
		} catch (error) {
			return fail(error);
		}
		let stored: string | null = null;
		try {
			stored = window.sessionStorage.getItem("aidr-assistant-lang");
		} catch {
			stored = null;
		}
		model.locale = stored === "tr" || stored === "en" ? stored : model.state.locale;
		if (model.state.pending && !model.state.company?.enrolled) {
			model.companyChoice = "connect";
			model.endpoint = model.state.pending.endpoint;
		} else if (model.state.company && !model.state.company.enrolled) {
			model.endpoint = model.state.company.endpoint;
		}
		render(true);
	}

	const ready = start();
	return { ready, model, stop: stopTimers };
}

const script =
	typeof document !== "undefined" ? (document.currentScript as HTMLScriptElement | null) : null;
if (script?.src.endsWith("/app.js")) {
	const root = document.getElementById("app");
	if (root) boot(root);
}
