import type {
	ActionResult,
	AidrBridge,
	AppInfo,
	AuditEvent,
	BrowserGuardStatus,
	ConnectorView,
	ConnectPreview,
	Decision,
	Lang,
	SelfTestCase,
	SelfTestResult,
	StatusSnapshot,
} from "../shared/contract.js";
import { type MessageKey, translate } from "../shared/i18n.js";

declare global {
	interface Window {
		aidr: AidrBridge;
	}
}

const api = window.aidr;

type Page = "status" | "selftest" | "activity" | "browserGuard" | "settings";
const PAGES: Array<{ id: Page; key: MessageKey }> = [
	{ id: "status", key: "nav.status" },
	{ id: "selftest", key: "nav.selftest" },
	{ id: "activity", key: "nav.activity" },
	{ id: "browserGuard", key: "nav.browserGuard" },
	{ id: "settings", key: "nav.settings" },
];

interface State {
	page: Page;
	info: AppInfo | null;
	status: StatusSnapshot | null;
	statusError: string | null;
	selfTest: SelfTestResult | null;
	selfTestRunning: boolean;
	events: AuditEvent[];
	freshIds: Set<string>;
	filter: "all" | Decision;
	search: string;
	hideSelfTest: boolean;
	browserGuard: BrowserGuardStatus | null;
	lastAction: { kind: "connect" | "disconnect"; result: ActionResult } | null;
	busy: string | null;
}

const state: State = {
	page: "status",
	info: null,
	status: null,
	statusError: null,
	selfTest: null,
	selfTestRunning: false,
	events: [],
	freshIds: new Set(),
	filter: "all",
	search: "",
	hideSelfTest: false,
	browserGuard: null,
	lastAction: null,
	busy: null,
};

const lang = (): Lang => state.info?.language ?? "en";
const t = (key: MessageKey, params?: Record<string, string | number>) => translate(lang(), key, params);

// ── DOM helpers ────────────────────────────────────────────────────────

type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, string | number | boolean | EventListener | undefined>;

/** Build an element. Text is always set as text, never parsed as HTML. */
function h(tag: string, attrs: Attrs = {}, ...children: Child[]): HTMLElement {
	const element = document.createElement(tag);
	for (const [name, value] of Object.entries(attrs)) {
		if (value === undefined || value === false) continue;
		if (typeof value === "function") element.addEventListener(name.replace(/^on/, ""), value);
		else if (value === true) element.setAttribute(name, "");
		else element.setAttribute(name, String(value));
	}
	for (const child of children) {
		if (child === null || child === undefined || child === false) continue;
		element.append(child instanceof Node ? child : document.createTextNode(String(child)));
	}
	return element;
}

function clear(element: Element): void {
	while (element.firstChild) element.firstChild.remove();
}

function button(
	label: Child,
	onClick: () => void,
	options: { variant?: string; disabled?: boolean; testId?: string; busy?: boolean } = {},
): HTMLElement {
	return h(
		"button",
		{
			class: `btn ${options.variant ?? ""}`.trim(),
			type: "button",
			disabled: options.disabled || options.busy,
			"data-testid": options.testId,
			onclick: () => onClick(),
		},
		options.busy ? h("span", { class: "spinner", "aria-hidden": "true" }) : null,
		label,
	);
}

function toast(message: string): void {
	const root = document.getElementById("toast-root");
	if (!root) return;
	const element = h("div", { class: "toast" }, message);
	root.append(element);
	setTimeout(() => element.remove(), 4000);
}

function relativeTime(iso: string): string {
	const seconds = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
	if (seconds < 5) return t("time.justNow");
	if (seconds < 60) return t("time.secondsAgo", { n: seconds });
	if (seconds < 3600) return t("time.minutesAgo", { n: Math.round(seconds / 60) });
	if (seconds < 86400) return t("time.hoursAgo", { n: Math.round(seconds / 3600) });
	return t("time.daysAgo", { n: Math.round(seconds / 86400) });
}

function clockTime(iso: string): string {
	return new Date(iso).toLocaleString(lang() === "tr" ? "tr-TR" : "en-GB", {
		year: "numeric",
		month: "2-digit",
		day: "2-digit",
		hour: "2-digit",
		minute: "2-digit",
		second: "2-digit",
	});
}

function decisionChip(decision: Decision | "unknown", testId?: string): HTMLElement {
	return h("span", { class: `chip ${decision}`, "data-testid": testId }, t(`decision.${decision}`));
}

function yesNo(value: boolean | null, testId?: string): HTMLElement {
	if (value === null) return h("span", { class: "check-value na", "data-testid": testId }, t("common.na"));
	return h(
		"span",
		{ class: `check-value ${value ? "yes" : "no"}`, "data-testid": testId },
		value ? t("common.yes") : t("common.no"),
	);
}

function modal(build: (close: () => void) => HTMLElement): void {
	const root = document.getElementById("modal-root");
	if (!root) return;
	clear(root);
	const close = () => clear(root);
	const backdrop = h("div", { class: "modal-backdrop", role: "dialog", "aria-modal": "true" });
	backdrop.append(build(close));
	backdrop.addEventListener("keydown", (event) => {
		if ((event as KeyboardEvent).key === "Escape") close();
	});
	root.append(backdrop);
	(backdrop.querySelector("button") as HTMLElement | null)?.focus();
}

// ── Chrome (sidebar) ───────────────────────────────────────────────────

function renderSidebar(): void {
	const nav = document.getElementById("nav");
	if (nav) {
		clear(nav);
		for (const page of PAGES) {
			nav.append(
				h(
					"button",
					{
						type: "button",
						"data-testid": `nav-${page.id}`,
						"aria-current": state.page === page.id ? "page" : undefined,
						onclick: () => go(page.id),
					},
					h("span", { class: "nav-dot", "aria-hidden": "true" }),
					t(page.key),
				),
			);
		}
	}
	const tagline = document.getElementById("brand-tagline");
	if (tagline) tagline.textContent = t("app.tagline");
	const badge = document.getElementById("protection-badge");
	if (badge) {
		const status = state.status;
		badge.className = `badge-pill ${status ? (status.protected ? "ok" : "warn") : "pending"}`;
		badge.setAttribute("data-testid", "protection-badge");
		badge.textContent = status
			? status.protected
				? t("badge.protected")
				: t("badge.notProtected")
			: t("common.loading");
	}
	const version = document.getElementById("app-version");
	if (version && state.info) version.textContent = `v${state.info.appVersion}`;
	document.documentElement.lang = lang();
	document.title = t("app.name");
}

function go(page: Page): void {
	state.page = page;
	render();
	(document.getElementById("main") as HTMLElement | null)?.scrollTo({ top: 0 });
	if (page === "browserGuard") void loadBrowserGuard();
	if (page === "status") void loadStatus(false);
}

// ── Status page ────────────────────────────────────────────────────────

function hero(status: StatusSnapshot | null): HTMLElement {
	if (!status) {
		return h(
			"section",
			{ class: "hero pending", "data-testid": "status-hero" },
			h("div", { class: "seal" }, h("span", { class: "mark" })),
			h("div", {}, h("h2", {}, t("common.loading"))),
		);
	}
	const claude = status.connectors.find((connector) => connector.id === "claude-code");
	let detail: string;
	if (status.protected) detail = t("status.hero.protectedDetail", { rules: status.engine.rules ?? 0 });
	else if (!status.engine.ok) detail = t("status.hero.engineDown", { detail: status.engine.detail });
	else if (claude?.hook.registered && claude.hook.binaryPresent === false)
		detail = t("status.hero.binaryMissing", { path: claude.hook.commands[0] ?? "" });
	else detail = t("status.hero.notConnected");
	return h(
		"section",
		{ class: `hero ${status.protected ? "ok" : "warn"}`, "data-testid": "status-hero" },
		h("div", { class: "seal" }, h("span", { class: "mark" })),
		h(
			"div",
			{},
			h(
				"h2",
				{ "data-testid": "status-headline" },
				status.protected ? t("status.hero.protected") : t("status.hero.notProtected"),
			),
			h("p", { class: "muted" }, detail),
		),
	);
}

function facts(status: StatusSnapshot | null): HTMLElement {
	const modeText = status
		? t(status.mode === "local" ? "status.mode.local" : status.mode === "managed" ? "status.mode.managed" : "status.mode.unknown")
		: "…";
	const fact = (label: string, value: string, sub: string, testId: string) =>
		h(
			"div",
			{ class: "fact" },
			h("span", { class: "label" }, label),
			h("span", { class: "value", "data-testid": testId }, value),
			h("span", { class: "sub" }, sub),
		);
	return h(
		"section",
		{ class: "facts" },
		fact(t("status.fact.version"), status?.aidrVersion ?? "…", status ? `app v${status.appVersion}` : "", "fact-version"),
		fact(
			t("status.fact.rules"),
			status?.engine.rules !== null && status?.engine.rules !== undefined ? String(status.engine.rules) : "—",
			status ? (status.engine.ok ? status.engine.detail : status.engine.detail || "") : "",
			"fact-rules",
		),
		fact(t("status.fact.mode"), modeText, status?.configState ?? "", "fact-mode"),
		fact(
			t("status.fact.lastVerdict"),
			status?.lastVerdict ? relativeTime(status.lastVerdict.at) : t("common.never"),
			status?.lastVerdict ? t(`decision.${status.lastVerdict.decision}`) : "",
			"fact-last-verdict",
		),
	);
}

function stateChip(connector: ConnectorView): HTMLElement {
	const tone =
		connector.state === "installed"
			? "ok"
			: connector.state === "installed_but_degraded" || connector.state === "unavailable"
				? "danger"
				: connector.state === "runtime_present_not_installed"
					? "warn"
					: "neutral";
	return h(
		"span",
		{ class: `chip ${tone}`, "data-testid": `connector-state-${connector.id}` },
		t(`state.${connector.state}`),
	);
}

function connectorCard(connector: ConnectorView): HTMLElement {
	const isClaude = connector.id === "claude-code";
	const checks = h("div", { class: "checks" });
	checks.append(
		h("span", {}, t("status.row.installed")),
		yesNo(connector.state === "installed", `check-installed-${connector.id}`),
	);
	if (connector.hook.kind === "command") {
		checks.append(
			h("span", {}, t("status.row.hook")),
			yesNo(connector.hook.registered, `check-hook-${connector.id}`),
			h("span", {}, t("status.row.binary")),
			yesNo(connector.hook.binaryPresent, `check-binary-${connector.id}`),
		);
	} else {
		checks.append(h("span", { class: "muted" }, t("status.row.inProcess")), h("span", {}, ""));
	}
	const actions = h("div", { class: "row" });
	if (isClaude) {
		const connected = connector.hook.registered === true;
		actions.append(
			button(connected ? t("claude.reconnect") : t("claude.connect"), () => void openConnect(), {
				variant: connected ? "" : "primary",
				testId: "connect-claude",
				busy: state.busy === "connect",
				disabled: state.busy !== null,
			}),
		);
		if (connected) {
			actions.append(
				button(t("claude.disconnect"), () => openDisconnect(), {
					variant: "danger",
					testId: "disconnect-claude",
					busy: state.busy === "disconnect",
					disabled: state.busy !== null,
				}),
			);
		}
	}
	return h(
		"article",
		{ class: "card", "data-testid": `connector-${connector.id}` },
		h("div", { class: "card-head" }, h("h3", {}, connector.label), stateChip(connector)),
		h("p", { class: "muted small" }, connector.detail),
		checks,
		connector.hook.commands.length > 0
			? h(
					"details",
					{},
					h("summary", {}, t("claude.previewCommands")),
					h("ul", { class: "evidence" }, ...connector.hook.commands.map((command) => h("li", {}, h("code", {}, command)))),
				)
			: null,
		h(
			"details",
			{},
			h("summary", {}, t("status.evidence")),
			h("ul", { class: "evidence" }, ...connector.evidence.map((path) => h("li", {}, path))),
			connector.remedy ? h("p", { class: "small" }, connector.remedy) : null,
		),
		isClaude ? actions : null,
	);
}

function actionBanner(): HTMLElement | null {
	const action = state.lastAction;
	if (!action) return null;
	const { result } = action;
	const headline = result.ok
		? action.kind === "connect"
			? t("claude.connected")
			: t("claude.disconnected", { path: result.backupPath ?? "—" })
		: result.message;
	return h(
		"div",
		{ class: `banner ${result.ok ? "ok" : "danger"}`, "data-testid": "action-banner" },
		h("strong", {}, headline),
		result.ok ? h("span", { class: "small" }, result.message) : null,
		result.log
			? h("details", {}, h("summary", {}, t("common.details")), h("pre", { class: "log" }, result.log))
			: null,
	);
}

function runtimeCard(status: StatusSnapshot): HTMLElement {
	const runtime = status.runtime;
	return h(
		"section",
		{ class: "card" },
		h("h2", {}, t("status.runtime")),
		h(
			"dl",
			{ class: "kv" },
			h("dt", {}, t("status.runtime.bundled")),
			h("dd", {}, h("code", {}, runtime.bundledRoot ?? "—"), runtime.flavor ? ` · ${runtime.flavor}` : ""),
			h("dt", {}, t("status.runtime.installed")),
			h("dd", {}, runtime.installedRoot ? h("code", {}, runtime.installedRoot) : t("status.runtime.none")),
		),
		!runtime.signed ? h("p", { class: "small muted" }, t("status.runtime.unsigned")) : null,
		runtime.problems.length > 0
			? h("div", { class: "banner danger" }, t("status.runtime.problems", { problems: runtime.problems.slice(0, 3).join("; ") }))
			: null,
	);
}

function renderStatus(): HTMLElement {
	const status = state.status;
	return h(
		"div",
		{ class: "page", "data-testid": "page-status" },
		h(
			"div",
			{ class: "page-head" },
			h(
				"div",
				{},
				h("h1", {}, t("status.title")),
				status ? h("p", { class: "muted" }, t("status.subtitle", { home: status.home })) : null,
			),
			button(t("common.refresh"), () => void loadStatus(), { variant: "ghost", testId: "refresh-status" }),
		),
		state.statusError ? h("div", { class: "banner danger" }, state.statusError) : null,
		hero(status),
		facts(status),
		actionBanner(),
		h(
			"section",
			{ class: "section" },
			h("div", { class: "card-head" }, h("h2", {}, t("status.connectors"))),
			h("p", { class: "muted small" }, t("status.connectorsHint")),
			h("div", { class: "connectors" }, ...(status?.connectors ?? []).map(connectorCard)),
		),
		status ? runtimeCard(status) : null,
	);
}

async function openConnect(): Promise<void> {
	let preview: ConnectPreview;
	try {
		preview = await api.invoke("claude:preview");
	} catch (error) {
		toast((error as Error).message);
		return;
	}
	modal((close) =>
		h(
			"div",
			{ class: "modal", "data-testid": "connect-modal" },
			h("h2", {}, t("claude.previewTitle")),
			h("p", { class: "muted" }, t("claude.previewIntro")),
			h(
				"dl",
				{ class: "kv" },
				h("dt", {}, t("claude.previewFile")),
				h(
					"dd",
					{},
					h("code", {}, preview.settingsPath),
					preview.settingsExists ? "" : ` ${t("claude.previewNewFile")}`,
				),
				h("dt", {}, t("claude.previewRuntime")),
				h("dd", {}, h("code", {}, preview.runtimeRoot || "—")),
			),
			preview.blocker
				? h(
						"div",
						{ class: "banner danger", "data-testid": "connect-blocker" },
						h("strong", {}, t("claude.previewBlocked")),
						preview.blocker,
					)
				: h(
						"div",
						{},
						h("h3", {}, t("claude.previewDiff")),
						preview.changed
							? h(
									"div",
									{ class: "diff", "data-testid": "connect-diff" },
									...preview.diff.map((line) => h("div", { class: line.kind }, line.text || " ")),
								)
							: h("p", { class: "muted" }, t("claude.previewNoChange")),
					),
			h(
				"div",
				{ class: "modal-actions" },
				button(t("common.cancel"), close, { testId: "connect-cancel" }),
				button(
					t("claude.confirmConnect"),
					() => {
						close();
						void runAction("connect");
					},
					{ variant: "primary", disabled: preview.blocker !== null, testId: "connect-confirm" },
				),
			),
		),
	);
}

function openDisconnect(): void {
	modal((close) =>
		h(
			"div",
			{ class: "modal", "data-testid": "disconnect-modal" },
			h("h2", {}, t("claude.disconnectTitle")),
			h("p", {}, t("claude.disconnectBody")),
			h(
				"div",
				{ class: "modal-actions" },
				button(t("common.cancel"), close),
				button(
					t("claude.confirmDisconnect"),
					() => {
						close();
						void runAction("disconnect");
					},
					{ variant: "danger", testId: "disconnect-confirm" },
				),
			),
		),
	);
}

async function runAction(kind: "connect" | "disconnect"): Promise<void> {
	state.busy = kind;
	state.lastAction = null;
	render();
	try {
		const result = await api.invoke(kind === "connect" ? "claude:connect" : "claude:disconnect");
		state.lastAction = { kind, result };
	} catch (error) {
		state.lastAction = { kind, result: { ok: false, message: (error as Error).message, log: "" } };
	} finally {
		state.busy = null;
	}
	await loadStatus();
}

// ── Self-test page ─────────────────────────────────────────────────────

function caseCard(entry: SelfTestCase): HTMLElement {
	return h(
		"article",
		{ class: `case ${entry.pass ? "pass" : "fail"}`, "data-testid": `case-${entry.name}` },
		h(
			"div",
			{ class: "card-head" },
			h("h3", {}, t(entry.name === "benign" ? "selftest.case.benign" : "selftest.case.canary")),
			h("span", { class: `chip ${entry.pass ? "ok" : "danger"}` }, entry.pass ? "PASS" : "FAIL"),
		),
		h("div", { class: "cmd" }, entry.command),
		h(
			"dl",
			{ class: "kv" },
			h("dt", {}, t("selftest.expected")),
			h("dd", {}, decisionChip(entry.expected)),
			h("dt", {}, t("selftest.got")),
			h("dd", {}, decisionChip(entry.decision, `verdict-${entry.name}`)),
			h("dt", {}, t("selftest.latency")),
			h("dd", { class: "latency", "data-testid": `latency-${entry.name}` }, `${entry.latencyMs} ms`),
			h("dt", {}, t("selftest.rule")),
			h("dd", {}, entry.ruleId ? h("code", {}, entry.ruleId) : "—"),
			h("dt", {}, t("selftest.reason")),
			h("dd", { class: "small" }, entry.reason || "—"),
		),
	);
}

function renderSelfTest(): HTMLElement {
	const result = state.selfTest;
	let body: HTMLElement;
	if (state.selfTestRunning) {
		body = h("div", { class: "banner" }, h("div", { class: "row" }, h("span", { class: "spinner" }), t("selftest.running")));
	} else if (!result) {
		body = h("p", { class: "muted" }, t("selftest.notRun"));
	} else if (result.error) {
		body = h(
			"div",
			{ class: "banner danger", "data-testid": "selftest-error" },
			h("strong", {}, t("selftest.error")),
			result.error,
			result.hookCommand ? h("code", {}, result.hookCommand) : null,
		);
	} else {
		body = h(
			"div",
			{ class: "stack" },
			h(
				"div",
				{ class: `banner ${result.ok ? "ok" : "danger"}`, "data-testid": "selftest-summary" },
				h("strong", {}, result.ok ? t("selftest.pass") : t("selftest.fail")),
				h("span", { class: "small" }, t("selftest.ranAt", { time: clockTime(result.ranAt) })),
			),
			h("div", { class: "cases" }, ...result.cases.map(caseCard)),
			h(
				"dl",
				{ class: "kv small" },
				h("dt", {}, t("selftest.hookUsed")),
				h("dd", {}, h("code", {}, result.hookCommand ?? "—")),
			),
			h("p", { class: "small muted" }, t("selftest.auditNote")),
		);
	}
	return h(
		"div",
		{ class: "page", "data-testid": "page-selftest" },
		h(
			"div",
			{ class: "page-head" },
			h("h1", {}, t("selftest.title")),
			button(t("selftest.run"), () => void runSelfTest(), {
				variant: "primary",
				testId: "run-selftest",
				busy: state.selfTestRunning,
			}),
		),
		h("p", { class: "muted" }, t("selftest.intro")),
		body,
	);
}

async function runSelfTest(): Promise<void> {
	state.selfTestRunning = true;
	render();
	try {
		state.selfTest = await api.invoke("selftest:run");
	} catch (error) {
		state.selfTest = {
			ok: false,
			error: (error as Error).message,
			hookCommand: null,
			settingsPath: "",
			ranAt: new Date().toISOString(),
			cases: [],
		};
	} finally {
		state.selfTestRunning = false;
	}
	render();
}

// ── Activity page ──────────────────────────────────────────────────────

function filteredEvents(): AuditEvent[] {
	const query = state.search.trim().toLowerCase();
	return state.events
		.filter((event) => state.filter === "all" || event.decision === state.filter)
		.filter((event) => !(state.hideSelfTest && event.origin !== null))
		.filter(
			(event) =>
				!query ||
				[event.tool, event.summary, event.ruleId ?? "", event.reason]
					.join(" ")
					.toLowerCase()
					.includes(query),
		)
		.slice()
		.reverse();
}

function eventRows(): HTMLElement {
	const list = filteredEvents();
	if (list.length === 0) {
		return h(
			"div",
			{ class: "empty", "data-testid": "activity-empty" },
			state.events.length === 0 ? t("activity.empty") : t("activity.emptyFiltered"),
		);
	}
	return h(
		"table",
		{ "data-testid": "activity-table" },
		h(
			"thead",
			{},
			h(
				"tr",
				{},
				h("th", {}, t("activity.col.time")),
				h("th", {}, t("activity.col.decision")),
				h("th", {}, t("activity.col.tool")),
				h("th", {}, t("activity.col.summary")),
				h("th", {}, t("activity.col.rule")),
			),
		),
		h(
			"tbody",
			{},
			...list.slice(0, 500).map((event) =>
				h(
					"tr",
					{
						class: state.freshIds.has(event.id) ? "fresh" : undefined,
						"data-testid": "activity-row",
						"data-decision": event.decision,
						"data-origin": event.origin ?? "agent",
					},
					h("td", { class: "time", title: event.at }, clockTime(event.at)),
					h("td", {}, decisionChip(event.decision)),
					h(
						"td",
						{},
						event.tool,
						event.origin
							? h(
									"div",
									{},
									h(
										"span",
										{ class: "chip tag" },
										t(event.origin === "self-test" ? "activity.selfTestTag" : "activity.setupTag"),
									),
								)
							: null,
					),
					h("td", { class: "summary" }, event.summary),
					h(
						"td",
						{ class: "rule" },
						event.ruleId ? h("div", { class: "rule-id" }, event.ruleId) : null,
						event.reason ? h("div", { class: "reason" }, event.reason) : null,
					),
				),
			),
		),
	);
}

function renderActivity(): HTMLElement {
	const status = state.status;
	const tableWrap = h("div", { class: "table-wrap", id: "activity-rows" }, eventRows());
	const refreshRows = () => {
		clear(tableWrap);
		tableWrap.append(eventRows());
	};
	const filters = h("div", { class: "segmented", role: "group" });
	for (const filter of ["all", "deny", "ask", "allow"] as const) {
		filters.append(
			h(
				"button",
				{
					type: "button",
					"aria-pressed": state.filter === filter ? "true" : "false",
					"data-testid": `filter-${filter}`,
					onclick: () => {
						state.filter = filter;
						render();
					},
				},
				t(`activity.filter.${filter}`),
			),
		);
	}
	const search = h("input", {
		type: "search",
		placeholder: t("activity.search"),
		value: state.search,
		"data-testid": "activity-search",
		oninput: (event: Event) => {
			state.search = (event.target as HTMLInputElement).value;
			refreshRows();
		},
	});
	const hideSelfTest = h(
		"label",
		{ class: "toggle small" },
		h("input", {
			type: "checkbox",
			checked: state.hideSelfTest,
			onchange: (event: Event) => {
				state.hideSelfTest = (event.target as HTMLInputElement).checked;
				refreshRows();
			},
		}),
		t("activity.hideSelfTest"),
	);
	const logClean = h(
		"label",
		{ class: "toggle" },
		h("input", {
			type: "checkbox",
			"data-testid": "log-clean-toggle",
			checked: status?.logClean === true,
			disabled: !status?.configExists,
			onchange: async (event: Event) => {
				const input = event.target as HTMLInputElement;
				input.disabled = true;
				const result = await api.invoke("audit:setLogClean", { enabled: input.checked });
				if (!result.ok) toast(result.message);
				await loadStatus();
			},
		}),
		t("activity.logClean"),
	);
	return h(
		"div",
		{ class: "page", "data-testid": "page-activity" },
		h(
			"div",
			{ class: "page-head" },
			h("h1", {}, t("activity.title")),
			button(t("activity.openLog"), () => void openTarget("auditLog"), { variant: "ghost" }),
		),
		h("p", { class: "muted" }, t("activity.intro", { path: status?.auditPath ?? "audit.jsonl" })),
		h(
			"div",
			{ class: "card" },
			logClean,
			h(
				"p",
				{ class: "small muted" },
				status?.configExists ? t("activity.logCleanHint") : t("activity.logCleanNeedsConfig"),
			),
		),
		h("div", { class: "row" }, filters, search, h("span", { class: "spacer" }), hideSelfTest),
		tableWrap,
	);
}

// ── Browser Guard page ─────────────────────────────────────────────────

function renderBrowserGuard(): HTMLElement {
	const bg = state.browserGuard;
	if (!bg) {
		return h("div", { class: "page", "data-testid": "page-browser-guard" }, h("h1", {}, t("bg.title")), h("p", { class: "muted" }, t("common.loading")));
	}
	const browserName = (id: "chrome" | "edge") => (id === "chrome" ? "Chrome" : "Edge");
	const browsers = h(
		"div",
		{ class: "checks" },
		...bg.browsers.flatMap((entry) => [
			h("span", {}, browserName(entry.browser)),
			h(
				"span",
				{ class: `check-value ${entry.installed ? "yes" : "na"}` },
				entry.installed ? t("bg.browserInstalled") : t("bg.browserMissing"),
			),
		]),
	);
	const extension =
		bg.extensions.length > 0
			? h(
					"ul",
					{ class: "evidence", "data-testid": "bg-extensions" },
					...bg.extensions.map((hit) =>
						h(
							"li",
							{},
							t("bg.extFound", {
								browser: browserName(hit.browser),
								profile: hit.profile,
								version: hit.version ?? "?",
							}),
							hit.enabled ? "" : ` — ${t("bg.extDisabled")}`,
						),
					),
				)
			: h("p", { class: "muted", "data-testid": "bg-extensions" }, t("bg.extNone"));
	const native =
		bg.nativeHost.registrations.length > 0
			? h(
					"ul",
					{ class: "evidence" },
					...bg.nativeHost.registrations.map((entry) =>
						h(
							"li",
							{},
							t(entry.manifestExists ? "bg.nativeHostRegistered" : "bg.nativeHostMissingFile", {
								browser: browserName(entry.browser),
								scope: entry.scope,
							}),
							entry.manifestPath ? h("div", {}, h("code", {}, entry.manifestPath)) : null,
						),
					),
				)
			: h("p", { class: "muted small" }, t("bg.nativeHostNone"));
	const staged = bg.bundled.stagedPath;
	const install = bg.bundled.available
		? h(
				"section",
				{ class: "card", "data-testid": "bg-install" },
				h("h2", {}, t("bg.install")),
				h("p", { class: "muted" }, t("bg.installSteps")),
				h("ol", { class: "steps" }, h("li", {}, t("bg.step1")), h("li", {}, t("bg.step2")), h("li", {}, t("bg.step3"))),
				h(
					"div",
					{ class: "row" },
					button(t("bg.prepare"), () => void stageBrowserGuard(), { variant: staged ? "" : "primary", testId: "bg-prepare" }),
					...bg.browsers
						.filter((entry) => entry.installed)
						.map((entry) =>
							button(t(entry.browser === "chrome" ? "bg.openChrome" : "bg.openEdge"), () => void openExtensions(entry.browser), {
								disabled: !staged,
							}),
						),
				),
				staged
					? h(
							"div",
							{ class: "path-box", "data-testid": "bg-staged-path" },
							h("span", { class: "spacer" }, staged),
							button(t("bg.copyPath"), () => {
								void navigator.clipboard.writeText(staged).then(() => toast(t("bg.copied")));
							}, { variant: "small" }),
							button(t("bg.openFolder"), () => void openTarget("browserGuardFolder"), { variant: "small" }),
						)
					: null,
				h("p", { class: "small muted" }, t("bg.typeUrl", { url: "chrome://extensions · edge://extensions" })),
			)
		: h("div", { class: "banner warn" }, t("bg.notBundled"));
	return h(
		"div",
		{ class: "page", "data-testid": "page-browser-guard" },
		h(
			"div",
			{ class: "page-head" },
			h("h1", {}, t("bg.title")),
			button(t("common.refresh"), () => void loadBrowserGuard(), { variant: "ghost" }),
		),
		h("p", { class: "muted" }, t("bg.intro")),
		h(
			"div",
			{ class: "connectors" },
			h("section", { class: "card" }, h("h2", {}, t("bg.browsers")), browsers),
			h("section", { class: "card" }, h("h2", {}, t("bg.extension")), extension),
			h("section", { class: "card" }, h("h2", {}, t("bg.nativeHost")), native),
		),
		install,
	);
}

async function stageBrowserGuard(): Promise<void> {
	const result = await api.invoke("browserGuard:stage");
	toast(result.ok ? t("bg.staged", { path: result.message }) : result.message);
	await loadBrowserGuard();
}

async function openExtensions(browser: "chrome" | "edge"): Promise<void> {
	const result = await api.invoke("browserGuard:openExtensionsPage", { browser });
	if (!result.ok) toast(result.message);
}

// ── Settings page ──────────────────────────────────────────────────────

function select(
	value: string,
	options: Array<[string, string]>,
	onChange: (value: string) => void,
	testId: string,
): HTMLElement {
	const element = h(
		"select",
		{ "data-testid": testId, onchange: (event: Event) => onChange((event.target as HTMLSelectElement).value) },
		...options.map(([optionValue, label]) => {
			const option = h("option", { value: optionValue }, label) as HTMLOptionElement;
			option.selected = optionValue === value;
			return option;
		}),
	);
	return element;
}

async function setPreference(patch: Record<string, unknown>): Promise<void> {
	try {
		state.info = await api.invoke("prefs:set", patch);
	} catch (error) {
		toast((error as Error).message);
	}
	render();
}

function renderSettings(): HTMLElement {
	const prefs = state.info?.preferences;
	if (!prefs) return h("div", { class: "page" }, t("common.loading"));
	const toggle = (key: "notifyOnDeny" | "startAtLogin", label: string, testId: string) =>
		h(
			"label",
			{ class: "toggle" },
			h("input", {
				type: "checkbox",
				checked: prefs[key],
				"data-testid": testId,
				onchange: (event: Event) => void setPreference({ [key]: (event.target as HTMLInputElement).checked }),
			}),
			label,
		);
	return h(
		"div",
		{ class: "page", "data-testid": "page-settings" },
		h("h1", {}, t("settings.title")),
		h(
			"section",
			{ class: "card" },
			h(
				"div",
				{ class: "setting" },
				h("span", {}, t("settings.language")),
				select(
					prefs.language,
					[
						["auto", t("settings.language.auto")],
						["tr", "Türkçe"],
						["en", "English"],
					],
					(value) => void setPreference({ language: value }),
					"pref-language",
				),
			),
			h(
				"div",
				{ class: "setting" },
				h("span", {}, t("settings.theme")),
				select(
					prefs.theme,
					[
						["system", t("settings.theme.system")],
						["light", t("settings.theme.light")],
						["dark", t("settings.theme.dark")],
					],
					(value) => void setPreference({ theme: value }),
					"pref-theme",
				),
			),
			h("div", { class: "setting" }, toggle("notifyOnDeny", t("settings.notify"), "pref-notify")),
			h(
				"div",
				{ class: "setting" },
				h("div", {}, toggle("startAtLogin", t("settings.startAtLogin"), "pref-login"), h("p", { class: "small muted" }, t("settings.startAtLoginHint"))),
			),
		),
		h(
			"section",
			{ class: "card" },
			h("h2", {}, t("settings.about")),
			h(
				"dl",
				{ class: "kv" },
				h("dt", {}, t("settings.appVersion")),
				h("dd", {}, state.info?.appVersion ?? ""),
				h("dt", {}, t("status.fact.version")),
				h("dd", {}, state.status?.aidrVersion ?? "—"),
				h("dt", {}, t("settings.platform")),
				h("dd", {}, state.info?.platform ?? ""),
			),
			h(
				"div",
				{ class: "row" },
				button(t("settings.openData"), () => void openTarget("dataDir")),
				button(t("settings.openSettings"), () => void openTarget("claudeSettings")),
			),
		),
	);
}

async function openTarget(target: "auditLog" | "claudeSettings" | "dataDir" | "browserGuardFolder"): Promise<void> {
	const result = await api.invoke("open:target", { target });
	if (!result.ok) toast(result.message);
}

// ── Data loading & render loop ─────────────────────────────────────────

/** Equal apart from the measurement time. */
function sameStatus(a: StatusSnapshot | null, b: StatusSnapshot): boolean {
	if (!a) return false;
	return JSON.stringify({ ...a, checkedAt: "", engine: { ...a.engine, latencyMs: 0 } }) ===
		JSON.stringify({ ...b, checkedAt: "", engine: { ...b.engine, latencyMs: 0 } });
}

/** Fetch the status; `force` re-renders even when nothing changed (after an action). */
async function loadStatus(force = true): Promise<void> {
	let unchanged = false;
	try {
		const status = await api.invoke("status:get");
		unchanged = sameStatus(state.status, status) && state.statusError === null;
		state.status = status;
		state.statusError = null;
	} catch (error) {
		state.statusError = (error as Error).message;
	}
	if (force || !unchanged) render();
	else renderSidebar();
}

async function loadBrowserGuard(): Promise<void> {
	try {
		state.browserGuard = await api.invoke("browserGuard:status");
	} catch (error) {
		toast((error as Error).message);
	}
	if (state.page === "browserGuard") render();
}

function render(): void {
	renderSidebar();
	const main = document.getElementById("main");
	if (!main) return;
	const focused = document.activeElement as HTMLElement | null;
	const focusedTestId = focused?.getAttribute("data-testid");
	clear(main);
	const pages: Record<Page, () => HTMLElement> = {
		status: renderStatus,
		selftest: renderSelfTest,
		activity: renderActivity,
		browserGuard: renderBrowserGuard,
		settings: renderSettings,
	};
	main.append(pages[state.page]());
	if (focusedTestId === "activity-search") {
		const input = main.querySelector<HTMLInputElement>('[data-testid="activity-search"]');
		input?.focus();
		input?.setSelectionRange(input.value.length, input.value.length);
	}
}

async function start(): Promise<void> {
	state.info = await api.invoke("app:info");
	render();
	api.on("status:changed", (status) => {
		const unchanged = sameStatus(state.status, status);
		state.status = status;
		// Rebuild only a page that shows status, and only when it changed: the
		// DOM (and any control the user is about to click) stays otherwise.
		if (!unchanged && (state.page === "status" || state.page === "activity")) render();
		else renderSidebar();
	});
	api.on("audit:events", (fresh) => {
		state.events.push(...fresh);
		if (state.events.length > 1000) state.events.splice(0, state.events.length - 1000);
		for (const event of fresh) state.freshIds.add(event.id);
		setTimeout(() => {
			for (const event of fresh) state.freshIds.delete(event.id);
		}, 2000);
		if (state.page === "activity") {
			const wrap = document.getElementById("activity-rows");
			if (wrap) {
				clear(wrap);
				wrap.append(eventRows());
			}
		}
	});
	api.on("nav:go", (page) => {
		if (PAGES.some((entry) => entry.id === page)) go(page as Page);
	});
	state.events = await api.invoke("audit:recent");
	await loadStatus(false);
}

void start();
