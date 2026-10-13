// @vitest-environment jsdom
/**
 * jsdom smoke of the Setup Assistant page: token exchange, all seven steps
 * against a fake local API, the language switch, text-only rendering of
 * server data, and the expired-link screen.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { ASSISTANT_EN, ASSISTANT_TR } from "../../../i18n/assistant-messages.js";
import type { AssistantState, DetectedTool, EnrollView, SetupEvent } from "../../types.js";
import { boot } from "../app.js";

const TOKEN = "ab".repeat(32);

interface Backend {
	calls: string[];
	sessionStatus: number;
	stateStatus: number;
	tools: DetectedTool[];
	polls: EnrollView[];
	state: Partial<AssistantState>;
}

function backend(overrides: Partial<Backend> = {}): Backend {
	return {
		calls: [],
		sessionStatus: 200,
		stateStatus: 200,
		tools: [
			{ id: "claude-code", label: "Claude Code", state: "not_detected", preview: false },
			{ id: "cursor", label: "Cursor", state: "not_detected", preview: true },
			{ id: "vscode", label: "VS Code", state: "not_detected", preview: true },
			{ id: "openclaw", label: "OpenClaw", state: "not_detected", preview: false },
			{ id: "opencode", label: "OpenCode", state: "runtime_present_not_installed", preview: false },
			{ id: "codex", label: "<img src=x onerror=alert(1)>", state: "installed", preview: false },
		],
		polls: [
			{
				phase: "waiting",
				userCode: "ABCD-EFGH",
				verificationUrl: "https://aidr.corp.example/verify",
				interval: 1,
			},
			{ phase: "enrolled", endpoint: "https://aidr.corp.example" },
		],
		state: {},
		...overrides,
	};
}

function fakeFetch(server: Backend): typeof fetch {
	let setupPolls = 0;
	const json = (status: number, body: unknown) =>
		new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
	return (async (input: RequestInfo | URL, init?: RequestInit) => {
		const path = String(input);
		const method = init?.method ?? "GET";
		const body = init?.body ? JSON.parse(String(init.body)) : undefined;
		server.calls.push(
			`${method} ${path}${body && Object.keys(body).length ? ` ${JSON.stringify(body)}` : ""}`,
		);
		expect(init?.credentials).toBe("same-origin");
		if (method === "POST")
			expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
		switch (`${method} ${path}`) {
			case "POST /api/session":
				return json(
					server.sessionStatus,
					server.sessionStatus === 200 ? { ok: true } : { error: "token_used" },
				);
			case "GET /api/state":
				if (server.stateStatus !== 200) return json(server.stateStatus, { error: "no_session" });
				return json(200, {
					version: "0.6.0",
					locale: "en",
					company: null,
					pending: null,
					pendingIgnored: false,
					browserGuard: {
						chrome: "https://chromewebstore.google.com/detail/aidr",
						edge: null,
						firefox: null,
						downloads: "https://aidr.corp.example/downloads",
					},
					dashboard: "https://aidr.corp.example",
					...server.state,
				});
			case "POST /api/detect":
				return json(200, server.tools);
			case "POST /api/enroll/start":
				return json(200, server.polls[0]);
			case "POST /api/enroll/poll":
				return json(200, server.polls[1]);
			case "POST /api/setup":
				return json(202, { job: "j1" });
			case "GET /api/setup": {
				setupPolls += 1;
				const events: SetupEvent[] = [
					{ type: "rules", rules: 519 },
					{ type: "host-start", id: "opencode", label: "OpenCode" },
				];
				if (setupPolls < 2) return json(200, { events, done: false, result: null, error: null });
				const opencode = {
					id: "opencode" as const,
					label: "OpenCode",
					outcome: "restart" as const,
					detail: "registered",
					steps: [],
				};
				const codex = {
					id: "codex" as const,
					label: "Codex",
					outcome: "manual" as const,
					detail: "needs the bundle",
					steps: ["Codex: aidr setup --host codex"],
				};
				return json(200, {
					events: [
						...events,
						{ type: "host-done", result: opencode },
						{ type: "host-done", result: codex },
					],
					done: true,
					result: { ok: false, rules: 519, hosts: [opencode, codex] },
					error: null,
				});
			}
			case "POST /api/verify":
				return json(200, {
					hosts: [
						{ id: "opencode", label: "OpenCode", outcome: "skip", detail: "in-process" },
						{ id: "codex", label: "Codex", outcome: "fail", detail: "canary allow" },
					],
				});
			case "GET /api/status":
				return json(200, {
					detection: { ok: true, rules: 519 },
					protected: [],
					restart: ["OpenCode"],
					manual: [{ label: "Codex", command: "aidr setup --host codex" }],
				});
			case "POST /api/finish":
				return json(200, { ok: true });
		}
		return json(404, { error: "not_found" });
	}) as typeof fetch;
}

async function until(check: () => boolean, label: string): Promise<void> {
	for (let i = 0; i < 200; i++) {
		if (check()) return;
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	throw new Error(`timed out waiting for ${label}: ${document.body.textContent}`);
}

function button(root: HTMLElement, text: string): HTMLButtonElement | HTMLAnchorElement {
	const found = [...root.querySelectorAll<HTMLButtonElement | HTMLAnchorElement>("button, a")].find(
		(element) => element.textContent?.trim() === text,
	);
	if (!found) throw new Error(`no button "${text}" in: ${root.textContent}`);
	return found;
}

function heading(root: HTMLElement): string {
	return root.querySelector("h1")?.textContent ?? "";
}

let stops: Array<() => void> = [];
afterEach(() => {
	for (const stop of stops) stop();
	stops = [];
	document.body.replaceChildren();
	try {
		window.sessionStorage.clear();
	} catch {
		// Not available.
	}
});

function mount(server: Backend) {
	const root = document.createElement("div");
	document.body.append(root);
	const replaceState = vi.fn();
	const wizard = boot(root, {
		fetch: fakeFetch(server),
		location: { hash: `#t=${TOKEN}` },
		history: { replaceState },
		progressMs: 1,
		pollScale: 40,
	});
	stops.push(wizard.stop);
	return { root, wizard, replaceState };
}

describe("Setup Assistant page", () => {
	it("walks all seven steps against the local API", async () => {
		const writeText = vi.fn(async (_text: string) => {});
		Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
		const server = backend();
		const { root, wizard, replaceState } = mount(server);
		await wizard.ready;

		// 1. Welcome: the token was exchanged and wiped from the address bar.
		expect(server.calls[0]).toBe(`POST /api/session {"token":"${TOKEN}"}`);
		expect(replaceState).toHaveBeenCalledWith(null, "", "/");
		expect(heading(root)).toBe(ASSISTANT_EN["welcome.heading"]);
		expect(document.activeElement?.tagName).toBe("H1");
		expect(root.querySelector('[aria-current="step"]')?.textContent).toBe(
			ASSISTANT_EN["step.welcome"],
		);
		expect(root.querySelector('span[lang="en"]')?.textContent).toBe("Singularity AIDR");

		// 2. AI tools: found tools pre-selected, missing ones greyed and disabled.
		button(root, ASSISTANT_EN["welcome.start"]).click();
		await until(() => root.querySelectorAll('input[type="checkbox"]').length === 6, "tool list");
		const box = (id: string) =>
			root.querySelector<HTMLInputElement>(`#tool-${id}`) as HTMLInputElement;
		expect(box("opencode").checked).toBe(true);
		expect(box("claude-code").disabled).toBe(true);
		expect(box("claude-code").closest("li")?.className).toContain("disabled");
		expect(box("claude-code").closest("li")?.textContent).toContain(
			ASSISTANT_EN["badge.not_detected"],
		);
		expect(root.querySelector('label[for="tool-opencode"]')).not.toBeNull();
		// Server data is text, never markup.
		expect(root.querySelector("img[onerror]")).toBeNull();
		expect(root.textContent).toContain("<img src=x onerror=alert(1)>");
		box("opencode").click();
		box("codex").click();
		expect((button(root, ASSISTANT_EN["ui.next"]) as HTMLButtonElement).disabled).toBe(true);
		box("opencode").click();
		box("codex").click();
		// Re-rendering keeps keyboard focus on the control that had it.
		box("codex").focus();
		box("codex").click();
		expect(document.activeElement?.id).toBe("tool-codex");
		box("codex").click();
		button(root, ASSISTANT_EN["ui.next"]).click();

		// 3. Company: local by default; connecting shows the code, then polls to success.
		expect(heading(root)).toBe(ASSISTANT_EN["company.heading"]);
		expect(root.querySelector<HTMLInputElement>("#company-local")?.checked).toBe(true);
		const connect = root.querySelector<HTMLInputElement>("#company-connect") as HTMLInputElement;
		connect.checked = true;
		connect.dispatchEvent(new Event("change"));
		const url = root.querySelector<HTMLInputElement>("#company-url") as HTMLInputElement;
		expect(root.querySelector('label[for="company-url"]')).not.toBeNull();
		url.value = "https://aidr.corp.example";
		url.dispatchEvent(new Event("input"));
		button(root, ASSISTANT_EN["company.getCode"]).click();
		await until(() => root.textContent?.includes("ABCD-EFGH") ?? false, "device code");
		const page = button(root, ASSISTANT_EN["company.openPage"]) as HTMLAnchorElement;
		expect(page.getAttribute("href")).toBe("https://aidr.corp.example/verify");
		expect(page.getAttribute("rel")).toBe("noopener noreferrer");
		await until(
			() => root.textContent?.includes("Connected to https://aidr.corp.example") ?? false,
			"enrolled",
		);
		expect(server.calls).toContain(
			'POST /api/enroll/start {"endpoint":"https://aidr.corp.example","useInstallerToken":false}',
		);
		button(root, ASSISTANT_EN["ui.next"]).click();

		// 4. Protect: progress, then one result per tool with the exact manual command.
		expect(heading(root)).toBe(ASSISTANT_EN["protect.heading"]);
		expect((button(root, ASSISTANT_EN["ui.next"]) as HTMLButtonElement).disabled).toBe(true);
		button(root, ASSISTANT_EN["protect.start"]).click();
		await until(
			() => root.textContent?.includes("Restart OpenCode to turn protection on.") ?? false,
			"setup result",
		);
		expect(server.calls).toContain('POST /api/setup {"hosts":["opencode","codex"]}');
		expect(root.textContent).toContain(ASSISTANT_EN["protect.manual"]);
		expect([...root.querySelectorAll("pre")].map((pre) => pre.textContent)).toContain(
			"Codex: aidr setup --host codex",
		);
		button(root, ASSISTANT_EN["ui.copy"]).click();
		await until(() => writeText.mock.calls.length === 1, "copy");
		expect(writeText).toHaveBeenCalledWith("Codex: aidr setup --host codex");
		button(root, ASSISTANT_EN["ui.next"]).click();

		// 5. Verify runs on entry: red with a plain explanation, skip explained.
		await until(() => root.textContent?.includes(ASSISTANT_EN["verify.fail"]) ?? false, "verify");
		expect(root.textContent).toContain("Restart Codex and check again.");
		expect(root.textContent).toContain(
			"Open OpenCode once and confirm Singularity AIDR is listed there.",
		);
		button(root, ASSISTANT_EN["ui.next"]).click();

		// 6. Browser Guard: only configured https store links, plus the Download page.
		expect(heading(root)).toBe(ASSISTANT_EN["browser.heading"]);
		expect(button(root, ASSISTANT_EN["browser.chrome"]).getAttribute("href")).toBe(
			"https://chromewebstore.google.com/detail/aidr",
		);
		expect(() => button(root, ASSISTANT_EN["browser.edge"])).toThrow();
		expect(button(root, ASSISTANT_EN["browser.dashboard"]).getAttribute("href")).toBe(
			"https://aidr.corp.example/downloads",
		);
		expect(root.textContent).toContain("Already installed?");
		button(root, ASSISTANT_EN["ui.next"]).click();

		// 7. Done: restart, summary, quick start, run again, close.
		await until(
			() => root.textContent?.includes("To restart: OpenCode") ?? false,
			"status summary",
		);
		expect(root.textContent).toContain(ASSISTANT_EN["done.restart"]);
		expect(root.textContent).toContain("Codex → aidr setup --host codex");
		expect(root.textContent).toContain("Run again anytime: aidr assistant");
		expect(root.querySelectorAll("ol.steps li")).toHaveLength(4);
		expect(button(root, ASSISTANT_EN["done.dashboard"]).getAttribute("href")).toBe(
			"https://aidr.corp.example",
		);
		button(root, ASSISTANT_EN["done.close"]).click();
		await until(() => root.textContent?.includes(ASSISTANT_EN["done.closed"]) ?? false, "closed");
		expect(server.calls.at(-1)).toBe("POST /api/finish");
	});

	it("switches to Turkish without touching the brand", async () => {
		const server = backend();
		const { root, wizard } = mount(server);
		await wizard.ready;
		const select = root.querySelector<HTMLSelectElement>("#lang") as HTMLSelectElement;
		expect(root.querySelector('label[for="lang"]')?.textContent).toBe(ASSISTANT_EN["ui.language"]);
		select.value = "tr";
		select.dispatchEvent(new Event("change"));
		expect(document.documentElement.lang).toBe("tr");
		expect(heading(root)).toBe(ASSISTANT_TR["welcome.heading"]);
		expect(button(root, ASSISTANT_TR["welcome.start"])).toBeTruthy();
		for (const brand of root.querySelectorAll('span[lang="en"]')) {
			expect(brand.textContent).toBe("Singularity AIDR");
		}
		expect(root.textContent).not.toContain("SİNGULARİTY");
	});

	it("pre-fills the address the installer left and offers to connect at once", async () => {
		const server = backend({
			state: { pending: { endpoint: "https://aidr.corp.example", hasToken: true } },
			polls: [{ phase: "enrolled", endpoint: "https://aidr.corp.example" }, { phase: "idle" }],
		});
		const { root, wizard } = mount(server);
		await wizard.ready;
		button(root, ASSISTANT_EN["welcome.start"]).click();
		await until(() => root.querySelectorAll('input[type="checkbox"]').length === 6, "tools");
		button(root, ASSISTANT_EN["ui.next"]).click();
		expect(root.querySelector<HTMLInputElement>("#company-connect")?.checked).toBe(true);
		expect(root.querySelector<HTMLInputElement>("#company-url")?.value).toBe(
			"https://aidr.corp.example",
		);
		button(root, ASSISTANT_EN["company.connectNow"]).click();
		await until(() => root.textContent?.includes("Connected to") ?? false, "connected");
		expect(server.calls).toContain(
			'POST /api/enroll/start {"endpoint":"https://aidr.corp.example","useInstallerToken":true}',
		);
	});

	it("explains a used or expired link instead of showing the wizard", async () => {
		const server = backend({ sessionStatus: 403, stateStatus: 401 });
		const { root, wizard } = mount(server);
		await wizard.ready;
		expect(root.querySelector('[role="alert"]')?.textContent).toBe(ASSISTANT_EN["ui.expired"]);
		expect(root.querySelector(".stepper")).toBeNull();
	});
});
