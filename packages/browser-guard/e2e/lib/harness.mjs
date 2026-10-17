// Browser + extension harness: launches Chromium with the unpacked extension,
// serves the fixture sites through context.route, records every request the
// pages make, and talks to the extension through its own pages.

import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extensionIdForPath } from "../../scripts/native-host.mjs";
import { ANY_PLACEHOLDER } from "./data.mjs";
import { AssertionError, waitFor } from "./expect.mjs";
import { KIT_PATH, SITES, siteForUrl, UPLOAD_PATH } from "./sites.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.resolve(here, "../fixtures");
/** The first start of a fresh profile can be slow on a loaded CI machine. */
const WORKER_START_TIMEOUT_MS = Number(process.env.BG_E2E_WORKER_TIMEOUT_MS) || 30000;

/** Playwright resolves its browser registry at import time, so set the path first. */
async function loadPlaywright() {
	if (!process.env.PLAYWRIGHT_BROWSERS_PATH && fs.existsSync("/opt/pw-browsers")) {
		process.env.PLAYWRIGHT_BROWSERS_PATH = "/opt/pw-browsers";
	}
	return import("playwright-core");
}

/** Where Playwright installs browsers, per platform, plus the CI image location. */
function browserRoots() {
	const home = os.homedir();
	return [
		process.env.PLAYWRIGHT_BROWSERS_PATH,
		"/opt/pw-browsers",
		process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, "ms-playwright"),
		path.join(home, ".cache", "ms-playwright"),
		path.join(home, "Library", "Caches", "ms-playwright"),
	].filter((dir) => dir && fs.existsSync(dir));
}

/** The Chromium executable inside a `chromium-<revision>` directory (per-platform layouts). */
function chromiumExecutable(dir) {
	const mac = path.join("Chromium.app", "Contents", "MacOS", "Chromium");
	const layouts = [
		path.join("chrome-linux", "chrome"),
		path.join("chrome-linux64", "chrome"),
		path.join("chrome-win", "chrome.exe"),
		path.join("chrome-win64", "chrome.exe"),
		path.join("chrome-mac", mac),
		path.join("chrome-mac-arm64", mac),
		path.join("chrome-mac-x64", mac),
	];
	return layouts.map((layout) => path.join(dir, layout)).find((file) => fs.existsSync(file));
}

/**
 * The executable for the explicit-path launch strategy: `BG_E2E_CHROMIUM` when set;
 * otherwise the Chromium revision the pinned playwright-core expects, or, when that
 * revision is not installed, the newest installed Playwright Chromium (logged, since
 * the suite was verified against the pinned revision).
 */
function fallbackExecutable(log) {
	if (process.env.BG_E2E_CHROMIUM) {
		log(`chromium: BG_E2E_CHROMIUM=${process.env.BG_E2E_CHROMIUM}`);
		return process.env.BG_E2E_CHROMIUM;
	}
	let expected;
	try {
		const pkg = createRequire(import.meta.url).resolve("playwright-core/package.json");
		const browsers = JSON.parse(fs.readFileSync(path.join(path.dirname(pkg), "browsers.json"), "utf8"));
		expected = Number(browsers.browsers.find((b) => b.name === "chromium")?.revision);
	} catch {
		// Unknown expected revision: fall through to the newest installed one.
	}
	const installed = [];
	for (const root of browserRoots()) {
		for (const entry of fs.readdirSync(root)) {
			const revision = Number(/^chromium-(\d+)$/.exec(entry)?.[1]);
			const executable = revision ? chromiumExecutable(path.join(root, entry)) : undefined;
			if (executable) installed.push({ revision, executable });
		}
	}
	const exact = installed.find((c) => c.revision === expected);
	if (exact) return exact.executable;
	const newest = installed.sort((a, b) => b.revision - a.revision)[0];
	if (!newest) return undefined;
	log(
		`chromium: chromium-${expected || "?"} (pinned by playwright-core) is not installed; ` +
			`using chromium-${newest.revision} at ${newest.executable} (set BG_E2E_CHROMIUM to choose another build)`,
	);
	return newest.executable;
}

// ---------------------------------------------------------------------------
// Chrome match patterns (manifest content_scripts[].matches)
// ---------------------------------------------------------------------------

function patternToRegExp(pattern) {
	if (pattern === "<all_urls>") return /^(https?|wss?|file|ftp):\/\//;
	const m = /^(\*|https?|wss?|file|ftp):\/\/([^/]*)(\/.*)$/.exec(pattern);
	if (!m) return /$^/;
	const [, scheme, host, pathPart] = m;
	const esc = (s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
	const schemeRe = scheme === "*" ? "https?" : esc(scheme);
	let hostRe;
	if (host === "*") hostRe = "[^/]+";
	else if (host.startsWith("*.")) hostRe = `(?:[^/]+\\.)?${esc(host.slice(2))}`;
	else hostRe = esc(host);
	const pathRe = esc(pathPart).replace(/\\\*/g, ".*").replace(/\*/g, ".*");
	return new RegExp(`^${schemeRe}://${hostRe}(?::\\d+)?${pathRe}$`);
}

function manifestMatchesUrl(manifest, url) {
	for (const cs of manifest.content_scripts ?? []) {
		const included = (cs.matches ?? []).some((p) => patternToRegExp(p).test(url));
		const excluded = (cs.exclude_matches ?? []).some((p) => patternToRegExp(p).test(url));
		if (included && !excluded) return true;
	}
	return false;
}

// ---------------------------------------------------------------------------
// Request recorder
// ---------------------------------------------------------------------------

class Recorder {
	constructor() {
		/** Every request any page/worker in the context issued (as Playwright saw it). */
		this.requests = [];
		/** Fixture API calls (prompt sends and uploads) with their parsed bodies. */
		this.api = [];
		this.seq = 0;
	}

	mark() {
		return this.seq;
	}

	addRequest(entry) {
		this.seq += 1;
		this.requests.push({ seq: this.seq, ...entry });
	}

	addApi(entry) {
		this.seq += 1;
		this.api.push({ seq: this.seq, ...entry });
	}

	apiSince(mark, filter = {}) {
		return this.api.filter(
			(a) =>
				a.seq > mark &&
				(!filter.site || a.site === filter.site) &&
				(!filter.kind || a.kind === filter.kind),
		);
	}

	/** Requests since `mark` whose URL or body contains any of `values` (raw or URL-encoded). */
	leaks(mark, values) {
		const hits = [];
		for (const r of this.requests) {
			if (r.seq <= mark) continue;
			const haystack = `${r.url}\n${r.body ?? ""}`;
			for (const v of values) {
				if (haystack.includes(v) || haystack.includes(encodeURIComponent(v))) {
					hits.push({ url: r.url, value: v });
				}
			}
		}
		return hits;
	}
}

// ---------------------------------------------------------------------------
// Fake model: answers with the placeholders it received, like a real model
// that was asked to "email the customer about the refund".
// ---------------------------------------------------------------------------

function fakeModelReply(prompt) {
	const placeholders = [...new Set(String(prompt).match(ANY_PLACEHOLDER) ?? [])];
	if (placeholders.length === 0) return `You said: ${prompt}`;
	return `I will follow up with ${placeholders.join(" and ")} as requested.`;
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

/**
 * Resolves the extension's service worker. Listens for the `serviceworker`
 * event and also polls `context.serviceWorkers()`, so a worker that registered
 * between launch and the listener (seen on a loaded machine) is still found.
 */
async function findWorker(context, timeout, { wakeUrl = null, wakeAfterMs = 5000 } = {}) {
	const isExt = (w) => w.url().startsWith("chrome-extension://");
	let seen = null;
	const onWorker = (w) => {
		if (isExt(w)) seen = w;
	};
	context.on("serviceworker", onWorker);
	// On a heavily loaded machine the worker's first start is occasionally not
	// observed (or it already went idle); loading one of the extension's own pages
	// (which messages the worker) starts it again.
	let wakePage = null;
	const wakeTimer = wakeUrl
		? setTimeout(() => {
				if (seen || context.serviceWorkers().some(isExt)) return;
				context
					.newPage()
					.then((page) => {
						wakePage = page;
						return page.goto(wakeUrl);
					})
					.catch(() => {});
			}, wakeAfterMs)
		: null;
	try {
		return await waitFor(() => seen ?? context.serviceWorkers().find(isExt), {
			timeout,
			interval: 250,
			message: "the extension service worker to start",
		});
	} finally {
		if (wakeTimer) clearTimeout(wakeTimer);
		await wakePage?.close().catch(() => {});
		context.off("serviceworker", onWorker);
	}
}

/**
 * Id Chromium assigns to an unpacked extension: the first 128 bits of
 * SHA-256(absolute path), hex digits mapped to the letters a-p. On Windows the path
 * is hashed as UTF-16LE (scripts/native-host.mjs `extensionIdForPath`, unit-tested
 * against an id Chromium assigned); hashing UTF-8 there gave a wrong id, so the
 * popup wake-up below opened a page of no extension.
 */
function unpackedExtensionId(extDir) {
	return extensionIdForPath(fs.realpathSync(extDir));
}

/**
 * Launch strategies, tried in order. Playwright's `channel: "chromium"` runs the
 * full Chromium build in new-headless mode, which supports extensions; the
 * explicit-executable variant is kept as a fallback for older Playwright builds.
 */
function strategies({ extDir, headed, log, extraArgs = [] }) {
	const args = [
		`--disable-extensions-except=${extDir}`,
		`--load-extension=${extDir}`,
		"--lang=en-US",
		"--no-first-run",
		"--no-default-browser-check",
		...extraArgs,
	];
	const list = [
		{
			name: headed ? "channel=chromium headed" : "channel=chromium headless (new headless)",
			options: { channel: "chromium", headless: !headed, args },
		},
	];
	const executablePath = headed ? undefined : fallbackExecutable(log);
	if (executablePath && fs.existsSync(executablePath)) {
		list.push({
			name: "executablePath + --headless=new",
			options: {
				executablePath,
				headless: false,
				args: [...args, "--headless=new"],
			},
		});
	}
	return list;
}

/**
 * `recordVideo` ({ dir, size }) is passed to Playwright (WebM per page, used by e2e/demo.mjs);
 * `viewport` overrides the 1280x800 default; `extraArgs` are added to the browser's command line
 * (the demo passes `--window-size`: the headless window is narrower than the emulated
 * viewport, and the video only shows the window).
 */
export async function launch({ extDir, headed = false, log = () => {}, recordVideo, viewport, extraArgs }) {
	const manifestPath = path.join(extDir, "manifest.json");
	if (!fs.existsSync(manifestPath)) {
		throw new Error(
			`no manifest.json in ${extDir} (build the extension first: pnpm -C packages/browser-guard build)`,
		);
	}
	const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
	const { chromium } = await loadPlaywright();

	let context;
	let worker;
	let profileDir;
	let used;
	const errors = [];
	for (const strategy of strategies({ extDir, headed, log, extraArgs })) {
		profileDir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-e2e-profile-"));
		try {
			context = await chromium.launchPersistentContext(profileDir, {
				...strategy.options,
				locale: "en-US",
				// null = follow the window size (headed demo); undefined = the suite's default.
				viewport: viewport === undefined ? { width: 1280, height: 800 } : viewport,
				...(recordVideo ? { recordVideo } : {}),
			});
			worker = await findWorker(context, WORKER_START_TIMEOUT_MS, {
				wakeUrl: `chrome-extension://${unpackedExtensionId(extDir)}/${manifest.action?.default_popup ?? "popup.html"}`,
			});
			used = strategy.name;
			break;
		} catch (error) {
			errors.push(`${strategy.name}: ${error.message.split("\n")[0]}`);
			log(`launch strategy failed: ${strategy.name}: ${error.message.split("\n")[0]}`);
			await context?.close().catch(() => {});
			context = undefined;
			fs.rmSync(profileDir, { recursive: true, force: true });
		}
	}
	if (!context) throw new Error(`could not load the extension:\n  ${errors.join("\n  ")}`);

	const extensionId = new URL(worker.url()).host;
	const harness = new Harness({
		context,
		worker,
		extensionId,
		manifest,
		extDir,
		profileDir,
		launchMode: used,
	});
	await harness.installRoutes();
	return harness;
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

class Harness {
	constructor({ context, worker, extensionId, manifest, extDir, profileDir, launchMode }) {
		this.context = context;
		this.worker = worker;
		this.extensionId = extensionId;
		this.manifest = manifest;
		this.extDir = extDir;
		this.profileDir = profileDir;
		this.launchMode = launchMode;
		this.recorder = new Recorder();
		this.controlPage = null;
		this.browserVersion = context.browser()?.version() ?? "unknown";
	}

	get extensionOrigin() {
		return `chrome-extension://${this.extensionId}`;
	}

	/** Path of the extension's popup page (relative to the extension root). */
	get popupPath() {
		return this.manifest.action?.default_popup ?? "popup.html";
	}

	async installRoutes() {
		const { context, recorder } = this;
		const kit = fs.readFileSync(path.join(FIXTURES, "kit.js"), "utf8");

		context.on("request", (request) => {
			let body = null;
			try {
				body = request.postData();
			} catch {
				body = "<unreadable>";
			}
			recorder.addRequest({ url: request.url(), method: request.method(), body });
		});

		// Hermetic: anything that is not a fixture origin or the extension itself is refused.
		await context.route(
			(url) => !/^(chrome-extension|data|blob|about):/.test(url.protocol) && !siteForUrl(url.href),
			(route) => route.abort("blockedbyclient"),
		);

		await context.route(
			(url) => Boolean(siteForUrl(url.href)),
			async (route) => {
				const request = route.request();
				const url = new URL(request.url());
				const site = siteForUrl(url.href);
				if (url.pathname === KIT_PATH) {
					return route.fulfill({ status: 200, contentType: "text/javascript", body: kit });
				}
				if (
					request.method() === "POST" &&
					(url.pathname === site.endpoint || url.pathname === UPLOAD_PATH)
				) {
					const raw = request.postData() ?? "";
					let json = null;
					try {
						json = JSON.parse(raw);
					} catch {
						json = null;
					}
					const kind = url.pathname === UPLOAD_PATH ? "upload" : "prompt";
					recorder.addApi({ site: site.siteId, kind, url: url.href, raw, json });
					const reply = kind === "prompt" ? fakeModelReply(json?.prompt ?? "") : "stored";
					return route.fulfill({
						status: 200,
						contentType: "application/json",
						body: JSON.stringify({ reply }),
					});
				}
				if (request.method() === "GET" && request.resourceType() === "document") {
					const fixture = site.pathFixtures?.[url.pathname] ?? site.fixture;
					const html = fs.readFileSync(path.join(FIXTURES, fixture), "utf8");
					return route.fulfill({
						status: 200,
						contentType: "text/html; charset=utf-8",
						body: html,
					});
				}
				if (url.pathname === "/favicon.ico") return route.fulfill({ status: 204, body: "" });
				return route.fulfill({ status: 404, contentType: "text/plain", body: "not found" });
			},
		);
	}

	/** Whether the extension's content scripts are declared for `siteKey`. */
	coversSite(siteKey) {
		const s = SITES[siteKey];
		return manifestMatchesUrl(this.manifest, `${s.origin}${s.path}`);
	}

	/**
	 * Opens a fixture site in a fresh tab and waits until both the page and the
	 * extension's content script are ready. Readiness of the content script is
	 * observed through CDP: its isolated world shows up as an execution context
	 * whose origin is the extension.
	 */
	async openSite(siteKey, { expectContentScript = true, path: sitePath } = {}) {
		const site = SITES[siteKey];
		const page = await this.context.newPage();
		const pageErrors = [];
		page.on("pageerror", (e) => pageErrors.push(String(e.message ?? e)));
		page.on("console", (m) => {
			if (m.type() === "error") pageErrors.push(`console: ${m.text()}`);
		});
		page.__pageErrors = pageErrors;

		const cdp = await this.context.newCDPSession(page);
		const worlds = [];
		// Content-script worlds report the extension origin (and the extension name);
		// Playwright's own utility world is also "isolated" but has the page origin.
		cdp.on("Runtime.executionContextCreated", ({ context }) => {
			if (String(context.origin ?? "").startsWith(this.extensionOrigin)) worlds.push(context);
		});
		await cdp.send("Runtime.enable");

		await page.goto(`${site.origin}${sitePath ?? site.path}`, { waitUntil: "load" });
		await page.bringToFront();
		await waitFor(
			() => page.evaluate(() => document.documentElement.getAttribute("data-fixture-ready")),
			{
				timeout: 5000,
				message: `fixture ${site.fixture} to initialise`,
			},
		);
		if (expectContentScript) {
			await waitFor(() => worlds.length > 0, {
				timeout: 8000,
				message: `extension content script to be injected into ${site.origin}`,
			});
			// Give the content script's async start-up (GET_POLICY round trip) a moment.
			await page.waitForTimeout(300);
		}
		await cdp.detach().catch(() => {});
		return page;
	}

	/** A long-lived extension page used to message the background worker. */
	async control() {
		if (this.controlPage && !this.controlPage.isClosed()) return this.controlPage;
		this.controlPage = await this.context.newPage();
		await this.controlPage.goto(`${this.extensionOrigin}/${this.popupPath}`);
		return this.controlPage;
	}

	/** Sends a GuardMessage to the background worker from an extension page. */
	async sendMessage(message) {
		const page = await this.control();
		return page.evaluate(async (msg) => {
			try {
				return { ok: true, value: await chrome.runtime.sendMessage(msg) };
			} catch (error) {
				return { ok: false, error: String(error?.message ?? error) };
			}
		}, message);
	}

	async getPolicy() {
		const res = await this.sendMessage({ type: "GET_POLICY" });
		if (!res.ok) throw new Error(`GET_POLICY failed: ${res.error}`);
		const v = res.value;
		return v?.policy ?? v;
	}

	async getStats(tabId) {
		const res = await this.sendMessage(
			tabId === undefined ? { type: "GET_STATS" } : { type: "GET_STATS", tabId },
		);
		if (!res.ok) throw new Error(`GET_STATS failed: ${res.error}`);
		return res.value?.stats ?? res.value;
	}

	/** Current extension service worker (MV3 workers are restarted after idling). */
	async currentWorker() {
		const live = this.context
			.serviceWorkers()
			.find((w) => w.url().startsWith(this.extensionOrigin));
		if (live) return live;
		// Waking the worker: any extension page load or message restarts it.
		await this.sendMessage({ type: "GET_POLICY" });
		return findWorker(this.context, 5000);
	}

	/**
	 * Applies user settings and waits until the effective policy (GET_POLICY)
	 * reflects them. Primary path: write chrome.storage.local.userSettings from
	 * the service worker with `worker.evaluate` (the background reloads its policy
	 * on storage.onChanged). If the policy does not follow within 2s, the
	 * documented SET_USER_SETTINGS message is sent from an extension page.
	 */
	async setUserSettings(settings, { storageKey = "userSettings" } = {}) {
		const reflected = async () => {
			const policy = await this.getPolicy();
			return Object.entries(settings).every(
				([k, v]) => JSON.stringify(policy?.[k]) === JSON.stringify(v),
			);
		};
		const describe = JSON.stringify(settings);
		let viaStorage = false;
		try {
			const worker = await this.currentWorker();
			await worker.evaluate(
				async ({ key, patch }) => {
					const current = (await chrome.storage.local.get(key))[key] ?? {};
					await chrome.storage.local.set({ [key]: { ...current, ...patch } });
				},
				{ key: storageKey, patch: settings },
			);
			viaStorage = await waitFor(reflected, {
				timeout: 2000,
				message: `policy to reflect ${describe}`,
			})
				.then(() => true)
				.catch(() => false);
		} catch {
			viaStorage = false;
		}
		if (viaStorage) return "storage";
		const res = await this.sendMessage({ type: "SET_USER_SETTINGS", settings });
		if (!res.ok || res.value?.ok === false) {
			throw new AssertionError(
				`SET_USER_SETTINGS ${describe} was rejected`,
				res.ok ? res.value : res.error,
			);
		}
		await waitFor(reflected, { timeout: 5000, message: `effective policy to reflect ${describe}` });
		return "message";
	}

	/**
	 * Snapshot of visible extension-owned overlays (bubble/toast) as `tag:text`.
	 *
	 * The product renders its UI in a CLOSED shadow root (the host page must not
	 * read it), which page scripts and Playwright locators cannot enter, so this
	 * reads the DOM over CDP with `pierce: true` (open and closed shadow roots).
	 * An overlay is an element whose tag/id/class/data-* mentions
	 * aidr|browser-guard|privacy-guard, that is not the editor or one of its
	 * ancestors, is not inside a `hidden` subtree and has a non-empty layout box.
	 */
	async overlays(page, siteKey) {
		const editorSelector = SITES[siteKey].editor;
		return withCdp(page, async (cdp) => {
			const RX = /aidr|browser-guard|privacy-guard/i;
			const { root } = await cdp.send("DOM.getDocument", { depth: -1, pierce: true });
			const editor = await cdp
				.send("DOM.querySelector", { nodeId: root.nodeId, selector: editorSelector })
				.then((r) => r.nodeId)
				.catch(() => 0);
			const attrs = (node) => {
				const out = {};
				const list = node.attributes ?? [];
				for (let i = 0; i + 1 < list.length; i += 2) out[list[i]] = list[i + 1];
				return out;
			};
			const kids = (node) => [...(node.shadowRoots ?? []), ...(node.children ?? [])];
			const textOf = (node) => {
				if (node.nodeType === 3) return node.nodeValue ?? "";
				if (node.nodeType === 1) {
					if (["STYLE", "SCRIPT", "TEMPLATE"].includes(node.nodeName)) return "";
					if ("hidden" in attrs(node)) return "";
				}
				return kids(node).map(textOf).join(" ");
			};
			const containsEditor = (node) =>
				node.nodeId === editor || kids(node).some((child) => containsEditor(child));
			const candidates = [];
			const visit = (node, hiddenAbove) => {
				const a = node.nodeType === 1 ? attrs(node) : {};
				const hidden = hiddenAbove || "hidden" in a;
				if (node.nodeType === 1 && !hidden && !["HTML", "BODY"].includes(node.nodeName)) {
					const signature = [
						node.localName,
						a.id ?? "",
						a.class ?? "",
						...Object.entries(a)
							.filter(([k]) => k.startsWith("data-"))
							.map(([k, v]) => `${k}=${v}`),
					].join(" ");
					if (RX.test(signature) && !(editor && containsEditor(node))) candidates.push(node);
				}
				for (const child of kids(node)) visit(child, hidden);
			};
			visit(root, false);
			const out = [];
			for (const node of candidates) {
				const box = await cdp
					.send("DOM.getBoxModel", { backendNodeId: node.backendNodeId })
					.catch(() => null);
				if (!box || box.model.width <= 0 || box.model.height <= 0) continue;
				out.push(`${node.localName}:${textOf(node).replace(/\s+/g, " ").trim().slice(0, 400)}`);
			}
			return out;
		});
	}

	/**
	 * Clicks a button of an extension overlay like a user would (a real mouse click
	 * at its centre). Buttons are found in Chromium's accessibility tree by role and
	 * accessible name; the tree includes closed shadow roots.
	 * @returns {Promise<boolean>} whether a matching visible button was clicked
	 */
	async clickOverlayButton(page, name) {
		const point = await withCdp(page, async (cdp) => {
			const { nodes } = await cdp.send("Accessibility.getFullAXTree");
			for (const node of nodes) {
				if (node.ignored || node.role?.value !== "button" || !node.backendDOMNodeId) continue;
				if (!name.test(String(node.name?.value ?? ""))) continue;
				const box = await cdp
					.send("DOM.getBoxModel", { backendNodeId: node.backendDOMNodeId })
					.catch(() => null);
				if (!box || box.model.width <= 0) continue;
				const q = box.model.content;
				return { x: (q[0] + q[4]) / 2, y: (q[1] + q[5]) / 2 };
			}
			return null;
		});
		if (!point) return false;
		await page.mouse.click(point.x, point.y);
		return true;
	}

	/**
	 * Make a per-user native host registration visible to this browser. On Linux and macOS
	 * Chromium looks for per-user host manifests in `<user-data-dir>/NativeMessagingHosts`,
	 * and the harness runs a temporary profile, so the copy under the default profile
	 * (~/.config/chromium) is never read; the manifest is mirrored into the temporary
	 * profile (removed with it). Windows reads the HKCU registry key, which needs nothing.
	 */
	exposeNativeHostManifest(manifestPath) {
		if (process.platform === "win32") return;
		const dir = path.join(this.profileDir, "NativeMessagingHosts");
		fs.mkdirSync(dir, { recursive: true });
		fs.copyFileSync(manifestPath, path.join(dir, path.basename(manifestPath)));
	}

	async close() {
		await this.context.close().catch(() => {});
		// Windows: Chromium's child processes can hold profile files for a while after close
		// (seen with a headed browser); a leftover temp profile must not fail the run.
		try {
			fs.rmSync(this.profileDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
		} catch (error) {
			console.error(`[harness] could not remove the temporary profile ${this.profileDir}: ${error.code ?? error}`);
		}
	}
}

// ---------------------------------------------------------------------------
// Page actions shared by scenarios
// ---------------------------------------------------------------------------

export async function readEditor(page, siteKey) {
	const site = SITES[siteKey];
	return page.evaluate(
		({ sel, kind }) => window.FixtureChat.readEditor(document.querySelector(sel), kind),
		{ sel: site.editor, kind: site.kind },
	);
}

/** Focuses the editor and types like a user (one key event per character). */
export async function typePrompt(page, siteKey, text) {
	const site = SITES[siteKey];
	await page.locator(site.editor).click();
	const lines = text.split("\n");
	for (let i = 0; i < lines.length; i += 1) {
		if (i > 0) await page.keyboard.press("Shift+Enter");
		if (lines[i]) await page.keyboard.type(lines[i]);
	}
	await waitFor(async () => (await readEditor(page, siteKey)).includes(lines.at(-1)), {
		timeout: 3000,
		message: "typed text to appear in the editor",
	});
}

/** Dispatches a paste carrying `text` on the editor, as the browser does for Ctrl+V. */
export async function pasteText(page, siteKey, text) {
	const site = SITES[siteKey];
	await page.locator(site.editor).click();
	await page.locator(site.editor).evaluate((el, value) => {
		const data = new DataTransfer();
		data.setData("text/plain", value);
		el.dispatchEvent(
			new ClipboardEvent("paste", {
				clipboardData: data,
				bubbles: true,
				cancelable: true,
				composed: true,
			}),
		);
	}, text);
}

/** Waits for the next prompt request to the site's API after `mark`. */
export async function waitForPrompt(h, siteKey, mark, timeout = 8000) {
	const siteId = SITES[siteKey].siteId;
	return waitFor(() => h.recorder.apiSince(mark, { site: siteId, kind: "prompt" })[0], {
		timeout,
		message: `a prompt request to ${SITES[siteKey].origin}${SITES[siteKey].endpoint}`,
	});
}

/**
 * Text of the most recent assistant response as the USER perceives it.
 *
 * The product renders restored values from a closed shadow root that page
 * scripts (and Playwright locators) cannot see, so this reads Chromium's own
 * accessibility tree over CDP: it is built from the rendered (flat) tree,
 * includes closed shadow content and leaves out aria-hidden/invisible nodes.
 */
export async function lastResponseText(page, siteKey) {
	const site = SITES[siteKey];
	return withCdp(page, async (cdp) => {
		const { root } = await cdp.send("DOM.getDocument", { depth: 0 });
		const { nodeIds } = await cdp.send("DOM.querySelectorAll", {
			nodeId: root.nodeId,
			selector: site.response,
		});
		const target = nodeIds.at(-1);
		if (!target) return null;
		const { node } = await cdp.send("DOM.describeNode", {
			nodeId: target,
			depth: -1,
			pierce: true,
		});
		const { nodes } = await cdp.send("Accessibility.getFullAXTree");
		const byId = new Map(nodes.map((n) => [n.nodeId, n]));
		const byDom = new Map(
			nodes.filter((n) => n.backendDOMNodeId).map((n) => [n.backendDOMNodeId, n]),
		);
		let text = "";
		const visitAx = (ax) => {
			if (ax.role?.value === "StaticText") {
				if (!ax.ignored) text += ax.name?.value ?? "";
				return;
			}
			for (const id of ax.childIds ?? []) {
				const child = byId.get(id);
				if (child) visitAx(child);
			}
		};
		// Elements without an accessibility node of their own (e.g. unknown custom
		// elements such as Gemini's <message-content>) contribute their descendants'.
		const visitDom = (dom) => {
			const ax = byDom.get(dom.backendNodeId);
			if (ax && !ax.ignored) return visitAx(ax);
			if (dom.nodeType === 3) return;
			for (const child of [...(dom.shadowRoots ?? []), ...(dom.children ?? [])]) visitDom(child);
		};
		visitDom(node);
		return text;
	});
}

/**
 * Runs `fn` with a short-lived CDP session attached to `target`: a page, or a frame that
 * runs out of process (a cross-site iframe under site isolation, e.g. the Copilot pane).
 */
export async function withCdp(target, fn) {
	const page = typeof target.page === "function" ? target.page() : target;
	const cdp = await page.context().newCDPSession(target);
	try {
		return await fn(cdp);
	} finally {
		await cdp.detach().catch(() => {});
	}
}

/** Text of the most recent assistant response as the PAGE's own scripts read it (innerText). */
export async function lastResponsePageText(page, siteKey) {
	return page.evaluate((sel) => {
		const nodes = document.querySelectorAll(sel);
		const last = nodes[nodes.length - 1];
		return last ? last.innerText : null;
	}, SITES[siteKey].response);
}

export async function waitForResponseComplete(page) {
	await waitFor(() => page.locator("[data-fixture-complete]").count(), {
		timeout: 8000,
		message: "the assistant response to finish streaming",
	});
}

export function assertNoLeaks(
	checks,
	h,
	mark,
	values,
	label = "no request carried the original values",
) {
	const leaks = h.recorder.leaks(mark, values);
	checks.check(label, leaks.length === 0, leaks);
}

