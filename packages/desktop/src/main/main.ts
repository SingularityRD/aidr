import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import {
	app,
	BrowserWindow,
	dialog,
	ipcMain,
	Menu,
	Notification,
	nativeImage,
	nativeTheme,
	protocol,
	session,
	shell,
	Tray,
} from "electron";
import { auditLogFiles, readAuditEntries } from "../../../cli/src/commands/audit.js";
import type {
	ActionResult,
	AppInfo,
	AuditEvent,
	Lang,
	OpenTarget,
	Preferences,
	PushChannel,
	PushMap,
	StatusSnapshot,
} from "../shared/contract.js";
import { type MessageKey, resolveLanguage, translate } from "../shared/i18n.js";
import { setLogClean } from "./aidr-config.js";
import {
	APP_ENTRY,
	APP_HOST,
	APP_SCHEME,
	CONTENT_SECURITY_POLICY,
	resolveAppAsset,
} from "./app-protocol.js";
import { AuditReader, type AuditRecord, watchAudit } from "./audit.js";
import { AuditStore } from "./audit-store.js";
import {
	browserGuardStatus,
	extensionsPageCommand,
	stagedExtensionDir,
	stageExtension,
} from "./browser-guard.js";
import { connectClaude, disconnectClaude, previewConnect } from "./claude.js";
import { runFile } from "./exec.js";
import { assertHandlersMatchContract, createIpcHandlers, isTrustedSender } from "./ipc.js";
import { aidrHome, claudeSettingsPath, dataDir, runtimeBinary } from "./paths.js";
import { loadPreferences, savePreferences } from "./prefs.js";
import { runSelfTest } from "./selftest.js";
import { auditLogPath, auditMaxFiles, collectStatus } from "./status.js";

// Tests and demos can isolate Chromium's profile data (never the AIDR files,
// which follow HOME/USERPROFILE exactly like the hooks).
const userDataOverride = process.env.AIDR_DESKTOP_USER_DATA?.trim();
if (userDataOverride) app.setPath("userData", userDataOverride);

const APP_ID = "com.singularityrd.aidr.desktop";
const STATUS_INTERVAL_MS = 30_000;

protocol.registerSchemesAsPrivileged([
	{ scheme: APP_SCHEME, privileges: { standard: true, secure: true, supportFetchAPI: false } },
]);

const home = aidrHome();
const appRoot = app.getAppPath();
const resourceRoot = app.isPackaged ? process.resourcesPath : join(appRoot, "build", "runtime");
const bundledRuntimeDir = join(
	resourceRoot,
	app.isPackaged ? join("runtime", "aidr-sea") : "aidr-sea",
);
const bundledRuntime = existsSync(bundledRuntimeDir) ? bundledRuntimeDir : null;
const bundledExtensionDir = join(
	resourceRoot,
	app.isPackaged ? join("runtime", "browser-guard") : "browser-guard",
);
const bundledExtension = existsSync(join(bundledExtensionDir, "manifest.json"))
	? bundledExtensionDir
	: null;
const rendererRoot = join(__dirname, "..", "renderer");
const iconRoot = join(rendererRoot, "icons");

let preferencesPath = "";
let preferences: Preferences;
let language: Lang = "en";
let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let quitting = false;
let lastStatus: StatusSnapshot | null = null;
let statusInFlight: Promise<StatusSnapshot> | null = null;
let auditPath = "";
let auditReader: AuditReader | null = null;
let stopAuditWatch: (() => void) | null = null;
let store = new AuditStore();

const t = (key: MessageKey, params?: Record<string, string | number>) =>
	translate(language, key, params);

function push<C extends PushChannel>(channel: C, payload: PushMap[C]): void {
	if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, payload);
}

function applyLanguage(): void {
	language = resolveLanguage(preferences.language, app.getPreferredSystemLanguages());
}

function appInfo(): AppInfo {
	return {
		appVersion: app.getVersion(),
		language,
		preferences,
		platform: `${process.platform}/${process.arch}`,
	};
}

// ── Audit log ──────────────────────────────────────────────────────────

function notifyDeny(event: AuditEvent): void {
	if (!preferences.notifyOnDeny || !Notification.isSupported()) return;
	const notification = new Notification({
		title: t("notify.denyTitle"),
		body: t("notify.denyBody", { tool: event.tool, summary: event.summary.slice(0, 120) }),
		icon: join(iconRoot, "icon-256.png"),
	});
	notification.on("click", () => {
		showWindow();
		push("nav:go", "activity");
	});
	notification.show();
}

function onAuditRecords(records: AuditRecord[]): void {
	const { rows, incidentsChanged } = store.ingest(records);
	if (rows.length > 0) push("audit:events", rows);
	if (incidentsChanged) push("incidents:changed", store.incidentList());
	for (const row of rows)
		if (row.recordType === "runtime_verdict" && row.decision === "deny") notifyDeny(row);
}

/**
 * (Re)start following the audit log; its path can change with `logging.path`.
 * History comes from the rotated files (read with the CLI's own reader, the
 * one `aidr audit export` uses) and the active file; new records are tailed.
 */
async function followAudit(): Promise<void> {
	const path = auditLogPath(home);
	if (path === auditPath && auditReader) return;
	stopAuditWatch?.();
	auditPath = path;
	auditReader = new AuditReader(path);
	store = new AuditStore();
	const rotated = auditLogFiles({ path, max_files: auditMaxFiles(home) }).filter(
		(file) => file !== path,
	);
	try {
		store.ingest((await readAuditEntries(rotated)).entries);
	} catch {
		// Unreadable backups only shorten the history shown.
	}
	store.ingest(auditReader.initial());
	stopAuditWatch = watchAudit(auditReader, onAuditRecords);
	push("incidents:changed", store.incidentList());
}

// ── Status and tray ────────────────────────────────────────────────────

function refreshStatus(): Promise<StatusSnapshot> {
	statusInFlight ??= collectStatus({
		home,
		appVersion: app.getVersion(),
		bundledRuntime,
		run: runFile,
		lastVerdict: store.lastVerdict(),
	})
		.then((status) => {
			lastStatus = status;
			void followAudit();
			updateTray();
			push("status:changed", status);
			return status;
		})
		.finally(() => {
			statusInFlight = null;
		});
	return statusInFlight;
}

function trayIcon(protectedNow: boolean): Electron.NativeImage {
	const file = join(iconRoot, protectedNow ? "tray-protected.png" : "tray-unprotected.png");
	const image = nativeImage.createFromPath(file);
	return image.isEmpty() ? nativeImage.createFromPath(join(iconRoot, "icon-32.png")) : image;
}

function updateTray(): void {
	if (!tray) return;
	const protectedNow = lastStatus?.protected === true;
	tray.setImage(trayIcon(protectedNow));
	const state = protectedNow ? t("tray.protected") : t("tray.notProtected");
	tray.setToolTip(`${t("app.name")} — ${state}`);
	tray.setContextMenu(
		Menu.buildFromTemplate([
			{ label: `${t("app.name")}: ${state}`, enabled: false },
			{ type: "separator" },
			{ label: t("tray.open"), click: () => showWindow() },
			{
				label: t("tray.selftest"),
				click: () => {
					showWindow();
					push("nav:go", "selftest");
				},
			},
			{ type: "separator" },
			{
				label: t("tray.quit"),
				click: () => {
					quitting = true;
					app.quit();
				},
			},
		]),
	);
}

function createTray(): void {
	try {
		tray = new Tray(trayIcon(false));
		tray.on("click", () => showWindow());
		updateTray();
	} catch {
		tray = null;
	}
}

// ── Window ─────────────────────────────────────────────────────────────

function applyTheme(): void {
	nativeTheme.themeSource = preferences.theme;
}

function showWindow(): void {
	if (!mainWindow || mainWindow.isDestroyed()) createWindow(true);
	else {
		if (mainWindow.isMinimized()) mainWindow.restore();
		mainWindow.show();
		mainWindow.focus();
	}
}

function createWindow(show: boolean): void {
	mainWindow = new BrowserWindow({
		width: 1200,
		height: 800,
		minWidth: 940,
		minHeight: 640,
		show: false,
		title: t("app.name"),
		icon: join(iconRoot, "icon-256.png"),
		backgroundColor: nativeTheme.shouldUseDarkColors ? "#14161b" : "#f6f5f1",
		autoHideMenuBar: true,
		webPreferences: {
			preload: join(__dirname, "..", "preload", "preload.cjs"),
			contextIsolation: true,
			nodeIntegration: false,
			sandbox: true,
			webSecurity: true,
			spellcheck: false,
			devTools: !app.isPackaged,
		},
	});
	mainWindow.removeMenu();
	mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
	mainWindow.webContents.on("will-navigate", (event, url) => {
		if (!url.startsWith(`${APP_SCHEME}://${APP_HOST}/`)) event.preventDefault();
	});
	mainWindow.once("ready-to-show", () => {
		if (show) mainWindow?.show();
	});
	mainWindow.on("close", (event) => {
		// Closing keeps the app in the tray (the audit feed and notifications keep running).
		if (!quitting && tray) {
			event.preventDefault();
			mainWindow?.hide();
		}
	});
	void mainWindow.loadURL(APP_ENTRY);
}

// ── Services behind the IPC allowlist ──────────────────────────────────

function claudeDeps() {
	if (!bundledRuntime) throw new Error("this build does not include the AIDR runtime");
	return { home, bundledRuntime, run: runFile, language };
}

async function afterChange<T>(result: T): Promise<T> {
	await refreshStatus().catch(() => undefined);
	return result;
}

const errorResult = (error: unknown): ActionResult => ({
	ok: false,
	message: error instanceof Error ? error.message : String(error),
	log: "",
});

function bgDeps() {
	return { home, run: runFile, bundledExtension };
}

async function openTarget(target: OpenTarget): Promise<ActionResult> {
	const paths: Record<OpenTarget, string | null> = {
		auditLog: auditLogPath(home),
		claudeSettings: claudeSettingsPath(home),
		dataDir: dataDir(home),
		browserGuardFolder: stagedExtensionDir(bgDeps()),
	};
	const path = paths[target];
	if (!path || !existsSync(path))
		return { ok: false, message: `${path ?? target} does not exist`, log: "" };
	if (target === "browserGuardFolder" || target === "dataDir") {
		const error = await shell.openPath(path);
		return { ok: error === "", message: error || path, log: "" };
	}
	shell.showItemInFolder(path);
	return { ok: true, message: path, log: "" };
}

/**
 * Export through `aidr audit export` (redacted again, session ids digested,
 * rotated files included) to a file the user picks. Read-only on the log.
 */
async function exportAudit(format: "jsonl" | "csv"): Promise<ActionResult> {
	const receipt = (() => {
		try {
			return JSON.parse(readFileSync(join(dataDir(home), "installation.json"), "utf8")) as {
				path?: unknown;
			};
		} catch {
			return null;
		}
	})();
	const root =
		typeof receipt?.path === "string" && existsSync(runtimeBinary(receipt.path))
			? receipt.path
			: bundledRuntime;
	if (!root) return { ok: false, message: "no AIDR runtime is available", log: "" };
	const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
	const options = {
		defaultPath: join(app.getPath("documents"), `aidr-audit-${stamp}.${format}`),
		filters: [{ name: format.toUpperCase(), extensions: [format] }],
	};
	const choice = mainWindow
		? await dialog.showSaveDialog(mainWindow, options)
		: await dialog.showSaveDialog(options);
	if (choice.canceled || !choice.filePath) return { ok: false, message: "canceled", log: "" };
	// The save dialog already asked before replacing an existing file; the CLI
	// itself only ever creates a new one.
	if (existsSync(choice.filePath)) rmSync(choice.filePath);
	const result = await runFile(
		runtimeBinary(root),
		["audit", "export", "--format", format, "--output", choice.filePath],
		{
			cwd: home,
			timeoutMs: 120_000,
		},
	);
	const log = [result.stdout.trim(), result.stderr.trim(), result.error ?? ""]
		.filter(Boolean)
		.join("\n");
	return result.exitCode === 0 && existsSync(choice.filePath)
		? { ok: true, message: choice.filePath, log }
		: {
				ok: false,
				message: `aidr audit export failed (exit ${result.exitCode ?? result.error})`,
				log,
			};
}

function applyStartAtLogin(): void {
	if (!app.isPackaged) return;
	app.setLoginItemSettings({
		openAtLogin: preferences.startAtLogin,
		path: process.env.PORTABLE_EXECUTABLE_FILE || process.execPath,
		args: ["--hidden"],
	});
}

const handlers = createIpcHandlers({
	info: appInfo,
	status: () => refreshStatus(),
	previewConnect: async () => previewConnect(claudeDeps()),
	connect: async () => {
		try {
			return await afterChange(await connectClaude(claudeDeps()));
		} catch (error) {
			return errorResult(error);
		}
	},
	disconnect: async () => {
		try {
			return await afterChange(await disconnectClaude(claudeDeps()));
		} catch (error) {
			return errorResult(error);
		}
	},
	selfTest: async () => {
		const result = await runSelfTest({ home, run: runFile });
		// Pick up the verdicts the hook just wrote without waiting for the next tick.
		if (auditReader) {
			const fresh = auditReader.poll();
			if (fresh.length > 0) onAuditRecords(fresh);
		}
		return result;
	},
	recentAudit: () => store.allRows(),
	incidentList: async () => store.incidentList(),
	incidentDetail: async (id) => store.incidentDetail(id),
	exportAudit: (format) => exportAudit(format),
	setLogClean: async (enabled) => {
		try {
			setLogClean(enabled);
			// The status refresh runs in the background: it must not hold the
			// action lock (a self-test right after the toggle would be refused).
			void refreshStatus().catch(() => undefined);
			return { ok: true, message: `logging.log_clean = ${enabled}`, log: "" };
		} catch (error) {
			return errorResult(error);
		}
	},
	browserGuardStatus: () => browserGuardStatus(bgDeps()),
	stageBrowserGuard: async () => {
		try {
			const path = stageExtension(bgDeps());
			return { ok: true, message: path, log: "" };
		} catch (error) {
			return errorResult(error);
		}
	},
	openExtensionsPage: async (browser) => {
		const command = extensionsPageCommand(browser);
		if (!command) return { ok: false, message: `${browser} was not found`, log: "" };
		const result = await runFile(command.file, command.args, { timeoutMs: 3_000 });
		// The browser keeps running; only a failure to start it is an error.
		return {
			ok: result.error === null || result.error.startsWith("timed out"),
			message: command.url,
			log: result.error ?? "",
		};
	},
	setPreferences: async (patch) => {
		const previous = preferences;
		preferences = { ...preferences, ...patch };
		savePreferences(preferencesPath, preferences);
		applyLanguage();
		applyTheme();
		if (previous.startAtLogin !== preferences.startAtLogin) applyStartAtLogin();
		updateTray();
		return appInfo();
	},
	open: openTarget,
});
assertHandlersMatchContract(handlers);

// ── Lifecycle ──────────────────────────────────────────────────────────

if (!app.requestSingleInstanceLock()) {
	app.quit();
} else {
	app.on("second-instance", () => showWindow());
	app.setAppUserModelId(APP_ID);
	app.on("web-contents-created", (_event, contents) => {
		contents.on("will-attach-webview", (event) => event.preventDefault());
	});
	app.whenReady().then(() => {
		preferencesPath = join(app.getPath("userData"), "preferences.json");
		preferences = loadPreferences(preferencesPath);
		applyLanguage();
		applyTheme();
		Menu.setApplicationMenu(null);
		// Only "Copy path" needs a permission (writing text to the clipboard).
		session.defaultSession.setPermissionRequestHandler((_contents, permission, callback) =>
			callback(permission === "clipboard-sanitized-write"),
		);
		session.defaultSession.setPermissionCheckHandler(
			(_contents, permission) => permission === "clipboard-sanitized-write",
		);
		session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
			// No remote content: only the app's own scheme (and devtools in development).
			const allowed =
				details.url.startsWith(`${APP_SCHEME}://`) ||
				details.url.startsWith("devtools://") ||
				details.url.startsWith("data:");
			callback({ cancel: !allowed });
		});
		protocol.handle(APP_SCHEME, (request) => {
			const asset = resolveAppAsset(rendererRoot, request.url);
			if (!asset || !existsSync(asset.file)) return new Response("not found", { status: 404 });
			return new Response(readFileSync(asset.file), {
				headers: {
					"content-type": asset.type,
					"content-security-policy": CONTENT_SECURITY_POLICY,
					"x-content-type-options": "nosniff",
					"cache-control": "no-store",
				},
			});
		});
		for (const [channel, handler] of Object.entries(handlers)) {
			ipcMain.handle(channel, (event, payload: unknown) => {
				if (!isTrustedSender(event.senderFrame?.url)) throw new Error("untrusted sender");
				return (handler as (payload: unknown) => Promise<unknown>)(payload);
			});
		}
		void followAudit();
		createTray();
		// Browser Guard ships with the app: keep its per-user folder current on every
		// start, so the browser only has to load it once (and reloads updates itself).
		if (bundledExtension) {
			try {
				stageExtension(bgDeps());
			} catch {
				// Shown on the Browser Guard page, which can stage it again.
			}
		}
		createWindow(!process.argv.includes("--hidden"));
		void refreshStatus().catch(() => undefined);
		setInterval(() => void refreshStatus().catch(() => undefined), STATUS_INTERVAL_MS);
	});
	app.on("before-quit", () => {
		quitting = true;
		stopAuditWatch?.();
	});
	app.on("window-all-closed", () => {
		if (!tray) app.quit();
	});
}
