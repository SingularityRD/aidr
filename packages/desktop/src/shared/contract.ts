/**
 * The typed IPC contract between the renderer (through the preload bridge) and
 * the main process. Every channel the renderer may use is listed here; the
 * preload exposes exactly these and nothing else, and the main process
 * validates every argument again before acting on it.
 */

export type Lang = "tr" | "en";
export type LanguagePref = "auto" | Lang;
type ThemePref = "system" | "light" | "dark";
export type Decision = "allow" | "ask" | "deny";

export interface Preferences {
	language: LanguagePref;
	theme: ThemePref;
	/** Desktop notification when a deny verdict is written to the audit log. */
	notifyOnDeny: boolean;
	/** Start the app (hidden, in the tray) when the user signs in. Off by default. */
	startAtLogin: boolean;
}

export const DEFAULT_PREFERENCES: Preferences = {
	language: "auto",
	theme: "system",
	notifyOnDeny: true,
	startAtLogin: false,
};

type ConnectorStateId =
	| "installed"
	| "unavailable"
	| "runtime_present_not_installed"
	| "not_detected"
	| "installed_but_degraded";

export type HostId = "claude-code" | "cursor" | "vscode" | "openclaw" | "opencode" | "codex";

export interface HookFacts {
	/** How the host runs AIDR: a command hook it spawns, or code loaded in-process. */
	kind: "command" | "in_process" | "extension";
	/** Whether an AIDR hook is registered in the host's config (null: not applicable). */
	registered: boolean | null;
	/** The registered PreToolUse commands, verbatim. */
	commands: string[];
	/** Whether every registered hook binary exists on disk (null: not applicable / not parseable). */
	binaryPresent: boolean | null;
	/** The config file the facts were read from. */
	configPath: string | null;
}

export interface ConnectorView {
	id: HostId;
	label: string;
	state: ConnectorStateId;
	detail: string;
	evidence: string[];
	remedy?: string;
	hook: HookFacts;
}

export interface EngineFacts {
	ok: boolean;
	/** Rules loaded by the shipped engine (`aidr status --json`), null when it did not answer. */
	rules: number | null;
	detail: string;
	/** Which binary answered. */
	binary: string | null;
	latencyMs: number | null;
}

interface RuntimeFacts {
	/** The AIDR runtime shipped inside the app. */
	bundledRoot: string | null;
	bundledVersion: string | null;
	flavor: string | null;
	signed: boolean;
	/** The per-user copy the hooks run from (null until Claude Code was connected). */
	installedRoot: string | null;
	/** Problems verifying the bundled runtime; empty when intact. */
	problems: string[];
}

export interface StatusSnapshot {
	checkedAt: string;
	appVersion: string;
	aidrVersion: string | null;
	home: string;
	engine: EngineFacts;
	mode: "local" | "managed" | "unknown";
	configState: string;
	connectors: ConnectorView[];
	lastVerdict: { at: string; decision: Decision } | null;
	auditPath: string;
	/** `logging.log_clean`: whether allowed calls are written to the audit log too. */
	logClean: boolean;
	configExists: boolean;
	runtime: RuntimeFacts;
	/** Claude Code hook registered, its binary present and the engine loaded rules. */
	protected: boolean;
}

export interface DiffLine {
	kind: "same" | "add" | "remove";
	text: string;
}

export interface ConnectPreview {
	settingsPath: string;
	settingsExists: boolean;
	runtimeRoot: string;
	/** Why connecting would not work, when it would not (shown instead of a diff). */
	blocker: string | null;
	changed: boolean;
	diff: DiffLine[];
	/** Commands that will be registered, verbatim. */
	commands: string[];
}

export interface ActionResult {
	ok: boolean;
	/** One sentence for the user. */
	message: string;
	/** Raw CLI output, for the details pane. */
	log: string;
	backupPath?: string | null;
}

export interface SelfTestCase {
	name: "benign" | "canary";
	command: string;
	expected: Decision;
	decision: Decision | "unknown";
	pass: boolean;
	latencyMs: number;
	reason: string;
	ruleId: string | null;
	exitCode: number | null;
}

export interface SelfTestResult {
	ok: boolean;
	/** Set when the hook could not be run at all (missing, unparseable, ...). */
	error: string | null;
	hookCommand: string | null;
	settingsPath: string;
	ranAt: string;
	cases: SelfTestCase[];
}

export interface AuditEvent {
	id: string;
	at: string;
	decision: Decision;
	tool: string;
	/** `tool_input_summary` exactly as the audit log stores it (already redacted there). */
	summary: string;
	ruleId: string | null;
	reason: string;
	severity: string | null;
	sessionId: string;
	/**
	 * Not agent activity: written by this app's "Prove it works" self-test, or by
	 * the canary the CLI sends a hook before registering / verifying it.
	 */
	origin: "self-test" | "setup-canary" | null;
	durationMs: number | null;
}

export interface BrowserExtensionHit {
	browser: "chrome" | "edge";
	profile: string;
	extensionId: string;
	version: string | null;
	enabled: boolean;
	unpacked: boolean;
	path: string | null;
}

export interface NativeHostFacts {
	browser: "chrome" | "edge";
	scope: "HKCU" | "HKLM";
	manifestPath: string | null;
	manifestExists: boolean;
}

export interface BrowserGuardStatus {
	browsers: Array<{ browser: "chrome" | "edge"; installed: boolean; executable: string | null }>;
	extensions: BrowserExtensionHit[];
	nativeHost: { name: string; registrations: NativeHostFacts[] };
	/** The unpacked extension the app ships, and where it was copied for loading. */
	bundled: { available: boolean; version: string | null; stagedPath: string | null };
}

export interface AppInfo {
	appVersion: string;
	language: Lang;
	preferences: Preferences;
	platform: string;
}

/** invoke() channels: request payload and response type. */
export interface InvokeMap {
	"app:info": { req: undefined; res: AppInfo };
	"status:get": { req: undefined; res: StatusSnapshot };
	"claude:preview": { req: undefined; res: ConnectPreview };
	"claude:connect": { req: undefined; res: ActionResult };
	"claude:disconnect": { req: undefined; res: ActionResult };
	"selftest:run": { req: undefined; res: SelfTestResult };
	"audit:recent": { req: undefined; res: AuditEvent[] };
	"audit:setLogClean": { req: { enabled: boolean }; res: ActionResult };
	"browserGuard:status": { req: undefined; res: BrowserGuardStatus };
	"browserGuard:stage": { req: undefined; res: ActionResult };
	"browserGuard:openExtensionsPage": { req: { browser: "chrome" | "edge" }; res: ActionResult };
	"prefs:set": { req: Partial<Preferences>; res: AppInfo };
	"open:target": { req: { target: OpenTarget }; res: ActionResult };
}

export type InvokeChannel = keyof InvokeMap;

/** Fixed places the renderer may ask the OS to open; never an arbitrary path. */
export type OpenTarget = "auditLog" | "claudeSettings" | "dataDir" | "browserGuardFolder";

export const INVOKE_CHANNELS: readonly InvokeChannel[] = [
	"app:info",
	"status:get",
	"claude:preview",
	"claude:connect",
	"claude:disconnect",
	"selftest:run",
	"audit:recent",
	"audit:setLogClean",
	"browserGuard:status",
	"browserGuard:stage",
	"browserGuard:openExtensionsPage",
	"prefs:set",
	"open:target",
];

/** main → renderer push channels. */
export interface PushMap {
	"audit:events": AuditEvent[];
	"status:changed": StatusSnapshot;
	"nav:go": string;
}

export type PushChannel = keyof PushMap;

export const PUSH_CHANNELS: readonly PushChannel[] = ["audit:events", "status:changed", "nav:go"];

/** What the preload exposes as `window.aidr`. */
export interface AidrBridge {
	invoke<C extends InvokeChannel>(
		channel: C,
		...payload: InvokeMap[C]["req"] extends undefined ? [] : [InvokeMap[C]["req"]]
	): Promise<InvokeMap[C]["res"]>;
	on<C extends PushChannel>(channel: C, listener: (payload: PushMap[C]) => void): () => void;
}
