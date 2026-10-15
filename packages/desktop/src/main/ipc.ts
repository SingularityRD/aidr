import type {
	ActionResult,
	AppInfo,
	AuditEvent,
	BrowserGuardStatus,
	ConnectPreview,
	InvokeChannel,
	InvokeMap,
	OpenTarget,
	Preferences,
	SelfTestResult,
	StatusSnapshot,
} from "../shared/contract.js";
import { INVOKE_CHANNELS } from "../shared/contract.js";
import { validatePreferencesPatch } from "./prefs.js";

/**
 * The main-process side of the IPC allowlist. Each channel has one handler;
 * every payload is validated here (the renderer is treated as untrusted even
 * though it only loads the app's own pages), and actions that change the
 * user's configuration or run hooks never run concurrently.
 */

export interface AppServices {
	info(): AppInfo;
	status(): Promise<StatusSnapshot>;
	previewConnect(): Promise<ConnectPreview>;
	connect(): Promise<ActionResult>;
	disconnect(): Promise<ActionResult>;
	selfTest(): Promise<SelfTestResult>;
	recentAudit(): AuditEvent[];
	setLogClean(enabled: boolean): Promise<ActionResult>;
	browserGuardStatus(): Promise<BrowserGuardStatus>;
	stageBrowserGuard(): Promise<ActionResult>;
	openExtensionsPage(browser: "chrome" | "edge"): Promise<ActionResult>;
	setPreferences(patch: Partial<Preferences>): Promise<AppInfo>;
	open(target: OpenTarget): Promise<ActionResult>;
}

export type IpcHandlers = {
	[C in InvokeChannel]: (payload: unknown) => Promise<InvokeMap[C]["res"]>;
};

class IpcValidationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "IpcValidationError";
	}
}

const OPEN_TARGETS: readonly OpenTarget[] = [
	"auditLog",
	"claudeSettings",
	"dataDir",
	"browserGuardFolder",
];

function noPayload(payload: unknown): void {
	if (payload !== undefined) throw new IpcValidationError("this channel takes no payload");
}

function objectPayload(payload: unknown, keys: readonly string[]): Record<string, unknown> {
	if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
		throw new IpcValidationError("payload must be an object");
	}
	const record = payload as Record<string, unknown>;
	const extra = Object.keys(record).filter((key) => !keys.includes(key));
	if (extra.length > 0) throw new IpcValidationError(`unexpected field ${extra[0]}`);
	return record;
}

/** Only the app's own pages may call the main process. */
export function isTrustedSender(url: string | undefined | null): boolean {
	if (!url) return false;
	try {
		const parsed = new URL(url);
		return parsed.protocol === "app:" && parsed.host === "aidr";
	} catch {
		return false;
	}
}

export function createIpcHandlers(services: AppServices): IpcHandlers {
	let busy: string | null = null;
	const exclusive = async <T>(name: string, action: () => Promise<T>): Promise<T> => {
		if (busy) throw new IpcValidationError(`${busy} is still running`);
		busy = name;
		try {
			return await action();
		} finally {
			busy = null;
		}
	};
	return {
		"app:info": async (payload) => {
			noPayload(payload);
			return services.info();
		},
		"status:get": async (payload) => {
			noPayload(payload);
			return services.status();
		},
		"claude:preview": async (payload) => {
			noPayload(payload);
			return services.previewConnect();
		},
		"claude:connect": async (payload) => {
			noPayload(payload);
			return exclusive("connect", () => services.connect());
		},
		"claude:disconnect": async (payload) => {
			noPayload(payload);
			return exclusive("disconnect", () => services.disconnect());
		},
		"selftest:run": async (payload) => {
			noPayload(payload);
			return exclusive("self-test", () => services.selfTest());
		},
		"audit:recent": async (payload) => {
			noPayload(payload);
			return services.recentAudit();
		},
		"audit:setLogClean": async (payload) => {
			const { enabled } = objectPayload(payload, ["enabled"]);
			if (typeof enabled !== "boolean") throw new IpcValidationError("enabled must be a boolean");
			return exclusive("configuration change", () => services.setLogClean(enabled));
		},
		"browserGuard:status": async (payload) => {
			noPayload(payload);
			return services.browserGuardStatus();
		},
		"browserGuard:stage": async (payload) => {
			noPayload(payload);
			return exclusive("Browser Guard preparation", () => services.stageBrowserGuard());
		},
		"browserGuard:openExtensionsPage": async (payload) => {
			const { browser } = objectPayload(payload, ["browser"]);
			if (browser !== "chrome" && browser !== "edge") {
				throw new IpcValidationError("browser must be chrome or edge");
			}
			return services.openExtensionsPage(browser);
		},
		"prefs:set": async (payload) => {
			let patch: Partial<Preferences>;
			try {
				patch = validatePreferencesPatch(payload);
			} catch (error) {
				throw new IpcValidationError((error as Error).message);
			}
			return services.setPreferences(patch);
		},
		"open:target": async (payload) => {
			const { target } = objectPayload(payload, ["target"]);
			if (!OPEN_TARGETS.includes(target as OpenTarget)) {
				throw new IpcValidationError("unknown open target");
			}
			return services.open(target as OpenTarget);
		},
	};
}

/** Every contract channel has a handler and nothing else does (checked at startup and in tests). */
export function assertHandlersMatchContract(handlers: IpcHandlers): void {
	const names = Object.keys(handlers).sort();
	const expected = [...INVOKE_CHANNELS].sort();
	if (names.join(",") !== expected.join(",")) {
		throw new Error(`IPC handlers do not match the contract: ${names.join(",")}`);
	}
}
