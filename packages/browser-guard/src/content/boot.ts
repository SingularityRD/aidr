/**
 * Content-script bootstrap, separated from the bundle entry (`index.ts`) so it can be
 * tested with fakes: fetches the effective policy from the background worker
 * (GET_POLICY), follows POLICY_CHANGED / SET_RESTORE_VISIBLE, and keeps one
 * placeholder vault per page.
 *
 * The vault lives only in this page's content-script memory: content scripts cannot
 * use chrome.storage.session by default, and originals must never be written to
 * storage.local or sent over the network. A reload therefore forgets the mapping
 * (placeholders already in the conversation then stay as placeholders).
 *
 * Until a valid policy arrives the guard fails closed (sends are blocked with a
 * message); policy fetches are retried with capped backoff for as long as the page lives.
 */
import type {
	DetectionEngine,
	DetectionOptions,
	EntityType,
	GuardMessage,
	GuardPolicy,
	PlaceholderVault,
	SiteAdapter,
	VaultSnapshot,
} from "../types.js";
import { type ContentGuard, type ContentGuardDeps, createContentGuard } from "./guard.js";

/** Engine limits: prompts larger than this are reported incomplete and fail closed. */
const MAX_INPUT_CHARS = 200_000;
const MAX_SCAN_MS = 1_000;

const GUARD_MODES = new Set(["auto", "confirm", "block", "monitor"]);
const SIGNAL_ACTIONS = new Set(["off", "warn", "block"]);
const FILE_HANDLING = new Set(["scan", "block", "allow"]);
const BOOLEAN_KEYS = [
	"detectSignals",
	"allowUserPause",
	"allowSendAnyway",
	"maskPaste",
	"restoreResponses",
] as const;
const ARRAY_KEYS = [
	"enabledEntities",
	"neverRestore",
	"literals",
	"exactData",
	"blockedSites",
	"disabledSites",
] as const;

const POLICY_RETRY_BASE_MS = 200;
const POLICY_RETRY_MAX_MS = 10_000;

/**
 * Accepts either a bare policy or `{ policy }` from the background worker. Anything
 * that is not a structurally valid policy is rejected (null) so the guard keeps
 * failing closed instead of running with undefined settings.
 */
export function extractPolicy(response: unknown): GuardPolicy | null {
	const candidate =
		response && typeof response === "object" && "policy" in response
			? (response as { policy: unknown }).policy
			: response;
	if (!candidate || typeof candidate !== "object") return null;
	const p = candidate as Record<string, unknown>;
	if (p.version !== 1 || !GUARD_MODES.has(p.mode as string)) return null;
	if (!SIGNAL_ACTIONS.has(p.signalAction as string)) return null;
	if (!FILE_HANDLING.has(p.fileHandling as string)) return null;
	if (typeof p.maxFileBytes !== "number" || !(p.maxFileBytes >= 0)) return null;
	if (!ARRAY_KEYS.every((key) => Array.isArray(p[key]))) return null;
	if (!BOOLEAN_KEYS.every((key) => typeof p[key] === "boolean")) return null;
	return candidate as GuardPolicy;
}

export function detectionOptions(policy: GuardPolicy): DetectionOptions {
	return {
		enabledEntities: policy.enabledEntities,
		literals: policy.literals,
		exactData: policy.exactData,
		detectSignals: policy.detectSignals,
		maxInputChars: MAX_INPUT_CHARS,
		maxScanMs: MAX_SCAN_MS,
	};
}

export interface RuntimeLike {
	readonly id: string;
	sendMessage(message: GuardMessage): Promise<unknown>;
	readonly onMessage: {
		addListener(listener: (message: unknown, sender: { readonly id?: string }) => void): void;
	};
}

export interface BootDeps
	extends Omit<ContentGuardDeps, "adapter" | "engine" | "vault" | "getPolicy" | "send"> {
	readonly url: string;
	readonly runtime: RuntimeLike;
	adapterForUrl(url: string): SiteAdapter;
	createDetectionEngine(options: DetectionOptions): DetectionEngine;
	createVault(options: {
		neverRestore: readonly EntityType[];
		snapshot?: VaultSnapshot;
	}): PlaceholderVault;
	/** Timer used between policy fetch retries (defaults to window.setTimeout). */
	sleep?(ms: number): Promise<void>;
}

export interface BootedGuard {
	readonly guard: ContentGuard;
	/** Current effective policy (null until one has been received). */
	policy(): GuardPolicy | null;
	/** Resolves once the first valid policy has been applied. */
	readonly ready: Promise<void>;
}

const sameList = (a: readonly string[], b: readonly string[]): boolean =>
	a.length === b.length && a.every((v, i) => v === b[i]);

export function bootContentGuard(deps: BootDeps): BootedGuard {
	const { runtime } = deps;
	const adapter = deps.adapterForUrl(deps.url);
	const sleep =
		deps.sleep ??
		((ms: number) =>
			new Promise<void>((resolve) => {
				deps.window.setTimeout(resolve, ms);
			}));
	let policy: GuardPolicy | null = null;
	let engine: DetectionEngine | null = null;
	let vault: PlaceholderVault = deps.createVault({ neverRestore: [] });
	let vaultNeverRestore: readonly string[] | null = null;

	// Stable facades so the guard keeps working across policy changes.
	const engineFacade: DetectionEngine = {
		scan: (text) => (engine ? engine.scan(text) : Promise.reject(new Error("POLICY_NOT_LOADED"))),
	};
	const vaultFacade: PlaceholderVault = {
		mask: (text, findings) => vault.mask(text, findings),
		unmask: (text) => vault.unmask(text),
		lookup: (placeholder) => vault.lookup(placeholder),
		size: () => vault.size(),
		clear: () => vault.clear(),
		exportSession: () => vault.exportSession(),
	};

	const guard = createContentGuard({
		...deps,
		adapter,
		engine: engineFacade,
		vault: vaultFacade,
		getPolicy: () => policy,
		send: (message) => runtime.sendMessage(message),
	});

	let markReady: () => void = () => undefined;
	const ready = new Promise<void>((resolve) => {
		markReady = resolve;
	});

	const apply = (next: GuardPolicy): void => {
		try {
			engine = deps.createDetectionEngine(detectionOptions(next));
		} catch {
			engine = null; // scans reject -> the guard fails closed
		}
		if (!vaultNeverRestore || !sameList(vaultNeverRestore, next.neverRestore)) {
			// Keep existing placeholders resolvable; only the restore rule changes.
			vault = deps.createVault({
				neverRestore: next.neverRestore,
				snapshot: vault.exportSession(),
			});
			vaultNeverRestore = [...next.neverRestore];
		}
		policy = next;
		guard.policyChanged();
		markReady();
	};

	const load = async (): Promise<void> => {
		for (let attempt = 0; policy === null; attempt++) {
			try {
				const next = extractPolicy(await runtime.sendMessage({ type: "GET_POLICY" }));
				if (next) {
					// A POLICY_CHANGED push may have arrived while GET_POLICY was in flight.
					if (policy === null) apply(next);
					return;
				}
			} catch {
				// The service worker may be starting; retry with backoff.
			}
			await sleep(Math.min(POLICY_RETRY_BASE_MS * 2 ** attempt, POLICY_RETRY_MAX_MS));
		}
	};

	runtime.onMessage.addListener((message, sender) => {
		// Only the extension itself may change policy or restore visibility.
		if (sender.id !== runtime.id || !message || typeof message !== "object") return;
		const msg = message as { type?: unknown; policy?: unknown; visible?: unknown };
		if (msg.type === "POLICY_CHANGED") {
			const next = extractPolicy(msg.policy);
			if (next) apply(next);
		} else if (msg.type === "SET_RESTORE_VISIBLE" && typeof msg.visible === "boolean") {
			guard.setRestoreVisible(msg.visible);
		}
	});

	guard.start();
	void load();
	return { guard, policy: () => policy, ready };
}
