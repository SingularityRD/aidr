/**
 * Content-script bootstrap, separated from the bundle entry (`index.ts`) so it can be
 * tested with fakes: fetches the effective policy from the background worker
 * (GET_POLICY), follows POLICY_CHANGED / SET_RESTORE_VISIBLE, and keeps one
 * placeholder vault per page.
 *
 * Vault persistence: the vault lives in this content script's memory and is mirrored to
 * the worker (VAULT_SAVE after every mask and every send), which keeps it in
 * chrome.storage.session keyed by this tab's id + origin (TRUSTED_CONTEXTS: page scripts
 * cannot read it; never storage.local, never the network). On boot the vault and the set
 * of placeholders already sent from this tab are rehydrated (VAULT_LOAD) before the first
 * policy is applied, so a reload keeps restoring answers to prompts sent earlier. Entity
 * types in `neverRestore` (secrets) are never persisted. If the worker does not answer
 * within VAULT_LOAD_TIMEOUT_MS the page starts with an empty vault (earlier placeholders
 * then stay as placeholders).
 *
 * Until a valid policy arrives the guard fails closed (sends are blocked with a
 * message); policy fetches are retried with capped backoff for as long as the page lives.
 */
import type {
	CustomSiteConfig,
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
/** How long boot waits for the persisted vault before starting with an empty one. */
export const VAULT_LOAD_TIMEOUT_MS = 1_500;

/** The persisted vault from a VAULT_LOAD reply, or null (nothing saved / malformed). */
export function extractVault(
	response: unknown,
): { snapshot: VaultSnapshot; sent: readonly string[] } | null {
	if (!response || typeof response !== "object") return null;
	const r = response as { ok?: unknown; snapshot?: unknown; sent?: unknown };
	if (r.ok !== true || !r.snapshot || typeof r.snapshot !== "object") return null;
	const sent = Array.isArray(r.sent) ? r.sent.filter((p) => typeof p === "string") : [];
	return { snapshot: r.snapshot as VaultSnapshot, sent };
}

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
	/** Site adapter for the page; custom sites resolve once the policy (customSites) is known. */
	adapterForUrl(url: string, customSites?: readonly CustomSiteConfig[]): SiteAdapter;
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

/**
 * Adapter whose fields always read the currently resolved adapter. A built-in site is
 * known from the URL alone; an administrator-configured custom site (whose content script
 * is registered dynamically) is only known once the policy with `customSites` arrived, and
 * until then the page runs with the generic selectors (and fails closed on send anyway).
 */
function liveAdapter(resolve: () => SiteAdapter): SiteAdapter {
	return {
		get id() {
			return resolve().id;
		},
		get label() {
			return resolve().label;
		},
		get hosts() {
			return resolve().hosts;
		},
		get editorSelectors() {
			return resolve().editorSelectors;
		},
		get sendButtonSelectors() {
			return resolve().sendButtonSelectors;
		},
		get responseSelectors() {
			return resolve().responseSelectors;
		},
		get userMessageSelectors() {
			return resolve().userMessageSelectors;
		},
		get fileInputSelectors() {
			return resolve().fileInputSelectors;
		},
	};
}

export function bootContentGuard(deps: BootDeps): BootedGuard {
	const { runtime } = deps;
	let resolvedAdapter = deps.adapterForUrl(deps.url);
	const adapter = liveAdapter(() => resolvedAdapter);
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
		mask: (text, findings) => {
			const result = vault.mask(text, findings);
			saveVault();
			return result;
		},
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
		onSent: () => saveVault(),
	});

	// ---- vault persistence (see the module comment) ----------------------------------

	let saving = false;
	let saveAgain = false;
	let savedOnce = false;

	/** Restorable entries (never `neverRestore` types) and the placeholders sent so far. */
	const persistable = (): { snapshot: VaultSnapshot; sent: string[] } => {
		const full = vault.exportSession();
		const locked = new Set<string>(policy?.neverRestore ?? []);
		const entries = full.entries.filter((e) => !locked.has(e.type));
		const known = new Set(entries.map((e) => e.placeholder));
		const sent = guard.unmasker.sentPlaceholders().filter((p) => known.has(p));
		return { snapshot: { version: 1, createdAt: full.createdAt, entries }, sent };
	};

	/** Mirrors the vault to the worker; calls made while a save is in flight coalesce. */
	function saveVault(): void {
		if (saving) {
			saveAgain = true;
			return;
		}
		let payload: { snapshot: VaultSnapshot; sent: string[] };
		try {
			payload = persistable();
		} catch {
			return;
		}
		if (payload.snapshot.entries.length === 0 && !savedOnce) return;
		saving = true;
		saveAgain = false;
		savedOnce = true;
		void Promise.resolve()
			.then(() => runtime.sendMessage({ type: "VAULT_SAVE", ...payload }))
			.catch(() => undefined)
			.finally(() => {
				saving = false;
				if (saveAgain) saveVault();
			});
	}

	const withTimeout = <T>(task: Promise<T>, ms: number): Promise<T | undefined> => {
		let timer: ReturnType<typeof setTimeout> | undefined;
		return Promise.race([
			task,
			new Promise<undefined>((resolve) => {
				timer = deps.window.setTimeout(() => resolve(undefined), ms);
			}),
		]).finally(() => deps.window.clearTimeout(timer));
	};

	let restored = false;
	/** Rehydrates the vault saved for this tab + origin; never rejects. */
	const restoring: Promise<void> = (async () => {
		try {
			const saved = extractVault(
				await withTimeout(
					Promise.resolve(runtime.sendMessage({ type: "VAULT_LOAD" })),
					VAULT_LOAD_TIMEOUT_MS,
				),
			);
			if (!saved) return;
			// Strict import: a malformed snapshot throws and the page starts empty.
			vault = deps.createVault({ neverRestore: [], snapshot: saved.snapshot });
			savedOnce = vault.size() > 0;
			guard.unmasker.rehydrateSent(saved.sent.filter((p) => vault.lookup(p) !== undefined));
		} catch {
			// Worker asleep or no saved vault: start with an empty vault.
		} finally {
			restored = true;
		}
	})();

	let markReady: () => void = () => undefined;
	const ready = new Promise<void>((resolve) => {
		markReady = resolve;
	});

	const apply = (next: GuardPolicy): void => {
		try {
			const customSites = Array.isArray(next.customSites) ? next.customSites : [];
			resolvedAdapter = deps.adapterForUrl(deps.url, customSites);
		} catch {
			// Keep the adapter resolved so far (the URL-only resolution).
		}
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
		// The first policy is applied only after the vault was rehydrated (the guard stays
		// fail-closed meanwhile), so nothing can be masked into a vault about to be replaced.
		await restoring;
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
			if (next && restored) apply(next);
			else if (next) void restoring.then(() => apply(next));
		} else if (msg.type === "SET_RESTORE_VISIBLE" && typeof msg.visible === "boolean") {
			guard.setRestoreVisible(msg.visible);
		}
	});

	guard.start();
	void load();
	return { guard, policy: () => policy, ready };
}
