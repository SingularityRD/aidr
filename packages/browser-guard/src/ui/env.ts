/**
 * Thin, typed wrapper around the handful of WebExtension APIs the popup and
 * options pages use. The pages never touch `chrome.*` directly so that the
 * controllers can be exercised in tests with a fake `chrome` global, and so that
 * this package does not need `@types/chrome` (tsconfig `types: []`).
 *
 * Every call uses the callback form wrapped in a Promise and checks
 * `runtime.lastError`, which works in Chrome, Edge and Firefox alike.
 */
import type { GuardMessage } from "../types.js";

/** Raw `messages.json` shape (Chrome i18n format). */
export type LocaleMessages = Readonly<
	Record<
		string,
		{
			readonly message: string;
			readonly description?: string;
			readonly placeholders?: Readonly<Record<string, { readonly content: string }>>;
		}
	>
>;

export interface ActiveTab {
	readonly id?: number;
	readonly url?: string;
}

export interface UiEnv {
	send(message: GuardMessage): Promise<unknown>;
	getActiveTab(): Promise<ActiveTab | null>;
	openOptionsPage(): void;
	getVersion(): string;
	/** Browser UI language, e.g. "tr" or "en-US". */
	uiLanguage(): string;
	/** chrome.i18n.getMessage; returns "" for unknown keys. */
	getMessage(key: string, substitutions?: readonly string[]): string;
	/** Loads a bundled locale file for an explicit language override. */
	loadLocaleMessages(lang: "en" | "tr"): Promise<LocaleMessages | null>;
	sessionGet(key: string): Promise<unknown>;
	sessionSet(key: string, value: unknown): Promise<void>;
	/**
	 * Calls `listener` when the effective policy or stats may have changed: a
	 * POLICY_CHANGED message, or a write to one of the given storage areas. The
	 * payload is never trusted; pages re-read state from the background worker.
	 */
	onInvalidate(areas: readonly StorageAreaName[], listener: () => void): void;
	now(): number;
	/** Whether an optional API permission is granted; null when the API is unavailable. */
	hasPermission?(permission: OptionalPermission): Promise<boolean | null>;
	/**
	 * Requests an optional API permission. Browsers only show the prompt when this is
	 * called synchronously from a user gesture (click/change handler), so callers must not
	 * await anything before it.
	 */
	requestPermission?(permission: OptionalPermission): Promise<boolean>;
}

/** Optional permissions the pages may request (manifest `optional_permissions`). */
type OptionalPermission = "nativeMessaging";

export type StorageAreaName = "local" | "managed" | "session" | "sync";

/** Storage keys the UI itself writes; changes to them never trigger a reload. */
export const UI_STORAGE_PREFIX = "aidr.ui.";

type Callback<T> = (value: T) => void;

interface ChromeLike {
	runtime: {
		id?: string;
		lastError?: { message?: string } | undefined;
		sendMessage(message: unknown, callback: Callback<unknown>): void;
		openOptionsPage?(callback?: () => void): void;
		getManifest(): { version: string };
		getURL(path: string): string;
		onMessage?: { addListener(listener: (message: unknown) => void): void };
	};
	tabs?: {
		query(
			query: { active: boolean; currentWindow: boolean },
			callback: Callback<ReadonlyArray<{ id?: number; url?: string }>>,
		): void;
	};
	i18n?: {
		getMessage(key: string, substitutions?: string | string[]): string;
		getUILanguage(): string;
	};
	storage?: {
		session?: {
			get(key: string, callback: Callback<Record<string, unknown>>): void;
			set(items: Record<string, unknown>, callback: () => void): void;
		};
		onChanged?: {
			addListener(listener: (changes: Record<string, unknown>, areaName: string) => void): void;
		};
	};
	permissions?: {
		contains(permissions: { permissions: string[] }, callback: Callback<boolean>): void;
		request(permissions: { permissions: string[] }, callback: Callback<boolean>): void;
	};
}

export function getChrome(): ChromeLike | undefined {
	const candidate = (globalThis as { chrome?: ChromeLike }).chrome;
	return candidate?.runtime ? candidate : undefined;
}

function lastErrorOf(chrome: ChromeLike): Error | null {
	const error = chrome.runtime.lastError;
	return error ? new Error(error.message ?? "Extension API error") : null;
}

function isPolicyChanged(message: unknown): boolean {
	return (
		typeof message === "object" &&
		message !== null &&
		(message as { type?: unknown }).type === "POLICY_CHANGED"
	);
}

/** Builds a UiEnv backed by the real extension APIs. */
export function chromeEnv(chrome: ChromeLike | undefined = getChrome()): UiEnv {
	if (!chrome) throw new Error("Extension APIs are unavailable");
	return {
		send(message) {
			return new Promise((resolve, reject) => {
				try {
					chrome.runtime.sendMessage(message, (response) => {
						const error = lastErrorOf(chrome);
						if (error) reject(error);
						else resolve(response);
					});
				} catch (error) {
					reject(error instanceof Error ? error : new Error(String(error)));
				}
			});
		},
		getActiveTab() {
			const tabs = chrome.tabs;
			if (!tabs) return Promise.resolve(null);
			return new Promise((resolve) => {
				tabs.query({ active: true, currentWindow: true }, (result) => {
					if (lastErrorOf(chrome)) resolve(null);
					else resolve(result?.[0] ?? null);
				});
			});
		},
		openOptionsPage() {
			if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage();
		},
		getVersion() {
			return chrome.runtime.getManifest().version;
		},
		uiLanguage() {
			return chrome.i18n?.getUILanguage() ?? "en";
		},
		getMessage(key, substitutions) {
			return chrome.i18n?.getMessage(key, substitutions ? [...substitutions] : undefined) ?? "";
		},
		async loadLocaleMessages(lang) {
			try {
				const response = await fetch(chrome.runtime.getURL(`_locales/${lang}/messages.json`));
				if (!response.ok) return null;
				return (await response.json()) as LocaleMessages;
			} catch {
				return null;
			}
		},
		sessionGet(key) {
			const session = chrome.storage?.session;
			if (!session) return Promise.resolve(undefined);
			return new Promise((resolve) => {
				session.get(key, (items) => {
					resolve(lastErrorOf(chrome) ? undefined : items?.[key]);
				});
			});
		},
		sessionSet(key, value) {
			const session = chrome.storage?.session;
			if (!session) return Promise.resolve();
			return new Promise((resolve) => {
				session.set({ [key]: value }, () => {
					lastErrorOf(chrome);
					resolve();
				});
			});
		},
		onInvalidate(areas, listener) {
			chrome.runtime.onMessage?.addListener((message) => {
				if (isPolicyChanged(message)) listener();
			});
			chrome.storage?.onChanged?.addListener((changes, areaName) => {
				if (!(areas as readonly string[]).includes(areaName)) return;
				const keys = Object.keys(changes ?? {});
				if (keys.length > 0 && keys.every((key) => key.startsWith(UI_STORAGE_PREFIX))) return;
				listener();
			});
		},
		now() {
			return Date.now();
		},
		hasPermission(permission) {
			const permissions = chrome.permissions;
			if (!permissions) return Promise.resolve(null);
			return new Promise((resolve) => {
				try {
					permissions.contains({ permissions: [permission] }, (granted) => {
						resolve(lastErrorOf(chrome) ? null : granted === true);
					});
				} catch {
					resolve(null);
				}
			});
		},
		requestPermission(permission) {
			const permissions = chrome.permissions;
			if (!permissions) return Promise.resolve(false);
			// The executor runs synchronously, so the request stays inside the user gesture.
			return new Promise((resolve) => {
				try {
					permissions.request({ permissions: [permission] }, (granted) => {
						resolve(!lastErrorOf(chrome) && granted === true);
					});
				} catch {
					resolve(false);
				}
			});
		},
	};
}
