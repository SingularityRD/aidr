/**
 * Popup controller: loads policy + stats from the background worker, renders
 * with renderPopup and turns user interactions into GuardMessages.
 */
import type { GuardMode, GuardPolicy, GuardStats } from "../types.js";
import { UI_STORAGE_PREFIX, type UiEnv } from "./env.js";
import { browserLocalizer, type Localizer, msg, relocalizeDocument } from "./i18n.js";
import {
	errorKeyFor,
	expectOk,
	GUARD_MODES,
	isLocked,
	policyFromResponse,
	protectionStatus,
	siteForUrl,
	statsFromResponse,
} from "./model.js";
import { renderNotice, replaceKeepingFocus } from "./render-common.js";
import { PAUSE_MINUTES, type PopupState, renderPopup, restoreToggle } from "./render-popup.js";

/** chrome.storage.session key remembering the popup's "show originals" choice. */
export const RESTORE_VISIBLE_KEY = `${UI_STORAGE_PREFIX}restoreVisible`;

export interface PopupElements {
	readonly app: HTMLElement;
	readonly live: HTMLElement;
}

export interface PopupController {
	/** Resolves once the first load (successful or not) has rendered. */
	readonly ready: Promise<void>;
	getState(): PopupState;
}

export function startPopup(doc: Document, env: UiEnv, elements: PopupElements): PopupController {
	let state: PopupState = { phase: "loading" };
	let localizer: Localizer = browserLocalizer(env);
	let tabId: number | undefined;

	const render = () => {
		replaceKeepingFocus(doc, elements.app, renderPopup(doc, state, localizer.t, localizer.locale));
	};

	const notify = (key: string | null, kind: "ok" | "error" = "ok") => {
		renderNotice(elements.live, key ? { kind, text: localizer.t(key) } : null);
	};

	const relocalize = async (language: GuardPolicy["language"]) => {
		localizer = await relocalizeDocument(doc, env, language);
	};

	const fetchPolicyAndStats = async (): Promise<{ policy: GuardPolicy; stats: GuardStats }> => {
		const [policyReply, statsReply] = await Promise.all([
			env.send({ type: "GET_POLICY" }),
			env.send(tabId === undefined ? { type: "GET_STATS" } : { type: "GET_STATS", tabId }),
		]);
		return { policy: policyFromResponse(policyReply), stats: statsFromResponse(statsReply) };
	};

	const load = async () => {
		try {
			const tab = await env.getActiveTab();
			tabId = tab?.id;
			const [{ policy, stats }, stored] = await Promise.all([
				fetchPolicyAndStats(),
				env.sessionGet(RESTORE_VISIBLE_KEY),
			]);
			await relocalize(policy.language);
			state = {
				phase: "ready",
				policy,
				stats,
				urlSite: siteForUrl(tab?.url),
				restoreVisible: typeof stored === "boolean" ? stored : policy.restoreResponses,
				now: env.now(),
				busy: false,
			};
		} catch {
			state = { phase: "error" };
		}
		render();
	};

	const refresh = async () => {
		if (state.phase !== "ready") return load();
		const { policy, stats } = await fetchPolicyAndStats();
		if (state.phase === "ready") state = { ...state, policy, stats, now: env.now() };
	};

	/** Runs a mutation with the controls disabled; re-renders from fresh data afterwards. */
	const mutate = async (operation: () => Promise<void>, successKey: string | null) => {
		if (state.phase !== "ready" || state.busy) return;
		state = { ...state, busy: true };
		render();
		let errorKey: string | null = null;
		try {
			await operation();
		} catch (error) {
			errorKey = errorKeyFor(error);
		}
		try {
			// Re-read even after a failure so the page shows what the worker enforces.
			await refresh();
		} catch {
			errorKey ??= errorKeyFor(null);
		}
		if (state.phase === "ready") state = { ...state, busy: false };
		render();
		notify(errorKey ?? successKey, errorKey ? "error" : "ok");
	};

	const onChange = (event: Event) => {
		const target = event.target;
		if (!(target instanceof HTMLInputElement) || state.phase !== "ready") return;
		const { policy } = state;
		switch (target.dataset.action) {
			case "set-mode": {
				const mode = target.value as GuardMode;
				if (!GUARD_MODES.includes(mode) || isLocked(policy, "mode") || mode === policy.mode) return;
				void mutate(async () => {
					expectOk(await env.send({ type: "SET_USER_SETTINGS", settings: { mode } }));
				}, msg("notice_saved"));
				return;
			}
			case "toggle-restore-visible": {
				const visible = target.checked;
				const status = protectionStatus(policy, state.stats, state.urlSite, env.now());
				if (!restoreToggle(policy, status).available) return;
				void mutate(
					async () => {
						expectOk(await env.send({ type: "SET_RESTORE_VISIBLE", visible }));
						await env.sessionSet(RESTORE_VISIBLE_KEY, visible);
						if (state.phase === "ready") state = { ...state, restoreVisible: visible };
					},
					visible ? msg("notice_restore_on") : msg("notice_restore_off"),
				);
				return;
			}
		}
	};

	const onClick = (event: Event) => {
		const target = event.target instanceof Element ? event.target.closest("[data-action]") : null;
		if (!(target instanceof HTMLButtonElement)) return;
		switch (target.dataset.action) {
			case "pause":
				if (state.phase !== "ready" || !state.policy.allowUserPause) return;
				void mutate(async () => {
					expectOk(await env.send({ type: "PAUSE", minutes: PAUSE_MINUTES }));
				}, msg("notice_paused"));
				return;
			case "resume":
				void mutate(async () => {
					expectOk(await env.send({ type: "PAUSE", minutes: 0 }));
				}, msg("notice_resumed"));
				return;
			case "open-options":
				env.openOptionsPage();
				return;
			case "retry":
				state = { phase: "loading" };
				render();
				void load();
				return;
		}
	};

	elements.app.addEventListener("change", onChange);
	elements.app.addEventListener("click", onClick);
	// Stats live in storage.session and pause/policy changes are broadcast, so keep
	// the popup current while it is open. Overlapping signals share one refresh.
	let refreshing = false;
	env.onInvalidate(["managed", "local", "session"], () => {
		if (state.phase !== "ready" || state.busy || refreshing) return;
		refreshing = true;
		refresh()
			.then(render, () => undefined)
			.finally(() => {
				refreshing = false;
			});
	});

	render();
	const ready = load();
	return { ready, getState: () => state };
}
