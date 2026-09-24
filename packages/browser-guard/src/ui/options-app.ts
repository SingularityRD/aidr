/**
 * Options page controller: loads the effective policy, renders it with
 * renderOptions and sends SET_USER_SETTINGS for every change. Keys locked by
 * managed policy are rejected here as well as rendered read-only.
 */
import { ENTITY_TYPES, type EntityType, type GuardPolicy, type UserSettings } from "../types.js";
import type { UiEnv } from "./env.js";
import { applyI18n, browserLocalizer, createLocalizer, type Localizer, msg } from "./i18n.js";
import {
	errorKeyFor,
	GUARD_MODES,
	isLocked,
	isSupportedSite,
	type ManagedKey,
	policyFromResponse,
	removeLiteral,
	toggleEntity,
	toggleSite,
	validateLiteral,
	validateTelemetry,
} from "./model.js";
import { renderNotice } from "./render-common.js";
import {
	emptyDraft,
	type OptionsDraft,
	type OptionsState,
	renderOptions,
} from "./render-options.js";

export interface OptionsElements {
	readonly app: HTMLElement;
	readonly live: HTMLElement;
}

export interface OptionsController {
	readonly ready: Promise<void>;
	getState(): OptionsState;
}

const LANGUAGES = ["auto", "en", "tr"] as const;

function isEntityType(value: unknown): value is EntityType {
	return (ENTITY_TYPES as readonly unknown[]).includes(value);
}

/**
 * Maps a changed control to the settings patch it requests, or null when the
 * change is a no-op or names an unknown value. Locked keys are filtered later.
 */
export function settingsForChange(
	policy: GuardPolicy,
	control: HTMLInputElement | HTMLSelectElement,
): Partial<UserSettings> | null {
	const checked = control instanceof HTMLInputElement && control.checked;
	switch (control.dataset.action) {
		case "set-language": {
			const language = LANGUAGES.find((candidate) => candidate === control.value);
			return language && language !== policy.language ? { language } : null;
		}
		case "set-mode": {
			const mode = GUARD_MODES.find((candidate) => candidate === control.value);
			return mode && mode !== policy.mode ? { mode } : null;
		}
		case "toggle-entity": {
			const type = control.dataset.entity;
			return isEntityType(type)
				? { enabledEntities: toggleEntity(policy.enabledEntities, type, checked) }
				: null;
		}
		case "toggle-mask-paste":
			return { maskPaste: checked };
		case "toggle-restore":
			return { restoreResponses: checked };
		case "toggle-site": {
			const site = control.dataset.site;
			if (!isSupportedSite(site) || policy.blockedSites.includes(site)) return null;
			return { disabledSites: toggleSite(policy.disabledSites, site, checked) };
		}
		default:
			return null;
	}
}

export function startOptions(
	doc: Document,
	env: UiEnv,
	elements: OptionsElements,
): OptionsController {
	let state: OptionsState = { phase: "loading" };
	let localizer: Localizer = browserLocalizer(env);
	let busy = false;

	const render = (focusId?: string) => {
		const active =
			focusId ?? (doc.activeElement instanceof HTMLElement ? doc.activeElement.id : "");
		elements.app.replaceChildren(renderOptions(doc, state, localizer.t, localizer.locale));
		if (active) {
			const again = doc.getElementById(active);
			if (again instanceof HTMLElement && !again.hasAttribute("disabled")) again.focus();
		}
	};

	const notify = (key: string | null, kind: "ok" | "error" = "ok") => {
		renderNotice(elements.live, key ? { kind, text: localizer.t(key) } : null);
	};

	const relocalize = async (language: GuardPolicy["language"]) => {
		localizer = await createLocalizer(env, language);
		doc.documentElement.lang = localizer.locale;
		applyI18n(doc, localizer.t);
	};

	const fetchPolicy = async (): Promise<GuardPolicy> => {
		return policyFromResponse(await env.send({ type: "GET_POLICY" }));
	};

	const load = async () => {
		try {
			const policy = await fetchPolicy();
			await relocalize(policy.language);
			state = { phase: "ready", policy, version: env.getVersion(), draft: emptyDraft(policy) };
		} catch {
			state = { phase: "error" };
		}
		render();
	};

	const updateDraft = (patch: Partial<OptionsDraft>) => {
		if (state.phase === "ready") state = { ...state, draft: { ...state.draft, ...patch } };
	};

	/** Sends the patch; returns an error message key, or null when the worker accepted it. */
	const persist = async (
		settings: Partial<UserSettings>,
		draft: Partial<OptionsDraft> | undefined,
	): Promise<string | null> => {
		try {
			// The reply carries the new effective policy (what the worker now enforces).
			const fresh = policyFromResponse(await env.send({ type: "SET_USER_SETTINGS", settings }));
			if (settings.language !== undefined) await relocalize(fresh.language);
			if (state.phase === "ready")
				state = { ...state, policy: fresh, draft: { ...state.draft, ...draft } };
			return null;
		} catch (error) {
			// Show the enforced policy again, e.g. when an admin locked the key meanwhile.
			await fetchPolicy().then(
				(fresh) => {
					if (state.phase === "ready") state = { ...state, policy: fresh };
				},
				() => undefined,
			);
			return errorKeyFor(error);
		}
	};

	/**
	 * Persists a settings patch unless one of its keys is locked, then reloads the
	 * effective policy so the page always shows what the background enforces.
	 */
	const save = async (
		settings: Partial<UserSettings>,
		options: {
			readonly successKey?: string;
			readonly focusId?: string;
			readonly draft?: Partial<OptionsDraft>;
		} = {},
	): Promise<boolean> => {
		if (state.phase !== "ready" || busy) return false;
		const policy = state.policy;
		const keys = Object.keys(settings) as ManagedKey[];
		if (keys.some((key) => isLocked(policy, key))) {
			render(options.focusId);
			notify(msg("error_locked"), "error");
			return false;
		}
		busy = true;
		const errorKey = await persist(settings, options.draft);
		busy = false;
		render(options.focusId);
		notify(errorKey ?? options.successKey ?? msg("notice_saved"), errorKey ? "error" : "ok");
		return errorKey === null;
	};

	const onChange = (event: Event) => {
		const target = event.target;
		if (state.phase !== "ready") return;
		if (target instanceof HTMLSelectElement && target.dataset.draft === "literalType") {
			if (isEntityType(target.value)) updateDraft({ literalType: target.value });
			return;
		}
		if (!(target instanceof HTMLInputElement || target instanceof HTMLSelectElement)) return;
		const settings = settingsForChange(state.policy, target);
		if (settings) void save(settings, { focusId: target.id });
	};

	const onInput = (event: Event) => {
		const target = event.target;
		if (!(target instanceof HTMLInputElement)) return;
		const field = target.dataset.draft;
		if (field === "literalValue" || field === "telemetryUrl" || field === "telemetryKey") {
			updateDraft({ [field]: target.value });
		}
	};

	const addLiteral = () => {
		if (state.phase !== "ready") return;
		const { policy, draft } = state;
		const result = validateLiteral(draft.literalValue, draft.literalType, policy.literals);
		if (!result.ok) {
			updateDraft({ literalError: result.error });
			render("literal-value");
			return;
		}
		updateDraft({ literalError: null });
		void save(
			{ literals: [...policy.literals, result.rule] },
			{
				successKey: msg("notice_term_added"),
				focusId: "literal-value",
				draft: { literalValue: "", literalError: null },
			},
		);
	};

	const saveTelemetry = () => {
		if (state.phase !== "ready") return;
		const { policy, draft } = state;
		const result = validateTelemetry(draft.telemetryUrl, draft.telemetryKey, policy.telemetry);
		if (!result.ok) {
			updateDraft({ telemetryError: result.error });
			render(result.error.startsWith("key") ? "telemetry-key" : "telemetry-url");
			return;
		}
		updateDraft({ telemetryError: null });
		void save(
			{ telemetry: result.config },
			{
				successKey: msg("notice_telemetry_saved"),
				focusId: "telemetry-save",
				draft: {
					telemetryUrl: result.config.controlPlaneUrl,
					telemetryKey: "",
					telemetryError: null,
				},
			},
		);
	};

	const onSubmit = (event: Event) => {
		const form = event.target;
		if (!(form instanceof HTMLFormElement)) return;
		event.preventDefault();
		if (form.dataset.action === "add-literal") addLiteral();
		else if (form.dataset.action === "save-telemetry") saveTelemetry();
	};

	const removeLiteralAt = (index: number) => {
		if (state.phase !== "ready") return;
		const { literals } = state.policy;
		if (!Number.isInteger(index) || index < 0 || index >= literals.length) return;
		const remaining = removeLiteral(literals, index);
		const focusId =
			remaining.length === 0
				? "literal-value"
				: `literal-remove-${Math.min(index, remaining.length - 1)}`;
		void save({ literals: remaining }, { successKey: msg("notice_term_removed"), focusId });
	};

	const onClick = (event: Event) => {
		const target = event.target instanceof Element ? event.target.closest("[data-action]") : null;
		if (!(target instanceof HTMLButtonElement)) return;
		switch (target.dataset.action) {
			case "retry":
				state = { phase: "loading" };
				render();
				void load();
				return;
			case "remove-literal":
				removeLiteralAt(Number(target.dataset.index));
				return;
			case "disconnect-telemetry":
				void save(
					{ telemetry: null },
					{
						successKey: msg("notice_telemetry_removed"),
						focusId: "telemetry-url",
						draft: { telemetryUrl: "", telemetryKey: "", telemetryError: null },
					},
				);
				return;
		}
	};

	elements.app.addEventListener("change", onChange);
	elements.app.addEventListener("input", onInput);
	elements.app.addEventListener("submit", onSubmit);
	elements.app.addEventListener("click", onClick);
	// An administrator can push a managed policy while the page is open: re-read the
	// effective policy so newly locked settings turn read-only immediately.
	let refreshing = false;
	env.onInvalidate(["managed", "local"], () => {
		if (state.phase !== "ready" || busy || refreshing) return;
		refreshing = true;
		fetchPolicy()
			.then(async (fresh) => {
				if (state.phase !== "ready" || busy) return;
				if (fresh.language !== state.policy.language) await relocalize(fresh.language);
				state = { ...state, policy: fresh };
				render();
			})
			.catch(() => undefined)
			.finally(() => {
				refreshing = false;
			});
	});

	render();
	const ready = load();
	return { ready, getState: () => state };
}
