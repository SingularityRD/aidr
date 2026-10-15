/**
 * Options page controller: loads the effective policy, renders it with
 * renderOptions and sends SET_USER_SETTINGS for every change. Keys locked by
 * managed policy are rejected here as well as rendered read-only.
 */
import {
	ENTITY_TYPES,
	type EntityType,
	type GuardPolicy,
	type SiteAccessStatus,
	type UserSettings,
} from "../types.js";
import type { UiEnv } from "./env.js";
import { browserLocalizer, type Localizer, msg, relocalizeDocument } from "./i18n.js";
import {
	errorKeyFor,
	GUARD_MODES,
	isLocked,
	isSupportedSite,
	type ManagedKey,
	policyFromResponse,
	removeLiteral,
	statsFromResponse,
	toggleEntity,
	toggleSite,
	validateLiteral,
	validateTelemetry,
} from "./model.js";
import { renderNotice, replaceKeepingFocus } from "./render-common.js";
import {
	emptyDraft,
	hasAiAccessPolicy,
	type NativeState,
	type OptionsDraft,
	type OptionsState,
	renderOptions,
} from "./render-options.js";

const NATIVE_PERMISSION = "nativeMessaging";

const isNativeToggle = (target: EventTarget | null): target is HTMLInputElement =>
	target instanceof HTMLInputElement && target.dataset.action === "toggle-native-host";

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
function settingsForChange(
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
		case "toggle-native-host":
			return checked === policy.useNativeHost ? null : { useNativeHost: checked };
		case "set-uninspected-images": {
			const value = control.value === "block" || control.value === "warn" ? control.value : null;
			return value && value !== (policy.uninspectedImages ?? "warn")
				? { uninspectedImages: value }
				: null;
		}
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
		replaceKeepingFocus(
			doc,
			elements.app,
			renderOptions(doc, state, localizer.t, localizer.locale),
			focusId,
		);
	};

	const notify = (key: string | null, kind: "ok" | "error" = "ok") => {
		renderNotice(elements.live, key ? { kind, text: localizer.t(key) } : null);
	};

	const relocalize = async (language: GuardPolicy["language"]) => {
		localizer = await relocalizeDocument(doc, env, language);
	};

	const fetchPolicy = async (): Promise<GuardPolicy> => {
		return policyFromResponse(await env.send({ type: "GET_POLICY" }));
	};

	/** Permission + bridge status for the native host subsection; never rejects. */
	const readNative = async (): Promise<NativeState> => {
		let granted: boolean | null = null;
		try {
			granted = env.hasPermission ? await env.hasPermission(NATIVE_PERMISSION) : null;
		} catch {
			granted = null;
		}
		let host: NativeState["host"] = null;
		try {
			host = statsFromResponse(await env.send({ type: "GET_STATS" })).nativeHost;
		} catch {
			host = null;
		}
		return { permission: granted === null ? "unsupported" : granted ? "granted" : "missing", host };
	};

	const refreshNative = async () => {
		const native = await readNative();
		if (state.phase === "ready") state = { ...state, native };
	};

	/** Host access for Shadow AI and custom sites; null when the worker cannot say. */
	const readAccess = async (policy: GuardPolicy): Promise<SiteAccessStatus | null> => {
		if (!hasAiAccessPolicy(policy)) return null;
		try {
			const response = (await env.send({ type: "GET_SITE_ACCESS" })) as {
				ok?: unknown;
				access?: SiteAccessStatus;
			};
			return response?.ok === true && response.access ? response.access : null;
		} catch {
			return null;
		}
	};

	const refreshAccess = async () => {
		if (state.phase !== "ready") return;
		const access = await readAccess(state.policy);
		if (state.phase === "ready") state = { ...state, access, now: env.now() };
	};

	const load = async () => {
		try {
			const policy = await fetchPolicy();
			await relocalize(policy.language);
			const [native, access] = await Promise.all([readNative(), readAccess(policy)]);
			state = {
				phase: "ready",
				policy,
				version: env.getVersion(),
				draft: emptyDraft(policy),
				native,
				access,
				now: env.now(),
			};
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

	/**
	 * Asks the browser for the optional nativeMessaging permission. Browsers only prompt
	 * inside a user gesture, so handlers call this synchronously, before any await.
	 */
	const requestNativePermission = (): Promise<boolean> =>
		env.requestPermission
			? env.requestPermission(NATIVE_PERMISSION).catch(() => false)
			: Promise.resolve(false);

	const afterPermissionRequest = async (granted: boolean, focusId: string) => {
		await refreshNative();
		render(focusId);
		notify(
			granted ? msg("notice_native_permission_granted") : msg("native_permission_denied"),
			granted ? "ok" : "error",
		);
	};

	/** Turning the native host on first obtains the permission it needs. */
	const onNativeToggle = (target: HTMLInputElement) => {
		if (state.phase !== "ready") return;
		if (!target.checked || state.native.permission !== "missing") {
			const settings = settingsForChange(state.policy, target);
			if (!settings) return;
			void save(settings, { focusId: target.id }).then(async () => {
				await refreshNative(); // the bridge status follows the new setting
				render(target.id);
			});
			return;
		}
		const request = requestNativePermission();
		void request.then(async (granted) => {
			if (!granted) {
				await afterPermissionRequest(false, target.id);
				return;
			}
			await refreshNative();
			await save({ useNativeHost: true }, { focusId: target.id });
		});
	};

	const onChange = (event: Event) => {
		const target = event.target;
		if (state.phase !== "ready") return;
		if (isNativeToggle(target)) {
			onNativeToggle(target);
			return;
		}
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

	/**
	 * Asks the browser for host access (optional host permissions). Called synchronously
	 * from the click so the browser shows its prompt; the worker re-syncs on the grant.
	 */
	const grantOrigins = (origins: readonly string[], focusId: string) => {
		if (origins.length === 0 || !env.requestOrigins) {
			notify(msg("notice_access_denied"), "error");
			return;
		}
		void env
			.requestOrigins(origins)
			.catch(() => false)
			.then(async (granted) => {
				await refreshAccess();
				render(focusId);
				notify(
					granted ? msg("notice_access_granted") : msg("notice_access_denied"),
					granted ? "ok" : "error",
				);
			});
	};

	const onClick = (event: Event) => {
		const target = event.target instanceof Element ? event.target.closest("[data-action]") : null;
		if (!(target instanceof HTMLButtonElement)) return;
		switch (target.dataset.action) {
			case "grant-shadow-access":
				if (state.phase === "ready" && state.access)
					grantOrigins(state.access.shadowAi.missingOrigins, "shadow-access");
				return;
			case "grant-custom-access": {
				const site =
					state.phase === "ready"
						? state.access?.customSites.find((entry) => entry.id === target.dataset.siteId)
						: undefined;
				if (site) grantOrigins(site.origins, `custom-site-${site.id}`);
				return;
			}
			case "retry":
				state = { phase: "loading" };
				render();
				void load();
				return;
			case "remove-literal":
				removeLiteralAt(Number(target.dataset.index));
				return;
			case "request-native-permission":
				void requestNativePermission().then((granted) =>
					afterPermissionRequest(granted, "native-host-toggle"),
				);
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
				await refreshAccess();
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
