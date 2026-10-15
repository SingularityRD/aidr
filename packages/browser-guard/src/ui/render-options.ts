/**
 * Options page renderer: a pure function from OptionsState to a DOM subtree.
 * Interactive elements carry `data-action` attributes; options-app.ts wires them.
 */
import { serviceById } from "../sites/catalog.js";
import {
	ENTITY_TYPES,
	type EntityType,
	type GuardPolicy,
	type NativeHostStatus,
	type SiteAccessStatus,
} from "../types.js";
import { h, icon } from "./dom.js";
import { entityLabel, formatNumber, msg, type Translate } from "./i18n.js";
import {
	ENTITY_GROUPS,
	isLocked,
	LITERAL_ERROR_KEYS,
	LITERAL_MAX_COUNT,
	LITERAL_MAX_LENGTH,
	LITERAL_MIN_LENGTH,
	type LiteralError,
	type ManagedKey,
	SUPPORTED_SITES,
	TELEMETRY_ERROR_KEYS,
	type TelemetryError,
} from "./model.js";
import { managedBadge, switchRow } from "./render-common.js";
import { policyErrorNotice, renderModeControl } from "./render-popup.js";

export interface OptionsDraft {
	readonly literalValue: string;
	readonly literalType: EntityType;
	readonly literalError: LiteralError | null;
	readonly telemetryUrl: string;
	readonly telemetryKey: string;
	readonly telemetryError: TelemetryError | null;
}

/** Native host (NER) state shown in the Protection section. */
export interface NativeState {
	/** Optional `nativeMessaging` permission; "unsupported" when the page cannot query it. */
	readonly permission: "granted" | "missing" | "unsupported";
	/** Bridge status from GET_STATS, or null when the worker did not report it. */
	readonly host: NativeHostStatus | null;
}

export type OptionsState =
	| { readonly phase: "loading" }
	| { readonly phase: "error" }
	| {
			readonly phase: "ready";
			readonly policy: GuardPolicy;
			readonly version: string;
			readonly draft: OptionsDraft;
			readonly native: NativeState;
			/** Host access for Shadow AI / custom sites (null: not loaded or unavailable). */
			readonly access?: SiteAccessStatus | null;
			/** Clock for the usage window (defaults to the render time). */
			readonly now?: number;
	  };

export function emptyDraft(policy: GuardPolicy | null): OptionsDraft {
	return {
		literalValue: "",
		literalType: "INTERNAL",
		literalError: null,
		telemetryUrl: policy?.telemetry?.controlPlaneUrl ?? "",
		telemetryKey: "",
		telemetryError: null,
	};
}

const OPTIONS_SECTIONS = [
	{ id: "protection", titleKey: msg("section_protection") },
	{ id: "terms", titleKey: msg("section_terms") },
	{ id: "sites", titleKey: msg("section_sites") },
	{ id: "ai-access", titleKey: msg("section_ai_access") },
	{ id: "organization", titleKey: msg("section_organization") },
	{ id: "language", titleKey: msg("section_language") },
	{ id: "about", titleKey: msg("section_about") },
] as const;

type SectionId = (typeof OPTIONS_SECTIONS)[number]["id"];

function section(
	doc: Document,
	id: SectionId,
	t: Translate,
	options: { readonly intro?: string; readonly locked?: boolean },
	children: readonly (Node | null)[],
): HTMLElement {
	const titleKey = OPTIONS_SECTIONS.find((entry) => entry.id === id)?.titleKey ?? id;
	return h(doc, "section", { className: "card section", id, "aria-labelledby": `${id}-title` }, [
		h(doc, "header", { className: "section__header" }, [
			h(doc, "h2", { className: "section__title", id: `${id}-title` }, [t(titleKey)]),
			options.locked ? managedBadge(doc, t) : null,
		]),
		options.intro ? h(doc, "p", { className: "section__intro" }, [options.intro]) : null,
		...children,
	]);
}

function lockedNote(doc: Document, t: Translate, locked: boolean): HTMLElement | null {
	return locked
		? h(doc, "p", { className: "locked-note" }, [
				icon(doc, "lock", "icon icon--sm"),
				t("managed_explanation"),
			])
		: null;
}

function renderEntityGroups(doc: Document, policy: GuardPolicy, t: Translate): HTMLElement {
	const locked = isLocked(policy, "enabledEntities");
	const enabled = new Set(policy.enabledEntities);
	const neverRestore = new Set(policy.neverRestore);
	return h(doc, "div", { className: "entity-groups" }, [
		h(doc, "div", { className: "subsection__header" }, [
			h(doc, "h3", { className: "subsection__title" }, [t("entities_title")]),
			locked ? managedBadge(doc, t) : null,
		]),
		h(doc, "p", { className: "section__intro" }, [t("entities_intro")]),
		...ENTITY_GROUPS.map((group) =>
			h(doc, "fieldset", { className: "entity-group", disabled: locked, "data-group": group.id }, [
				h(doc, "legend", { className: "entity-group__legend" }, [t(group.labelKey)]),
				h(
					doc,
					"div",
					{ className: "entity-group__items" },
					group.types.map((type) => {
						const id = `entity-${type}`;
						return h(doc, "div", { className: "check" }, [
							h(doc, "input", {
								type: "checkbox",
								id,
								className: "check__input",
								checked: enabled.has(type),
								"data-action": "toggle-entity",
								"data-entity": type,
							}),
							h(doc, "label", { for: id, className: "check__label" }, [
								entityLabel(t, type),
								neverRestore.has(type)
									? h(doc, "span", { className: "tag", title: t("never_restore_help") }, [
											t("never_restore_tag"),
										])
									: null,
							]),
						]);
					}),
				),
			]),
		),
	]);
}

const NATIVE_HOST_KEYS: Readonly<Record<NativeHostStatus, string>> = {
	connected: msg("native_connected"),
	unavailable: msg("native_unavailable"),
	disabled: msg("native_status_disabled"),
};

const NATIVE_PERMISSION_KEYS: Readonly<Record<NativeState["permission"], string>> = {
	granted: msg("native_permission_granted"),
	missing: msg("native_permission_missing"),
	unsupported: msg("native_permission_unsupported"),
};

/** What happens to a picture the helper app could not inspect (policy.uninspectedImages). */
function renderUninspectedImages(doc: Document, policy: GuardPolicy, t: Translate): HTMLElement {
	const locked = isLocked(policy, "uninspectedImages");
	const value = policy.uninspectedImages ?? "warn";
	const choices = [
		{ value: "warn", key: msg("uninspected_images_warn") },
		{ value: "block", key: msg("uninspected_images_block") },
	] as const;
	return h(doc, "div", { className: "field", id: "uninspected-images" }, [
		h(doc, "label", { for: "uninspected-images-select", className: "field__label" }, [
			t("uninspected_images_label"),
		]),
		h(
			doc,
			"select",
			{
				id: "uninspected-images-select",
				className: "input",
				disabled: locked,
				"data-action": "set-uninspected-images",
			},
			choices.map((choice) =>
				h(doc, "option", { value: choice.value, selected: value === choice.value }, [
					t(choice.key),
				]),
			),
		),
		locked ? managedBadge(doc, t) : null,
		h(doc, "p", { className: "field__hint" }, [t("uninspected_images_help")]),
	]);
}

/** Optional native host (NER): explanation, opt-in switch, permission and live status. */
function renderNative(
	doc: Document,
	policy: GuardPolicy,
	native: NativeState,
	t: Translate,
): HTMLElement {
	const locked = isLocked(policy, "useNativeHost");
	const host = policy.useNativeHost ? (native.host ?? "unavailable") : "disabled";
	return h(doc, "div", { className: "native-host", id: "native-host" }, [
		h(doc, "div", { className: "subsection__header" }, [
			h(doc, "h3", { className: "subsection__title" }, [t("native_title")]),
		]),
		h(doc, "p", { className: "section__intro" }, [t("native_intro")]),
		h(doc, "div", { className: "switch-list" }, [
			switchRow(doc, {
				id: "native-host-toggle",
				label: t("native_toggle_label"),
				description: t("native_toggle_help"),
				checked: policy.useNativeHost,
				disabled: locked,
				action: "toggle-native-host",
				trailing: locked ? managedBadge(doc, t) : null,
			}),
		]),
		policy.requireNativeNer === true
			? h(doc, "p", { className: "field__hint", id: "native-required" }, [t("native_required")])
			: null,
		renderUninspectedImages(doc, policy, t),
		h(doc, "p", { className: "field__hint", id: "native-permission" }, [
			t(NATIVE_PERMISSION_KEYS[native.permission]),
		]),
		native.permission === "missing"
			? h(
					doc,
					"button",
					{
						type: "button",
						className: "btn btn--secondary",
						id: "native-grant",
						"data-action": "request-native-permission",
					},
					[t("native_permission_button")],
				)
			: null,
		h(
			doc,
			"p",
			{
				className: `native native--${host === "connected" ? "on" : "off"}`,
				id: "native-status",
			},
			[
				h(doc, "span", { className: "native__dot", "aria-hidden": "true" }),
				t(NATIVE_HOST_KEYS[host]),
			],
		),
	]);
}

function renderProtection(
	doc: Document,
	policy: GuardPolicy,
	native: NativeState,
	t: Translate,
): HTMLElement {
	const pasteLocked = isLocked(policy, "maskPaste");
	const restoreLocked = isLocked(policy, "restoreResponses");
	return section(doc, "protection", t, { intro: t("protection_intro") }, [
		renderModeControl(doc, policy, t, { idPrefix: "opt-mode" }),
		renderEntityGroups(doc, policy, t),
		h(doc, "div", { className: "switch-list" }, [
			switchRow(doc, {
				id: "mask-paste",
				label: t("mask_paste_label"),
				description: t("mask_paste_help"),
				checked: policy.maskPaste,
				disabled: pasteLocked,
				action: "toggle-mask-paste",
				trailing: pasteLocked ? managedBadge(doc, t) : null,
			}),
			switchRow(doc, {
				id: "restore-responses",
				label: t("restore_responses_label"),
				description: t("restore_responses_help"),
				checked: policy.restoreResponses,
				disabled: restoreLocked,
				action: "toggle-restore",
				trailing: restoreLocked ? managedBadge(doc, t) : null,
			}),
		]),
		renderNative(doc, policy, native, t),
	]);
}

function typeOptions(doc: Document, t: Translate, selected: EntityType): HTMLOptionElement[] {
	return ENTITY_TYPES.map((type) =>
		h(doc, "option", { value: type, selected: type === selected }, [entityLabel(t, type)]),
	);
}

function renderTerms(
	doc: Document,
	policy: GuardPolicy,
	draft: OptionsDraft,
	t: Translate,
	locale: string,
): HTMLElement {
	const locked = isLocked(policy, "literals");
	if (locked) {
		// Organisation terms (e.g. project code names) are confidential: show the count only.
		return section(doc, "terms", t, { intro: t("terms_intro"), locked: true }, [
			lockedNote(doc, t, true),
			h(doc, "p", { className: "terms__count" }, [
				t("terms_managed_count", formatNumber(locale, policy.literals.length)),
			]),
		]);
	}
	const errorId = "literal-error";
	const hasError = draft.literalError !== null;
	const form = h(
		doc,
		"form",
		{ className: "term-form", "data-action": "add-literal", novalidate: true },
		[
			h(doc, "div", { className: "field term-form__value" }, [
				h(doc, "label", { for: "literal-value", className: "field__label" }, [
					t("terms_value_label"),
				]),
				h(doc, "input", {
					type: "text",
					id: "literal-value",
					className: "input",
					value: draft.literalValue,
					autocomplete: "off",
					spellcheck: "false",
					maxlength: LITERAL_MAX_LENGTH * 2,
					"aria-invalid": hasError ? "true" : undefined,
					"aria-describedby": hasError ? `${errorId} literal-hint` : "literal-hint",
					"data-draft": "literalValue",
				}),
			]),
			h(doc, "div", { className: "field term-form__type" }, [
				h(doc, "label", { for: "literal-type", className: "field__label" }, [
					t("terms_type_label"),
				]),
				h(
					doc,
					"select",
					{ id: "literal-type", className: "input", "data-draft": "literalType" },
					typeOptions(doc, t, draft.literalType),
				),
			]),
			h(
				doc,
				"button",
				{ type: "submit", className: "btn btn--primary term-form__submit", id: "literal-add" },
				[t("terms_add")],
			),
			h(doc, "p", { className: "field__hint", id: "literal-hint" }, [
				t("terms_hint", [String(LITERAL_MIN_LENGTH), String(LITERAL_MAX_LENGTH)]),
			]),
			hasError && draft.literalError
				? h(doc, "p", { className: "field__error", id: errorId, role: "alert" }, [
						t(LITERAL_ERROR_KEYS[draft.literalError]),
					])
				: null,
		],
	);
	const rows = policy.literals.map((rule, index) =>
		h(doc, "tr", {}, [
			h(doc, "td", { className: "terms__value" }, [rule.value]),
			h(doc, "td", {}, [entityLabel(t, rule.type)]),
			h(doc, "td", { className: "terms__actions" }, [
				h(
					doc,
					"button",
					{
						type: "button",
						className: "btn btn--ghost btn--icon",
						id: `literal-remove-${index}`,
						"data-action": "remove-literal",
						"data-index": index,
						"aria-label": t("terms_remove_label", rule.value),
						title: t("terms_remove"),
					},
					[icon(doc, "trash", "icon icon--sm")],
				),
			]),
		]),
	);
	return section(doc, "terms", t, { intro: t("terms_intro") }, [
		form,
		h(doc, "p", { className: "terms__count", id: "terms-count" }, [
			t("terms_count", [
				formatNumber(locale, policy.literals.length),
				formatNumber(locale, LITERAL_MAX_COUNT),
			]),
		]),
		h(doc, "div", { className: "table-wrap" }, [
			h(doc, "table", { className: "terms", "aria-describedby": "terms-count" }, [
				h(doc, "caption", { className: "sr-only" }, [t("terms_caption")]),
				h(doc, "thead", {}, [
					h(doc, "tr", {}, [
						h(doc, "th", { scope: "col" }, [t("terms_col_value")]),
						h(doc, "th", { scope: "col" }, [t("terms_col_type")]),
						h(doc, "th", { scope: "col" }, [
							h(doc, "span", { className: "sr-only" }, [t("terms_col_actions")]),
						]),
					]),
				]),
				h(
					doc,
					"tbody",
					{},
					rows.length > 0
						? rows
						: [
								h(doc, "tr", {}, [
									h(doc, "td", { colspan: 3, className: "terms__empty" }, [t("terms_empty")]),
								]),
							],
				),
			]),
		]),
	]);
}

function renderSites(doc: Document, policy: GuardPolicy, t: Translate): HTMLElement {
	const locked = isLocked(policy, "disabledSites");
	return section(doc, "sites", t, { intro: t("sites_intro"), locked }, [
		lockedNote(doc, t, locked),
		h(
			doc,
			"div",
			{ className: "switch-list" },
			SUPPORTED_SITES.map((site) => {
				const blocked = policy.blockedSites.includes(site.id);
				return switchRow(doc, {
					id: `site-${site.id}`,
					label: site.label,
					description: blocked ? t("site_blocked_help") : site.hosts.join(", "),
					checked: !blocked && !policy.disabledSites.includes(site.id),
					disabled: locked || blocked,
					action: "toggle-site",
					data: { "data-site": site.id },
					trailing: blocked
						? h(doc, "span", { className: "tag tag--danger" }, [t("site_blocked_tag")])
						: null,
				});
			}),
		),
	]);
}

/** Whether the organisation configured Shadow AI control or custom sites (section shown). */
export function hasAiAccessPolicy(policy: GuardPolicy): boolean {
	const shadow = policy.shadowAi;
	return (
		(shadow !== undefined && (shadow.mode !== "off" || shadow.blocked.length > 0)) ||
		(policy.customSites?.length ?? 0) > 0
	);
}

const SHADOW_MODE_KEYS = {
	off: msg("shadow_mode_off"),
	monitor: msg("shadow_mode_monitor"),
	"block-unsanctioned": msg("shadow_mode_block"),
} as const;

/** Visits per service over the last `days` UTC days, busiest first. */
export function usageTotals(
	usage: SiteAccessStatus["shadowAi"]["usage"],
	now: number,
	days = 7,
): Array<{ serviceId: string; visited: number; blocked: number }> {
	const oldest = new Date(now - (days - 1) * 86_400_000).toISOString().slice(0, 10);
	const totals = new Map<string, { serviceId: string; visited: number; blocked: number }>();
	for (const row of usage) {
		if (row.day < oldest) continue;
		const entry = totals.get(row.serviceId) ?? { serviceId: row.serviceId, visited: 0, blocked: 0 };
		entry.visited += row.visited;
		entry.blocked += row.blocked;
		totals.set(row.serviceId, entry);
	}
	return [...totals.values()].sort(
		(a, b) =>
			b.visited + b.blocked - (a.visited + a.blocked) || a.serviceId.localeCompare(b.serviceId),
	);
}

function renderShadowAi(
	doc: Document,
	policy: GuardPolicy,
	access: SiteAccessStatus | null,
	t: Translate,
	locale: string,
	now: number,
): HTMLElement {
	const shadow = policy.shadowAi;
	const sanctioned = shadow.sanctioned.map((id) => serviceById(id)?.name).filter(Boolean);
	const status = access?.shadowAi ?? null;
	const missing = status?.missingOrigins.length ?? 0;
	const totals = status ? usageTotals(status.usage, now).slice(0, 10) : [];
	return h(doc, "div", { className: "shadow-ai", id: "shadow-ai" }, [
		h(doc, "div", { className: "subsection__header" }, [
			h(doc, "h3", { className: "subsection__title" }, [t("shadow_title")]),
		]),
		h(doc, "p", { className: "section__intro", id: "shadow-mode" }, [
			t(SHADOW_MODE_KEYS[shadow.mode]),
		]),
		sanctioned.length > 0
			? h(doc, "p", { className: "field__hint", id: "shadow-sanctioned" }, [
					t("shadow_sanctioned", sanctioned.join(", ")),
				])
			: null,
		status && status.blocked.length > 0
			? h(doc, "p", { className: "field__hint", id: "shadow-blocked" }, [
					t("shadow_blocked_count", formatNumber(locale, status.blocked.length)),
				])
			: null,
		status === null
			? h(doc, "p", { className: "field__hint", id: "shadow-access" }, [t("access_unknown")])
			: missing > 0
				? h(doc, "div", { className: "access access--missing", id: "shadow-access" }, [
						h(doc, "p", { className: "field__hint" }, [
							t("shadow_access_missing", formatNumber(locale, status.origins.length)),
						]),
						h(
							doc,
							"button",
							{
								type: "button",
								className: "btn btn--secondary",
								id: "shadow-grant",
								"data-action": "grant-shadow-access",
							},
							[t("access_grant_button")],
						),
					])
				: h(doc, "p", { className: "field__hint", id: "shadow-access" }, [
						t("shadow_access_granted"),
					]),
		shadow.mode === "off"
			? null
			: h(doc, "div", { className: "table-wrap" }, [
					h(doc, "table", { className: "terms", id: "shadow-usage" }, [
						h(doc, "caption", {}, [t("shadow_usage_title")]),
						h(doc, "thead", {}, [
							h(doc, "tr", {}, [
								h(doc, "th", { scope: "col" }, [t("shadow_usage_service")]),
								h(doc, "th", { scope: "col" }, [t("shadow_usage_visits")]),
								h(doc, "th", { scope: "col" }, [t("shadow_usage_blocked")]),
							]),
						]),
						h(
							doc,
							"tbody",
							{},
							totals.length > 0
								? totals.map((row) =>
										h(doc, "tr", {}, [
											h(doc, "td", {}, [serviceById(row.serviceId)?.name ?? row.serviceId]),
											h(doc, "td", {}, [formatNumber(locale, row.visited)]),
											h(doc, "td", {}, [formatNumber(locale, row.blocked)]),
										]),
									)
								: [
										h(doc, "tr", {}, [
											h(doc, "td", { colspan: 3, className: "terms__empty" }, [
												t("shadow_usage_empty"),
											]),
										]),
									],
						),
					]),
				]),
	]);
}

function renderCustomSites(
	doc: Document,
	policy: GuardPolicy,
	access: SiteAccessStatus | null,
	t: Translate,
): HTMLElement {
	return h(doc, "div", { className: "custom-sites", id: "custom-sites" }, [
		h(doc, "div", { className: "subsection__header" }, [
			h(doc, "h3", { className: "subsection__title" }, [t("custom_title")]),
		]),
		h(doc, "p", { className: "section__intro" }, [t("custom_intro")]),
		h(
			doc,
			"ul",
			{ className: "custom-sites__list" },
			policy.customSites.map((site) => {
				const status = access?.customSites.find((entry) => entry.id === site.id);
				const granted = status?.granted === true;
				return h(doc, "li", { className: "custom-site", id: `custom-site-${site.id}` }, [
					h(doc, "div", { className: "custom-site__text" }, [
						h(doc, "strong", {}, [site.label]),
						h(doc, "span", { className: "field__hint" }, [site.hosts.join(", ")]),
					]),
					h(doc, "span", { className: granted ? "tag" : "tag tag--danger" }, [
						t(granted ? msg("custom_status_active") : msg("custom_status_missing")),
					]),
					!granted && status
						? h(
								doc,
								"button",
								{
									type: "button",
									className: "btn btn--secondary",
									id: `custom-grant-${site.id}`,
									"data-action": "grant-custom-access",
									"data-site-id": site.id,
								},
								[t("access_grant_button")],
							)
						: null,
				]);
			}),
		),
	]);
}

/** Administrator-managed Shadow AI control and internal AI sites (read-only + access grants). */
function renderAiAccess(
	doc: Document,
	policy: GuardPolicy,
	access: SiteAccessStatus | null,
	t: Translate,
	locale: string,
	now: number,
): HTMLElement {
	const shadow = policy.shadowAi;
	const showShadow = shadow.mode !== "off" || shadow.blocked.length > 0;
	return section(doc, "ai-access", t, { intro: t("ai_access_intro"), locked: true }, [
		showShadow ? renderShadowAi(doc, policy, access, t, locale, now) : null,
		policy.customSites.length > 0 ? renderCustomSites(doc, policy, access, t) : null,
	]);
}

function sentFieldsList(doc: Document, t: Translate): HTMLElement {
	return h(doc, "div", { className: "disclosure" }, [
		h(doc, "h3", { className: "subsection__title" }, [t("telemetry_sent_title")]),
		h(
			doc,
			"ul",
			{ className: "bullets" },
			[
				msg("telemetry_sent_counts"),
				msg("telemetry_sent_site"),
				msg("telemetry_sent_action"),
				msg("telemetry_sent_policy"),
			].map((key) => h(doc, "li", {}, [t(key)])),
		),
		h(doc, "p", { className: "disclosure__never" }, [
			h(doc, "strong", {}, [t("telemetry_never_title")]),
			" ",
			t("telemetry_never_body"),
		]),
	]);
}

function renderOrganization(
	doc: Document,
	policy: GuardPolicy,
	draft: OptionsDraft,
	t: Translate,
): HTMLElement {
	const locked = isLocked(policy, "telemetry");
	const current = policy.telemetry;
	const statusLine = h(
		doc,
		"p",
		{
			className: `connection ${current ? "connection--on" : "connection--off"}`,
			id: "connection-status",
		},
		[
			h(doc, "span", { className: "connection__dot", "aria-hidden": "true" }),
			current ? t("telemetry_connected", current.controlPlaneUrl) : t("telemetry_not_connected"),
		],
	);
	if (locked) {
		return section(doc, "organization", t, { intro: t("telemetry_intro"), locked: true }, [
			lockedNote(doc, t, true),
			statusLine,
			sentFieldsList(doc, t),
		]);
	}
	const errorId = "telemetry-error";
	const error = draft.telemetryError;
	const form = h(
		doc,
		"form",
		{ className: "stack", "data-action": "save-telemetry", novalidate: true },
		[
			h(doc, "div", { className: "field" }, [
				h(doc, "label", { for: "telemetry-url", className: "field__label" }, [
					t("telemetry_url_label"),
				]),
				h(doc, "input", {
					type: "url",
					id: "telemetry-url",
					className: "input",
					value: draft.telemetryUrl,
					placeholder: "https://aidr.example.com",
					autocomplete: "off",
					spellcheck: "false",
					"aria-invalid": error?.startsWith("url") ? "true" : undefined,
					"aria-describedby": error?.startsWith("url") ? errorId : undefined,
					"data-draft": "telemetryUrl",
				}),
			]),
			h(doc, "div", { className: "field" }, [
				h(doc, "label", { for: "telemetry-key", className: "field__label" }, [
					t("telemetry_key_label"),
				]),
				h(doc, "input", {
					type: "password",
					id: "telemetry-key",
					className: "input",
					value: draft.telemetryKey,
					placeholder: current ? t("telemetry_key_saved_placeholder") : "",
					autocomplete: "off",
					spellcheck: "false",
					"aria-invalid": error?.startsWith("key") ? "true" : undefined,
					"aria-describedby": error?.startsWith("key")
						? `${errorId} telemetry-key-hint`
						: "telemetry-key-hint",
					"data-draft": "telemetryKey",
				}),
				h(doc, "p", { className: "field__hint", id: "telemetry-key-hint" }, [
					t("telemetry_key_hint"),
				]),
			]),
			error
				? h(doc, "p", { className: "field__error", id: errorId, role: "alert" }, [
						t(TELEMETRY_ERROR_KEYS[error]),
					])
				: null,
			h(doc, "div", { className: "row" }, [
				h(doc, "button", { type: "submit", className: "btn btn--primary", id: "telemetry-save" }, [
					t("telemetry_save"),
				]),
				current
					? h(
							doc,
							"button",
							{
								type: "button",
								className: "btn btn--secondary",
								id: "telemetry-disconnect",
								"data-action": "disconnect-telemetry",
							},
							[t("telemetry_disconnect")],
						)
					: null,
			]),
			h(doc, "p", { className: "field__hint" }, [t("telemetry_test_note")]),
		],
	);
	return section(doc, "organization", t, { intro: t("telemetry_intro") }, [
		statusLine,
		form,
		sentFieldsList(doc, t),
	]);
}

function renderLanguage(doc: Document, policy: GuardPolicy, t: Translate): HTMLElement {
	const locked = isLocked(policy, "language");
	const choices = [
		{ value: "auto", key: msg("language_auto") },
		{ value: "en", key: msg("language_en") },
		{ value: "tr", key: msg("language_tr") },
	] as const;
	return section(doc, "language", t, { locked }, [
		lockedNote(doc, t, locked),
		h(doc, "div", { className: "field field--inline" }, [
			h(doc, "label", { for: "language-select", className: "field__label" }, [t("language_label")]),
			h(
				doc,
				"select",
				{
					id: "language-select",
					className: "input",
					disabled: locked,
					"data-action": "set-language",
				},
				choices.map((choice) =>
					h(doc, "option", { value: choice.value, selected: policy.language === choice.value }, [
						t(choice.key),
					]),
				),
			),
		]),
	]);
}

function renderAbout(
	doc: Document,
	policy: GuardPolicy,
	version: string,
	t: Translate,
): HTMLElement {
	return section(doc, "about", t, {}, [
		h(doc, "dl", { className: "facts" }, [
			h(doc, "div", {}, [h(doc, "dt", {}, [t("about_version")]), h(doc, "dd", {}, [version])]),
			policy.policyId
				? h(doc, "div", {}, [
						h(doc, "dt", {}, [t("about_policy")]),
						h(doc, "dd", { className: "mono" }, [policy.policyId]),
					])
				: null,
		]),
		h(doc, "h3", { className: "subsection__title" }, [t("about_privacy_title")]),
		h(doc, "p", {}, [t("about_privacy_body")]),
		h(doc, "h3", { className: "subsection__title" }, [t("about_support_title")]),
		h(doc, "p", {}, [t("about_support_body")]),
	]);
}

function managedKeysPresent(policy: GuardPolicy): readonly ManagedKey[] {
	const keys: readonly ManagedKey[] = [
		"mode",
		"enabledEntities",
		"literals",
		"disabledSites",
		"maskPaste",
		"restoreResponses",
		"useNativeHost",
		"language",
		"telemetry",
	];
	return keys.filter((key) => isLocked(policy, key));
}

export function renderOptions(
	doc: Document,
	state: OptionsState,
	t: Translate,
	locale: string,
): HTMLElement {
	if (state.phase === "loading") {
		return h(doc, "div", { className: "options", "aria-busy": "true" }, [
			h(doc, "p", { className: "placeholder" }, [t("status_loading")]),
		]);
	}
	if (state.phase === "error") {
		return h(doc, "div", { className: "options" }, [
			h(doc, "section", { className: "card status status--danger", role: "alert" }, [
				h(doc, "span", { className: "status__icon" }, [icon(doc, "alert")]),
				h(doc, "div", { className: "status__text" }, [
					h(doc, "h2", { className: "status__title" }, [t("error_title")]),
					h(doc, "p", { className: "status__detail" }, [t("error_background")]),
				]),
				h(
					doc,
					"button",
					{ type: "button", className: "btn btn--secondary", id: "retry", "data-action": "retry" },
					[t("retry_button")],
				),
			]),
		]);
	}
	const { policy, draft, native } = state;
	const managed = managedKeysPresent(policy).length > 0;
	const aiAccess = hasAiAccessPolicy(policy);
	return h(doc, "div", { className: "options" }, [
		h(doc, "nav", { className: "toc", "aria-label": t("toc_label") }, [
			h(
				doc,
				"ul",
				{},
				OPTIONS_SECTIONS.filter((entry) => entry.id !== "ai-access" || aiAccess).map((entry) =>
					h(doc, "li", {}, [h(doc, "a", { href: `#${entry.id}` }, [t(entry.titleKey)])]),
				),
			),
		]),
		managed
			? h(doc, "p", { className: "banner", role: "note" }, [
					icon(doc, "lock", "icon icon--sm"),
					t("managed_banner"),
				])
			: null,
		policyErrorNotice(doc, policy, t, locale),
		renderProtection(doc, policy, native, t),
		renderTerms(doc, policy, draft, t, locale),
		renderSites(doc, policy, t),
		aiAccess
			? renderAiAccess(doc, policy, state.access ?? null, t, locale, state.now ?? Date.now())
			: null,
		renderOrganization(doc, policy, draft, t),
		renderLanguage(doc, policy, t),
		renderAbout(doc, policy, state.version, t),
	]);
}
