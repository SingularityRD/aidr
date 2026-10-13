/**
 * Popup renderer: a pure function from PopupState to a DOM subtree.
 * Interactive elements carry `data-action` attributes; popup-app.ts wires them.
 */
import type { GuardPolicy, GuardStats } from "../types.js";
import { h, type IconName, icon } from "./dom.js";
import { entityLabel, formatClock, formatNumber, MODE_KEYS, msg, type Translate } from "./i18n.js";
import {
	GUARD_MODES,
	isLocked,
	type ProtectedSiteId,
	type ProtectionStatus,
	policyErrors,
	protectionStatus,
	siteLabel,
	topEntityTypes,
} from "./model.js";
import { managedBadge, switchRow } from "./render-common.js";

export const PAUSE_MINUTES = 15;

export type PopupState =
	| { readonly phase: "loading" }
	| { readonly phase: "error" }
	| {
			readonly phase: "ready";
			readonly policy: GuardPolicy;
			readonly stats: GuardStats;
			readonly urlSite: ProtectedSiteId | null;
			readonly restoreVisible: boolean;
			readonly now: number;
			readonly busy: boolean;
	  };

interface StatusView {
	readonly tone: "ok" | "warn" | "off" | "danger";
	readonly icon: IconName;
	readonly title: string;
	readonly detail: string;
}

/** Display name of the tab's site; custom sites use a localized generic name. */
function statusSiteLabel(site: ProtectedSiteId, t: Translate): string {
	return siteLabel(site) ?? (site === "custom" ? t("site_custom_label") : site);
}

function statusView(status: ProtectionStatus, t: Translate, locale: string): StatusView {
	switch (status.kind) {
		case "loading":
			return { tone: "off", icon: "shield", title: t("status_loading"), detail: "" };
		case "unsupported":
			return {
				tone: "off",
				icon: "info",
				title: t("status_unsupported"),
				detail: t("status_unsupported_detail"),
			};
		case "blocked":
			return {
				tone: "danger",
				icon: "block",
				title: t("status_blocked"),
				detail: t("status_blocked_detail", statusSiteLabel(status.site, t)),
			};
		case "disabled-policy":
			return {
				tone: "off",
				icon: "shieldOff",
				title: t("status_disabled_policy"),
				detail: t("status_disabled_policy_detail", statusSiteLabel(status.site, t)),
			};
		case "disabled-user":
			return {
				tone: "off",
				icon: "shieldOff",
				title: t("status_disabled_user"),
				detail: t("status_disabled_user_detail", statusSiteLabel(status.site, t)),
			};
		case "paused":
			return {
				tone: "warn",
				icon: "pause",
				title: t("status_paused", formatClock(locale, status.until)),
				detail: t("status_paused_detail", statusSiteLabel(status.site, t)),
			};
		case "inactive":
			return {
				tone: "danger",
				icon: "alert",
				title: t("status_inactive"),
				detail: t("status_inactive_detail", statusSiteLabel(status.site, t)),
			};
		case "monitoring":
			return {
				tone: "warn",
				icon: "eye",
				title: t("status_monitoring"),
				detail: t("status_monitoring_detail", statusSiteLabel(status.site, t)),
			};
		case "protected":
			return {
				tone: "ok",
				icon: "shield",
				title: t("status_protected"),
				detail: t("status_protected_detail", statusSiteLabel(status.site, t)),
			};
	}
}

export interface RestoreToggle {
	readonly available: boolean;
	readonly descriptionKey: string;
}

/**
 * Whether "Show original values in responses" can be changed for this tab. It
 * needs response restoring enabled by policy and a supported AI site in the
 * current tab (the worker forwards the switch to that tab's content script).
 */
export function restoreToggle(policy: GuardPolicy, status: ProtectionStatus): RestoreToggle {
	if (!policy.restoreResponses) {
		return {
			available: false,
			descriptionKey: isLocked(policy, "restoreResponses")
				? msg("restore_visible_off_managed")
				: msg("restore_visible_off"),
		};
	}
	const active =
		status.kind === "protected" || status.kind === "monitoring" || status.kind === "paused";
	return active
		? { available: true, descriptionKey: msg("restore_visible_help") }
		: { available: false, descriptionKey: msg("restore_visible_no_site") };
}

function renderStatus(doc: Document, view: StatusView): HTMLElement {
	return h(
		doc,
		"section",
		{ className: `status status--${view.tone}`, "aria-labelledby": "status-title", id: "status" },
		[
			h(doc, "span", { className: "status__icon" }, [icon(doc, view.icon)]),
			h(doc, "div", { className: "status__text" }, [
				h(doc, "h2", { className: "status__title", id: "status-title" }, [view.title]),
				view.detail ? h(doc, "p", { className: "status__detail" }, [view.detail]) : null,
			]),
		],
	);
}

/** Segmented control for the four guard modes. Shared by popup and options. */
export function renderModeControl(
	doc: Document,
	policy: GuardPolicy,
	t: Translate,
	options: { readonly idPrefix: string; readonly disabled?: boolean },
): HTMLElement {
	const locked = isLocked(policy, "mode");
	const disabled = locked || options.disabled === true;
	const helpId = `${options.idPrefix}-help`;
	const badgeId = `${options.idPrefix}-managed`;
	const fieldset = h(
		doc,
		"fieldset",
		{
			className: `segmented${locked ? " is-locked" : ""}`,
			disabled,
			"aria-describedby": locked ? `${helpId} ${badgeId}` : helpId,
			title: locked ? t("managed_by_org") : undefined,
		},
		[
			h(doc, "legend", { className: "segmented__legend" }, [
				h(doc, "span", {}, [t("mode_label")]),
				locked ? managedBadge(doc, t, badgeId) : null,
			]),
			h(
				doc,
				"div",
				{ className: "segmented__options" },
				GUARD_MODES.map((mode) => {
					const id = `${options.idPrefix}-${mode}`;
					return h(doc, "div", { className: "segmented__option" }, [
						h(doc, "input", {
							type: "radio",
							className: "segmented__input",
							name: `${options.idPrefix}-mode`,
							id,
							value: mode,
							checked: policy.mode === mode,
							"data-action": "set-mode",
						}),
						h(doc, "label", { className: "segmented__label", for: id }, [t(MODE_KEYS[mode].label)]),
					]);
				}),
			),
			h(doc, "p", { className: "segmented__help", id: helpId }, [t(MODE_KEYS[policy.mode].help)]),
		],
	);
	return fieldset;
}

function renderStats(doc: Document, stats: GuardStats, t: Translate, locale: string): HTMLElement {
	const tiles: ReadonlyArray<{ readonly key: string; readonly value: number }> = [
		{ key: msg("stats_prompts"), value: stats.protectedPrompts },
		{ key: msg("stats_masked"), value: stats.maskedItems },
		{ key: msg("stats_blocked"), value: stats.blockedSends },
	];
	const top = topEntityTypes(stats.byType);
	const max = top[0]?.count ?? 0;
	return h(doc, "section", { className: "card stats", "aria-labelledby": "stats-title" }, [
		h(doc, "h2", { className: "card__title", id: "stats-title" }, [t("stats_title")]),
		h(
			doc,
			"dl",
			{ className: "stats__tiles" },
			tiles.map((tile) =>
				h(doc, "div", { className: "stat" }, [
					h(doc, "dt", { className: "stat__label" }, [t(tile.key)]),
					h(doc, "dd", { className: "stat__value" }, [formatNumber(locale, tile.value)]),
				]),
			),
		),
		top.length === 0
			? h(doc, "p", { className: "stats__empty" }, [t("stats_empty")])
			: h(doc, "div", { className: "bars" }, [
					h(doc, "h3", { className: "bars__title", id: "bars-title" }, [t("stats_top_types")]),
					h(
						doc,
						"ul",
						{ className: "bars__list", "aria-labelledby": "bars-title" },
						top.map((entry) => {
							const fill = h(doc, "span", { className: "bar__fill" });
							fill.style.width = `${Math.max(4, Math.round((entry.count / max) * 100))}%`;
							return h(doc, "li", { className: "bar", "data-entity": entry.type }, [
								h(doc, "span", { className: "bar__label" }, [entityLabel(t, entry.type)]),
								h(doc, "span", { className: "bar__count" }, [formatNumber(locale, entry.count)]),
								h(doc, "span", { className: "bar__track", "aria-hidden": "true" }, [fill]),
							]);
						}),
					),
				]),
	]);
}

function renderActions(
	doc: Document,
	status: ProtectionStatus,
	policy: GuardPolicy,
	t: Translate,
): HTMLElement {
	const canPause =
		policy.allowUserPause && (status.kind === "protected" || status.kind === "monitoring");
	const canResume = status.kind === "paused";
	return h(doc, "div", { className: "actions" }, [
		canPause
			? h(
					doc,
					"button",
					{
						type: "button",
						className: "btn btn--secondary",
						id: "pause",
						"data-action": "pause",
					},
					[icon(doc, "pause", "icon icon--sm"), t("pause_button", String(PAUSE_MINUTES))],
				)
			: null,
		canResume
			? h(
					doc,
					"button",
					{
						type: "button",
						className: "btn btn--primary",
						id: "resume",
						"data-action": "resume",
					},
					[icon(doc, "play", "icon icon--sm"), t("resume_button")],
				)
			: null,
		h(
			doc,
			"button",
			{
				type: "button",
				className: "btn btn--ghost",
				id: "open-options",
				"data-action": "open-options",
			},
			[icon(doc, "settings", "icon icon--sm"), t("open_settings")],
		),
	]);
}

/** Invalid managed values fell back to fail-safe values: tell the user who can fix it. */
export function policyErrorNotice(
	doc: Document,
	policy: GuardPolicy,
	t: Translate,
	locale: string,
): HTMLElement | null {
	const count = policyErrors(policy).length;
	if (count === 0) return null;
	return h(doc, "p", { className: "banner banner--danger", role: "alert", id: "policy-error" }, [
		icon(doc, "alert", "icon icon--sm"),
		t("policy_error", formatNumber(locale, count)),
	]);
}

function nativeHostLine(doc: Document, stats: GuardStats, t: Translate): HTMLElement | null {
	if (stats.nativeHost === "disabled") return null;
	const connected = stats.nativeHost === "connected";
	return h(doc, "p", { className: `native native--${connected ? "on" : "off"}` }, [
		h(doc, "span", { className: "native__dot", "aria-hidden": "true" }),
		connected ? t("native_connected") : t("native_unavailable"),
	]);
}

export function renderPopup(
	doc: Document,
	state: PopupState,
	t: Translate,
	locale: string,
): HTMLElement {
	if (state.phase === "loading") {
		return h(doc, "div", { className: "popup", "aria-busy": "true" }, [
			renderStatus(doc, statusView({ kind: "loading" }, t, locale)),
		]);
	}
	if (state.phase === "error") {
		return h(doc, "div", { className: "popup" }, [
			renderStatus(doc, {
				tone: "danger",
				icon: "alert",
				title: t("error_title"),
				detail: t("error_background"),
			}),
			h(doc, "div", { className: "actions" }, [
				h(
					doc,
					"button",
					{ type: "button", className: "btn btn--secondary", id: "retry", "data-action": "retry" },
					[t("retry_button")],
				),
			]),
		]);
	}
	const { policy, stats } = state;
	const status = protectionStatus(policy, stats, state.urlSite, state.now);
	const restore = restoreToggle(policy, status);
	return h(doc, "div", { className: "popup", "aria-busy": state.busy ? "true" : undefined }, [
		renderStatus(doc, statusView(status, t, locale)),
		policyErrorNotice(doc, policy, t, locale),
		h(doc, "section", { className: "card" }, [
			renderModeControl(doc, policy, t, { idPrefix: "popup-mode" }),
		]),
		renderStats(doc, stats, t, locale),
		h(doc, "section", { className: "card" }, [
			switchRow(doc, {
				id: "restore-visible",
				label: t("restore_visible_label"),
				description: t(restore.descriptionKey),
				checked: restore.available && state.restoreVisible,
				disabled: !restore.available,
				action: "toggle-restore-visible",
			}),
		]),
		nativeHostLine(doc, stats, t),
		renderActions(doc, status, policy, t),
	]);
}
