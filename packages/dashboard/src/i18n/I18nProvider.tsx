import { createContext, Fragment, type ReactNode, useContext, useEffect, useState } from "react";
import { type DashboardMessageKey, en } from "./en";
import { tr } from "./tr";

/**
 * Minimal dashboard localization (English / Turkish). No i18n library: the
 * catalogs are plain objects, the key-parity test keeps them in step, and a
 * component rendered without the provider (unit tests) gets English.
 *
 * Locale: the viewer's saved choice, otherwise the browser language
 * (`tr*` selects Turkish), otherwise English.
 */
export type DashboardLocale = "en" | "tr";
export type MessageParams = Record<string, string | number>;

export const DASHBOARD_CATALOGS: Record<DashboardLocale, Record<DashboardMessageKey, string>> = {
	en,
	tr,
};

export const LOCALE_STORAGE_KEY = "aidr.locale";

function format(template: string, params?: MessageParams): string {
	if (!params) return template;
	return template.replace(/\{(\w+)\}/g, (match, name: string) =>
		name in params ? String(params[name]) : match,
	);
}

export function translate(
	locale: DashboardLocale,
	key: DashboardMessageKey,
	params?: MessageParams,
): string {
	return format(DASHBOARD_CATALOGS[locale][key] ?? en[key] ?? key, params);
}

/** The saved choice, then the browser language; never throws. */
export function detectDashboardLocale(): DashboardLocale {
	try {
		const stored = localStorage.getItem(LOCALE_STORAGE_KEY);
		if (stored === "en" || stored === "tr") return stored;
	} catch {
		// Storage disabled: fall back to the browser language.
	}
	const languages =
		typeof navigator === "undefined"
			? []
			: [...(navigator.languages ?? []), navigator.language].filter(Boolean);
	return languages[0]?.toLowerCase().startsWith("tr") ? "tr" : "en";
}

interface I18nContextValue {
	locale: DashboardLocale;
	setLocale: (locale: DashboardLocale) => void;
}

const I18nContext = createContext<I18nContextValue | undefined>(undefined);

export function I18nProvider({
	children,
	initialLocale,
}: {
	children: ReactNode;
	initialLocale?: DashboardLocale;
}) {
	const [locale, setLocaleState] = useState<DashboardLocale>(
		() => initialLocale ?? detectDashboardLocale(),
	);

	useEffect(() => {
		document.documentElement.setAttribute("lang", locale);
	}, [locale]);

	const setLocale = (next: DashboardLocale) => {
		setLocaleState(next);
		try {
			localStorage.setItem(LOCALE_STORAGE_KEY, next);
		} catch {
			// The choice still applies to this page view.
		}
	};

	return <I18nContext.Provider value={{ locale, setLocale }}>{children}</I18nContext.Provider>;
}

function useLocale(): I18nContextValue {
	return useContext(I18nContext) ?? { locale: "en", setLocale: () => {} };
}

/** `t(key, params)` in the current locale. */
export function useT(): (key: DashboardMessageKey, params?: MessageParams) => string {
	const { locale } = useLocale();
	return (key, params) => translate(locale, key, params);
}

/**
 * A message whose parameters are elements (links, <strong>): the template is
 * split at `{name}` and each part rendered in order, so word order follows the
 * locale instead of the JSX.
 */
export function useRichT(): (
	key: DashboardMessageKey,
	parts: Record<string, ReactNode>,
) => ReactNode {
	const { locale } = useLocale();
	return (key, parts) => {
		const template = DASHBOARD_CATALOGS[locale][key] ?? en[key];
		const pieces = template.split(/(\{\w+\})/g);
		return pieces.map((piece, index) => {
			const name = /^\{(\w+)\}$/.exec(piece)?.[1];
			return (
				<Fragment key={index}>{name !== undefined && name in parts ? parts[name] : piece}</Fragment>
			);
		});
	};
}

/** Header button that switches between English and Turkish. */
export function LanguageToggle() {
	const { locale, setLocale } = useLocale();
	const t = useT();
	const target: DashboardLocale = locale === "tr" ? "en" : "tr";
	return (
		<button
			type="button"
			className="theme-toggle language-toggle"
			lang={target}
			aria-label={t("language.switchToLabel")}
			title={t("language.switchToLabel")}
			onClick={() => setLocale(target)}
		>
			{target.toUpperCase()}
		</button>
	);
}
