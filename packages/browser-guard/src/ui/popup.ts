/**
 * Popup entry point (bundled to popup.js, loaded by static/popup.html).
 *
 * The same bundle also drives static/blocked.html, the page the background opens
 * in a tab whose navigation to a blocked site was refused: the build ships a fixed
 * set of entry points, and
 * the blocked page needs only the localizer plus a few lines of rendering.
 */
import { chromeEnv, getChrome } from "./env.js";
import { applyI18n, browserLocalizer } from "./i18n.js";
import { startPopup } from "./popup-app.js";
import { blockedByShadowAi, blockedSiteFromUrl, renderBlocked } from "./render-blocked.js";

function boot(): void {
	if (!getChrome()) return;
	const env = chromeEnv();
	const { t, locale } = browserLocalizer(env);
	document.documentElement.lang = locale;
	applyI18n(document, t);
	if (document.body.classList.contains("page--blocked")) {
		renderBlocked(document, t, blockedSiteFromUrl(location.href), blockedByShadowAi(location.href));
		return;
	}
	const app = document.getElementById("app");
	const live = document.getElementById("live");
	if (app && live) startPopup(document, env, { app, live });
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
else boot();
