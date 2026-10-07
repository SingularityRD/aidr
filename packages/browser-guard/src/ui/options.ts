/** Options page entry point (bundled to options.js, loaded by static/options.html). */
import { chromeEnv, getChrome } from "./env.js";
import { applyI18n, browserLocalizer } from "./i18n.js";
import { startOptions } from "./options-app.js";

function boot(): void {
	const app = document.getElementById("app");
	const live = document.getElementById("live");
	if (!app || !live || !getChrome()) return;
	const env = chromeEnv();
	const { t, locale } = browserLocalizer(env);
	document.documentElement.lang = locale;
	applyI18n(document, t);
	startOptions(document, env, { app, live });
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
else boot();
