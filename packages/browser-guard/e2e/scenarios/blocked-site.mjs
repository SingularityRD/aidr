// (9) Blocked AI site: a top-level navigation to a site in the managed
// `blockedSites` policy is refused by the declarativeNetRequest rule
// src/background/dnr.ts installs, and the background worker then navigates the
// tab to the extension's blocked.html (tabs.update), which must load together
// with its stylesheet and script.
//
// chrome.storage.managed cannot be written from a test, so the scenario installs
// exactly the rule dnr.ts builds for `blockedSites: ["gemini"]` (same rule id,
// same action; policy -> rule mapping is unit-tested in background-worker.test.ts)
// and removes it afterwards. The worker's redirect keys off the installed rule, so
// the page the user sees is the product's own behaviour, not a test shortcut.
//
// It also proves the fingerprinting fix (L6): blocked.html is not web accessible,
// so a web page cannot load it by the extension id, while the extension itself
// can (so the probe is not vacuous).

import fs from "node:fs";
import path from "node:path";
import { waitFor } from "../lib/expect.mjs";
import { SITES } from "../lib/sites.mjs";

/** dnr.ts: DNR_RULE_ID_BASE + index("gemini") * 2 + 1 (navigation rule). */
const GEMINI_NAVIGATION_RULE_ID = 7303;
const SITE = "gemini";

export default [
	{
		id: "blocked-site",
		title: "a blocked AI site's navigation lands on the extension's blocked page",
		skip: (h) =>
			fs.existsSync(path.join(h.extDir, "blocked.html"))
				? null
				: "the build does not ship a blocked-site page",
		async run({ h, checks }) {
			const site = SITES[SITE];
			checks.check(
				"blocked.html is not web accessible (no fingerprinting surface)",
				!(h.manifest.web_accessible_resources ?? []).some((entry) =>
					(entry.resources ?? []).some((r) => r.includes("blocked")),
				),
				h.manifest.web_accessible_resources,
			);
			const worker = await h.currentWorker();
			await h.sendMessage({ type: "GET_POLICY" });
			const hosts = [new URL(site.origin).hostname];
			// The worker rewrites its rule range whenever it loads the policy (at every
			// worker start, and on settings writes from earlier scenarios), so first wait
			// until it answers GET_POLICY (its start-up load is done), then (re)install the
			// rule until it has survived a quiet second.
			const ensureRule = () =>
				worker.evaluate(
					async ({ id, hosts }) => {
						const rules = await chrome.declarativeNetRequest.getDynamicRules();
						if (rules.some((r) => r.id === id)) return true;
						await chrome.declarativeNetRequest.updateDynamicRules({
							removeRuleIds: [id],
							addRules: [
								{
									id,
									priority: 1,
									action: { type: "block" },
									condition: { requestDomains: hosts, resourceTypes: ["main_frame"] },
								},
							],
						});
						return false;
					},
					{ id: GEMINI_NAVIGATION_RULE_ID, hosts },
				);
			let stable = 0;
			for (let i = 0; i < 20 && stable < 3; i++) {
				stable = (await ensureRule()) ? stable + 1 : 0;
				await new Promise((resolve) => setTimeout(resolve, 500));
			}
			checks.check("the product's gemini navigation rule is installed", stable >= 3, { stable });
			const page = await h.context.newPage();
			const errors = [];
			page.on("pageerror", (e) => errors.push(String(e.message ?? e)));
			page.on("console", (m) => {
				if (m.type() === "error") errors.push(`console: ${m.text()}`);
			});
			// A request refused by declarativeNetRequest is still announced to the page's
			// network observers, then fails with net::ERR_BLOCKED_BY_CLIENT before it is
			// sent; "reached the site" therefore means a request that finished.
			const finished = [];
			const failed = [];
			page.on("requestfinished", (r) => {
				if (r.url().startsWith(site.origin)) finished.push(r.url());
			});
			page.on("requestfailed", (r) => {
				if (r.url().startsWith(site.origin))
					failed.push({ url: r.url(), error: r.failure()?.errorText ?? "" });
			});
			try {
				await page.goto(`${site.origin}${site.path}`).catch(() => {});
				const landed = await waitFor(
					() => (page.url().includes("/blocked.html") ? page.url() : null),
					{ timeout: 8000, message: "the redirect to blocked.html" },
				).catch(() => page.url());
				checks.contains(
					"the navigation ends on the extension's blocked page",
					landed,
					/^chrome-extension:\/\/[^/]+\/blocked\.html\?site=gemini$/,
				);
				await page.waitForLoadState("load").catch(() => {});
				const view = await waitFor(
					async () => {
						const v = await page.evaluate(() => ({
							heading: document.getElementById("blocked-title")?.textContent?.trim() ?? "",
							title: document.title,
							lang: document.documentElement.lang,
							cssRules: [...document.styleSheets].reduce(
								(n, sheet) => n + (sheet.cssRules?.length ?? 0),
								0,
							),
						}));
						return /Gemini/.test(v.heading) ? v : null;
					},
					{ timeout: 5000, message: "blocked.html to render" },
				).catch(() => page.evaluate(() => document.documentElement.outerHTML.slice(0, 400)));
				checks.contains("the page names the blocked site (popup.js ran)", view?.heading, /Gemini/);
				checks.check("the page stylesheet loaded (ui.css)", view?.cssRules > 0, view);
				checks.check("the localized page title is set", /\S/.test(view?.title ?? ""), view);
				checks.check("no request reached the blocked site", finished.length === 0, finished);
				checks.check(
					"the browser refused the site navigation (ERR_BLOCKED_BY_CLIENT)",
					failed.length > 0 && failed.every((f) => /BLOCKED_BY_CLIENT/.test(f.error)),
					failed,
				);
				checks.check("blocked.html has no errors", errors.length === 0, errors);

				// Fingerprinting probe (L6): from a web page, the page must not load by the
				// extension id; from the extension's own page the same probe must load it.
				const pageUrl = await worker.evaluate(() => chrome.runtime.getURL("/blocked.html"));
				const stableUrl = `${h.extensionOrigin}/blocked.html`;
				const probe = await h.openSite("generic", { expectContentScript: false });
				const control = await h.control();
				try {
					const load = (urls) =>
						Promise.all(
							urls.map((url) =>
								fetch(url, { mode: "no-cors" }).then(
									() => "loaded",
									() => "refused",
								),
							),
						);
					const fromWeb = await probe.evaluate(load, [stableUrl, pageUrl]);
					const fromExtension = await control.evaluate(load, [stableUrl]);
					checks.check(
						"a web page cannot load blocked.html by the extension id",
						fromWeb.every((r) => r === "refused"),
						{ stableUrl, pageUrl, fromWeb },
					);
					checks.equal(
						"the extension's own page loads it with the same probe (control)",
						fromExtension[0],
						"loaded",
					);
				} finally {
					await probe.close().catch(() => {});
				}
			} finally {
				await page.close().catch(() => {});
				await worker
					.evaluate(
						(id) => chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [id] }),
						GEMINI_NAVIGATION_RULE_ID,
					)
					.catch(() => {});
			}
		},
	},
];
