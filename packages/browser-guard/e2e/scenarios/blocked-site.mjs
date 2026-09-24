// (9) Blocked AI site: a top-level navigation to a site in the managed
// `blockedSites` policy is redirected by declarativeNetRequest to the
// extension's blocked.html, which must load from a web-initiated navigation
// (web_accessible_resources) together with its stylesheet and script.
//
// chrome.storage.managed cannot be written from a test, so the scenario
// installs the same redirect rule src/background/dnr.ts builds for
// `blockedSites: ["gemini"]` (policy -> rule mapping is unit-tested in
// background-worker.test.ts) under a rule id outside the product's range, and
// removes it afterwards.

import { waitFor } from "../lib/expect.mjs";
import { SITES } from "../lib/sites.mjs";

const RULE_ID = 99_001;
const SITE = "gemini";

function blockedPageExposed(manifest) {
	return (manifest.web_accessible_resources ?? []).some((entry) =>
		(entry.resources ?? []).includes("blocked.html"),
	);
}

export default [
	{
		id: "blocked-site",
		title: "a blocked AI site's navigation lands on the extension's blocked page",
		skip: (h) =>
			blockedPageExposed(h.manifest) ? null : "the build does not ship a blocked-site page",
		async run({ h, checks }) {
			const site = SITES[SITE];
			const worker = await h.currentWorker();
			await worker.evaluate(
				async ({ id, hosts }) => {
					await chrome.declarativeNetRequest.updateDynamicRules({
						removeRuleIds: [id],
						addRules: [
							{
								id,
								priority: 1,
								action: {
									type: "redirect",
									redirect: { extensionPath: "/blocked.html?site=gemini" },
								},
								condition: { requestDomains: hosts, resourceTypes: ["main_frame"] },
							},
						],
					});
				},
				{ id: RULE_ID, hosts: [new URL(site.origin).hostname] },
			);
			const page = await h.context.newPage();
			const errors = [];
			page.on("pageerror", (e) => errors.push(String(e.message ?? e)));
			page.on("console", (m) => {
				if (m.type() === "error") errors.push(`console: ${m.text()}`);
			});
			const mark = h.recorder.mark();
			try {
				await page.goto(`${site.origin}${site.path}`).catch(() => {});
				const landed = await waitFor(
					() => (page.url().startsWith(`${h.extensionOrigin}/blocked.html`) ? page.url() : null),
					{ timeout: 5000, message: "the redirect to blocked.html" },
				).catch(() => page.url());
				checks.contains(
					"the navigation is redirected to the extension's blocked page",
					landed,
					`${h.extensionOrigin}/blocked.html?site=gemini`,
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
				const reached = h.recorder.requests.filter(
					(r) => r.seq > mark && r.url.startsWith(site.origin),
				);
				checks.check("no request reached the blocked site", reached.length === 0, reached);
				checks.check("blocked.html has no errors", errors.length === 0, errors);
			} finally {
				await page.close().catch(() => {});
				await worker
					.evaluate(
						(id) => chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [id] }),
						RULE_ID,
					)
					.catch(() => {});
			}
		},
	},
];
