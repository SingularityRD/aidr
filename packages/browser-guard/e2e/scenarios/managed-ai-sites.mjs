// (10) Administrator-managed AI sites, in a second browser whose extension copy carries
// the enterprise policy and the user's host-access grant (lib/managed-deployment.mjs):
//
// custom-site  a company-internal AI portal (https://ai.internal.example) configured
//              with managed `customSites`: the worker registers content.js for the
//              granted host (chrome.scripting), the page is masked on a click of its own
//              send button and the reply is restored in its own response blocks - both
//              recognised only through the policy's selectors.
// shadow-ai    managed `shadowAi` block-unsanctioned: an unsanctioned catalogued
//              service (https://poe.com) is refused by the product's DNR rule and the tab
//              lands on blocked.html?service=poe; a sanctioned one opens and is counted.
//              Only service ids and counts are stored, never URLs.

import fs from "node:fs";
import path from "node:path";
import { waitFor } from "../lib/expect.mjs";
import {
	assertNoLeaks,
	lastResponsePageText,
	lastResponseText,
	launch,
	readEditor,
	typePrompt,
	waitForPrompt,
	waitForResponseComplete,
} from "../lib/harness.mjs";
import { createManagedDeployment } from "../lib/managed-deployment.mjs";
import { SITES } from "../lib/sites.mjs";

const INTERNAL_ORIGIN = "https://ai.internal.example/*";
const POE_ORIGIN = "https://poe.com/*";

const MANAGED_POLICY = {
	policyId: "e2e-managed-ai-sites",
	customSites: [
		{
			id: "corp-gpt",
			label: "Corp GPT",
			hosts: ["ai.internal.example"],
			editorSelectors: ["#corp-composer"],
			sendButtonSelectors: [".corp-send"],
			responseSelectors: [".corp-answer"],
		},
	],
	shadowAi: {
		mode: "block-unsanctioned",
		sanctioned: [
			"chatgpt",
			"gemini",
			"claude",
			"copilot",
			"perplexity",
			"deepseek",
			"mistral",
			"grok",
		],
	},
};

const skipUnlessProductBuild = (h) =>
	(h.manifest.permissions ?? []).includes("scripting")
		? null
		: "the extension does not register content scripts for custom sites (no scripting permission)";

/** Launches the managed deployment, runs `fn` with its harness, always cleans up. */
async function withManagedBrowser(h, fn) {
	const dir = createManagedDeployment(h.extDir, {
		managedPolicy: MANAGED_POLICY,
		grantedOrigins: [INTERNAL_ORIGIN, POE_ORIGIN],
	});
	let managed;
	try {
		managed = await launch({ extDir: dir });
		return await fn(managed);
	} finally {
		await managed?.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

async function managedPolicy(m) {
	return waitFor(
		async () => {
			const policy = await m.getPolicy().catch(() => null);
			return policy?.customSites?.length ? policy : null;
		},
		{ timeout: 10_000, message: "the managed policy to be in force" },
	);
}

async function siteAccess(m) {
	const res = await m.sendMessage({ type: "GET_SITE_ACCESS" });
	return res.ok ? res.value?.access : null;
}

export default [
	{
		id: "custom-site",
		title: "an internal AI portal from managed customSites is masked after host access is granted",
		skip: skipUnlessProductBuild,
		async run({ h, checks, data }) {
			await withManagedBrowser(h, async (m) => {
				checks.check(
					"the static content scripts do not cover the internal host",
					!m.coversSite("internal"),
					m.manifest.content_scripts,
				);
				const policy = await managedPolicy(m);
				checks.equal("the custom site is in the effective policy", policy.customSites[0]?.id, "corp-gpt");
				checks.check(
					"customSites is locked by the administrator",
					policy.managedKeys.includes("customSites"),
					policy.managedKeys,
				);

				const worker = await m.currentWorker();
				const registered = await waitFor(
					async () => {
						const scripts = await worker.evaluate(() =>
							chrome.scripting.getRegisteredContentScripts(),
						);
						return scripts.find((s) => (s.matches ?? []).includes(INTERNAL_ORIGIN)) ?? null;
					},
					{ timeout: 8000, message: "content.js to be registered for the custom host" },
				).catch(() => null);
				checks.equal(
					"content.js is registered for exactly the granted custom host",
					JSON.stringify(registered?.matches),
					JSON.stringify([INTERNAL_ORIGIN]),
				);
				checks.equal(
					"the registered script is the product content script",
					JSON.stringify(registered?.js),
					JSON.stringify(["content.js"]),
				);
				const access = await siteAccess(m);
				checks.check(
					"the options-page status reports the site as granted and active",
					access?.customSites?.[0]?.granted === true && access.customSites[0].active === true,
					access?.customSites,
				);

				const page = await m.openSite("internal");
				const mark = m.recorder.mark();
				await typePrompt(page, "internal", data.prompt);
				// The portal's own button: only the policy's sendButtonSelectors identify it.
				await page.locator(SITES.internal.send).click();
				const sent = await waitForPrompt(m, "internal", mark);
				const body = sent.json?.prompt ?? sent.raw;
				checks.equal(
					"exactly one prompt request for one click",
					m.recorder.apiSince(mark, { kind: "prompt" }).length,
					1,
				);
				for (const item of data.items) {
					checks.excludes(`sent prompt does not contain the ${item.type} value`, body, item.value);
					checks.contains(`sent prompt contains a ${item.type} placeholder`, body, item.placeholder);
				}
				assertNoLeaks(
					checks,
					m,
					mark,
					data.items.map((i) => i.value),
				);

				await waitForResponseComplete(page);
				const email = data.items.find((i) => i.type === "EMAIL");
				const shown = await waitFor(
					async () => {
						const text = await lastResponseText(page, "internal");
						return text?.includes(email.value) ? text : null;
					},
					{ timeout: 5000, message: "the reply to show the restored email" },
				).catch(() => lastResponseText(page, "internal"));
				checks.contains(
					"the reply in the portal's .corp-answer block is restored locally",
					shown,
					email.value,
				);
				const pageText = await lastResponsePageText(page, "internal");
				checks.contains("page scripts still read the email placeholder", pageText, email.placeholder);
				checks.excludes("page scripts cannot read the restored email", pageText, email.value);
				checks.equal("editor is empty after the send", (await readEditor(page, "internal")).trim(), "");
				const stats = await m.getStats();
				checks.check("the send is counted as masked", stats?.maskedItems > 0, stats);
				await page.close().catch(() => {});
			});
		},
	},
	{
		id: "shadow-ai",
		title: "Shadow AI block-unsanctioned: an unsanctioned AI service is blocked, visits are counted",
		skip: (h) =>
			skipUnlessProductBuild(h) ??
			(fs.existsSync(path.join(h.extDir, "blocked.html"))
				? null
				: "the build does not ship blocked.html"),
		async run({ h, checks }) {
			await withManagedBrowser(h, async (m) => {
				await managedPolicy(m);
				const worker = await m.currentWorker();
				const rules = await waitFor(
					async () => {
						const list = await worker.evaluate(() =>
							chrome.declarativeNetRequest.getDynamicRules(),
						);
						return list.some((r) => r.condition.requestDomains?.includes("poe.com")) ? list : null;
					},
					{ timeout: 8000, message: "the Shadow AI block rules" },
				).catch(() => []);
				checks.check(
					"an unsanctioned service (poe.com) has a navigation block rule",
					rules.some(
						(r) =>
							r.action.type === "block" &&
							r.condition.requestDomains?.includes("poe.com") &&
							r.condition.resourceTypes.includes("main_frame"),
					),
					rules.map((r) => r.condition.requestDomains),
				);
				checks.check(
					"sanctioned services have no block rule",
					!rules.some((r) => r.condition.requestDomains?.includes("chatgpt.com")),
					rules.map((r) => r.condition.requestDomains),
				);

				// A sanctioned catalogued service opens normally (and is counted).
				const allowed = await m.openSite("perplexity");
				checks.contains("a sanctioned AI service opens", allowed.url(), /^https:\/\/www\.perplexity\.ai\//);
				await allowed.close().catch(() => {});

				const page = await m.context.newPage();
				const finished = [];
				const failed = [];
				page.on("requestfinished", (r) => {
					if (r.url().startsWith(SITES.poe.origin)) finished.push(r.url());
				});
				page.on("requestfailed", (r) => {
					if (r.url().startsWith(SITES.poe.origin))
						failed.push({ url: r.url(), error: r.failure()?.errorText ?? "" });
				});
				try {
					await page.goto(`${SITES.poe.origin}/chat/some-conversation?ref=e2e`).catch(() => {});
					const landed = await waitFor(
						() => (page.url().includes("/blocked.html") ? page.url() : null),
						{ timeout: 8000, message: "the redirect to blocked.html" },
					).catch(() => page.url());
					checks.contains(
						"the navigation ends on the extension's blocked page for the service",
						landed,
						/^chrome-extension:\/\/[^/]+\/blocked\.html\?service=poe$/,
					);
					await page.waitForLoadState("load").catch(() => {});
					const heading = await waitFor(
						async () => {
							const text = await page
								.evaluate(() => document.getElementById("blocked-title")?.textContent ?? "")
								.catch(() => "");
							return /Poe/.test(text) ? text : null;
						},
						{ timeout: 5000, message: "blocked.html to name the service" },
					).catch(() => null);
					checks.contains("the page names the blocked service", heading, /Poe is blocked/);
					checks.check("no request reached the blocked service", finished.length === 0, finished);
					checks.check(
						"the browser refused the navigation (ERR_BLOCKED_BY_CLIENT)",
						failed.length > 0 && failed.every((f) => /BLOCKED_BY_CLIENT/.test(f.error)),
						failed,
					);
				} finally {
					await page.close().catch(() => {});
				}

				const access = await waitFor(
					async () => {
						const status = await siteAccess(m);
						const usage = status?.shadowAi?.usage ?? [];
						const poe = usage.find((u) => u.serviceId === "poe");
						const pplx = usage.find((u) => u.serviceId === "perplexity");
						return poe?.blocked > 0 && pplx?.visited > 0 ? status : null;
					},
					{ timeout: 5000, message: "the Shadow AI counts" },
				).catch(() => siteAccess(m));
				const usage = access?.shadowAi?.usage ?? [];
				checks.check(
					"the blocked attempt is counted for poe",
					usage.some((u) => u.serviceId === "poe" && u.blocked > 0),
					usage,
				);
				checks.check(
					"the sanctioned visit is counted for perplexity",
					usage.some((u) => u.serviceId === "perplexity" && u.visited > 0),
					usage,
				);
				checks.check(
					"host access still missing for other catalogued services is reported, not hidden",
					(access?.shadowAi?.missingOrigins ?? []).includes("https://www.midjourney.com/*") &&
						!(access?.shadowAi?.missingOrigins ?? []).includes(POE_ORIGIN),
					access?.shadowAi?.missingOrigins?.length,
				);
				const stored = await (await m.currentWorker()).evaluate(async () =>
					JSON.stringify(await chrome.storage.local.get("shadowAiUsage")),
				);
				checks.check(
					"only service ids and counts are stored (no URL, host or path)",
					!/https?:|poe\.com|perplexity\.ai|some-conversation/.test(stored),
					stored,
				);
			});
		},
	},
];
