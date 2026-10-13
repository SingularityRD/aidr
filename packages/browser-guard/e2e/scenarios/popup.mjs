// (8) Policy via local settings + popup: the effective policy reflects the
// user's settings (no managed policy in this profile, so nothing is locked) and
// the popup renders the status and the protection statistics.
//
// chrome.storage.managed cannot be written from a test; managed-policy locking
// is covered by the background/policy unit tests (mergePolicy).

import { waitFor } from "../lib/expect.mjs";
import { typePrompt, waitForPrompt } from "../lib/harness.mjs";

const MODE_LABELS = {
	auto: /auto|otomatik/i,
	confirm: /ask me|bana sor/i,
	block: /block|engel/i,
	monitor: /count only|yalnızca say/i,
};

export default [
	{
		id: "popup-status",
		title: "local settings drive the policy; popup renders status and stats",
		settings: { mode: "auto" },
		async run({ h, checks, data, open }) {
			// Produce at least one protected prompt so the stats are non-zero.
			const site = await open("chatgpt");
			const mark = h.recorder.mark();
			await typePrompt(site, "chatgpt", data.prompt);
			await site.keyboard.press("Enter");
			await waitForPrompt(h, "chatgpt", mark);

			const stats = await waitFor(
				async () => {
					const s = await h.getStats();
					return s && s.protectedPrompts >= 1 ? s : null;
				},
				{ timeout: 5000, message: "GET_STATS to count the protected prompt" },
			).catch(async () => h.getStats().catch((e) => ({ error: e.message })));
			checks.check("GET_STATS counts the protected prompt", stats?.protectedPrompts >= 1, stats);
			checks.check("GET_STATS counts masked items", stats?.maskedItems >= data.items.length, stats);

			const policy = await h.getPolicy();
			checks.equal("effective policy mode comes from local settings", policy?.mode, "auto");
			checks.check(
				"no key is locked without a managed policy",
				Array.isArray(policy?.managedKeys) && policy.managedKeys.length === 0,
				policy?.managedKeys,
			);

			for (const mode of ["confirm", "auto"]) {
				await h.setUserSettings({ mode });
				// The toolbar popup reports on the ACTIVE tab (chrome.tabs.query). Opened as a
				// tab it would be the active tab itself, so load it in a background tab while
				// the ChatGPT tab is in front, as when the user clicks the toolbar icon there.
				const popup = await h.context.newPage();
				const errors = [];
				popup.on("pageerror", (e) => errors.push(String(e.message ?? e)));
				await site.bringToFront();
				await popup.goto(`${h.extensionOrigin}/${h.popupPath}`, { waitUntil: "load" });
				const text = await waitFor(
					async () => {
						const t = await popup.evaluate(() => document.body?.innerText ?? "");
						return MODE_LABELS[mode].test(t) && /\b[1-9]\d*\b/.test(t) ? t : null;
					},
					{ timeout: 5000, message: `popup to render mode "${mode}" and stats` },
				).catch(() => popup.evaluate(() => document.body?.innerText ?? ""));
				checks.check(`popup renders (mode ${mode})`, text.trim().length > 0, text);
				checks.contains(`popup shows the current mode (${mode})`, text, MODE_LABELS[mode]);
				checks.contains(
					`popup reports the active ChatGPT tab as protected (mode ${mode})`,
					text,
					/data you send to ChatGPT/i,
				);
				checks.contains(
					`popup shows non-zero protection stats (mode ${mode})`,
					text,
					/\b[1-9]\d*\b/,
				);
				checks.check(`popup has no uncaught errors (mode ${mode})`, errors.length === 0, errors);
				await popup.close();
			}
		},
	},
];
