// (1)(2) Auto mode: the prompt leaves the browser with placeholders only and
// the assistant's reply is restored locally in the page.

import { waitFor } from "../lib/expect.mjs";
import {
	assertNoLeaks,
	lastResponsePageText,
	lastResponseText,
	readEditor,
	typePrompt,
	waitForPrompt,
	waitForResponseComplete,
} from "../lib/harness.mjs";
import { SITES } from "../lib/sites.mjs";

function autoMask(siteKey) {
	return {
		id: `auto-${siteKey}`,
		title: `auto mode on ${SITES[siteKey].siteId} (${SITES[siteKey].kind}): mask on Enter, restore reply`,
		settings: { mode: "auto" },
		skip: (h) =>
			h.coversSite(siteKey)
				? null
				: `content scripts are not declared for ${SITES[siteKey].origin}`,
		async run({ h, checks, data, open }) {
			const page = await open(siteKey);
			const mark = h.recorder.mark();
			await typePrompt(page, siteKey, data.prompt);
			await page.keyboard.press("Enter");

			const sent = await waitForPrompt(h, siteKey, mark);
			const body = sent.json?.prompt ?? sent.raw;
			checks.equal(
				"exactly one prompt request for one Enter",
				h.recorder.apiSince(mark, { kind: "prompt" }).length,
				1,
			);
			for (const item of data.items) {
				checks.excludes(`sent prompt does not contain the ${item.type} value`, body, item.value);
				checks.contains(`sent prompt contains a ${item.type} placeholder`, body, item.placeholder);
			}
			assertNoLeaks(
				checks,
				h,
				mark,
				data.items.map((i) => i.value),
			);

			await waitForResponseComplete(page);
			const email = data.items.find((i) => i.type === "EMAIL");
			let shown = null;
			try {
				shown = await waitFor(
					async () => {
						const text = await lastResponseText(page, siteKey);
						return text?.includes(email.value) ? text : null;
					},
					{ timeout: 5000, message: "the reply to show the restored email" },
				);
			} catch {
				shown = await lastResponseText(page, siteKey);
			}
			checks.contains(
				"assistant reply is restored locally (shows the original email)",
				shown,
				email.value,
			);
			checks.excludes(
				"assistant reply no longer shows the email placeholder",
				shown,
				email.placeholder,
			);
			// The original is shown to the user only: the page's own scripts (innerText,
			// used by copy/edit actions and analytics) still read the placeholder.
			const pageText = await lastResponsePageText(page, siteKey);
			checks.contains("page scripts still read the email placeholder", pageText, email.placeholder);
			checks.excludes("page scripts cannot read the restored email", pageText, email.value);
			checks.equal("editor is empty after the send",(await readEditor(page, siteKey)).trim(), "");
			// The restore happened in the page only: nothing after the reply carried the value either.
			assertNoLeaks(
				checks,
				h,
				mark,
				[email.value],
				"restoring the reply sent nothing over the network",
			);
		},
	};
}

export default [
	"chatgpt",
	"gemini",
	"claude",
	"copilot",
	"perplexity",
	"deepseek",
	"mistral",
	"grok",
	"generic",
].map(autoMask);
