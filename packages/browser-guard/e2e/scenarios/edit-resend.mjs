// Edit-and-resend (GA audit BG-1): editing a sent message and pressing the edit form's
// own "Send" button (no data-testid, no aria-label) must be checked like any other send.

import {
	assertNoLeaks,
	typePrompt,
	waitForPrompt,
	waitForResponseComplete,
} from "../lib/harness.mjs";
import { CLEAN_PROMPT } from "../lib/data.mjs";
import { SITES } from "../lib/sites.mjs";

const USER_TURN = '[data-message-author-role="user"]';

function editResend(siteKey) {
	return {
		id: `edit-resend-${siteKey}`,
		title: `edit a sent message on ${siteKey} and press the edit form's Send: masked before it leaves`,
		settings: { mode: "auto" },
		skip: (h) =>
			h.coversSite(siteKey)
				? null
				: `content scripts are not declared for ${SITES[siteKey].origin}`,
		async run({ h, checks, data, open }) {
			const page = await open(siteKey);
			let mark = h.recorder.mark();
			await typePrompt(page, siteKey, CLEAN_PROMPT);
			await page.keyboard.press("Enter");
			await waitForPrompt(h, siteKey, mark);
			await waitForResponseComplete(page);

			const turn = page.locator(USER_TURN).last();
			await turn.locator('button[aria-label="Edit message"]').click();
			const area = turn.locator("textarea");
			await area.fill(data.prompt);

			mark = h.recorder.mark();
			await turn.locator("button.btn-primary").click();
			const sent = await waitForPrompt(h, siteKey, mark);
			const body = sent.json?.prompt ?? sent.raw;
			checks.equal("the edited prompt was sent", sent.json?.edit, true);
			checks.equal(
				"exactly one prompt request for one click",
				h.recorder.apiSince(mark, { kind: "prompt" }).length,
				1,
			);
			for (const item of data.items) {
				checks.excludes(`edited prompt does not contain the ${item.type} value`, body, item.value);
				checks.contains(`edited prompt contains a ${item.type} placeholder`, body, item.placeholder);
			}
			assertNoLeaks(
				checks,
				h,
				mark,
				data.items.map((i) => i.value),
			);
		},
	};
}

export default [editResend("chatgpt")];
