// (9) Text without findings passes unchanged; (10) Shift+Enter never sends.

import { CLEAN_PROMPT } from "../lib/data.mjs";
import { staysFalse } from "../lib/expect.mjs";
import { readEditor, typePrompt, waitForPrompt } from "../lib/harness.mjs";

function cleanPrompt(siteKey) {
	return {
		id: `clean-${siteKey}`,
		title: `no findings on ${siteKey}: prompt is sent byte-for-byte`,
		settings: { mode: "auto" },
		async run({ h, checks, open }) {
			const page = await open(siteKey);
			const mark = h.recorder.mark();
			await typePrompt(page, siteKey, CLEAN_PROMPT);
			await page.keyboard.press("Enter");
			const sent = await waitForPrompt(h, siteKey, mark);
			checks.equal("sent prompt is unchanged", sent.json?.prompt, CLEAN_PROMPT);
			checks.equal(
				"exactly one prompt request",
				h.recorder.apiSince(mark, { kind: "prompt" }).length,
				1,
			);
		},
	};
}

function shiftEnter(siteKey) {
	return {
		id: `shift-enter-${siteKey}`,
		title: `Shift+Enter on ${siteKey} inserts a newline and does not send`,
		settings: { mode: "auto" },
		async run({ h, checks, open }) {
			const page = await open(siteKey);
			const mark = h.recorder.mark();
			await typePrompt(page, siteKey, "first line");
			await page.keyboard.press("Shift+Enter");
			await page.keyboard.type("second line");

			let quiet = true;
			await staysFalse(() => h.recorder.apiSince(mark, { kind: "prompt" }).length > 0, {
				window: 1000,
				message: "a prompt request after Shift+Enter",
			}).catch(() => {
				quiet = false;
			});
			checks.check("Shift+Enter did not send", quiet, h.recorder.apiSince(mark));
			checks.equal(
				"editor holds both lines",
				await readEditor(page, siteKey),
				"first line\nsecond line",
			);

			await page.keyboard.press("Enter");
			const sent = await waitForPrompt(h, siteKey, mark);
			checks.equal(
				"Enter then sends both lines unchanged",
				sent.json?.prompt,
				"first line\nsecond line",
			);
		},
	};
}

export default [
	cleanPrompt("chatgpt"),
	cleanPrompt("gemini"),
	shiftEnter("chatgpt"),
	shiftEnter("copilot"),
];
