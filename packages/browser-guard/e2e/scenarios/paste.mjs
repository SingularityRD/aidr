// (3) Paste: sensitive text pasted into the composer lands as placeholders.

import { waitFor } from "../lib/expect.mjs";
import { assertNoLeaks, pasteText, readEditor, waitForPrompt } from "../lib/harness.mjs";

function paste(siteKey) {
	return {
		id: `paste-${siteKey}`,
		title: `paste on ${siteKey}: editor receives placeholders`,
		settings: { mode: "auto", maskPaste: true },
		async run({ h, checks, data, open }) {
			const page = await open(siteKey);
			const mark = h.recorder.mark();
			await pasteText(page, siteKey, data.pasteText);

			let editorText = "";
			try {
				editorText = await waitFor(
					async () => {
						const text = await readEditor(page, siteKey);
						return data.pasteItems.every((i) => i.placeholder.test(text)) ? text : null;
					},
					{ timeout: 4000, message: "placeholders to appear in the editor" },
				);
			} catch {
				editorText = await readEditor(page, siteKey);
			}
			for (const item of data.pasteItems) {
				checks.contains(`editor shows a ${item.type} placeholder`, editorText, item.placeholder);
				checks.excludes(
					`editor does not show the pasted ${item.type} value`,
					editorText,
					item.value,
				);
			}
			checks.contains("the rest of the pasted text is kept", editorText, "Customer record:");

			await page.keyboard.press("Enter");
			const sent = await waitForPrompt(h, siteKey, mark);
			for (const item of data.pasteItems) {
				checks.excludes(
					`sent prompt does not contain the pasted ${item.type} value`,
					sent.json?.prompt ?? sent.raw,
					item.value,
				);
			}
			assertNoLeaks(
				checks,
				h,
				mark,
				data.pasteItems.map((i) => i.value),
			);
		},
	};
}

export default [paste("chatgpt"), paste("copilot")];
