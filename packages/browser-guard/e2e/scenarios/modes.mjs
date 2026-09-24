// (4) monitor, (5) block and (6) confirm modes.

import { staysFalse, waitFor } from "../lib/expect.mjs";
import { assertNoLeaks, readEditor, typePrompt, waitForPrompt } from "../lib/harness.mjs";

const SITE = "chatgpt";

/** Waits for an extension overlay that was not on screen in `baseline`. */
async function waitForNewOverlay(h, page, baseline) {
	const before = new Set(baseline);
	return waitFor(
		async () => {
			const now = await h.overlays(page, SITE);
			const added = now.filter((o) => !before.has(o));
			return added.length > 0 ? added : null;
		},
		{ timeout: 4000, message: "an in-page Browser Guard bubble to appear" },
	).catch(() => null);
}

const monitor = {
	id: "mode-monitor",
	title: "monitor mode: original prompt is sent unchanged",
	settings: { mode: "monitor" },
	async run({ h, checks, data, open }) {
		const page = await open(SITE);
		const mark = h.recorder.mark();
		await typePrompt(page, SITE, data.prompt);
		await page.keyboard.press("Enter");
		const sent = await waitForPrompt(h, SITE, mark);
		const body = sent.json?.prompt ?? sent.raw;
		checks.equal("sent prompt equals what the user typed", body, data.prompt);
		for (const item of data.items) {
			checks.contains(`sent prompt keeps the ${item.type} value`, body, item.value);
		}
	},
};

const block = {
	id: "mode-block",
	title: "block mode: nothing is sent and a bubble explains why",
	settings: { mode: "block" },
	async run({ h, checks, data, open }) {
		const page = await open(SITE);
		const baseline = await h.overlays(page, SITE);
		const mark = h.recorder.mark();
		await typePrompt(page, SITE, data.prompt);
		await page.keyboard.press("Enter");

		const added = await waitForNewOverlay(h, page, baseline);
		checks.check("an in-page bubble is visible after Enter", added, await h.overlays(page, SITE));

		let quiet = true;
		await staysFalse(() => h.recorder.apiSince(mark, { kind: "prompt" }).length > 0, {
			window: 1500,
			message: "a prompt request",
		}).catch(() => {
			quiet = false;
		});
		checks.check("Enter did not send the prompt", quiet, h.recorder.apiSince(mark));

		// Clicking the send button is blocked as well.
		await page
			.locator('button[data-testid="send-button"]')
			.click({ timeout: 2000, force: true })
			.catch(() => {});
		quiet = true;
		await staysFalse(() => h.recorder.apiSince(mark, { kind: "prompt" }).length > 0, {
			window: 1000,
			message: "a prompt request after clicking send",
		}).catch(() => {
			quiet = false;
		});
		checks.check(
			"clicking the send button did not send the prompt",
			quiet,
			h.recorder.apiSince(mark),
		);
		checks.equal(
			"page never issued its send()",
			await page.evaluate(() => window.__fixture.sends.length),
			0,
		);
		assertNoLeaks(
			checks,
			h,
			mark,
			data.items.map((i) => i.value),
		);
		const editor = await readEditor(page, SITE);
		checks.check(
			"the prompt stays in the editor for the user to edit",
			editor.trim().length > 0,
			editor,
		);
	},
};

const confirm = {
	id: "mode-confirm",
	title: 'confirm mode: bubble, then "Send masked" sends placeholders',
	settings: { mode: "confirm" },
	async run({ h, checks, data, open }) {
		const page = await open(SITE);
		const baseline = await h.overlays(page, SITE);
		const mark = h.recorder.mark();
		await typePrompt(page, SITE, data.prompt);
		await page.keyboard.press("Enter");

		const added = await waitForNewOverlay(h, page, baseline);
		checks.must(
			"a confirmation bubble is visible after Enter",
			added,
			await h.overlays(page, SITE),
		);
		let quiet = true;
		await staysFalse(() => h.recorder.apiSince(mark, { kind: "prompt" }).length > 0, {
			window: 800,
			message: "a prompt request before confirming",
		}).catch(() => {
			quiet = false;
		});
		checks.check("nothing is sent before the user decides", quiet, h.recorder.apiSince(mark));

		// The bubble is in a closed shadow root: the button is found in the
		// accessibility tree and clicked with the mouse. English UI (--lang=en-US).
		const clicked = await waitFor(
			() => h.clickOverlayButton(page, /^(send masked|maskeli g[öo]nder)$/i),
			{ timeout: 3000, message: '"Send masked" button' },
		).catch(() => false);
		checks.must(
			'the bubble offers a "Send masked" button',
			clicked,
			await h.overlays(page, SITE),
		);

		const sent = await waitForPrompt(h, SITE, mark);
		const body = sent.json?.prompt ?? sent.raw;
		for (const item of data.items) {
			checks.excludes(`sent prompt does not contain the ${item.type} value`, body, item.value);
			checks.contains(`sent prompt contains a ${item.type} placeholder`, body, item.placeholder);
		}
		checks.equal(
			"exactly one prompt request",
			h.recorder.apiSince(mark, { kind: "prompt" }).length,
			1,
		);
		assertNoLeaks(
			checks,
			h,
			mark,
			data.items.map((i) => i.value),
		);
	},
};

export default [monitor, block, confirm];
