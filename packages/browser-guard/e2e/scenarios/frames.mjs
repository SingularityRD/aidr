// Microsoft 365 Copilot pane inside an Office web app: the pane is a cross-origin iframe
// on a Microsoft 365 Copilot host (fixtures/m365-copilot-pane.html at
// https://copilot.cloud.microsoft) embedded by an Office page (fixtures/office-word.html at
// https://word-edit.officeapps.live.com). The extension declares content scripts with
// `all_frames: true` for the Microsoft 365 Copilot hosts only (src/sites/frames.ts), so:
// - the pane frame gets the content script, the Office page does not;
// - a prompt typed into the pane leaves the browser with placeholders only, and the reply
//   in the pane shows the original to the user while the pane's own innerText keeps the
//   placeholder;
// - the Office page's own comment box is not touched (control: sent as typed).

import { waitFor } from "../lib/expect.mjs";
import {
	assertNoLeaks,
	lastResponseText,
	waitForPrompt,
	withCdp,
} from "../lib/harness.mjs";
import { SITES } from "../lib/sites.mjs";

const PANE = SITES.m365pane;
const OFFICE = SITES.office;

/**
 * Whether the manifest runs content.js in subframes of the pane's origin. For the product
 * build this is a check, not a skip condition: a manifest that drops the frame entry fails.
 */
function coversPaneFrames(h) {
	return (h.manifest.content_scripts ?? []).some(
		(cs) =>
			cs.all_frames === true &&
			cs.js?.includes("content.js") &&
			(cs.matches ?? []).includes(`${PANE.origin}/*`),
	);
}

/**
 * Frame ids that host an extension content-script world, as seen by a CDP session on
 * `target`. A cross-site iframe runs out of process under site isolation and has its own
 * session; should it share its parent's process, the page session reports its worlds too.
 */
async function extensionWorldFrames(h, target) {
	return withCdp(target, (cdp) => worlds(h, cdp)).catch(() =>
		withCdp(target.page(), (cdp) => worlds(h, cdp)),
	);
}

async function worlds(h, cdp) {
	const frames = new Set();
	cdp.on("Runtime.executionContextCreated", ({ context }) => {
		if (String(context.origin ?? "").startsWith(h.extensionOrigin))
			frames.add(context.auxData?.frameId ?? "?");
	});
	// Enabling replays every existing execution context before it returns.
	await cdp.send("Runtime.enable");
	const { frameTree } = await cdp.send("Page.getFrameTree");
	await cdp.send("Runtime.disable").catch(() => {});
	return { frames, rootFrameId: frameTree.frame.id };
}

async function paneFrame(page) {
	return waitFor(
		async () => {
			const frame = page.frames().find((f) => f.url().startsWith(`${PANE.origin}/`));
			if (!frame) return null;
			const ready = await frame
				.evaluate(() => document.documentElement.getAttribute("data-fixture-ready"))
				.catch(() => null);
			return ready ? frame : null;
		},
		{ timeout: 8000, message: "the Copilot pane iframe to load" },
	);
}

async function readFrameEditor(frame) {
	return frame.evaluate(
		({ sel, kind }) => window.FixtureChat.readEditor(document.querySelector(sel), kind),
		{ sel: PANE.editor, kind: PANE.kind },
	);
}

export default [
	{
		id: "frame-copilot-office",
		title: "Copilot pane iframe inside an Office web app: masked on Enter, Office page untouched",
		settings: { mode: "auto" },
		// Frame coverage is product behaviour the self-test extension (top frame only) lacks.
		skip: (_h, data) =>
			(data?.items ?? []).some((i) => i.type === "TC_KIMLIK")
				? null
				: "product feature (subframe coverage) not implemented by the self-test extension",
		async run({ h, checks, data, open }) {
			checks.check(
				`the manifest runs content.js in subframes of ${PANE.origin} (all_frames)`,
				coversPaneFrames(h),
				h.manifest.content_scripts,
			);
			const page = await open("office", { expectContentScript: false });
			const frame = await paneFrame(page);

			// The content script runs in the pane frame, and not in the Office page.
			const pane = await waitFor(
				async () => {
					const seen = await extensionWorldFrames(h, frame);
					return seen.frames.size > 0 ? seen : null;
				},
				{ timeout: 8000, message: "the content script to be injected into the Copilot pane frame" },
			);
			checks.check("the content script runs in the Copilot pane frame", pane.frames.size > 0);
			const top = await extensionWorldFrames(h, page);
			checks.check(
				"no content script runs in the Office page's own frame",
				!top.frames.has(top.rootFrameId),
				[...top.frames],
			);
			// Give the content script's start-up (GET_POLICY round trip) a moment.
			await page.waitForTimeout(300);

			// 1. A prompt typed into the pane leaves with placeholders only.
			const mark = h.recorder.mark();
			await frame.locator(PANE.editor).click();
			const lines = data.prompt.split("\n");
			for (let i = 0; i < lines.length; i += 1) {
				if (i > 0) await page.keyboard.press("Shift+Enter");
				if (lines[i]) await page.keyboard.type(lines[i]);
			}
			await waitFor(async () => (await readFrameEditor(frame)).includes(lines.at(-1)), {
				timeout: 3000,
				message: "typed text to appear in the pane editor",
			});
			await page.keyboard.press("Enter");

			const sent = await waitForPrompt(h, "m365pane", mark);
			const body = sent.json?.prompt ?? sent.raw;
			checks.equal(
				"exactly one prompt request from the pane for one Enter",
				h.recorder.apiSince(mark, { site: PANE.siteId, kind: "prompt" }).length,
				1,
			);
			for (const item of data.items) {
				checks.excludes(`pane prompt does not contain the ${item.type} value`, body, item.value);
				checks.contains(`pane prompt contains a ${item.type} placeholder`, body, item.placeholder);
			}
			assertNoLeaks(
				checks,
				h,
				mark,
				data.items.map((i) => i.value),
			);

			// 2. The reply in the pane is restored for the user only.
			await waitFor(() => frame.locator("[data-fixture-complete]").count(), {
				timeout: 8000,
				message: "the pane's response to finish streaming",
			});
			const email = data.items.find((i) => i.type === "EMAIL");
			let shown = null;
			try {
				shown = await waitFor(
					async () => {
						const text = await lastResponseText(frame, "m365pane");
						return text?.includes(email.value) ? text : null;
					},
					{ timeout: 5000, message: "the pane reply to show the restored email" },
				);
			} catch {
				shown = await lastResponseText(frame, "m365pane").catch(() => null);
			}
			checks.contains("pane reply is restored locally (shows the original email)", shown, email.value);
			const pageText = await frame.evaluate((sel) => {
				const nodes = document.querySelectorAll(sel);
				return nodes[nodes.length - 1]?.innerText ?? null;
			}, PANE.response);
			checks.contains("the pane's own scripts still read the placeholder", pageText, email.placeholder);
			checks.excludes("the pane's own scripts cannot read the restored email", pageText, email.value);

			// 3. Control: the Office page itself is not a protected site; its comment box is
			// sent as typed (the guard does not run on, or block, the Office app).
			const officeMark = h.recorder.mark();
			await page.locator(OFFICE.editor).click();
			await page.keyboard.type(`Comment for ${email.value}`);
			await page.locator(OFFICE.send).click();
			const comment = await waitForPrompt(h, "office", officeMark);
			checks.contains(
				"the Office page's own field is untouched (control)",
				comment.json?.prompt ?? comment.raw,
				email.value,
			);
		},
	},
];
