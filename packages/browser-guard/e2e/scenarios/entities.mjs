// (12) The customer-demo data set on every supported site: e-mail, Turkish mobile number,
// TCKN (checksum), spaced TR IBAN (mod-97), card number (Luhn) and three API keys
// (OpenAI-, GitHub- and AWS-shaped) are masked before the prompt leaves the browser; the
// reply that echoes the placeholders shows the originals to the user (closed shadow root),
// except secrets, which the default policy never restores (`neverRestore`).
//
// entities-<site>          typed prompt + Enter on each site fixture
// paste-entities-chatgpt   the same text pasted: the editor receives placeholders
// native-host-fallback     useNativeHost on, but no host (nativeMessaging not granted): the
//                          prompt is still masked by the in-browser rules and the user is
//                          told that the helper app could not be used

import { waitFor } from "../lib/expect.mjs";
import {
	assertNoLeaks,
	lastResponsePageText,
	lastResponseText,
	pasteText,
	readEditor,
	typePrompt,
	waitForPrompt,
	waitForResponseComplete,
} from "../lib/harness.mjs";
import { DEMO_ITEMS, DEMO_PROMPT } from "../lib/data.mjs";
import { SITES } from "../lib/sites.mjs";

const skipUnlessProductBuild = (h, data) =>
	(data?.items ?? []).length > 1 ? null : "the self-test extension masks e-mail addresses only";

function skipFor(siteKey) {
	return (h, data) =>
		skipUnlessProductBuild(h, data) ??
		(h.coversSite(siteKey) ? null : `content scripts are not declared for ${SITES[siteKey].origin}`);
}

/** Checks the sent body: no value, one placeholder per type. */
function checkMasked(checks, body, label = "sent prompt") {
	for (const item of DEMO_ITEMS) {
		checks.excludes(`${label} does not contain the ${item.type} value ${item.value.slice(0, 8)}...`, body, item.value);
		checks.contains(`${label} contains a ${item.type} placeholder`, body, item.placeholder);
	}
	const secrets = String(body).match(/\[SECRET_[1-9][0-9]*_[a-z0-9]{4}\]/g) ?? [];
	checks.equal(`${label}: each of the three keys has its own placeholder`, new Set(secrets).size, 3);
}

/** Waits until the user-visible reply shows every restorable value; returns that text. */
async function restoredReply(page, siteKey) {
	const wanted = DEMO_ITEMS.filter((i) => i.restore).map((i) => i.value);
	try {
		return await waitFor(
			async () => {
				const text = await lastResponseText(page, siteKey);
				return text && wanted.every((v) => text.includes(v)) ? text : null;
			},
			{ timeout: 6000, message: "the reply to show every restored value" },
		);
	} catch {
		return (await lastResponseText(page, siteKey)) ?? "";
	}
}

function entities(siteKey) {
	return {
		id: `entities-${siteKey}`,
		title: `demo data set on ${SITES[siteKey].siteId}: 8 identifiers masked, reply restored (secrets stay masked)`,
		settings: { mode: "auto" },
		skip: skipFor(siteKey),
		async run({ h, checks, open }) {
			const page = await open(siteKey);
			const mark = h.recorder.mark();
			await typePrompt(page, siteKey, DEMO_PROMPT);
			await page.keyboard.press("Enter");

			const sent = await waitForPrompt(h, siteKey, mark);
			checkMasked(checks, sent.json?.prompt ?? sent.raw);
			checks.contains("the rest of the prompt is sent unchanged", sent.json?.prompt ?? sent.raw, "iade yazısı hazırla");
			assertNoLeaks(
				checks,
				h,
				mark,
				DEMO_ITEMS.map((i) => i.value),
			);

			await waitForResponseComplete(page);
			const shown = await restoredReply(page, siteKey);
			for (const item of DEMO_ITEMS) {
				if (item.restore) {
					checks.contains(`the reply shows the original ${item.type} to the user`, shown, item.value);
				} else {
					checks.excludes(`the reply does not restore the ${item.type} (neverRestore)`, shown, item.value);
					checks.contains(`the reply keeps the ${item.type} placeholder`, shown, item.placeholder);
				}
			}
			const pageText = await lastResponsePageText(page, siteKey);
			for (const item of DEMO_ITEMS) {
				checks.excludes(`page scripts cannot read the ${item.type} value`, pageText, item.value);
			}
			assertNoLeaks(
				checks,
				h,
				mark,
				DEMO_ITEMS.map((i) => i.value),
				"restoring the reply sent nothing over the network",
			);
		},
	};
}

const pasteEntities = {
	id: "paste-entities-chatgpt",
	title: "paste of the demo data set on chatgpt: the editor receives placeholders only",
	settings: { mode: "auto", maskPaste: true },
	skip: skipFor("chatgpt"),
	async run({ h, checks, open }) {
		const page = await open("chatgpt");
		const mark = h.recorder.mark();
		await pasteText(page, "chatgpt", DEMO_PROMPT);
		let editorText = "";
		try {
			editorText = await waitFor(
				async () => {
					const text = await readEditor(page, "chatgpt");
					return DEMO_ITEMS.every((i) => i.placeholder.test(text)) ? text : null;
				},
				{ timeout: 4000, message: "placeholders to appear in the editor" },
			);
		} catch {
			editorText = await readEditor(page, "chatgpt");
		}
		checkMasked(checks, editorText, "editor after paste");
		await page.keyboard.press("Enter");
		const sent = await waitForPrompt(h, "chatgpt", mark);
		checkMasked(checks, sent.json?.prompt ?? sent.raw);
		assertNoLeaks(
			checks,
			h,
			mark,
			DEMO_ITEMS.map((i) => i.value),
		);
	},
};

const nativeFallback = {
	id: "native-host-fallback",
	title: "useNativeHost without a reachable host: rules-only masking, and the user is told",
	settings: { mode: "auto", useNativeHost: true },
	skip: skipUnlessProductBuild,
	async run({ h, checks, open }) {
		try {
			const policy = await h.getPolicy();
			checks.equal("the native host is enabled in the effective policy", policy.useNativeHost, true);
			const page = await open("chatgpt");
			const baseline = await h.overlays(page, "chatgpt");
			const mark = h.recorder.mark();
			await typePrompt(page, "chatgpt", DEMO_PROMPT);
			await page.keyboard.press("Enter");
			// The page waits for the host (at most 2.5 s) before it falls back to the rules.
			const sent = await waitForPrompt(h, "chatgpt", mark, 10_000);
			checkMasked(checks, sent.json?.prompt ?? sent.raw);
			assertNoLeaks(
				checks,
				h,
				mark,
				DEMO_ITEMS.map((i) => i.value),
			);
			const notice = await waitFor(
				async () => {
					const overlays = await h.overlays(page, "chatgpt");
					return overlays.find((o) => !baseline.includes(o) && /built-in rules only/i.test(o)) ?? null;
				},
				{ timeout: 4000, message: "the rules-only notice" },
			).catch(() => null);
			checks.check("the user is told the helper app could not be used (rules only)", notice, {
				overlays: await h.overlays(page, "chatgpt"),
			});
		} finally {
			await h.setUserSettings({ useNativeHost: false });
		}
	},
};

export default [
	...["chatgpt", "gemini", "claude", "copilot", "perplexity", "deepseek", "mistral", "grok"].map(entities),
	pasteEntities,
	nativeFallback,
];
