// (11) The placeholder mapping survives a page reload.
//
// The content script mirrors its vault (and the placeholders sent from the tab) to the
// service worker, which keeps it in chrome.storage.session under vault:<tab>:<origin>.
// After a reload the fixture re-renders the conversation like an SPA; the reply that
// carries the placeholder must show the original to the user again, while the page
// itself still reads the placeholder. Another tab never gets this tab's mapping, and
// closing the tab removes it.

import { waitFor } from "../lib/expect.mjs";
import {
	assertNoLeaks,
	lastResponsePageText,
	lastResponseText,
	typePrompt,
	waitForPrompt,
	waitForResponseComplete,
} from "../lib/harness.mjs";
import { SITES } from "../lib/sites.mjs";

const SITE = "chatgpt";
const ORIGIN = SITES[SITE].origin;

/** Vault keys and a serialisation of every storage area, read inside the worker. */
async function readStorage(h) {
	const worker = await h.currentWorker();
	return worker.evaluate(async () => {
		const session = await chrome.storage.session.get(null);
		const local = await chrome.storage.local.get(null);
		return {
			vaultKeys: Object.keys(session).filter((k) => k.startsWith("vault:")),
			local: JSON.stringify(local),
		};
	});
}

/**
 * Tries chrome.storage.session from inside the extension's content-script world of
 * `page` (over CDP). Page scripts have no extension APIs at all; the content script
 * does, so this is the context the access level has to keep out.
 */
async function contentScriptSessionAccess(h, page) {
	const cdp = await page.context().newCDPSession(page);
	try {
		const worlds = [];
		cdp.on("Runtime.executionContextCreated", ({ context }) => {
			if (String(context.origin ?? "").startsWith(h.extensionOrigin)) worlds.push(context.id);
		});
		await cdp.send("Runtime.enable");
		const contextId = await waitFor(() => worlds.at(-1), {
			timeout: 3000,
			message: "the content-script world",
		});
		const { result } = await cdp.send("Runtime.evaluate", {
			contextId,
			awaitPromise: true,
			returnByValue: true,
			// With TRUSTED_CONTEXTS the area is either absent or rejects: both are "denied".
			expression:
				"(async () => { try { await chrome.storage.session.get(null); return 'readable'; } catch { return 'denied'; } })()",
		});
		return result?.value ?? `unexpected: ${JSON.stringify(result)}`;
	} catch (error) {
		return `probe failed: ${error?.message ?? error}`;
	} finally {
		await cdp.detach().catch(() => {});
	}
}

async function waitForRestored(page, value, message) {
	try {
		return await waitFor(
			async () => {
				const text = await lastResponseText(page, SITE);
				return text?.includes(value) ? text : null;
			},
			{ timeout: 8000, message },
		);
	} catch {
		return lastResponseText(page, SITE);
	}
}

export default [
	{
		id: "reload-restore",
		title: "a reply is still restored after a page reload (per-tab vault in storage.session)",
		settings: { mode: "auto", restoreResponses: true },
		skip: (h, data) => {
			if (!h.coversSite(SITE)) return `content scripts are not declared for ${ORIGIN}`;
			return (data?.items ?? []).length > 1
				? null
				: "product feature (vault persistence) not implemented by the self-test extension";
		},
		async run({ h, checks, data, open }) {
			const email = data.items.find((i) => i.type === "EMAIL");
			const page = await open(SITE);
			const mark = h.recorder.mark();
			await typePrompt(page, SITE, data.prompt);
			await page.keyboard.press("Enter");
			const sent = await waitForPrompt(h, SITE, mark);
			const body = sent.json?.prompt ?? sent.raw;
			const placeholder = String(body).match(email.placeholder)?.[0] ?? null;
			checks.check("the sent prompt carries an email placeholder", placeholder !== null, body);
			await waitForResponseComplete(page);
			const before = await waitForRestored(page, email.value, "the reply to be restored");
			checks.contains("before the reload the reply is restored", before, email.value);

			const stored = await waitFor(
				async () => {
					const s = await readStorage(h);
					return s.vaultKeys.some((k) => k.endsWith(`:${ORIGIN}`)) ? s : null;
				},
				{ timeout: 5000, message: "the vault to be saved in storage.session" },
			).catch(() => null);
			checks.check(
				"the vault is kept in storage.session under vault:<tab>:<origin>",
				stored !== null,
				stored,
			);
			const ownKeys = stored?.vaultKeys.filter((k) => k.endsWith(`:${ORIGIN}`)) ?? [];
			checks.excludes(
				"storage.local never holds the original",
				stored?.local ?? "",
				email.value,
			);
			checks.equal(
				"the content script itself cannot read storage.session (TRUSTED_CONTEXTS)",
				await contentScriptSessionAccess(h, page),
				"denied",
			);

			await page.reload({ waitUntil: "load" });
			await waitFor(
				() => page.evaluate(() => document.documentElement.getAttribute("data-fixture-history")),
				{ timeout: 8000, message: "the fixture to re-render the conversation" },
			);
			const after = await waitForRestored(page, email.value, "the reply to be restored after reload");
			checks.contains("after the reload the reply shows the original email again", after, email.value);
			checks.excludes(
				"after the reload the reply no longer shows the email placeholder",
				after,
				email.placeholder,
			);
			const pageText = await lastResponsePageText(page, SITE);
			checks.contains(
				"page scripts still read the placeholder after the reload",
				pageText,
				email.placeholder,
			);
			checks.excludes(
				"page scripts cannot read the restored email after the reload",
				pageText,
				email.value,
			);
			assertNoLeaks(
				checks,
				h,
				mark,
				data.items.map((i) => i.value),
				"no request carried the originals, before or after the reload",
			);

			// Another tab of the same site never restores this tab's placeholder.
			const other = await open(SITE);
			await other.evaluate((ph) => {
				const reply = document.createElement("div");
				reply.setAttribute("data-message-author-role", "assistant");
				reply.textContent = `Reply to ${ph}`;
				document.querySelector("#thread")?.appendChild(reply);
			}, placeholder ?? "[EMAIL_1]");
			await other.waitForTimeout(500);
			checks.excludes(
				"another tab does not restore this tab's placeholder",
				await lastResponseText(other, SITE),
				email.value,
			);

			// Closing the tab removes its vault from storage.session.
			await page.close();
			const cleared = await waitFor(
				async () => {
					const s = await readStorage(h);
					return ownKeys.every((k) => !s.vaultKeys.includes(k)) ? true : null;
				},
				{ timeout: 5000, message: "the vault to be removed when the tab closes" },
			).catch(() => false);
			checks.check("closing the tab removes its vault", cleared === true && ownKeys.length > 0, {
				ownKeys,
			});
		},
	},
];
