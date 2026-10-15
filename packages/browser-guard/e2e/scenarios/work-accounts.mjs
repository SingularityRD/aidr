// (11) Personal vs company AI accounts (managed `workAccounts`, src/sites/accounts.ts), in a
// managed browser (lib/managed-deployment.mjs). The account signals are modelled in the
// hermetic fixtures: Gemini's Google bar account button (fixtures/gemini-account-*.html at
// /u/1/app and /u/2/app), the Microsoft 365 account manager (fixtures/m365-copilot-chat.html
// at copilot.cloud.microsoft/chat), the consumer Copilot host, and ChatGPT's `_account`
// workspace cookie (set here as the site would set it).
//
// work-accounts-block      action "block": a personal Gemini account and a personal ChatGPT
//                          account cannot send (nothing reaches the site, a bubble says why);
//                          the company Workspace account and the company ChatGPT workspace
//                          send as usual (masked).
// work-accounts-warn       action "warn": the first send from a personal Gemini account is
//                          held with Continue / Cancel; after Continue the masked prompt goes.
// work-accounts-mask-only  action "mask-only" under managed mode "monitor": consumer Copilot
//                          is masked anyway, while Microsoft 365 Copilot Chat signed in with
//                          the company domain stays in monitor mode (sent unchanged).

import fs from "node:fs";
import { staysFalse, waitFor } from "../lib/expect.mjs";
import { assertNoLeaks, launch, typePrompt, waitForPrompt } from "../lib/harness.mjs";
import { createManagedDeployment } from "../lib/managed-deployment.mjs";
import { SITES } from "../lib/sites.mjs";

const COMPANY_WORKSPACE = "ws-e2e-acme";

const BLOCK_POLICY = {
	policyId: "e2e-work-accounts-block",
	workAccounts: {
		action: "block",
		sites: {
			gemini: { emailDomains: ["acme.example"] },
			chatgpt: { workspaceIds: [COMPANY_WORKSPACE] },
		},
	},
};

const WARN_POLICY = {
	policyId: "e2e-work-accounts-warn",
	workAccounts: {
		action: "warn",
		sites: { gemini: { emailDomains: ["acme.example"] } },
	},
};

const MASK_ONLY_POLICY = {
	policyId: "e2e-work-accounts-mask-only",
	mode: "monitor",
	workAccounts: {
		action: "mask-only",
		sites: { copilot: { emailDomains: ["acme.example"] } },
	},
};

const skipUnlessProductBuild = (h, data) =>
	(data?.items ?? []).length > 1
		? null
		: "product feature (workAccounts) not implemented by the self-test extension";

async function withManagedBrowser(h, managedPolicy, fn) {
	const dir = createManagedDeployment(h.extDir, { managedPolicy, grantedOrigins: [] });
	let managed;
	try {
		managed = await launch({ extDir: dir });
		await waitFor(
			async () => {
				const policy = await managed.getPolicy().catch(() => null);
				return policy?.workAccounts ? policy : null;
			},
			{ timeout: 10_000, message: "the managed workAccounts policy to be in force" },
		);
		return await fn(managed);
	} finally {
		await managed?.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

/** Sends `prompt` with the site's own send button. */
async function send(page, siteKey, prompt) {
	await typePrompt(page, siteKey, prompt);
	await page.locator(SITES[siteKey].send).click({ timeout: 3000, force: true });
}

/** Opens `siteKey` (at `path`), sends, and checks that nothing reached the site. */
async function expectBlocked(m, checks, data, siteKey, path, label) {
	const page = await m.openSite(siteKey, path ? { path } : {});
	const mark = m.recorder.mark();
	await send(page, siteKey, data.prompt);
	const bubble = await waitFor(
		async () => {
			const overlays = await m.overlays(page, siteKey);
			return overlays.find((o) => /company account/i.test(o)) ?? null;
		},
		{ timeout: 4000, message: "the account bubble" },
	).catch(() => null);
	checks.check(`${label}: a bubble explains the company-account rule`, bubble, {
		overlays: await m.overlays(page, siteKey),
	});
	let quiet = true;
	await staysFalse(() => m.recorder.apiSince(mark, { kind: "prompt" }).length > 0, {
		window: 1500,
		message: "a prompt request",
	}).catch(() => {
		quiet = false;
	});
	checks.check(`${label}: nothing was sent`, quiet, m.recorder.apiSince(mark));
	checks.equal(
		`${label}: the page never issued its send()`,
		await page.evaluate(() => window.__fixture.sends.length),
		0,
	);
	assertNoLeaks(
		checks,
		m,
		mark,
		data.items.map((i) => i.value),
	);
	await page.close().catch(() => {});
}

/** Opens `siteKey`, sends, and returns the body the site received. */
async function sentBody(m, siteKey, path, prompt) {
	const page = await m.openSite(siteKey, path ? { path } : {});
	const mark = m.recorder.mark();
	await send(page, siteKey, prompt);
	const sent = await waitForPrompt(m, siteKey, mark);
	await page.close().catch(() => {});
	return sent.json?.prompt ?? sent.raw;
}

function expectMasked(checks, data, label, body) {
	for (const item of data.items) {
		checks.excludes(`${label}: sent prompt does not contain the ${item.type} value`, body, item.value);
		checks.contains(`${label}: sent prompt contains a ${item.type} placeholder`, body, item.placeholder);
	}
}

async function setChatgptWorkspace(m, value) {
	await m.context.addCookies([
		{ name: "_account", value, url: SITES.chatgpt.origin, secure: true, sameSite: "Lax" },
	]);
}

export default [
	{
		id: "work-accounts-block",
		title: "workAccounts block: personal Gemini/ChatGPT accounts cannot send, company accounts can",
		skip: skipUnlessProductBuild,
		async run({ h, checks, data }) {
			await withManagedBrowser(h, BLOCK_POLICY, async (m) => {
				const policy = await m.getPolicy();
				checks.check(
					"workAccounts is locked by the administrator",
					policy.managedKeys.includes("workAccounts"),
					policy.managedKeys,
				);

				await expectBlocked(m, checks, data, "gemini", "/u/2/app", "personal Google account");
				const workspace = await sentBody(m, "gemini", "/u/1/app", data.prompt);
				expectMasked(checks, data, "Google Workspace account (acme.example)", workspace);

				await setChatgptWorkspace(m, "personal");
				await expectBlocked(m, checks, data, "chatgpt", null, "personal ChatGPT account");
				await setChatgptWorkspace(m, COMPANY_WORKSPACE);
				const company = await sentBody(m, "chatgpt", null, data.prompt);
				expectMasked(checks, data, "company ChatGPT workspace", company);

				const stats = await m.getStats();
				checks.check("the refused sends are counted", stats?.blockedSends >= 2, stats);
			});
		},
	},
	{
		id: "work-accounts-warn",
		title: "workAccounts warn: a personal Gemini account is warned once, Continue lets the masked prompt through",
		skip: skipUnlessProductBuild,
		async run({ h, checks, data }) {
			await withManagedBrowser(h, WARN_POLICY, async (m) => {
				const page = await m.openSite("gemini", { path: "/u/2/app" });
				const mark = m.recorder.mark();
				await send(page, "gemini", data.prompt);
				const bubble = await waitFor(
					async () => (await m.overlays(page, "gemini")).find((o) => /company account/i.test(o)) ?? null,
					{ timeout: 4000, message: "the account warning" },
				).catch(() => null);
				checks.check("a warning names the company-account rule", bubble, {
					overlays: await m.overlays(page, "gemini"),
				});
				let quiet = true;
				await staysFalse(() => m.recorder.apiSince(mark, { kind: "prompt" }).length > 0, {
					window: 1000,
					message: "a prompt request before the user decides",
				}).catch(() => {
					quiet = false;
				});
				checks.check("nothing is sent before the user decides", quiet, m.recorder.apiSince(mark));
				const clicked = await waitFor(() => m.clickOverlayButton(page, /^(continue|devam)$/i), {
					timeout: 3000,
					message: '"Continue" button',
				}).catch(() => false);
				checks.must('the warning offers "Continue"', clicked, await m.overlays(page, "gemini"));
				// The prompt stayed in the editor; the user presses send again (as the toast says).
				await page.locator(SITES.gemini.send).click({ timeout: 3000, force: true });
				const sent = await waitForPrompt(m, "gemini", mark);
				expectMasked(checks, data, "after Continue", sent.json?.prompt ?? sent.raw);
				checks.equal(
					"exactly one prompt request",
					m.recorder.apiSince(mark, { kind: "prompt" }).length,
					1,
				);
				assertNoLeaks(
					checks,
					m,
					mark,
					data.items.map((i) => i.value),
				);
				await page.close().catch(() => {});
			});
		},
	},
	{
		id: "work-accounts-mask-only",
		title: "workAccounts mask-only: consumer Copilot is masked even in monitor mode, the company account is not",
		skip: skipUnlessProductBuild,
		async run({ h, checks, data }) {
			await withManagedBrowser(h, MASK_ONLY_POLICY, async (m) => {
				const consumer = await sentBody(m, "copilot", null, data.prompt);
				expectMasked(checks, data, "consumer Copilot (personal account)", consumer);

				const company = await sentBody(m, "m365pane", "/chat", data.prompt);
				checks.equal(
					"Microsoft 365 Copilot Chat with the company account stays in monitor mode",
					company,
					data.prompt,
				);
			});
		},
	},
];
