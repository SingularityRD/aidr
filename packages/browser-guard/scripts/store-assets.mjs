#!/usr/bin/env node
/**
 * Generates the store screenshots (1280x800) and small promo tiles (440x280) in
 * store/images/ from the real extension running against the hermetic E2E fixtures.
 *
 *   pnpm build:browser-guard && node scripts/store-assets.mjs [--ext <dir>] [--out <dir>]
 *
 * It reuses the E2E harness (e2e/lib/harness.mjs): the built, unpacked extension is loaded
 * into the pinned Playwright Chromium, the AI site is served from e2e/fixtures/ (no real
 * product is contacted, every other origin is refused), and the pictures show what the
 * extension really did: the confirmation bubble, the placeholders the simulated AI service
 * received, the restored reply, the popup and the options page. Each capture is then framed
 * with a caption in a local page and screenshotted at the store size.
 *
 * The data is synthetic (example.com addresses, checksum-valid test identifiers). Output is
 * stable for a given browser build and font set; a different OS or font package changes
 * anti-aliasing, so regenerate the images on one machine (CI uses ubuntu-22.04 with
 * chromium-1194) and commit them together.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	launch,
	lastResponseText,
	typePrompt,
	waitForPrompt,
	waitForResponseComplete,
} from "../e2e/lib/harness.mjs";
import { waitFor } from "../e2e/lib/expect.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(scriptDir, "..");
const SITE = "chatgpt";

/** Synthetic values (same as the E2E data set): example.com mail, checksum-valid TCKN and IBAN. */
const EMAIL = "ayse.yilmaz@example.com";
const PROMPTS = {
	en: `Draft a short refund reply to ${EMAIL}. Customer TCKN 10000000146, IBAN TR330006100519786457841326.`,
	tr: `${EMAIL} adresine kısa bir iade yanıtı yaz. Müşteri TCKN 10000000146, IBAN TR330006100519786457841326.`,
};

const COPY = {
	en: {
		mask: {
			title: "Sensitive data is masked before it is sent",
			body: "E-mail addresses, Turkish ID numbers, IBANs, card numbers, secrets and your organisation's own terms are replaced with labels such as [EMAIL_1] in the browser.",
			sentLabel: "What the AI service received",
		},
		restore: {
			title: "Answers show your original values, locally",
			body: "Labels in the reply are shown as your original values in your browser only. The AI service never sees the originals.",
		},
		confirm: {
			title: "Review before sending",
			body: "In \"Ask me\" mode you see what was found and choose: send masked or edit. Administrators choose the mode.",
		},
		manage: {
			title: "Clear status, central policy",
			body: "The popup shows whether this tab is protected. Organisations set and lock every option with Chrome, Edge and Firefox policies.",
		},
		tile: { name: "AIDR Browser Guard", tagline: "Masks personal data before it reaches AI chat tools" },
	},
	tr: {
		mask: {
			title: "Hassas veriler gönderilmeden önce maskelenir",
			body: "E-posta adresleri, T.C. Kimlik Numaraları, IBAN'lar, kart numaraları, gizli anahtarlar ve kurumunuzun terimleri tarayıcıda [EMAIL_1] gibi etiketlerle değiştirilir.",
			sentLabel: "Yapay zekâ hizmetine giden",
		},
		restore: {
			title: "Yanıtlarda özgün değerler yerel olarak görünür",
			body: "Yanıttaki etiketler yalnızca tarayıcınızda özgün değerlerle gösterilir. Yapay zekâ hizmeti özgün değerleri görmez.",
		},
		confirm: {
			title: "Göndermeden önce gözden geçirin",
			body: "\"Bana sor\" modunda bulunanları görür ve seçersiniz: maskeli gönder veya düzenle. Modu yöneticiler belirler.",
		},
		manage: {
			title: "Net durum, merkezi politika",
			body: "Açılır pencere bu sekmenin korunup korunmadığını gösterir. Kurumlar tüm seçenekleri Chrome, Edge ve Firefox politikalarıyla belirler ve kilitler.",
		},
		tile: { name: "AIDR Browser Guard", tagline: "Kişisel verileri yapay zekâ araçlarına ulaşmadan maskeler" },
	},
};

const escapeHtml = (text) =>
	String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const dataUrl = (png) => `data:image/png;base64,${png.toString("base64")}`;

/** The brand logo as defined for the extension UI (static/ui.css `--logo`). */
function brandLogo() {
	const css = readFileSync(join(PACKAGE_ROOT, "static", "ui.css"), "utf8");
	const match = /--logo:\s*url\("([^"]+)"\)/.exec(css);
	if (!match) throw new Error("static/ui.css has no --logo");
	return match[1];
}

const FRAME_CSS = `
	* { box-sizing: border-box; }
	html, body { margin: 0; }
	body { font-family: "DejaVu Sans", "Segoe UI", Arial, sans-serif; color: #10203a; -webkit-font-smoothing: antialiased; }
	.frame { width: 1280px; height: 800px; display: grid; grid-template-columns: 400px 1fr; background: #0a3d91; overflow: hidden; }
	.copy { padding: 64px 40px 48px 56px; color: #fff; display: flex; flex-direction: column; gap: 20px; }
	.brand { display: flex; align-items: center; gap: 12px; font-size: 16px; font-weight: 600; opacity: .95; }
	.brand i { width: 34px; height: 44px; background: var(--logo) center / contain no-repeat; }
	h1 { font-size: 36px; line-height: 1.18; margin: 24px 0 0; font-weight: 700; }
	p { font-size: 19px; line-height: 1.5; margin: 0; color: #dbe7fb; }
	.stage { padding: 48px 48px 48px 0; display: flex; flex-direction: column; justify-content: center; gap: 18px; }
	.shot { background: #fff; border-radius: 12px; overflow: hidden; max-height: 640px; }
	.shot img { display: block; width: 100%; }
	.sent { background: #0e1a2e; color: #cfe0ff; border-radius: 12px; padding: 16px 20px; font: 15px/1.5 "DejaVu Sans Mono", Consolas, monospace; word-break: break-word; }
	.sent b { display: block; font: 600 13px "DejaVu Sans", Arial, sans-serif; letter-spacing: .06em; text-transform: uppercase; color: #8fb4ff; margin-bottom: 6px; }
	.pair { display: grid; grid-template-columns: 360px 1fr; gap: 24px; align-items: start; }
	.tile { width: 440px; height: 280px; padding: 28px; background: #0a3d91; color: #fff; display: flex; flex-direction: column; justify-content: center; gap: 14px; }
	.tile i { width: 54px; height: 70px; background: var(--logo) center / contain no-repeat; }
	.tile strong { font-size: 30px; line-height: 1.15; }
	.tile span { font-size: 18px; line-height: 1.35; color: #dbe7fb; }
`;

function framePage(logo, copy, stage) {
	return `<!doctype html><html><head><meta charset="utf-8"><style>:root{--logo:url("${logo}")}${FRAME_CSS}</style></head>
<body><div class="frame"><div class="copy"><div class="brand"><i></i>Singularity AIDR Browser Guard</div>
<h1>${escapeHtml(copy.title)}</h1><p>${escapeHtml(copy.body)}</p></div><div class="stage">${stage}</div></div></body></html>`;
}

function tilePage(logo, tile) {
	return `<!doctype html><html><head><meta charset="utf-8"><style>:root{--logo:url("${logo}")}${FRAME_CSS}</style></head>
<body><div class="tile"><i></i><strong>${escapeHtml(tile.name)}</strong><span>${escapeHtml(tile.tagline)}</span></div></body></html>`;
}

/** Renders `html` in a local page at width x height and returns the PNG. */
async function render(h, html, width, height) {
	const page = await h.context.newPage();
	try {
		await page.setViewportSize({ width, height });
		await page.setContent(html, { waitUntil: "load" });
		return await page.screenshot({ clip: { x: 0, y: 0, width, height }, animations: "disabled" });
	} finally {
		await page.close();
	}
}

/** Screenshot of a whole extension page at its natural width (no scrollbars); the frame crops it. */
async function fullPage(page) {
	const width = await page.evaluate(() => Math.ceil(document.documentElement.scrollWidth));
	await page.setViewportSize({ width, height: page.viewportSize().height });
	return page.screenshot({ fullPage: true, animations: "disabled" });
}

/** Captures the real extension on the fixture site for one UI language. */
async function capture(h, language) {
	const out = {};
	// Confirm mode: the in-page bubble lists the findings before anything is sent.
	await h.setUserSettings({ mode: "confirm", language });
	let page = await h.openSite(SITE);
	await page.setViewportSize({ width: 880, height: 560 });
	await typePrompt(page, SITE, PROMPTS[language]);
	await page.keyboard.press("Enter");
	await waitFor(async () => (await h.overlays(page, SITE)).length > 0, { timeout: 5000, message: "the confirm bubble" });
	await page.waitForTimeout(500);
	out.confirm = await page.screenshot({ animations: "disabled" });
	await page.close();

	// Auto mode: what the simulated service received, and the locally restored reply.
	await h.setUserSettings({ mode: "auto", language });
	page = await h.openSite(SITE);
	await page.setViewportSize({ width: 880, height: 420 });
	const mark = h.recorder.mark();
	await typePrompt(page, SITE, PROMPTS[language]);
	await page.keyboard.press("Enter");
	const sent = await waitForPrompt(h, SITE, mark);
	out.sent = String(sent.json?.prompt ?? sent.raw);
	if (out.sent.includes(EMAIL)) throw new Error("the captured prompt was not masked; refusing to generate store images");
	await waitForResponseComplete(page);
	await waitFor(async () => (await lastResponseText(page, SITE))?.includes(EMAIL), {
		timeout: 5000,
		message: "the restored reply",
	});
	await page.waitForTimeout(500);
	out.restore = await page.screenshot({ animations: "disabled" });

	// Popup of the protected tab, and the options page.
	const popup = await h.context.newPage();
	await popup.setViewportSize({ width: 360, height: 560 });
	await page.bringToFront();
	await popup.goto(`${h.extensionOrigin}/${h.popupPath}`);
	await popup.waitForTimeout(800);
	out.popup = await fullPage(popup);
	await popup.setViewportSize({ width: 960, height: 760 });
	await popup.goto(`${h.extensionOrigin}/options.html`);
	await popup.waitForTimeout(800);
	out.options = await fullPage(popup);
	await popup.close();
	await page.close();
	return out;
}

export async function generateStoreAssets({ extDir, outDir, log = console.log }) {
	mkdirSync(outDir, { recursive: true });
	const h = await launch({ extDir, log: (line) => log(`[store-assets] ${line}`) });
	const written = [];
	const write = (name, png) => {
		writeFileSync(join(outDir, name), png);
		written.push(name);
		log(`[store-assets] ${name} (${png.length} bytes)`);
	};
	try {
		const logo = brandLogo();
		for (const language of ["en", "tr"]) {
			const copy = COPY[language];
			const shots = await capture(h, language);
			const img = (png) => `<div class="shot"><img src="${dataUrl(png)}" alt=""></div>`;
			const sent = `<div class="sent"><b>${escapeHtml(copy.mask.sentLabel)}</b>${escapeHtml(shots.sent)}</div>`;
			write(`screenshot-1-mask-${language}.png`, await render(h, framePage(logo, copy.mask, `${img(shots.restore)}${sent}`), 1280, 800));
			write(`screenshot-2-confirm-${language}.png`, await render(h, framePage(logo, copy.confirm, img(shots.confirm)), 1280, 800));
			write(
				`screenshot-3-manage-${language}.png`,
				await render(h, framePage(logo, copy.manage, `<div class="pair">${img(shots.popup)}${img(shots.options)}</div>`), 1280, 800),
			);
			write(`promo-small-${language}.png`, await render(h, tilePage(logo, copy.tile), 440, 280));
		}
	} finally {
		await h.close();
	}
	return written;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const args = process.argv.slice(2);
	const option = (flag, fallback) => {
		const i = args.indexOf(flag);
		return i >= 0 && args[i + 1] ? resolve(args[i + 1]) : fallback;
	};
	try {
		await generateStoreAssets({
			extDir: option("--ext", join(PACKAGE_ROOT, "dist", "chrome")),
			outDir: option("--out", join(PACKAGE_ROOT, "store", "images")),
		});
	} catch (error) {
		console.error(`[store-assets] ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
}
