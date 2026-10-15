#!/usr/bin/env node
// Browser Guard customer demo on the hermetic E2E fixtures (no real AI service is contacted).
//
//   node e2e/demo.mjs --record [--out docs/screenshots] [--ext dist/chrome]
//       Headless walkthrough in Turkish UI: types the demo prompt on the ChatGPT fixture,
//       shows the masked text the (simulated) service received, the locally restored reply,
//       paste masking, "Ask me" and "Block" modes, the popup and options page, Gemini and
//       Claude, and a personal-account block (managed workAccounts). Every step is checked
//       like an E2E scenario (no value may leave the page) before its screenshot is kept.
//       Writes NN-*.png, browser-guard-demo.apng.png (animated PNG of the page screenshots)
//       and demo-evidence.json (what was sent at each step: placeholders only) to --out,
//       and the Playwright video of the main tab to --video-out
//       (default dist/demo/browser-guard-demo.webm, not committed).
//
//   node e2e/demo.mjs --interactive [--ext dist/chrome]
//       Opens a visible Chromium with the extension and the fixture sites in demo mode
//       (banner + "sent to the AI service" panel) for a live presentation; type anything,
//       the simulated model echoes the placeholders it received. Close the window to end.
//
// The fixture pages are local simulations of each product's composer DOM, served at the
// real origins through Playwright routing; see e2e/README.md.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { deflateSync } from "node:zlib";
import { decodePng } from "../scripts/icons.mjs";
import { crc32 } from "../scripts/zip.mjs";
import { DEMO_ITEMS, DEMO_PROMPT, PROFILES } from "./lib/data.mjs";
import { waitFor } from "./lib/expect.mjs";
import {
	lastResponsePageText,
	lastResponseText,
	launch,
	pasteText,
	readEditor,
	waitForPrompt,
	waitForResponseComplete,
} from "./lib/harness.mjs";
import { createManagedDeployment } from "./lib/managed-deployment.mjs";
import { SITES } from "./lib/sites.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = path.resolve(here, "..");
// The Playwright screencast of new-headless Chromium on Windows showed only the left 1076 px
// of a 1280 px viewport (with or without --window-size), so the demo uses a viewport that
// fits inside it.
const VIEWPORT = { width: 1024, height: 680 };
const DEMO_QUERY = "demo=1";

const { values: args } = parseArgs({
	options: {
		record: { type: "boolean", default: false },
		interactive: { type: "boolean", default: false },
		out: { type: "string", default: path.join(PACKAGE_ROOT, "docs", "screenshots") },
		// The WebM is ~3 MB: kept out of git (pre-commit check-added-large-files, 500 KB).
		"video-out": { type: "string", default: path.join(PACKAGE_ROOT, "dist", "demo", "browser-guard-demo.webm") },
		ext: { type: "string", default: path.join(PACKAGE_ROOT, "dist", "chrome") },
	},
});

const demoPath = (siteKey, sitePath = SITES[siteKey].path) =>
	`${sitePath}${sitePath.includes("?") ? "&" : "?"}${DEMO_QUERY}`;

class DemoFailure extends Error {}

function must(condition, message, detail) {
	if (!condition) throw new DemoFailure(`${message}${detail === undefined ? "" : `: ${JSON.stringify(detail).slice(0, 600)}`}`);
}

/** Types like a person (visible in the video), then waits until the editor holds the text. */
async function typeSlowly(page, siteKey, text) {
	await page.locator(SITES[siteKey].editor).click();
	await page.keyboard.type(text, { delay: 8 });
	await waitFor(async () => (await readEditor(page, siteKey)).includes(text.slice(-12)), {
		timeout: 5000,
		message: "the typed text in the editor",
	});
}

function checkMaskedBody(body, items = DEMO_ITEMS) {
	for (const item of items) {
		must(!String(body).includes(item.value), `the ${item.type} value left the page`);
		must(item.placeholder.test(String(body)), `no ${item.type} placeholder in what was sent`, body);
	}
}

async function waitOverlay(h, page, siteKey, pattern, message) {
	return waitFor(async () => (await h.overlays(page, siteKey)).find((o) => pattern.test(o)) ?? null, {
		timeout: 6000,
		message,
	});
}

// ---------------------------------------------------------------------------
// Animated PNG (APNG) of equally sized screenshots: no extra dependency, plays in
// every current browser and inline on GitHub.
// ---------------------------------------------------------------------------

function pngChunk(type, body) {
	const length = Buffer.alloc(4);
	length.writeUInt32BE(body.length);
	const typed = Buffer.concat([Buffer.from(type, "latin1"), body]);
	const crc = Buffer.alloc(4);
	crc.writeUInt32BE(crc32(typed));
	return Buffer.concat([length, typed, crc]);
}

export function encodeApng(frames, delayMs) {
	const { width, height } = frames[0];
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(width, 0);
	ihdr.writeUInt32BE(height, 4);
	ihdr[8] = 8;
	ihdr[9] = 6;
	const actl = Buffer.alloc(8);
	actl.writeUInt32BE(frames.length, 0);
	actl.writeUInt32BE(0, 4); // loop forever
	const parts = [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), pngChunk("IHDR", ihdr), pngChunk("acTL", actl)];
	let seq = 0;
	frames.forEach((frame, index) => {
		if (frame.width !== width || frame.height !== height) throw new Error("APNG frames must share one size");
		const fctl = Buffer.alloc(26);
		fctl.writeUInt32BE(seq++, 0);
		fctl.writeUInt32BE(width, 4);
		fctl.writeUInt32BE(height, 8);
		fctl.writeUInt16BE(delayMs, 20);
		fctl.writeUInt16BE(1000, 22);
		parts.push(pngChunk("fcTL", fctl));
		const stride = width * 4;
		const raw = Buffer.alloc((stride + 1) * height);
		for (let y = 0; y < height; y++) {
			Buffer.from(frame.data.buffer, frame.data.byteOffset + y * stride, stride).copy(raw, y * (stride + 1) + 1);
		}
		const data = deflateSync(raw, { level: 9 });
		if (index === 0) parts.push(pngChunk("IDAT", data));
		else {
			const seqBuf = Buffer.alloc(4);
			seqBuf.writeUInt32BE(seq++);
			parts.push(pngChunk("fdAT", Buffer.concat([seqBuf, data])));
		}
	});
	parts.push(pngChunk("IEND", Buffer.alloc(0)));
	return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// Recorded walkthrough
// ---------------------------------------------------------------------------

async function record() {
	const out = path.resolve(args.out);
	fs.mkdirSync(out, { recursive: true });
	const videoDir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-demo-video-"));
	const shots = [];
	const evidence = { generated: new Date().toISOString(), steps: [] };
	const shot = async (page, name, caption, { frame = true } = {}) => {
		await page.waitForTimeout(350);
		const file = path.join(out, name);
		fs.writeFileSync(file, await page.screenshot({ animations: "disabled" }));
		shots.push({ file, frame });
		evidence.steps.push({ screenshot: name, caption });
		console.log(`[demo] ${name}: ${caption}`);
	};

	const h = await launch({ extDir: path.resolve(args.ext), recordVideo: { dir: videoDir, size: VIEWPORT },
		viewport: VIEWPORT,
		extraArgs: [`--window-size=${VIEWPORT.width},${VIEWPORT.height + 100}`],
	});
	evidence.browser = h.browserVersion;
	evidence.extension = `Singularity AIDR Browser Guard ${h.manifest.version} (${path.relative(PACKAGE_ROOT, path.resolve(args.ext)).split(path.sep).join("/") || "."})`;
	evidence.data = "synthetic, checksum-valid demo values (e2e/lib/data.mjs DEMO_PROMPT); 'sent' holds what the simulated AI service received";
	let mainVideo = null;
	try {
		await h.setUserSettings({ mode: "auto", language: "tr", maskPaste: true });
		const site = "chatgpt";
		const page = await h.openSite(site, { path: demoPath(site) });
		mainVideo = page.video();

		// 1. Type: originals are visible in the user's own editor only.
		await typeSlowly(page, site, DEMO_PROMPT);
		await shot(page, "01-istem-yazildi.png", "Kullanıcı e-posta, telefon, TCKN, IBAN, kart ve API anahtarları içeren bir istem yazıyor");

		// 2. Enter: masked before sending.
		let mark = h.recorder.mark();
		await page.keyboard.press("Enter");
		let sent = await waitForPrompt(h, site, mark);
		let body = sent.json?.prompt ?? sent.raw;
		checkMaskedBody(body);
		must(h.recorder.leaks(mark, DEMO_ITEMS.map((i) => i.value)).length === 0, "a request carried an original value");
		await waitOverlay(h, page, site, /maskelendi|masked/i, "the masked toast");
		await shot(page, "02-gonderimden-once-maskelendi.png", "Gönderimden önce maskelendi: servise yalnızca [EMAIL_1_xxxx] gibi etiketler gitti (üstteki koyu panel)");
		evidence.steps.at(-1).sent = body;

		// 3. Reply restored locally (user's view), page still reads placeholders.
		await waitForResponseComplete(page);
		const restorable = DEMO_ITEMS.filter((i) => i.restore);
		const shown = await waitFor(
			async () => {
				const text = await lastResponseText(page, site);
				return text && restorable.every((i) => text.includes(i.value)) ? text : null;
			},
			{ timeout: 6000, message: "the restored reply" },
		);
		const pageText = await lastResponsePageText(page, site);
		must(DEMO_ITEMS.every((i) => !pageText.includes(i.value)), "the page could read a restored value", pageText);
		must(DEMO_ITEMS.filter((i) => !i.restore).every((i) => !shown.includes(i.value)), "a secret was restored");
		await shot(page, "03-yanit-yerelde-geri-yuklendi.png", "Yanıttaki etiketler yalnızca bu tarayıcıda gerçek değerlere çevrildi; API anahtarları maskeli kalır");

		// 4. Paste: the editor receives placeholders.
		mark = h.recorder.mark();
		await pasteText(page, site, DEMO_PROMPT);
		const pasted = await waitFor(
			async () => {
				const text = await readEditor(page, site);
				return DEMO_ITEMS.every((i) => i.placeholder.test(text)) ? text : null;
			},
			{ timeout: 5000, message: "placeholders in the editor after paste" },
		);
		checkMaskedBody(pasted);
		await shot(page, "04-yapistirma-maskelendi.png", "Yapıştırılan metin editöre zaten maskeli olarak giriyor");
		await page.keyboard.press("Enter");
		sent = await waitForPrompt(h, site, mark);
		checkMaskedBody(sent.json?.prompt ?? sent.raw);
		await waitForResponseComplete(page);
		await page.waitForTimeout(600);

		// 5. "Ask me" (confirm) mode.
		await h.setUserSettings({ mode: "confirm" });
		await page.waitForTimeout(400);
		mark = h.recorder.mark();
		await typeSlowly(page, site, `Ayşe'nin e-postası ${DEMO_ITEMS[0].value}, TCKN ${DEMO_ITEMS[2].value}`);
		await page.keyboard.press("Enter");
		await waitOverlay(h, page, site, /maskeli g[öo]nder|send masked/i, "the confirm bubble");
		must(h.recorder.apiSince(mark, { kind: "prompt" }).length === 0, "something was sent before the user decided");
		await shot(page, "05-bana-sor-modu.png", "\"Bana sor\" modu: bulunanları gösterir, kullanıcı maskeli göndermeyi veya düzenlemeyi seçer");
		must(await h.clickOverlayButton(page, /^(maskeli g[öo]nder|send masked)$/i), "no Send masked button");
		sent = await waitForPrompt(h, site, mark);
		checkMaskedBody(sent.json?.prompt ?? sent.raw, [DEMO_ITEMS[0], DEMO_ITEMS[2]]);
		await waitForResponseComplete(page);
		await page.waitForTimeout(600);

		// 6. Block mode.
		await h.setUserSettings({ mode: "block" });
		await page.waitForTimeout(400);
		mark = h.recorder.mark();
		await typeSlowly(page, site, `Kart numaram ${DEMO_ITEMS[4].value}`);
		await page.keyboard.press("Enter");
		await waitOverlay(h, page, site, /g[öo]nderilmedi|not sent|engellendi|blocked/i, "the block bubble");
		await page.waitForTimeout(800);
		must(h.recorder.apiSince(mark, { kind: "prompt" }).length === 0, "block mode sent the prompt");
		await shot(page, "06-engelle-modu.png", "\"Engelle\" modu: hassas veri varken gönderim durdurulur, hiçbir şey gönderilmez");
		await h.setUserSettings({ mode: "auto" });

		// 7./8. Popup (for this tab) and options page.
		await page.bringToFront();
		const popup = await h.context.newPage();
		await popup.setViewportSize({ width: 380, height: 640 });
		await popup.goto(`${h.extensionOrigin}/${h.popupPath}`);
		await page.bringToFront();
		await popup.reload();
		await popup.waitForTimeout(800);
		await shot(popup, "07-acilir-pencere.png", "Araç çubuğu penceresi: sekme korunuyor, mod ve bu oturumun sayıları", { frame: false });
		await popup.setViewportSize({ width: 1100, height: 900 });
		await popup.goto(`${h.extensionOrigin}/options.html`);
		await popup.waitForTimeout(800);
		await shot(popup, "08-ayarlar.png", "Ayarlar: koruma modu, algılanan veri türleri, yardımcı uygulama (yerel NER)", { frame: false });
		await popup.close();

		// 9./10. Gemini and Claude.
		for (const [index, other] of [
			[9, "gemini"],
			[10, "claude"],
		]) {
			const p = await h.openSite(other, { path: demoPath(other) });
			mark = h.recorder.mark();
			await typeSlowly(p, other, DEMO_PROMPT);
			await p.keyboard.press("Enter");
			const s = await waitForPrompt(h, other, mark);
			checkMaskedBody(s.json?.prompt ?? s.raw);
			await waitForResponseComplete(p);
			await waitFor(async () => (await lastResponseText(p, other))?.includes(DEMO_ITEMS[0].value), {
				timeout: 6000,
				message: `the restored reply on ${other}`,
			});
			await shot(p, `${String(index).padStart(2, "0")}-${other}.png`, `${SITES[other].siteId}: aynı maskeleme ve yerel geri yükleme`);
			evidence.steps.at(-1).sent = s.json?.prompt ?? s.raw;
			await p.close();
		}
		await page.close();
	} finally {
		await h.close();
	}

	// 11. Personal account blocked (managed workAccounts), in a managed browser copy.
	const managedDir = createManagedDeployment(path.resolve(args.ext), {
		managedPolicy: {
			policyId: "demo-work-accounts",
			language: "tr",
			workAccounts: { action: "block", sites: { gemini: { emailDomains: ["acme.example"] } } },
		},
		grantedOrigins: [],
	});
	try {
		const m = await launch({ extDir: managedDir, viewport: VIEWPORT });
		try {
			await waitFor(async () => ((await m.getPolicy().catch(() => null))?.workAccounts ? true : null), {
				timeout: 10_000,
				message: "the managed policy",
			});
			const p = await m.openSite("gemini", { path: demoPath("gemini", "/u/2/app") });
			const mark = m.recorder.mark();
			await typeSlowly(p, "gemini", PROFILES.full.prompt);
			await p.locator(SITES.gemini.send).click({ force: true });
			await waitOverlay(m, p, "gemini", /kurum hesab|company account/i, "the company-account bubble");
			await p.waitForTimeout(800);
			must(m.recorder.apiSince(mark, { kind: "prompt" }).length === 0, "a personal account could send");
			await shot(p, "11-kisisel-hesap-engellendi.png", "Kurum politikası: Gemini'de kişisel (gmail.com) hesapla gönderim engellendi");
		} finally {
			await m.close();
		}
	} finally {
		fs.rmSync(managedDir, { recursive: true, force: true });
	}

	// Video of the main tab, and an animated PNG of the page screenshots.
	const videoPath = mainVideo ? await mainVideo.path().catch(() => null) : null;
	if (videoPath && fs.existsSync(videoPath)) {
		const videoOut = path.resolve(args["video-out"]);
		fs.mkdirSync(path.dirname(videoOut), { recursive: true });
		fs.copyFileSync(videoPath, videoOut);
		console.log(`[demo] ${videoOut}`);
	}
	fs.rmSync(videoDir, { recursive: true, force: true });
	const frames = shots.filter((s) => s.frame).map((s) => decodePng(fs.readFileSync(s.file)));
	const sameSize = frames.filter((f) => f.width === frames[0].width && f.height === frames[0].height);
	fs.writeFileSync(path.join(out, "browser-guard-demo.apng.png"), encodeApng(sameSize, 2200));
	console.log(`[demo] browser-guard-demo.apng.png (${sameSize.length} frames)`);
	for (const step of evidence.steps) {
		if (step.sent) must(DEMO_ITEMS.every((i) => !step.sent.includes(i.value)), "evidence would contain an original value");
	}
	fs.writeFileSync(path.join(out, "demo-evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`);
	console.log(`[demo] done: ${out}`);
}

// ---------------------------------------------------------------------------
// Interactive (live presentation)
// ---------------------------------------------------------------------------

async function interactive() {
	const h = await launch({ extDir: path.resolve(args.ext), headed: true, viewport: null });
	await h.setUserSettings({ mode: "auto", language: "tr" });
	for (const siteKey of ["gemini", "claude", "chatgpt"]) {
		await h.openSite(siteKey, { path: demoPath(siteKey) });
	}
	console.log(`Browser Guard demo is open (${h.browserVersion}, extension id ${h.extensionId}).
Tabs: ChatGPT, Claude, Gemini simulations. Type or paste, e.g.:

  ${DEMO_PROMPT}

The dark panel at the top shows what the simulated AI service received. Close the browser window to finish.`);
	const closed = new Promise((resolve) => h.context.on("close", resolve));
	// Smoke-test hook: close by itself after N ms (a killed Node process would leave Chromium running).
	const closeAfter = Number(process.env.BG_DEMO_CLOSE_AFTER_MS);
	if (closeAfter > 0) setTimeout(() => void h.context.close().catch(() => {}), closeAfter);
	await closed;
	await h.close();
}

if (args.interactive) await interactive();
else if (args.record) await record();
else {
	console.error("usage: node e2e/demo.mjs --record [--out <dir>] [--ext <dir>] | --interactive [--ext <dir>]");
	process.exitCode = 2;
}
