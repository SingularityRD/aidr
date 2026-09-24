#!/usr/bin/env node
/**
 * Render the Singularity AIDR product brochure (docs/sales/brochure/brochure.<lang>.html)
 * to an A4 PDF and per-page PNG previews with headless Chromium.
 *
 *   node scripts/render-brochure.mjs                 # both languages, PDF + PNG previews
 *   node scripts/render-brochure.mjs --lang=tr       # one language
 *   node scripts/render-brochure.mjs --check         # layout checks only, write nothing
 *   node scripts/render-brochure.mjs --force         # write output even when a check fails (for iterating)
 *
 * playwright-core is a devDependency of packages/browser-guard, so it is resolved from
 * there. The Chromium build comes from PLAYWRIGHT_BROWSERS_PATH (or AIDR_CHROMIUM_PATH).
 *
 * Before writing anything the script checks the rendered layout and exits non-zero when a
 * page overflows, content runs into the page footer, an element leaves the page, diagram
 * text leaves its figure, or the PDF does not have exactly the expected number of pages.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const brochureDir = path.join(repositoryRoot, "docs", "sales", "brochure");
const previewDir = path.join(brochureDir, "preview");
export const LANGUAGES = ["tr", "en"];
export const EXPECTED_PAGES = 4;

function parseArgs(argv) {
	const args = { langs: LANGUAGES, check: false, force: false, scale: 1.5 };
	for (const arg of argv) {
		if (arg === "--check") args.check = true;
		else if (arg === "--force") args.force = true;
		else if (arg.startsWith("--lang=")) {
			const lang = arg.slice("--lang=".length);
			if (!LANGUAGES.includes(lang)) throw new Error(`Unknown language ${lang}; use ${LANGUAGES.join(" or ")}`);
			args.langs = [lang];
		} else if (arg.startsWith("--scale=")) {
			args.scale = Number(arg.slice("--scale=".length));
			if (!(args.scale >= 1 && args.scale <= 3)) throw new Error("--scale must be between 1 and 3");
		} else if (arg === "--help" || arg === "-h") {
			console.log("Usage: node scripts/render-brochure.mjs [--lang=tr|en] [--check] [--force] [--scale=1.5]");
			process.exit(0);
		} else throw new Error(`Unknown argument: ${arg}`);
	}
	return args;
}

function loadChromium() {
	const require = createRequire(path.join(repositoryRoot, "packages", "browser-guard", "package.json"));
	try {
		return require("playwright-core").chromium;
	} catch (error) {
		throw new Error(`playwright-core is not installed for packages/browser-guard (run pnpm install): ${error.message}`);
	}
}

/** Count page objects in a PDF produced by Chromium (pages are never inside object streams there). */
export function countPdfPages(buffer) {
	return (buffer.toString("latin1").match(/\/Type\s*\/Page(?![s\w])/g) ?? []).length;
}

/** Runs in the page: returns human-readable layout problems (empty when clean). */
function inspectLayout() {
	const problems = [];
	const pages = [...document.querySelectorAll(".page")];
	const tolerance = 0.5;
	pages.forEach((page, index) => {
		const label = `page ${index + 1}`;
		if (page.scrollHeight > page.clientHeight + 1) problems.push(`${label}: content overflows vertically (${page.scrollHeight} > ${page.clientHeight}px)`);
		if (page.scrollWidth > page.clientWidth + 1) problems.push(`${label}: content overflows horizontally (${page.scrollWidth} > ${page.clientWidth}px)`);
		const box = page.getBoundingClientRect();
		const style = getComputedStyle(page);
		const inner = {
			left: box.left + Number.parseFloat(style.paddingLeft) - tolerance,
			right: box.right - Number.parseFloat(style.paddingRight) + tolerance,
			top: box.top + Number.parseFloat(style.paddingTop) - tolerance,
		};
		const foot = page.querySelector(":scope > .foot");
		const bottomLimit = foot ? foot.getBoundingClientRect().top - 2 : box.bottom - Number.parseFloat(style.paddingBottom) + tolerance;
		for (const child of page.children) {
			if (child.classList.contains("foot") || child.classList.contains("grid-bg")) continue;
			const rect = child.getBoundingClientRect();
			if (rect.bottom > bottomLimit) problems.push(`${label}: <${child.tagName.toLowerCase()} class="${child.className}"> ends ${Math.round(rect.bottom - bottomLimit)}px below the content area`);
		}
		for (const element of page.querySelectorAll("*")) {
			if (element.parentElement?.closest("svg")) continue; // SVG internals are checked per figure below
			if (element.closest(".grid-bg")) continue;
			const rect = element.getBoundingClientRect();
			if (rect.width === 0 && rect.height === 0) continue;
			if (rect.left < inner.left || rect.right > inner.right || rect.top < inner.top) {
				if (element.closest(".foot")) continue;
				problems.push(`${label}: <${element.tagName.toLowerCase()} class="${element.getAttribute("class") ?? ""}"> leaves the safe area`);
			}
			const clipsX = element.scrollWidth > element.clientWidth + 1 && element.clientWidth > 0;
			const clipsY = element.scrollHeight > element.clientHeight + 1 && element.clientHeight > 0;
			if ((clipsX || clipsY) && getComputedStyle(element).overflow !== "visible" && !element.classList.contains("page")) {
				problems.push(`${label}: <${element.tagName.toLowerCase()} class="${element.getAttribute("class") ?? ""}"> clips its content`);
			}
		}
		for (const figure of page.querySelectorAll(".diagram > svg")) {
			const frame = figure.getBoundingClientRect();
			for (const text of figure.querySelectorAll("text")) {
				const rect = text.getBoundingClientRect();
				if (rect.left < frame.left - tolerance || rect.right > frame.right + tolerance || rect.top < frame.top - tolerance || rect.bottom > frame.bottom + tolerance) {
					problems.push(`${label}: diagram text "${text.textContent}" leaves the figure`);
				}
			}
		}
	});
	return { pageCount: pages.length, problems };
}

export async function renderBrochure(lang, { chromium, check = false, force = false, scale = 1.5 } = {}) {
	const source = path.join(brochureDir, `brochure.${lang}.html`);
	readFileSync(source); // fail early with a clear ENOENT
	const browser = await chromium.launch(process.env.AIDR_CHROMIUM_PATH ? { executablePath: process.env.AIDR_CHROMIUM_PATH } : {});
	try {
		const context = await browser.newContext({ viewport: { width: 794, height: 1123 }, deviceScaleFactor: scale });
		const page = await context.newPage();
		const blocked = [];
		await page.route("**/*", (route) => {
			const url = route.request().url();
			if (url.startsWith("file:") || url.startsWith("data:")) return route.continue();
			blocked.push(url);
			return route.abort();
		});
		await page.goto(pathToFileURL(source).href, { waitUntil: "load" });
		await page.emulateMedia({ media: "print" });
		await page.evaluate(() => document.fonts.ready);
		const layout = await page.evaluate(inspectLayout);
		const problems = [...layout.problems];
		if (blocked.length > 0) problems.push(`external requests are not allowed: ${blocked.join(", ")}`);
		if (layout.pageCount !== EXPECTED_PAGES) problems.push(`expected ${EXPECTED_PAGES} .page sections, found ${layout.pageCount}`);

		const pdf = await page.pdf({ format: "A4", printBackground: true, preferCSSPageSize: true });
		const pdfPages = countPdfPages(pdf);
		if (pdfPages !== EXPECTED_PAGES) problems.push(`PDF has ${pdfPages} pages, expected ${EXPECTED_PAGES}`);
		if (check || (problems.length > 0 && !force)) return { lang, pdfPages, problems, written: [] };

		const written = [];
		const pdfPath = path.join(brochureDir, `singularity-aidr-brochure-${lang}.pdf`);
		writeFileSync(pdfPath, pdf);
		written.push(pdfPath);
		mkdirSync(previewDir, { recursive: true });
		const sections = await page.$$(".page");
		for (const [index, section] of sections.entries()) {
			// Show one page at a time so it starts at y=0: A4 is not a whole number of CSS
			// pixels, and a stacked page would pick up a sliver of its neighbour.
			await page.evaluate((keep) => {
				document.querySelectorAll(".page").forEach((node, i) => {
					node.style.display = i === keep ? "" : "none";
				});
			}, index);
			const pngPath = path.join(previewDir, `brochure-${lang}-p${index + 1}.png`);
			await section.screenshot({ path: pngPath, animations: "disabled" });
			written.push(pngPath);
		}
		return { lang, pdfPages, problems, written };
	} finally {
		await browser.close();
	}
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	const chromium = loadChromium();
	let failed = false;
	for (const lang of args.langs) {
		const result = await renderBrochure(lang, { chromium, check: args.check, force: args.force, scale: args.scale });
		if (result.problems.length > 0) {
			failed = true;
			console.error(`brochure.${lang}.html: layout check FAILED`);
			for (const problem of result.problems) console.error(`  - ${problem}`);
		} else {
			console.log(`brochure.${lang}.html: ${result.pdfPages} pages, layout clean`);
		}
		for (const file of result.written) console.log(`  wrote ${path.relative(repositoryRoot, file)}`);
	}
	if (failed) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main().catch((error) => {
		console.error(error.message ?? error);
		process.exitCode = 1;
	});
}
