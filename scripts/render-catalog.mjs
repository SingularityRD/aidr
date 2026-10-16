#!/usr/bin/env node
/**
 * Build the Singularity AIDR product catalog (scripts/build-catalog.mjs writes
 * docs/sales/catalog/catalog.<lang>.html) and render it to an A4 PDF and per-page PNG
 * previews with headless Chromium.
 *
 *   node scripts/render-catalog.mjs                 # build, then PDF + PNG previews for both languages
 *   node scripts/render-catalog.mjs --lang=tr       # one language
 *   node scripts/render-catalog.mjs --check         # layout checks only, write nothing
 *   node scripts/render-catalog.mjs --force         # write output even when a check fails (for iterating)
 *
 * playwright-core is a devDependency of packages/browser-guard, so it is resolved from
 * there. The Chromium build comes from PLAYWRIGHT_BROWSERS_PATH (or AIDR_CHROMIUM_PATH); on
 * Linux only the fonts in scripts/lib/render-fonts.conf are visible (scripts/lib/render-browser.mjs).
 *
 * Before writing anything the script checks the rendered layout and exits non-zero when a
 * page overflows, content runs into the page footer, an element leaves the safe area or
 * clips its content, diagram text leaves its figure, a heading is orphaned at the bottom
 * of a page or column, a table-of-contents page number is wrong, an icon reference is
 * broken, the page makes a network request, or the PDF does not have exactly the
 * expected number of pages (ten: the catalog is deliberately short).
 */
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildCatalog, CATALOG_DIR, htmlPath, LANGUAGES } from "./build-catalog.mjs";
import { launchRenderBrowser, loadChromium } from "./lib/render-browser.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const previewDir = path.join(CATALOG_DIR, "preview");
export { LANGUAGES };
/** Cover, eight content pages, back cover. Never more than MAX_PAGES. */
export const EXPECTED_PAGES = 10;
export const MAX_PAGES = 10;

export const sourcePath = htmlPath;
export const pdfPath = (lang) => path.join(CATALOG_DIR, `singularity-aidr-catalog-${lang}.pdf`);
export const previewPath = (lang, page) =>
	path.join(previewDir, `catalog-${lang}-p${String(page).padStart(2, "0")}.png`);

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
			console.log("Usage: node scripts/render-catalog.mjs [--lang=tr|en] [--check] [--force] [--scale=1.5]");
			process.exit(0);
		} else throw new Error(`Unknown argument: ${arg}`);
	}
	return args;
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
	const mm = 96 / 25.4;
	const describe = (element) => {
		const text = (element.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
		return `<${element.tagName.toLowerCase()} class="${element.getAttribute("class") ?? ""}">${text ? ` "${text}"` : ""}`;
	};
	const chrome = (element) => element.closest(".hdr, .foot");

	pages.forEach((page, index) => {
		const label = `page ${index + 1} (${page.id || "no id"})`;
		if (page.scrollHeight > page.clientHeight + 1) problems.push(`${label}: content overflows vertically (${page.scrollHeight} > ${page.clientHeight}px)`);
		if (page.scrollWidth > page.clientWidth + 1) problems.push(`${label}: content overflows horizontally (${page.scrollWidth} > ${page.clientWidth}px)`);
		const box = page.getBoundingClientRect();
		const style = getComputedStyle(page);
		const inner = {
			left: box.left + Number.parseFloat(style.paddingLeft) - tolerance,
			right: box.right - Number.parseFloat(style.paddingRight) + tolerance,
			top: box.top + Number.parseFloat(style.paddingTop) - tolerance,
			bottom: box.bottom - Number.parseFloat(style.paddingBottom) + tolerance,
		};
		const foot = page.querySelector(":scope > .foot");
		const bottomLimit = foot ? Math.min(inner.bottom, foot.getBoundingClientRect().top - 2) : inner.bottom;
		if (!page.classList.contains("cover")) {
			if (!page.querySelector(":scope > .hdr")) problems.push(`${label}: missing page header`);
			if (!foot?.querySelector(".pn")) problems.push(`${label}: missing page-number footer`);
		}
		for (const child of page.children) {
			if (chrome(child)) continue;
			const rect = child.getBoundingClientRect();
			if (rect.bottom > bottomLimit) problems.push(`${label}: ${describe(child)} ends ${Math.round(rect.bottom - bottomLimit)}px below the content area`);
		}
		for (const element of page.querySelectorAll("*")) {
			if (element.parentElement?.closest("svg")) continue; // SVG internals are checked per figure below
			if (element.closest(".sprite")) continue;
			const rect = element.getBoundingClientRect();
			if (rect.width === 0 && rect.height === 0) continue;
			if (!chrome(element) && (rect.left < inner.left || rect.right > inner.right || rect.top < inner.top || rect.bottom > inner.bottom)) {
				problems.push(`${label}: ${describe(element)} leaves the safe area`);
			}
			const clipsX = element.scrollWidth > element.clientWidth + 1 && element.clientWidth > 0;
			const clipsY = element.scrollHeight > element.clientHeight + 1 && element.clientHeight > 0;
			if ((clipsX || clipsY) && getComputedStyle(element).overflow !== "visible" && !element.classList.contains("page")) {
				problems.push(`${label}: ${describe(element)} clips its content`);
			}
		}
		// A heading must be followed by content in the same column and must not sit at the
		// very bottom of the page.
		for (const heading of page.querySelectorAll("h2, h3, h4")) {
			if (chrome(heading) || heading.closest(".head, .band, .gain")) continue;
			const next = heading.nextElementSibling;
			if (!next) problems.push(`${label}: heading "${heading.textContent.trim()}" has no content after it`);
			const rect = heading.getBoundingClientRect();
			if (rect.bottom > bottomLimit - 14 * mm) problems.push(`${label}: heading "${heading.textContent.trim()}" is orphaned at the bottom of the page`);
			if (next) {
				const nextRect = next.getBoundingClientRect();
				if (nextRect.top > rect.bottom + 12 * mm || nextRect.left > rect.right + 2) problems.push(`${label}: heading "${heading.textContent.trim()}" is separated from its content (column break)`);
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

	// Table-of-contents and cross-reference page numbers must point at the right page.
	for (const ref of document.querySelectorAll("[data-page-of]")) {
		const target = ref.getAttribute("data-page-of");
		const section = document.getElementById(target)?.closest(".page");
		const expected = section ? pages.indexOf(section) + 1 : undefined;
		if (!expected) problems.push(`page reference to unknown section #${target}`);
		else if (ref.textContent.trim() !== String(expected).padStart(2, "0")) problems.push(`page reference to #${target} says ${ref.textContent.trim()}, section is on page ${String(expected).padStart(2, "0")}`);
	}
	for (const use of document.querySelectorAll("use")) {
		const href = use.getAttribute("href") ?? "";
		if (!href.startsWith("#") || !document.getElementById(href.slice(1))) problems.push(`broken icon reference ${href}`);
	}
	return { pageCount: pages.length, problems };
}

export async function renderCatalog(lang, { chromium, check = false, force = false, scale = 1.5 } = {}) {
	const source = sourcePath(lang);
	readFileSync(source); // fail early with a clear ENOENT
	const browser = await launchRenderBrowser(chromium);
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
		writeFileSync(pdfPath(lang), pdf);
		written.push(pdfPath(lang));
		mkdirSync(previewDir, { recursive: true });
		for (const stale of readdirSync(previewDir)) {
			if (stale.startsWith(`catalog-${lang}-p`)) rmSync(path.join(previewDir, stale));
		}
		const sections = await page.$$(".page");
		for (const [index, section] of sections.entries()) {
			// Show one page at a time so it starts at y=0: A4 is not a whole number of CSS
			// pixels, and a stacked page would pick up a sliver of its neighbour. Hidden pages
			// no longer increment the page counter, so seed it for the visible page, and paint
			// the body in the page colour so the sub-pixel bottom row does not show through.
			await page.evaluate((keep) => {
				document.querySelectorAll(".page").forEach((node, i) => {
					node.style.display = i === keep ? "" : "none";
					node.style.counterReset = i === keep ? `pg ${keep}` : "";
					if (i === keep) document.body.style.background = getComputedStyle(node).backgroundColor;
				});
			}, index);
			const png = previewPath(lang, index + 1);
			await section.screenshot({ path: png, animations: "disabled" });
			written.push(png);
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
		if (!args.check) writeFileSync(sourcePath(lang), await buildCatalog(lang));
		const result = await renderCatalog(lang, { chromium, check: args.check, force: args.force, scale: args.scale });
		if (result.problems.length > 0) {
			failed = true;
			console.error(`catalog.${lang}.html: layout check FAILED`);
			for (const problem of result.problems) console.error(`  - ${problem}`);
		} else {
			console.log(`catalog.${lang}.html: ${result.pdfPages} pages, layout clean`);
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
