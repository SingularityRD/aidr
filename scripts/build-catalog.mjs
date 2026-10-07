#!/usr/bin/env node
/**
 * Build the Singularity AIDR product catalog HTML (docs/sales/catalog/catalog.<lang>.html)
 * from one bilingual source, so the Turkish and English editions always carry the same
 * pages, features and numbers.
 *
 *   node scripts/build-catalog.mjs            # write catalog.tr.html and catalog.en.html
 *   node scripts/build-catalog.mjs --check    # exit 1 when a committed HTML file is stale
 *
 * Sources (docs/sales/catalog/src/):
 *   content.mjs  facts, lifecycle stages, the numbered feature list (with evidence paths)
 *                and the page templates, written with t("Türkçe", "English") pairs
 *   styles.css   the one stylesheet both editions share (the logo is inlined at build time)
 *   icons.svg    the inline line-icon sprite
 *
 * The logo is images/singularity-logo.png, embedded unchanged as a base64 data URI. Edition
 * membership comes from the plan catalog mirror in packages/dashboard/src/billing/plans.ts.
 * The pages carry no prices by design.
 */
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const CATALOG_DIR = path.join(repositoryRoot, "docs", "sales", "catalog");
const SRC_DIR = path.join(CATALOG_DIR, "src");
export const LANGUAGES = ["tr", "en"];
export const htmlPath = (lang) => path.join(CATALOG_DIR, `catalog.${lang}.html`);

const LOCALE = { tr: "tr-TR", en: "en-GB" };

/** Parse the static plan catalog mirror (no TypeScript toolchain needed). */
export function parsePlanCatalog(source) {
	const catalog = source.slice(source.indexOf("PLAN_CATALOG"), source.indexOf("PLAN_FEATURE_LABELS"));
	const plans = {};
	for (const block of catalog.split(/\n\t\{\n/).slice(1)) {
		const scalar = (name) => {
			const match = block.match(new RegExp(`\\b${name}: ([^,\\n]+),`));
			if (!match) throw new Error(`plans.ts: ${name} not found`);
			const raw = match[1].trim();
			if (raw === "null") return null;
			return raw.startsWith('"') ? JSON.parse(raw) : Number(raw);
		};
		const list = (name) => {
			const match = block.match(new RegExp(`\\b${name}: \\[([^\\]]*)\\]`));
			if (!match) throw new Error(`plans.ts: ${name} not found`);
			return [...match[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
		};
		const id = scalar("id");
		plans[id] = {
			id,
			displayName: scalar("displayName"),
			minSeats: scalar("minSeats"),
			retentionDays: scalar("retentionDays"),
			features: list("features"),
			deployment: list("deployment"),
		};
	}
	return plans;
}

async function loadContent() {
	return import(pathToFileURL(path.join(SRC_DIR, "content.mjs")).href);
}

function escapeHtml(text) {
	return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function helpers(lang, content, plans) {
	const t = (tr, en) => (lang === "tr" ? tr : en);
	const format = (value) => {
		if (typeof value === "object" && value !== null) return `${format(value.n)}${value.plus ? "+" : ""}`;
		return typeof value === "number" ? value.toLocaleString(LOCALE[lang]) : String(value);
	};
	const fact = (key) => {
		if (!(key in content.FACTS)) throw new Error(`unknown fact ${key}`);
		return `<span data-fact="${key}">${format(content.FACTS[key])}</span>`;
	};
	/** Replace {fact-key} tokens inside feature text. */
	const withFacts = (text) => text.replace(/\{([a-z0-9-]+)\}/g, (_, key) => fact(key));
	const icon = (name, cls = "i") => `<svg class="${cls}"><use href="#i-${name}"/></svg>`;
	const numberOf = new Map(content.FEATURES.map((feature, index) => [feature.key, index + 1]));
	const stage = (key) => {
		const found = content.STAGES.find((s) => s.key === key);
		if (!found) throw new Error(`unknown stage ${key}`);
		return { ...found, ...found[lang] };
	};
	const featureItem = (feature) => {
		const [name, description] = feature[lang];
		const no = String(numberOf.get(feature.key)).padStart(2, "0");
		return `<li id="f-${feature.key}" data-feature="${feature.key}"><span class="no">${no}</span><span><b>${withFacts(name)}</b><span class="d"> — ${withFacts(description)}</span></span></li>`;
	};
	/**
	 * Numbered list of a stage's features; `groups` splits it under small sub-headings.
	 * A group without a label (`tr`/`en`) lists the stage's ungrouped features.
	 */
	const featureList = (stageKey, { cols = false, groups = null } = {}) => {
		const features = content.FEATURES.filter((f) => f.stage === stageKey);
		if (features.length === 0) throw new Error(`stage ${stageKey} has no features`);
		const list = (items) => `<ol class="flist${cols ? " cols" : ""}">\n${items.map((f) => `\t\t${featureItem(f)}`).join("\n")}\n\t</ol>`;
		if (!groups) return list(features);
		const listed = new Set();
		const html = groups
			.map((group) => {
				const items = features.filter((f) => (f.group ?? null) === (group.key ?? null));
				if (items.length === 0) throw new Error(`stage ${stageKey}: group ${group.key} has no features`);
				for (const item of items) listed.add(item.key);
				if (!group.tr) return list(items);
				const cls = group.cls ? `lsub ${group.cls}` : "lsub";
				const lang = group.lang ? ` lang="${group.lang}"` : "";
				return `<p class="${cls}"${lang}>${t(group.tr, group.en)}</p>\n\t${list(items)}`;
			})
			.join("\n\t");
		const missing = features.filter((f) => !listed.has(f.key)).map((f) => f.key);
		if (missing.length > 0) throw new Error(`stage ${stageKey}: features outside every group: ${missing.join(", ")}`);
		return html;
	};
	/** A cross-reference to a numbered feature, e.g. the "Also covered" line of a group. */
	const ref = (key) => {
		if (!numberOf.has(key)) throw new Error(`unknown feature ${key}`);
		return `<span class="ref" data-ref="${key}">${String(numberOf.get(key)).padStart(2, "0")}</span>`;
	};
	const header = (section) =>
		`<header class="hdr"><span class="brand"><span class="badge" aria-hidden="true"></span><b>Singularity AIDR</b>${t("Ürün Kataloğu 2026", "Product Catalog 2026")}</span><span class="sec">${section}</span></header>`;
	const footer = () =>
		`<footer class="foot"><span>Singularity AIDR · ${t("Ürün Kataloğu 2026", "Product Catalog 2026")}</span><span>singularityrd.com</span><span class="pn"></span></footer>`;
	const page = (id, label, section, body) =>
		`<section class="page" id="${id}" aria-label="${escapeHtml(label)}">\n\t${header(section)}\n${body}\n\t${footer()}\n</section>`;
	/** Stage heading block: number, name, the one sentence that places it in the lifecycle. */
	const stageIntro = (key) => {
		const s = stage(key);
		return `<div class="stage-intro"><span class="num">${s.n}</span><div><h2>${s.name}</h2><p>${s.intro}</p></div></div>`;
	};
	const gain = (key) => {
		const s = stage(key);
		return `<p class="gain inline"><span class="k">${t("Bu aşamada ne kazanırsınız", "What you get")}</span><span>${s.gain}</span></p>`;
	};
	return { lang, t, fact, withFacts, icon, stage, featureList, ref, header, footer, page, stageIntro, gain, plans, numberOf, escapeHtml };
}

export async function buildCatalog(lang) {
	if (!LANGUAGES.includes(lang)) throw new Error(`unknown language ${lang}`);
	const content = await loadContent();
	const plans = parsePlanCatalog(readFileSync(path.join(repositoryRoot, "packages/dashboard/src/billing/plans.ts"), "utf8"));
	const logo = readFileSync(path.join(repositoryRoot, "images", "singularity-logo.png")).toString("base64");
	const css = readFileSync(path.join(SRC_DIR, "styles.css"), "utf8").replace("__LOGO__", logo);
	const sprite = readFileSync(path.join(SRC_DIR, "icons.svg"), "utf8").trim();
	const h = helpers(lang, content, plans);
	const pages = content.pages(h);
	const title = h.t("Singularity AIDR · Ürün Kataloğu 2026", "Singularity AIDR · Product Catalog 2026");
	return `<!DOCTYPE html>
<!-- Generated from the catalog sources (see the catalog README). Do not edit by hand. -->
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
${css.trimEnd()}
</style>
</head>
<body>
${sprite}

<main class="doc">
${pages.join("\n\n")}
</main>
</body>
</html>
`;
}

async function main() {
	const check = process.argv.includes("--check");
	let stale = false;
	for (const lang of LANGUAGES) {
		const html = await buildCatalog(lang);
		const target = htmlPath(lang);
		if (check) {
			let current = "";
			try {
				current = readFileSync(target, "utf8");
			} catch {}
			if (current !== html) {
				stale = true;
				console.error(`${path.relative(repositoryRoot, target)} is out of date; run node scripts/build-catalog.mjs`);
			}
		} else {
			writeFileSync(target, html);
			console.log(`wrote ${path.relative(repositoryRoot, target)}`);
		}
	}
	if (stale) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main().catch((error) => {
		console.error(error.message ?? error);
		process.exitCode = 1;
	});
}
