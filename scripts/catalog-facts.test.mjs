/**
 * Fact, honesty and structure checks for the product catalog (docs/sales/catalog/).
 *
 *   node --test scripts/catalog-facts.test.mjs
 *
 * - Every countable claim is marked data-fact="<key>" and is recomputed here from the
 *   repository (threat rules, AI component and CVE data, MCP risk taxonomy, Browser Guard
 *   entity types and sites, DLP detectors, connectors, plan catalog, trial length).
 * - Every numbered feature carries evidence paths (docs/sales/catalog/src/content.mjs).
 *   Paths must exist, and no feature may be marked `pending`: the catalog lists shipped
 *   capabilities only.
 * - Turkish and English list the same features in the same order, with the same numbers.
 * - The copy follows the sales honesty rules: no prices, no certification, efficacy or
 *   superlative claims, no upstream vendor names, no internal codes or repository paths.
 * - The committed HTML matches the generator, the PDFs have at most ten pages, and the
 *   page previews exist.
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildCatalog, htmlPath, LANGUAGES, parsePlanCatalog } from "./build-catalog.mjs";
import { countPdfPages, EXPECTED_PAGES, MAX_PAGES, pdfPath, previewPath } from "./render-catalog.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => readFileSync(path.join(root, relative), "utf8");
const html = Object.fromEntries(LANGUAGES.map((lang) => [lang, readFileSync(htmlPath(lang), "utf8")]));
const content = await import(pathToFileURL(path.join(root, "docs/sales/catalog/src/content.mjs")).href);

function countFiles(dir) {
	let count = 0;
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		count += entry.isDirectory() ? countFiles(full) : 1;
	}
	return count;
}

const productFacts = read("packages/dashboard/src/ui/pages/public/product-facts.ts");
const listConst = (name) => [...productFacts.match(new RegExp(`${name} = \\[([^\\]]*)\\]`))[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);

function expectedFacts() {
	const threatFiles = readdirSync(path.join(root, "threats")).filter((name) => name.endsWith(".yaml"));
	const threatRules = threatFiles.reduce((sum, name) => sum + (read(`threats/${name}`).match(/^- id:/gm) ?? []).length, 0);
	const cveFloor = Number(productFacts.match(/AIG_CVE_RULES_FLOOR = (\d+)/)[1]);
	const cveRules = countFiles(path.join(root, "vendor/ai-infra-guard/data/vuln"));
	assert.ok(cveRules >= cveFloor, `CVE rule files (${cveRules}) fell below the advertised floor ${cveFloor}`);
	const mcpCategories = JSON.parse(read("packages/core/src/generated/aig-mcp-categories.json")).categories;
	const entityTypes = read("packages/browser-guard/src/types.ts").match(/export const ENTITY_TYPES = \[([\s\S]*?)\] as const/)[1].match(/"[A-Z_]+"/g);
	const dlpDetectors = read("packages/core/src/dlp/policy.ts").match(/DlpDetectorSchema = z\.enum\(\[([\s\S]*?)\]\)/)[1].match(/"[a-z_]+"/g);
	const trial = read("supabase/migrations/20260923000034_tenant_ga_admission.sql").match(/v_expires_at := v_started_at \+ interval '(\d+) days'/);
	assert.ok(trial, "trial length not found in the admission migration");
	const plans = parsePlanCatalog(read("packages/dashboard/src/billing/plans.ts"));
	return {
		"threat-rules": threatRules,
		"ai-components": countFiles(path.join(root, "vendor/ai-infra-guard/data/fingerprints")),
		"cve-rules": `${cveFloor}+`,
		"mcp-categories": mcpCategories.length,
		"bg-sites": listConst("BROWSER_GUARD_SITES").length,
		"bg-entities": entityTypes.length,
		"dlp-detectors": dlpDetectors.length,
		connectors: listConst("AGENT_CONNECTORS").length,
		"trial-days": Number(trial[1]),
		"plan-free-retention": plans.free.retentionDays,
		"plan-team-retention": plans.team.retentionDays,
		"plan-business-retention": plans.business.retentionDays,
		"plan-team-min": plans.team.minSeats,
		"plan-business-min": plans.business.minSeats,
	};
}

/** Catalog numbers use locale digit grouping ("2,000+" / "2.000+"); compare digits only. */
const normalize = (value) => String(value).replace(/[.,\s]/g, "");

function factsIn(source) {
	const facts = new Map();
	for (const match of source.matchAll(/data-fact="([a-z0-9-]+)"[^>]*>([^<]*)</g)) {
		const [, key, value] = match;
		facts.set(key, [...(facts.get(key) ?? []), value.trim()]);
	}
	return facts;
}

/** Visible text only: drop the style block, the icon sprite, comments, tags and entities. */
function visibleText(source) {
	return source
		.replace(/<style[\s\S]*?<\/style>/g, " ")
		.replace(/<svg class="sprite"[\s\S]*?<\/svg>/, " ")
		.replace(/<!--[\s\S]*?-->/g, " ")
		.replace(/<[^>]+>/g, " ")
		.replace(/&amp;/g, "&")
		.replace(/&#8209;/g, "-")
		.replace(/\s+/g, " ");
}

const featureKeys = (source) => [...source.matchAll(/data-feature="([a-z0-9-]+)"/g)].map((m) => m[1]);

test("the committed HTML matches the generator", async () => {
	for (const lang of LANGUAGES) {
		assert.equal(html[lang], await buildCatalog(lang), `catalog.${lang}.html is stale; run pnpm catalog:render`);
	}
});

test("every countable claim matches the repository", () => {
	const expected = expectedFacts();
	assert.deepEqual(Object.keys(content.FACTS).sort(), Object.keys(expected).sort(), "FACTS and the derivations in this test must cover the same keys");
	for (const [key, value] of Object.entries(expected)) {
		assert.equal(normalize(typeof content.FACTS[key] === "object" ? `${content.FACTS[key].n}+` : content.FACTS[key]), normalize(value), `FACTS.${key} is ${JSON.stringify(content.FACTS[key])}, repository says ${value}`);
	}
	for (const lang of LANGUAGES) {
		const facts = factsIn(html[lang]);
		for (const [key, value] of Object.entries(expected)) {
			const found = facts.get(key);
			assert.ok(found, `catalog.${lang}.html: data-fact="${key}" is missing`);
			for (const text of found) assert.equal(normalize(text), normalize(value), `catalog.${lang}.html: ${key} says ${text}, repository says ${value}`);
		}
		for (const key of facts.keys()) assert.ok(key in expected, `catalog.${lang}.html: unknown data-fact="${key}"`);
	}
});

test("Turkish and English list the same numbered features", () => {
	const keys = content.FEATURES.map((f) => f.key);
	assert.equal(new Set(keys).size, keys.length, "feature keys must be unique");
	const tr = featureKeys(html.tr);
	const en = featureKeys(html.en);
	assert.deepEqual(tr, keys, "catalog.tr.html feature list differs from content.mjs");
	assert.deepEqual(en, keys, "catalog.en.html feature list differs from content.mjs");
	assert.equal(tr.length, en.length, "TR and EN feature counts differ");
	for (const lang of LANGUAGES) {
		const numbers = [...html[lang].matchAll(/data-feature="[a-z0-9-]+"><span class="no">(\d+)<\/span>/g)].map((m) => Number(m[1]));
		assert.deepEqual(numbers, keys.map((_, i) => i + 1), `catalog.${lang}.html: features must be numbered 1..${keys.length} in order`);
	}
	const stages = new Set(content.STAGES.map((s) => s.key));
	for (const feature of content.FEATURES) {
		assert.ok(stages.has(feature.stage), `${feature.key}: unknown stage ${feature.stage}`);
		for (const lang of LANGUAGES) assert.ok(Array.isArray(feature[lang]) && feature[lang].length === 2 && feature[lang].every(Boolean), `${feature.key}: needs a ${lang} name and line`);
	}
	for (const stage of content.STAGES) {
		assert.ok(content.FEATURES.some((f) => f.stage === stage.key), `stage ${stage.key} lists no features`);
		for (const lang of LANGUAGES) assert.ok(html[lang].includes(stage[lang].intro), `catalog.${lang}.html: stage ${stage.key} does not open with its lifecycle sentence`);
	}
	console.log(`# catalog lists ${keys.length} features in both languages`);
});

test("every feature is backed by code in this repository", async (t) => {
	for (const feature of content.FEATURES) {
		assert.ok(Array.isArray(feature.evidence) && feature.evidence.length > 0, `${feature.key}: evidence paths are required`);
		assert.ok(!("pending" in feature), `${feature.key}: the published catalog lists shipped features only; remove "pending" and point evidence at the merged code`);
		await t.test(feature.key, () => {
			for (const evidence of feature.evidence) assert.ok(existsSync(path.join(root, evidence)), `${feature.key}: ${evidence} does not exist`);
		});
	}
});

test("the AI safety group lists its features and cross-references shipped controls", () => {
	const safety = content.FEATURES.filter((f) => f.group === "safety");
	assert.ok(safety.length >= 9, "the AI safety group lists at least nine features");
	const index = new Map(content.FEATURES.map((feature, i) => [feature.key, i + 1]));
	for (const item of content.SAFETY_ALSO) {
		for (const [file, pattern] of item.evidence) assert.ok(read(file).includes(pattern), `${item.key}: ${file} does not contain "${pattern}"`);
		for (const key of item.refs) {
			assert.ok(index.has(key), `${item.key}: unknown feature ${key}`);
			assert.ok(!content.FEATURES[index.get(key) - 1].pending, `${item.key}: ${key} is still pending, so it is not a shipped control`);
		}
	}
	for (const lang of LANGUAGES) {
		assert.ok(visibleText(html[lang]).includes(lang === "tr" ? "Yapay zekâ güvenliği" : "AI safety"), `catalog.${lang}.html has no AI safety label`);
		const shown = [...html[lang].matchAll(/data-safety="([a-z-]+)"/g)].map((m) => m[1]);
		assert.deepEqual(shown, content.SAFETY_ALSO.map((item) => item.key), `catalog.${lang}.html: safety cross-references differ from content.mjs`);
		for (const [, key, number] of html[lang].matchAll(/data-ref="([a-z0-9-]+)">(\d+)</g)) assert.equal(Number(number), index.get(key), `catalog.${lang}.html: reference to ${key} shows ${number}`);
	}
});

test("every connector, Browser Guard site and browser from product-facts.ts is named", () => {
	const names = [...listConst("AGENT_CONNECTORS"), ...listConst("BROWSER_GUARD_SITES"), ...listConst("BROWSER_GUARD_BROWSERS")];
	assert.ok(names.length >= 17);
	for (const lang of LANGUAGES) {
		const text = visibleText(html[lang]);
		for (const name of names) assert.ok(text.includes(name), `catalog.${lang}.html does not name ${name}`);
	}
});

test("MCP risk categories and component examples match the product data", () => {
	const categories = JSON.parse(read("packages/core/src/generated/aig-mcp-categories.json")).categories;
	const en = visibleText(html.en);
	for (const category of categories) assert.ok(en.includes(category.name), `catalog.en.html is missing MCP risk category "${category.name}"`);
	for (const lang of LANGUAGES) assert.equal((html[lang].match(/data-mcp-category/g) ?? []).length, categories.length);
	const fingerprints = readdirSync(path.join(root, "vendor/ai-infra-guard/data/fingerprints")).map((name) => name.toLowerCase());
	const prefix = { "Open WebUI": "openwebui", Jupyter: "jupyter-" };
	for (const lang of LANGUAGES) {
		const components = [...html[lang].matchAll(/data-component="([^"]+)"/g)].map((m) => m[1]);
		assert.ok(components.length >= 8, "name at least eight recognised components");
		for (const component of components) {
			const key = prefix[component] ?? component.toLowerCase();
			assert.ok(fingerprints.some((name) => name.startsWith(key)), `no fingerprint for ${component}`);
		}
	}
});

test("the editions table follows the plan catalog", () => {
	const plans = parsePlanCatalog(read("packages/dashboard/src/billing/plans.ts"));
	for (const lang of LANGUAGES) {
		const cells = [...html[lang].matchAll(/data-plan-feature="([a-z]+):([a-z_]+)"[^>]*>([\s\S]*?)<\/td>/g)];
		assert.ok(cells.length >= 36, `catalog.${lang}.html: editions table is incomplete`);
		for (const [, plan, feature, cell] of cells) {
			const included = plans[plan].features.includes(feature);
			assert.equal(cell.includes('class="yes"'), included, `catalog.${lang}.html: ${plan} ${included ? "includes" : "does not include"} ${feature}`);
		}
		for (const plan of Object.keys(plans)) assert.ok(html[lang].includes(`data-plan-deploy="${plan}"`), `catalog.${lang}.html: deployment missing for ${plan}`);
	}
});

test("copy follows the sales honesty rules", () => {
	const registry = JSON.parse(read("docs/production-readiness/commercial-go-evidence-registry.json"));
	const banned = [
		/fail[- ]?open/i,
		/\bMIT\b/,
		/open[- ]source/i,
		/açık kaynak/i,
		/\b\d+\s?ms\b/i,
		/millisecond|milisaniye|latency|gecikme/i,
		/\bonly (?:tool|solution|product|platform)\b|\btek (?:araç|çözüm)\b/i,
		/\b(?:the )?(?:first|best|leading|number one|#1)\s+(?:ai|platform|solution|product|tool|vendor)\b/i,
		/\b(?:ilk|en iyi|lider)\s+(?:platform|çözüm|ürün|araç)/i,
		/SOC ?2|ISO ?27001|HIPAA/i,
		/\bcertified\b|\bcertification\b|sertifikal|sertifikasyon/i,
		/testimonial|case stud|referans müşteri/i,
		/\bguarantee|garanti/i,
		...registry.claimPatterns.map((pattern) => new RegExp(pattern.pattern, "iu")),
	];
	// No prices: no currency symbols, codes, per-period wording or amounts with a currency.
	const prices = [/[$€₺£]/, /\b(?:USD|EUR|TRY|TL|GBP)\b/, /\bper (?:month|year|seat|developer)\b/i, /\/\s?(?:ay|month|mo|yıl|year|yr)\b/i, /\baylık\b|\byıllık\b/i, /\d\s?(?:USD|EUR|TL|TRY|dolar|lira)\b/i];
	for (const lang of LANGUAGES) {
		const text = visibleText(html[lang]);
		for (const pattern of [...banned, ...prices]) assert.doesNotMatch(text, pattern, `catalog.${lang}.html matches banned pattern ${pattern}`);
		// Anywhere in the file, comments and attributes included.
		assert.doesNotMatch(html[lang], /ai[- ]?infra[- ]?guard|\bAIG\b|tencent/i, `catalog.${lang}.html names an upstream vendor`);
		assert.doesNotMatch(html[lang], /\bCOM-\d|\bAIDR-\d{3}|NO-GO|\bpnpm\b|(?:packages|docs|scripts|supabase|vendor)\/[a-z]/, `catalog.${lang}.html contains an internal code or repository path`);
		assert.doesNotMatch(html[lang], /sales@singularityrd\.com/, `catalog.${lang}.html uses the old contact address`);
	}
	const required = {
		tr: [
			"Yapay zekâ ajan güvenliğinin tüm yaşam döngüsü, tek platformda.",
			"KVKK ve GDPR yükümlülüklerini desteklemek üzere tasarlandı",
			"Fiyatlandırma ve teklif için bizimle iletişime geçin: anil@singularityrd.com",
			"Keşiften kanıta — ajanlarınızın her adımı görünür, denetlenir ve kanıtlanır.",
			"singularityrd.com",
		],
		en: [
			"The entire AI agent security lifecycle, in one platform.",
			"Designed to support KVKK and GDPR obligations",
			"Contact us for pricing and a quote: anil@singularityrd.com",
			"From discovery to proof — every step your agents take is visible, controlled and proven.",
			"singularityrd.com",
		],
	};
	for (const lang of LANGUAGES) {
		const text = visibleText(html[lang]);
		for (const phrase of required[lang]) assert.ok(text.includes(phrase), `catalog.${lang}.html lacks "${phrase}"`);
	}
});

test("pages are self-contained, share one stylesheet and embed the brand logo unchanged", () => {
	const style = (source) => source.match(/<style>[\s\S]*?<\/style>/)[0];
	assert.equal(style(html.tr), style(html.en), "the two catalogs must carry an identical <style> block");
	const logo = readFileSync(path.join(root, "images/singularity-logo.png")).toString("base64");
	const oldShield = [...read("images/aidr-logo-shaded.svg").matchAll(/<path d="([^"]+)"/g)].map((m) => m[1]);
	for (const lang of LANGUAGES) {
		const source = html[lang];
		assert.match(source, /@page\s*\{\s*size:\s*A4/);
		assert.ok(source.includes(`data:image/png;base64,${logo}`), `catalog.${lang}.html does not embed images/singularity-logo.png unchanged`);
		for (const d of oldShield) assert.ok(!source.includes(d), `catalog.${lang}.html uses the old shield logo`);
		assert.equal((source.match(/<section class="page[ "]/g) ?? []).length, EXPECTED_PAGES);
		assert.doesNotMatch(source, /<link\b|<script\b|@import|@font-face|\b(?:src|href)="(?:https?:)?\/\//i, `catalog.${lang}.html loads an external resource`);
		assert.doesNotMatch(source, /url\(\s*['"]?(?:https?:)?\/\//i, `catalog.${lang}.html references an external URL in CSS`);
	}
});

test("rendered PDFs have at most ten pages and every page has a preview", () => {
	assert.ok(EXPECTED_PAGES <= MAX_PAGES);
	for (const lang of LANGUAGES) {
		const pdf = pdfPath(lang);
		assert.ok(existsSync(pdf), `${pdf} is missing; run pnpm catalog:render`);
		const pages = countPdfPages(readFileSync(pdf));
		assert.ok(pages <= MAX_PAGES, `${path.basename(pdf)} has ${pages} pages; the catalog must stay within ${MAX_PAGES}`);
		assert.equal(pages, EXPECTED_PAGES);
		for (let page = 1; page <= EXPECTED_PAGES; page += 1) {
			const png = previewPath(lang, page);
			assert.ok(existsSync(png), `${png} is missing; run pnpm catalog:render`);
			assert.equal(readFileSync(png).subarray(1, 4).toString("latin1"), "PNG");
		}
		assert.ok(!existsSync(previewPath(lang, EXPECTED_PAGES + 1)), `stale preview beyond page ${EXPECTED_PAGES}`);
	}
});

test("countPdfPages counts page objects, not the page tree", () => {
	const pdf = Buffer.from("<< /Type /Pages /Kids [1 0 R 2 0 R] >> << /Type /Page >> << /Type/Page /Parent 3 0 R >>", "latin1");
	assert.equal(countPdfPages(pdf), 2);
});
