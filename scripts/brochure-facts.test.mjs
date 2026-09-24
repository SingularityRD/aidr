/**
 * Fact and honesty checks for the product brochure (docs/sales/brochure/).
 *
 *   node --test scripts/brochure-facts.test.mjs
 *
 * Every countable claim in the brochure is marked with data-fact="<key>". This test
 * recomputes each value from the repository (threat rules, AIG data, plan catalog,
 * trial length) so a rule or price change that is not reflected in the brochure fails
 * here instead of shipping stale sales copy. It also enforces the sales honesty rules
 * (docs/sales/pricing.md §6) and the brochure's self-containment.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { countPdfPages, EXPECTED_PAGES, LANGUAGES } from "./render-brochure.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const brochureDir = path.join(root, "docs", "sales", "brochure");
const read = (relative) => readFileSync(path.join(root, relative), "utf8");
const html = Object.fromEntries(LANGUAGES.map((lang) => [lang, read(`docs/sales/brochure/brochure.${lang}.html`)]));

function countFiles(dir) {
	let count = 0;
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		count += entry.isDirectory() ? countFiles(full) : 1;
	}
	return count;
}

function planCatalog() {
	const source = read("packages/dashboard/src/billing/plans.ts");
	const catalog = source.slice(source.indexOf("PLAN_CATALOG"), source.indexOf("PLAN_FEATURE_LABELS"));
	const plans = {};
	for (const block of catalog.split(/\n\t\{\n/).slice(1)) {
		const field = (name) => {
			const match = block.match(new RegExp(`\\b${name}: ([^,\\n]+),`));
			assert.ok(match, `plans.ts: ${name} not found`);
			const raw = match[1].trim();
			if (raw === "null") return null;
			return raw.startsWith('"') ? JSON.parse(raw) : Number(raw);
		};
		plans[field("id")] = {
			includedAgents: field("includedAgents"),
			minSeats: field("minSeats"),
			monthly: field("priceMonthlyCents"),
			yearly: field("priceYearlyCents"),
			retentionDays: field("retentionDays"),
		};
	}
	return plans;
}

const dollars = (cents) => `$${cents / 100}`;

function expectedFacts() {
	const threatFiles = readdirSync(path.join(root, "threats")).filter((name) => name.endsWith(".yaml"));
	const threatRules = threatFiles.reduce((sum, name) => sum + (read(`threats/${name}`).match(/^- id:/gm) ?? []).length, 0);
	const productFacts = read("packages/dashboard/src/ui/pages/public/product-facts.ts");
	const cveFloor = Number(productFacts.match(/AIG_CVE_RULES_FLOOR = (\d+)/)[1]);
	const cveRules = countFiles(path.join(root, "vendor/ai-infra-guard/data/vuln"));
	assert.ok(cveRules >= cveFloor, `AIG CVE rules (${cveRules}) fell below the advertised floor ${cveFloor}`);
	const trial = read("supabase/migrations/20260923000034_tenant_ga_admission.sql").match(/v_expires_at := v_started_at \+ interval '(\d+) days'/);
	assert.ok(trial, "trial length not found in the admission migration");
	const plans = planCatalog();
	return {
		"threat-rules": threatRules,
		"threat-files": threatFiles.length,
		"aig-cve-floor": `${cveFloor}+`,
		"aig-components": countFiles(path.join(root, "vendor/ai-infra-guard/data/fingerprints")),
		"plan-free-price": dollars(plans.free.monthly),
		"plan-free-agents": plans.free.includedAgents,
		"plan-free-retention": plans.free.retentionDays,
		"plan-team-monthly": dollars(plans.team.monthly),
		"plan-team-annual-monthly": dollars(Math.round(plans.team.yearly / 12)),
		"plan-team-min": plans.team.minSeats,
		"plan-team-retention": plans.team.retentionDays,
		"plan-business-annual-monthly": dollars(Math.round(plans.business.yearly / 12)),
		"plan-business-min": plans.business.minSeats,
		"plan-business-retention": plans.business.retentionDays,
		"trial-days": Number(trial[1]),
		// The plan catalog must still offer what the brochure's table assumes.
		_shape: [plans.business.monthly, plans.enterprise.monthly, plans.enterprise.yearly, plans.enterprise.retentionDays],
	};
}

/** Brochure numbers use locale digit grouping ("2,000+" / "2.000+"); compare digits only. */
const normalize = (value) => String(value).replace(/[.,\s]/g, "");

function factsIn(source) {
	const facts = new Map();
	for (const match of source.matchAll(/data-fact="([a-z0-9-]+)"[^>]*>([^<]*)</g)) {
		const [, key, value] = match;
		facts.set(key, [...(facts.get(key) ?? []), value.trim()]);
	}
	return facts;
}

/** Visible text only: drop the style block, scripts, tags and entities. */
function visibleText(source) {
	return source
		.replace(/<style[\s\S]*?<\/style>/g, " ")
		.replace(/<script[\s\S]*?<\/script>/g, " ")
		.replace(/<[^>]+>/g, " ")
		.replace(/&amp;/g, "&")
		.replace(/\s+/g, " ");
}

test("every countable claim matches the repository", () => {
	const expected = expectedFacts();
	assert.deepEqual(expected._shape, [null, null, null, null], "plan catalog changed shape (Business monthly / Enterprise pricing); update the brochure table");
	for (const lang of LANGUAGES) {
		const facts = factsIn(html[lang]);
		for (const [key, value] of Object.entries(expected)) {
			if (key.startsWith("_")) continue;
			const found = facts.get(key);
			assert.ok(found, `brochure.${lang}.html: data-fact="${key}" is missing`);
			for (const text of found) assert.equal(normalize(text), normalize(value), `brochure.${lang}.html: ${key} says ${text}, repository says ${value}`);
		}
		for (const key of facts.keys()) assert.ok(key in expected, `brochure.${lang}.html: unknown data-fact="${key}"`);
	}
});

test("every connector and Browser Guard site from product-facts.ts is named", () => {
	const productFacts = read("packages/dashboard/src/ui/pages/public/product-facts.ts");
	const list = (name) => [...productFacts.match(new RegExp(`${name} = \\[([^\\]]*)\\]`))[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
	const names = [...list("AGENT_CONNECTORS"), ...list("BROWSER_GUARD_SITES"), ...list("BROWSER_GUARD_BROWSERS")];
	assert.ok(names.length >= 17);
	for (const lang of LANGUAGES) {
		const text = visibleText(html[lang]);
		for (const name of names) assert.ok(text.includes(name), `brochure.${lang}.html does not name ${name}`);
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
		/\bonly (?:tool|solution|product)\b|\btek (?:araç|çözüm)\b/i,
		/SOC ?2|ISO ?27001|certif|sertifika/i,
		/testimonial|case stud|referans müşteri/i,
		/\bguarantee|garanti/i,
		...registry.claimPatterns.map((pattern) => new RegExp(pattern.pattern, "iu")),
	];
	for (const lang of LANGUAGES) {
		const text = visibleText(html[lang]);
		for (const pattern of banned) assert.doesNotMatch(text, pattern, `brochure.${lang}.html matches banned pattern ${pattern}`);
	}
	const required = {
		tr: ["Liste fiyatlarıdır; nihai ticari onaya tabidir", "KVKK ve GDPR yükümlülüklerini desteklemek üzere tasarlandı", "sales@singularityrd.com", "singularityrd.com"],
		en: ["List prices; subject to final commercial approval", "Designed to support KVKK and GDPR obligations", "sales@singularityrd.com", "singularityrd.com"],
	};
	for (const lang of LANGUAGES) {
		const text = visibleText(html[lang]);
		for (const phrase of required[lang]) assert.ok(text.includes(phrase), `brochure.${lang}.html lacks "${phrase}"`);
	}
});

test("pages are self-contained, share one stylesheet and embed the brand logo", () => {
	const style = (source) => source.match(/<style>[\s\S]*?<\/style>/)[0];
	assert.equal(style(html.tr), style(html.en), "the two brochures must carry an identical <style> block");
	const logo = read("images/aidr-logo-shaded.svg");
	const paths = [...logo.matchAll(/<path d="([^"]+)"/g)].map((m) => m[1]);
	assert.ok(paths.length > 0);
	for (const lang of LANGUAGES) {
		const source = html[lang];
		assert.match(source, /@page\s*\{\s*size:\s*A4/);
		assert.equal((source.match(/<section class="page[ "]/g) ?? []).length, EXPECTED_PAGES);
		assert.doesNotMatch(source, /<link\b|@import|@font-face|\b(?:src|href)="(?:https?:)?\/\//i, `brochure.${lang}.html loads an external resource`);
		assert.doesNotMatch(source, /url\(\s*['"]?(?:https?:)?\/\//i, `brochure.${lang}.html references an external URL in CSS`);
		for (const d of paths) assert.ok(source.includes(`d="${d}"`), `brochure.${lang}.html is missing a logo path`);
	}
});

test("rendered PDFs and previews are committed with the expected page count", () => {
	for (const lang of LANGUAGES) {
		const pdf = path.join(brochureDir, `singularity-aidr-brochure-${lang}.pdf`);
		assert.ok(existsSync(pdf), `${pdf} is missing; run pnpm brochure:render`);
		assert.equal(countPdfPages(readFileSync(pdf)), EXPECTED_PAGES);
		assert.ok(statSync(pdf).mtimeMs > 0);
		for (let page = 1; page <= EXPECTED_PAGES; page += 1) {
			const png = path.join(brochureDir, "preview", `brochure-${lang}-p${page}.png`);
			assert.ok(existsSync(png), `${png} is missing; run pnpm brochure:render`);
			assert.equal(readFileSync(png).subarray(1, 4).toString("latin1"), "PNG");
		}
	}
});

test("countPdfPages counts page objects, not the page tree", () => {
	const pdf = Buffer.from("<< /Type /Pages /Kids [1 0 R 2 0 R] >> << /Type /Page >> << /Type/Page /Parent 3 0 R >>", "latin1");
	assert.equal(countPdfPages(pdf), 2);
});
