/**
 * Fact and honesty checks for the product brochure (docs/sales/brochure/).
 *
 *   node --test scripts/brochure-facts.test.mjs
 *
 * Every countable claim in the brochure is marked with data-fact="<key>". This test
 * recomputes each value from the repository (threat rules, posture scanner data, plan
 * catalog, trial length) so a rule or catalog change that is not reflected in the
 * brochure fails here instead of shipping stale sales copy. It also enforces the sales
 * honesty rules (docs/sales/pricing.md §6), the brochure's no-price rule, the contact
 * address, the company logo and the brochure's self-containment.
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
const CONTACT = "anil@singularityrd.com";
const EDITIONS = ["Free", "Team", "Business", "Enterprise"];

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
		const list = (name) => {
			const match = block.match(new RegExp(`\\b${name}: \\[([^\\]]*)\\]`));
			assert.ok(match, `plans.ts: ${name} not found`);
			return [...match[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
		};
		plans[field("id")] = {
			includedAgents: field("includedAgents"),
			minSeats: field("minSeats"),
			retentionDays: field("retentionDays"),
			deployment: list("deployment"),
			features: list("features"),
		};
	}
	return plans;
}

/** Skill-scan categories as the brochure writes them: "T01–T09" (contiguous, en dash). */
function skillScanCodes() {
	const codes = [...new Set([...read("threats/skill-scan.yaml").matchAll(/^- id: "SKILL-(T\d\d)-/gm)].map((m) => m[1]))].sort();
	assert.ok(codes.length > 0, "threats/skill-scan.yaml has no SKILL-Txx rules");
	const numbers = codes.map((code) => Number(code.slice(1)));
	numbers.forEach((n, i) => assert.equal(n, numbers[0] + i, `skill-scan categories are not contiguous: ${codes.join(", ")}`));
	return `${codes[0]}–${codes.at(-1)}`;
}

function expectedFacts() {
	const threatFiles = readdirSync(path.join(root, "threats")).filter((name) => name.endsWith(".yaml"));
	const threatRules = threatFiles.reduce((sum, name) => sum + (read(`threats/${name}`).match(/^- id:/gm) ?? []).length, 0);
	const productFacts = read("packages/dashboard/src/ui/pages/public/product-facts.ts");
	const cveFloor = Number(productFacts.match(/AIG_CVE_RULES_FLOOR = (\d+)/)[1]);
	const cveRules = countFiles(path.join(root, "vendor/ai-infra-guard/data/vuln"));
	assert.ok(cveRules >= cveFloor, `CVE rules (${cveRules}) fell below the advertised floor ${cveFloor}`);
	const mcpCategories = new Set(read("packages/core/src/mcp-aig-categories.ts").match(/\bid: "mcp-\d+"/g) ?? []).size;
	const trial = read("supabase/migrations/20260923000034_tenant_ga_admission.sql").match(/v_expires_at := v_started_at \+ interval '(\d+) days'/);
	assert.ok(trial, "trial length not found in the admission migration");
	const plans = planCatalog();
	return {
		"threat-rules": threatRules,
		"threat-files": threatFiles.length,
		"posture-cve-floor": `${cveFloor}+`,
		"posture-components": countFiles(path.join(root, "vendor/ai-infra-guard/data/fingerprints")),
		"mcp-risk-categories": mcpCategories,
		"skill-scan-codes": skillScanCodes(),
		"plan-free-agents": plans.free.includedAgents,
		"plan-free-retention": plans.free.retentionDays,
		"plan-team-min": plans.team.minSeats,
		"plan-team-retention": plans.team.retentionDays,
		"plan-business-min": plans.business.minSeats,
		"plan-business-retention": plans.business.retentionDays,
		"trial-days": Number(trial[1]),
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

/** Markup and text, including attributes and comments, without the style block, scripts and data: URIs. */
function markup(source) {
	return source
		.replace(/<style[\s\S]*?<\/style>/g, " ")
		.replace(/<script[\s\S]*?<\/script>/g, " ")
		.replace(/data:[a-z]+\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+/g, "data:");
}

test("every countable claim matches the repository", () => {
	const expected = expectedFacts();
	for (const lang of LANGUAGES) {
		const facts = factsIn(html[lang]);
		for (const [key, value] of Object.entries(expected)) {
			const found = facts.get(key);
			assert.ok(found, `brochure.${lang}.html: data-fact="${key}" is missing`);
			for (const text of found) assert.equal(normalize(text), normalize(value), `brochure.${lang}.html: ${key} says ${text}, repository says ${value}`);
		}
		for (const key of facts.keys()) assert.ok(key in expected, `brochure.${lang}.html: unknown data-fact="${key}"`);
	}
});

test("the editions block matches the plan catalog", () => {
	const plans = planCatalog();
	assert.deepEqual(Object.keys(plans), EDITIONS.map((name) => name.toLowerCase()), "plan catalog ids changed; update the brochure editions");
	// What the four edition cards say about deployment, retention and features. A catalog change
	// here must be carried into both brochures before this expectation is updated.
	const shape = Object.fromEntries(Object.entries(plans).map(([id, plan]) => [id, { deployment: plan.deployment, features: plan.features, retentionDays: plan.retentionDays }]));
	assert.deepEqual(shape, {
		free: { deployment: ["cloud"], features: ["local_detection", "dashboard"], retentionDays: 7 },
		team: { deployment: ["cloud"], features: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso"], retentionDays: 90 },
		business: {
			deployment: ["cloud", "onprem"],
			features: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso", "siem_export", "scim", "ai_security_posture"],
			retentionDays: 365,
		},
		enterprise: {
			deployment: ["onprem", "air-gapped"],
			features: [
				"local_detection",
				"dashboard",
				"browser_privacy_guard",
				"entra_sso",
				"siem_export",
				"scim",
				"ai_security_posture",
				"air_gapped_deployment",
				"dedicated_support",
			],
			retentionDays: null,
		},
	});
	for (const lang of LANGUAGES) {
		const names = [...html[lang].matchAll(/<div class="ed(?: [^"]*)?">\s*<h4>([^<]+)<\/h4>/g)].map((m) => m[1]);
		assert.deepEqual(names, EDITIONS, `brochure.${lang}.html: edition cards`);
	}
});

test("the brochure carries no prices", () => {
	const banned = [
		/[$€₺£¥]/u,
		/\b(?:USD|EUR|GBP|TRY|TL)\b/,
		/\d[\d.,]*\s?(?:dollars?|dolar|lira|euros?|avro|cents?|kuruş)/iu,
		/\b(?:dollars?|dolar|lira|euros?|avro)\b/iu,
		/\bper (?:month|year|seat|developer|user|agent)\b|\/\s?(?:month|mo|year|yr|seat|ay|yıl)(?![\p{L}])/iu,
		/\b(?:monthly|annual(?:ly)?|yearly|billed|billing|invoice)\b/i,
		/aylık|yıllık|fatura/iu,
		/\blist price|\bprices?\b|\bcost\b|liste fiyat|fiyatı|\bücret(?!siz)/iu,
	];
	for (const lang of LANGUAGES) {
		const source = markup(html[lang]);
		for (const pattern of banned) assert.doesNotMatch(source, pattern, `brochure.${lang}.html matches price pattern ${pattern}`);
	}
});

test("the brochure never names the upstream scanner project or its vendor", () => {
	for (const lang of LANGUAGES) {
		// Raw source (comments, attributes, CSS included) minus embedded base64 data.
		const source = html[lang].replace(/data:[a-z]+\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+/g, "data:");
		assert.doesNotMatch(source, /AI[\s_-]*Infra[\s_-]*Guard|\bAIG\b|Tencent/i, `brochure.${lang}.html names the upstream project`);
	}
});

test("contact is anil@singularityrd.com everywhere", () => {
	for (const lang of LANGUAGES) {
		const source = markup(html[lang]);
		const addresses = source.match(/[\w.+-]+@singularityrd\.com/gi) ?? [];
		assert.ok(addresses.length >= 3, `brochure.${lang}.html shows the contact address ${addresses.length} times`);
		for (const address of addresses) assert.equal(address, CONTACT, `brochure.${lang}.html: unexpected address ${address}`);
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
		/\bgate\b|readiness|NO-GO|\b(?:COM|CLM|SEC|POV|INV)-\d{3}\b/i,
		...registry.claimPatterns.map((pattern) => new RegExp(pattern.pattern, "iu")),
	];
	for (const lang of LANGUAGES) {
		const text = visibleText(html[lang]);
		for (const pattern of banned) assert.doesNotMatch(text, pattern, `brochure.${lang}.html matches banned pattern ${pattern}`);
	}
	const required = {
		tr: [`Fiyatlandırma ve teklif için: ${CONTACT}`, "KVKK ve GDPR yükümlülüklerini desteklemek üzere tasarlandı", "Yapay Zekâ Güvenlik Duruşu", "singularityrd.com"],
		en: [`For pricing and a quote: ${CONTACT}`, "Designed to support KVKK and GDPR obligations", "AI Security Posture", "singularityrd.com"],
	};
	for (const lang of LANGUAGES) {
		const text = visibleText(html[lang]);
		for (const phrase of required[lang]) assert.ok(text.includes(phrase), `brochure.${lang}.html lacks "${phrase}"`);
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

test("pages are self-contained, share one stylesheet and embed the company logo unchanged", () => {
	const style = (source) => source.match(/<style>[\s\S]*?<\/style>/)[0];
	assert.equal(style(html.tr), style(html.en), "the two brochures must carry an identical <style> block");
	const logo = readFileSync(path.join(root, "images", "singularity-logo.png")).toString("base64");
	const oldShield = read("images/aidr-logo-shaded.svg").match(/<path d="([^"]+)"/)[1];
	for (const lang of LANGUAGES) {
		const source = html[lang];
		assert.match(source, /@page\s*\{\s*size:\s*A4/);
		assert.equal((source.match(/<section class="page[ "]/g) ?? []).length, EXPECTED_PAGES);
		assert.doesNotMatch(source, /<link\b|@import|@font-face|\b(?:src|href)="(?:https?:)?\/\//i, `brochure.${lang}.html loads an external resource`);
		assert.doesNotMatch(source, /url\(\s*['"]?(?:https?:)?\/\//i, `brochure.${lang}.html references an external URL in CSS`);
		assert.ok(source.includes(`url("data:image/png;base64,${logo}")`), `brochure.${lang}.html does not embed images/singularity-logo.png byte for byte`);
		assert.match(source, /class="sg-logo cover-logo"/, `brochure.${lang}.html: the cover does not show the company logo`);
		assert.equal((source.match(/<span class="brand"><span class="sg-logo"/g) ?? []).length, EXPECTED_PAGES - 1, `brochure.${lang}.html: every inner page header needs the logo badge`);
		assert.doesNotMatch(source, /aidr-logo/, `brochure.${lang}.html still references the old shield logo`);
		assert.ok(!source.includes(oldShield), `brochure.${lang}.html still embeds the old shield logo`);
	}
	assert.match(style(html.en), /\.cover \{\s*background: #000;/, "the cover background must be pure black so the logo background blends in");
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
