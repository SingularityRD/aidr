/**
 * Every console page shows its text through the EN/TR catalogs (src/i18n).
 *
 * A pragmatic source check, not a renderer: it parses each page under
 * src/ui/pages (and the shared components those pages render) and fails on
 *   - JSX text containing a word,
 *   - a word in a user-facing attribute (aria-label, title, placeholder, alt, label),
 *   - a string or template literal that reads like an English sentence
 *     (a capitalised word followed by two lower-case words), wherever it is.
 * Code, product names and developer-only text are allowed: text inside
 * <code>/<pre>/<kbd>/<samp>, `new Error(...)`/`console.*` arguments, and the
 * names in ALLOWED_TEXT, and literals marked `// i18n-exempt: <reason>`.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SRC = resolve(__dirname, "..");

/** Directories whose .tsx files render console UI. */
const UI_DIRS = ["ui/pages", "ui", "enterprise", "onboarding", "billing", "components"];

/** Product, protocol and format names shown as-is in every language. */
const ALLOWED_TEXT = new Set([
	"AIDR",
	"Singularity AIDR",
	"Singularity",
	"Browser Guard",
	"AutoSecOps",
	"Claude Code",
	"Cursor",
	"VS Code",
	"Codex",
	"OpenCode",
	"OpenClaw",
	"Windows",
	"Linux",
	"macOS",
	"Chrome",
	"Edge",
	"Firefox",
	"GitHub",
	"Google",
	"Microsoft",
	"SIEM",
	"SCIM",
	"OIDC",
	"SAML",
	"SSO",
	"MFA",
	"API",
	"YAML",
	"JSON",
	"CSV",
	"PDF",
	"SHA-256",
	"CVSS",
	"CVE",
	"ID",
	"OWASP",
	"MITRE ATLAS",
	"Ed25519",
	"OK",
	"EN",
	"TR",
]);

const ATTRIBUTES = new Set(["aria-label", "title", "placeholder", "alt", "label"]);
const CODE_TAGS = new Set(["code", "pre", "kbd", "samp"]);
const SENTENCE = /[A-Z][a-z]+(?:[ ,]+[a-z][a-z'’-]*){2,}/;
const WORD = /[A-Za-z]{2,}/;

/**
 * Files not yet moved to the catalogs, with the number of literals they still
 * hold. The list may only shrink: a new literal anywhere fails the test.
 */
const PENDING: Record<string, number> = {
	"enterprise/agent-profile-editor.tsx": 38,
	"enterprise/agent-profiles-panel.tsx": 30,
	"enterprise/dlp-editor.tsx": 127,
	"enterprise/dlp-history.tsx": 31,
	"ui/pages/CompliancePage.tsx": 2,
	"ui/pages/DetectionExceptionsPage.tsx": 1,
	"ui/pages/OidcSsoPage.tsx": 5,
	"ui/pages/OperatorPage.tsx": 100,
	"ui/pages/RetentionPage.tsx": 1,
	"ui/pages/ScimPage.tsx": 2,
	"ui/pages/public/LandingPage.tsx": 47,
	"ui/pages/public/PilotPage.tsx": 28,
	"ui/pages/public/PricingPage.tsx": 29,
	"ui/pages/public/PublicInfoPage.tsx": 21,
	"ui/pages/public/VerifyPage.tsx": 33,
};

function tsxFiles(dir: string, out: string[] = []): string[] {
	for (const entry of readdirSync(dir)) {
		const path = join(dir, entry);
		if (statSync(path).isDirectory()) {
			if (entry !== "__tests__") tsxFiles(path, out);
		} else if (entry.endsWith(".tsx")) out.push(path);
	}
	return out;
}

/** Tokens that are addresses, paths or code (`a@b.c`, `https://…`, `t=…`), not words. */
const CODE_TOKEN = /\S*[@:/.=_]\S*/g;

function allowed(text: string): boolean {
	const trimmed = text.replace(/\s+/g, " ").trim();
	return ALLOWED_TEXT.has(trimmed) || !WORD.test(trimmed.replace(CODE_TOKEN, ""));
}

function insideCode(node: ts.Node): boolean {
	for (let current = node.parent; current; current = current.parent) {
		if (ts.isJsxElement(current)) {
			const opening = current.openingElement;
			if (CODE_TAGS.has(opening.tagName.getText())) return true;
			// <span className="mono"> marks commands, ids and other literal values.
			const className = opening.attributes.properties.find(
				(attribute) => ts.isJsxAttribute(attribute) && attribute.name.getText() === "className",
			);
			if (className && /\bmono\b/.test(className.getText())) return true;
		}
	}
	return false;
}

function developerOnly(node: ts.Node): boolean {
	for (let current = node.parent; current; current = current.parent) {
		if (ts.isNewExpression(current) && /Error$/.test(current.expression.getText())) return true;
		if (ts.isCallExpression(current) && /^console\./.test(current.expression.getText()))
			return true;
		if (ts.isImportDeclaration(current) || ts.isExportDeclaration(current)) return true;
	}
	return false;
}

/** English UI text written directly in `file`. */
function literalUiText(file: string): string[] {
	const source = ts.createSourceFile(
		file,
		readFileSync(file, "utf8"),
		ts.ScriptTarget.Latest,
		true,
		ts.ScriptKind.TSX,
	);
	const lines = source.text.split("\n");
	// `// i18n-exempt: <why>` on the line above (or the same line) marks stored
	// content or other text that is deliberately not UI copy.
	const exempt = (node: ts.Node): boolean => {
		const line = source.getLineAndCharacterOfPosition(node.getStart()).line;
		return [lines[line], lines[line - 1]].some((text) => text?.includes("i18n-exempt"));
	};
	const found: string[] = [];
	// A declaration or property whose leading comment says i18n-exempt is
	// skipped whole (for example an English prompt written for an AI agent).
	const exemptSubtree = (node: ts.Node): boolean =>
		(ts.getLeadingCommentRanges(source.text, node.getFullStart()) ?? []).some((range) =>
			source.text.slice(range.pos, range.end).includes("i18n-exempt"),
		);
	const visit = (node: ts.Node): void => {
		if (exemptSubtree(node)) return;
		if (
			exempt(node) &&
			(ts.isStringLiteral(node) || ts.isTemplateExpression(node) || ts.isJsxText(node))
		)
			return;
		if (ts.isJsxText(node)) {
			if (!allowed(node.getText()) && !insideCode(node)) found.push(node.getText().trim());
			return;
		}
		if (
			ts.isJsxAttribute(node) &&
			ATTRIBUTES.has(node.name.getText()) &&
			node.initializer &&
			ts.isStringLiteral(node.initializer)
		) {
			if (!allowed(node.initializer.text)) found.push(node.initializer.text);
			return;
		}
		if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
			if (SENTENCE.test(node.text) && !developerOnly(node) && !insideCode(node))
				found.push(node.text);
			return;
		}
		if (ts.isTemplateExpression(node)) {
			const text = [node.head.text, ...node.templateSpans.map((span) => span.literal.text)].join(
				" ",
			);
			if (SENTENCE.test(text) && !developerOnly(node) && !insideCode(node)) found.push(text);
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return found;
}

describe("console pages use the translation catalogs", () => {
	const files = [...new Set(UI_DIRS.flatMap((dir) => tsxFiles(join(SRC, dir))))]
		.map((path) => relative(SRC, path).split("\\").join("/"))
		.sort();

	it("covers every page", () => {
		expect(files).toContain("ui/pages/ApprovalsPage.tsx");
		expect(files).toContain("ui/AppLayout.tsx");
	});

	it("renders no literal English UI text outside the catalog", () => {
		const offenders: Record<string, string[]> = {};
		for (const file of files) {
			const literals = literalUiText(join(SRC, file));
			const pending = PENDING[file] ?? 0;
			if (literals.length > pending) offenders[file] = literals;
		}
		expect(offenders).toEqual({});
	});

	it("keeps the pending list honest (shrink it when a page is translated)", () => {
		const stale = Object.entries(PENDING).filter(
			([file, count]) => !files.includes(file) || literalUiText(join(SRC, file)).length < count,
		);
		expect(stale).toEqual([]);
	});

	it("catches the heuristic's targets", () => {
		// Guard the guard: a synthetic page with each kind of literal is flagged.
		const probe = join(SRC, "__tests__", "fixtures", "i18n-literal-probe.tsx.txt");
		const found = literalUiText(probe);
		expect(found).toHaveLength(4);
		expect(found).toEqual(
			expect.arrayContaining([
				"Approval signing key rotated.",
				"Pending approvals",
				"Search agents",
				expect.stringContaining("Showing the newest requests"),
			]),
		);
	});
});
