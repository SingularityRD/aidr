/** Source-backed interpretation of Knip's runtime-blind unlisted findings.
 * Fail closed on missing/stale locations, unsupported syntax, and resolution errors.
 * This is not a file or package allowlist: every reported reference needs proof.
 */
import { readFileSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const packagePart = "[a-z0-9][a-z0-9._-]*";
const packageName = `(?:@${packagePart}/)?${packagePart}`;
// Deno accepts numeric major/minor selectors as well as exact SemVer. A major
// selector is versioned, NOT reproducibly pinned; deployment locks are separate.
const numeric = "(?:0|[1-9][0-9]*)";
const versionSelector = `${numeric}(?:\\.${numeric})?|${numeric}\\.${numeric}\\.${numeric}(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?`;
const versionedNpm = new RegExp(`^npm:(${packageName})@(${versionSelector})(/[^?#\\\\%\\s]+)?$`);
const barePackage = new RegExp(`^(${packageName})(/[^?#\\\\%\\s]+)?$`);

function safeSubpath(path = "") {
	return !path || path.slice(1).split("/").every((part) => part && part !== "." && part !== "..");
}

export function parseVersionedDenoNpm(specifier) {
	const match = versionedNpm.exec(specifier);
	if (!match || match[0] !== specifier || match[1].length > 214 || match[2].length > 256 || !safeSubpath(match[3])) return null;
	if (match[2].split(/[+-]/)[0].split(".").some((part) => !Number.isSafeInteger(Number(part)))) return null;
	// SemVer numeric prerelease identifiers cannot have leading zeroes.
	const prerelease = match[2].split("+")[0].split("-").slice(1).join("-");
	if (prerelease.split(".").some((part) => /^0[0-9]+$/.test(part))) return null;
	if (match[1].split("/").some((part) => ["node_modules", "favicon.ico"].includes(part))) return null;
	return { name: match[1], version: match[2] };
}

function inside(root, path) {
	const rel = relative(root, path);
	return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

function moduleLiteral(node) {
	if (!ts.isStringLiteralLike(node)) return false;
	const parent = node.parent;
	// Discovery is deliberately broader than approval, including unsupported call
	// forms so Knip's package deduplication cannot conceal unsafe siblings.
	return ((ts.isImportDeclaration(parent) || ts.isExportDeclaration(parent)) && parent.moduleSpecifier === node) ||
		(ts.isCallExpression(parent) && parent.arguments[0] === node) ||
		ts.isExternalModuleReference(parent) ||
		(ts.isLiteralTypeNode(parent) && ts.isImportTypeNode(parent.parent));
}

function matchesReportedPosition(literal, pos, source) {
	if (literal.getStart(source) === pos || literal.pos === pos) return true;
	const call = literal.parent;
	// Knip's requireCall visitor reports require("pkg").member at the member
	// identifier, not the string. Only map an immediate, ordinary require call;
	// this still goes through the same binding, anchor and resolution proof.
	return ts.isCallExpression(call) && ts.isIdentifier(call.expression) && call.expression.text === "require" &&
		call.arguments.length === 1 && ts.isPropertyAccessExpression(call.parent) &&
		call.parent.expression === call && call.parent.name.getStart(source) === pos;
}

function hasOnlyUse(identifier, checker, source) {
	const symbol = checker.getSymbolAtLocation(identifier);
	let safe = true;
	function visit(node) {
		if (ts.isIdentifier(node) && checker.getSymbolAtLocation(node) === symbol && node !== identifier &&
			!symbol?.declarations?.some((declaration) => declaration.name === node)) safe = false;
		ts.forEachChild(node, visit);
	}
	visit(source);
	return safe;
}

function makeSourceAudit(file, text) {
	const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
	const host = ts.createCompilerHost({});
	host.getSourceFile = (name) => resolve(name) === file ? source : undefined;
	const checker = ts.createProgram([file], { noLib: true, noResolve: true, allowJs: true }, host).getTypeChecker();
	const literals = [];
	function visit(node) {
		if (moduleLiteral(node)) literals.push(node);
		ts.forEachChild(node, visit);
	}
	visit(source);
	return { source, checker, literals };
}

function constInitializer(node, checker, seen = new Set(), singleUseSource) {
	if (!ts.isIdentifier(node)) return node;
	if (singleUseSource && !hasOnlyUse(node, checker, singleUseSource)) return null;
	const symbol = checker.getSymbolAtLocation(node);
	if (!symbol || seen.has(symbol) || symbol.declarations?.length !== 1) return null;
	seen.add(symbol);
	const declaration = symbol.declarations[0];
	if (!ts.isVariableDeclaration(declaration) || !ts.isIdentifier(declaration.name) ||
		!(declaration.parent.flags & ts.NodeFlags.Const) || !declaration.initializer) return null;
	return constInitializer(declaration.initializer, checker, seen, singleUseSource);
}

function isNodeCreateRequire(node, checker) {
	if (!ts.isIdentifier(node)) return false;
	const declarations = checker.getSymbolAtLocation(node)?.declarations;
	if (declarations?.length !== 1) return false;
	const declaration = declarations[0];
	return ts.isImportSpecifier(declaration) && !declaration.isTypeOnly &&
		(declaration.propertyName ?? declaration.name).text === "createRequire" &&
		!declaration.parent.parent.isTypeOnly &&
		declaration.parent.parent.parent.moduleSpecifier.text === "node:module";
}

function coreRequireReference(literal, audit, file, coreManifest) {
	const call = literal.parent;
	if (!ts.isCallExpression(call) || call.arguments.length !== 1 || !ts.isIdentifier(call.expression)) return false;
	const factory = constInitializer(call.expression, audit.checker);
	if (!factory || !ts.isCallExpression(factory) || factory.arguments.length !== 1 ||
		!isNodeCreateRequire(factory.expression, audit.checker)) return false;
	const anchor = constInitializer(factory.arguments[0], audit.checker, new Set(), audit.source);
	if (!anchor || !ts.isNewExpression(anchor) || !ts.isIdentifier(anchor.expression) ||
		anchor.expression.text !== "URL" || audit.checker.getSymbolAtLocation(anchor.expression) ||
		anchor.arguments?.length !== 2) return false;
	const [path, base] = anchor.arguments;
	if (!ts.isStringLiteral(path) || !/^\.\.?\//.test(path.text) || /[\\%?#]/.test(path.text) ||
		!ts.isPropertyAccessExpression(base) || base.name.text !== "url" ||
		!ts.isMetaProperty(base.expression) || base.expression.keywordToken !== ts.SyntaxKind.ImportKeyword ||
		base.expression.name.text !== "meta") return false;
	const resolved = fileURLToPath(new URL(path.text, pathToFileURL(file)));
	return resolved === coreManifest && realpathSync(resolved) === coreManifest;
}

export function createDependencyAuditor(root) {
	root = realpathSync(root);
	const cache = new Map();
	const coreManifest = resolve(root, "packages/core/package.json");
	return (issue, type, value) => {
		if (type !== "unlisted" || typeof issue.file !== "string" || typeof value?.name !== "string") return false;
		try {
			// Reports must name canonical repository files, never traversal/symlink aliases.
			const normalized = issue.file.replaceAll("\\", "/");
			if (isAbsolute(normalized) || normalized.split("/").some((part) => !part || part === "." || part === "..")) return false;
			const file = resolve(root, normalized);
			if (!inside(root, file) || realpathSync(file) !== file) return false;
			let audit = cache.get(file);
			if (!audit) {
				audit = makeSourceAudit(file, readFileSync(file, "utf8"));
				cache.set(file, audit);
			}
			if (audit.source.parseDiagnostics.length || !Number.isInteger(value.pos) || value.pos < 0 || value.pos >= audit.source.text.length) return false;
			const location = audit.source.getLineAndCharacterOfPosition(value.pos);
			// Both versions use zero-based pos and a one-based line. They disagree on
			// the column: knip 5 reported `character + 2`, knip 6 reports
			// `character + 1`. Accept either, because the position is not the proof -
			// it only locates the literal, and the literal must still satisfy the
			// Deno or core-anchored-require proof below. A tolerance of one column
			// cannot approve a finding that is not there.
			if (value.line !== location.line + 1 ||
				(value.col !== location.character + 1 && value.col !== location.character + 2)) return false;
			const literal = audit.literals.find((node) => matchesReportedPosition(node, value.pos, audit.source));
			if (!literal) return false;
			if (value.name === "npm") {
				if (!/^(?:packages\/dashboard\/)?supabase\/functions\/.+\.tsx?$/.test(normalized) || normalized.includes("/__tests__/")) return false;
				const isDeno = (node) => {
					const parent = node.parent;
					return parseVersionedDenoNpm(node.text) && (ts.isImportDeclaration(parent) || ts.isExportDeclaration(parent) ||
						(ts.isCallExpression(parent) && parent.expression.kind === ts.SyntaxKind.ImportKeyword) ||
						(ts.isLiteralTypeNode(parent) && ts.isImportTypeNode(parent.parent)));
				};
				// Knip can collapse multiple references to one package into one finding.
				return !!isDeno(literal) && audit.literals.filter((node) => /^npm(?::|\/|$)/.test(node.text)).every(isDeno);
			}
			const match = barePackage.exec(literal.text);
			if (!match || match[1] !== value.name || !safeSubpath(match[2])) return false;
			const manifest = JSON.parse(readFileSync(coreManifest, "utf8"));
			if (!Object.hasOwn(manifest.dependencies ?? {}, value.name) ||
				typeof manifest.dependencies[value.name] !== "string" || !manifest.dependencies[value.name].trim()) return false;
			const require = createRequire(coreManifest);
			const prove = (node) => {
				const dependency = barePackage.exec(node.text);
				if (!dependency || !safeSubpath(dependency[2]) || !coreRequireReference(node, audit, file, coreManifest)) return false;
				// Resolve, never execute dependency code. Require the package reached from
				// core's node_modules, not a coincidental root/transitive installation.
				const packageRoot = realpathSync(resolve(root, "packages/core/node_modules", value.name));
				const installed = JSON.parse(readFileSync(resolve(packageRoot, "package.json"), "utf8"));
				return installed.name === value.name && inside(packageRoot, realpathSync(require.resolve(node.text)));
			};
			return prove(literal) && audit.literals.filter((node) => node.text === value.name || node.text.startsWith(`${value.name}/`)).every(prove);
		} catch {
			return false;
		}
	};
}

export function evaluateReport(report, approveDependency) {
	// knip 5 put unused files in a top-level `files` array beside `issues`; knip 6
	// moved them inside each issue and emits `issues` alone. Accept both shapes so
	// the gate survives the upgrade, and keep the strictness identical: only
	// `files`, `exports` and `duplicates` are review debt, everything else blocks
	// unless the auditor proves it. A shape the gate does not recognise still
	// throws rather than reporting a clean run.
	if (!report || Array.isArray(report) || !Array.isArray(report.issues) ||
		Object.keys(report).some((key) => key !== "files" && key !== "issues")) {
		throw new Error("Invalid Knip report shape");
	}
	const legacyFiles = Array.isArray(report.files) ? report.files : null;
	for (const issue of report.issues) {
		if (!issue || typeof issue.file !== "string" || Object.entries(issue).some(([key, value]) => key !== "file" && !Array.isArray(value))) {
			throw new Error("Invalid Knip issue shape");
		}
	}
	const review = new Set(["files", "exports", "duplicates"]);
	// `owners` is authorship metadata, not a finding, in both report versions.
	const metadata = new Set(["owners"]);
	const counts = { files: legacyFiles ? legacyFiles.length : 0, exports: 0, duplicates: 0 };
	const blocking = [];
	for (const issue of report.issues ?? []) {
		for (const [type, values] of Object.entries(issue)) {
			if (!Array.isArray(values) || metadata.has(type)) continue;
			if (review.has(type)) {
				counts[type] += values.length;
				continue;
			}
			for (const value of values) {
				const workflowTool = type === "binaries" && value?.name === "typedoc" &&
					issue.file?.replaceAll("\\", "/") === ".github/workflows/docs-generation.yml";
				if (!workflowTool && !approveDependency(issue, type, value)) {
					blocking.push(`${issue.file ?? "<unknown>"}: ${type} ${JSON.stringify(value)}`);
				}
			}
		}
	}
	return { counts, blocking };
}
