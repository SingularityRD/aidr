#!/usr/bin/env node

/**
 * Release-facing claim and commercial evidence gate.
 *
 * This is intentionally dependency-free so it can run before the workspace
 * packages are installed. It does not decide whether a claim is true; it
 * proves only that every release-facing claim is registered, approved, and
 * backed by an immutable evidence record. It scans claim-facing surfaces and
 * hashes every configured release artifact, so binary/runtime strings are
 * inventory evidence without being mistaken for marketing copy. Missing or
 * unapproved evidence is a hard failure in --mode=gate.
 *
 * Examples:
 *   node docs/scripts/claim-check.mjs --mode=inventory
 *   node docs/scripts/claim-check.mjs --mode=gate --root packages/dashboard/dist
 *   node docs/scripts/claim-check.mjs --mode=gate --json > claim-check.json
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDir, "../..");
const defaultRegistry = resolve(repositoryRoot, "docs/production-readiness/commercial-go-evidence-registry.json");
const allowedExtensions = new Set([
	".cjs",
	".css",
	".html",
	".js",
	".json",
	".mjs",
	".md",
	".mdx",
	".svg",
	".txt",
	".ts",
	".tsx",
]);
const ignoredDirectoryNames = new Set([".git", ".next", ".turbo", "coverage", "node_modules"]);

function parseArgs(argv) {
	const args = { mode: "inventory", json: false, registry: defaultRegistry, roots: [] };
	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
		if (arg === "--json") {
			args.json = true;
			continue;
		}
		if (arg === "--mode") {
			args.mode = argv[++index];
			continue;
		}
		if (arg.startsWith("--mode=")) {
			args.mode = arg.slice("--mode=".length);
			continue;
		}
		if (arg === "--registry") {
			args.registry = argv[++index];
			continue;
		}
		if (arg.startsWith("--registry=")) {
			args.registry = arg.slice("--registry=".length);
			continue;
		}
		if (arg === "--root") {
			args.roots.push(argv[++index]);
			continue;
		}
		if (arg.startsWith("--root=")) {
			args.roots.push(arg.slice("--root=".length));
			continue;
		}
		if (arg === "--help" || arg === "-h") {
			console.log("Usage: node docs/scripts/claim-check.mjs [--mode inventory|gate] [--root PATH]... [--json]");
			process.exit(0);
		}
		throw new Error(`Unknown argument: ${arg}`);
	}
	if (!new Set(["inventory", "gate"]).has(args.mode)) {
		throw new Error(`Unsupported mode ${args.mode}; use inventory or gate`);
	}
	return args;
}

function resolvePath(value) {
	return isAbsolute(value) ? value : resolve(repositoryRoot, value);
}

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function collectFiles(target) {
	if (!existsSync(target)) {
		return [];
	}
	const info = statSync(target);
	if (info.isFile()) {
		return allowedExtensions.has(extname(target).toLowerCase()) ? [target] : [];
	}
	const files = [];
	for (const entry of readdirSync(target, { withFileTypes: true })) {
		if (entry.isDirectory() && ignoredDirectoryNames.has(entry.name)) {
			continue;
		}
		files.push(...collectFiles(join(target, entry.name)));
	}
	return files;
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function validateRegistry(registry) {
	const errors = [];
	if (registry?.registryKind !== "commercial-go-evidence") {
		errors.push("registryKind must be commercial-go-evidence");
	}
	if (registry?.decision !== "NO-GO" && !registry?.releaseCandidate) {
		errors.push("a registry without a releaseCandidate must remain NO-GO");
	}
	if (!Array.isArray(registry?.claimPatterns) || registry.claimPatterns.length === 0) {
		errors.push("claimPatterns must be a non-empty array");
	}
	if (!Array.isArray(registry?.hardGates) || registry.hardGates.length === 0) {
		errors.push("hardGates must be a non-empty array");
	}
	const ids = new Set();
	for (const collectionName of ["claimPatterns", "hardGates", "claims"]) {
		for (const item of registry[collectionName] ?? []) {
			if (!item.id) {
				errors.push(`${collectionName} contains an item without an id`);
			} else if (ids.has(item.id)) {
				errors.push(`duplicate registry id: ${item.id}`);
			} else {
				ids.add(item.id);
			}
			if (collectionName !== "claimPatterns" && !registry.policy.acceptedStatuses.includes(item.status)) {
				errors.push(`${item.id ?? collectionName} has unsupported status ${item.status}`);
			}
		}
	}
	for (const pattern of registry.claimPatterns ?? []) {
		try {
			new RegExp(pattern.pattern, "giu");
		} catch (error) {
			errors.push(`${pattern.id} has invalid regex: ${error.message}`);
		}
	}
	for (const templatePath of registry.templatePaths ?? []) {
		if (!existsSync(resolvePath(templatePath))) errors.push(`required commercial template is missing: ${templatePath}`);
	}
	return errors;
}

function validateCommercialDecision(registry) {
	const expected = {
		launchModel: "direct-ga",
		connectorScope: "all-connectors",
		deploymentModel: "hybrid",
		billingModel: "enterprise-invoice",
		distribution: "private-registry",
	};
	const decision = registry.commercialDecision ?? {};
	const errors = [];
	if (decision.status !== "locked-product-decision-evidence-open") {
		errors.push("commercialDecision.status must remain locked-product-decision-evidence-open until external evidence closes");
	}
	for (const [key, value] of Object.entries(expected)) {
		if (decision[key] !== value) errors.push(`commercialDecision.${key} must be locked to ${value}`);
	}
	const regions = Array.isArray(decision.regions) ? new Set(decision.regions) : new Set();
	for (const region of ["EU", "US", "APAC"]) {
		if (!regions.has(region)) errors.push(`commercialDecision.regions must include ${region}`);
	}
	if (decision.sla?.target !== "99.9% monthly availability") {
		errors.push("commercialDecision.sla.target must be 99.9% monthly availability");
	}
	if (!decision.sla?.scope || decision.sla.status !== "contract-evidence-open") {
		errors.push("commercialDecision.sla must declare scope and remain contract-evidence-open until approved");
	}
	return errors;
}

function buildPatternIndex(registry) {
	return registry.claimPatterns.map((pattern) => ({
		...pattern,
		regex: new RegExp(pattern.pattern, "giu"),
	}));
}

function inspectLicenseMetadata(registry) {
	const config = registry.licenseCheck ?? {};
	const errors = [];
	const warnings = [];
	const pathFor = (value) => resolvePath(value);
	const licensePath = pathFor(config.licensePath ?? "LICENSE");
	const noticePath = pathFor(config.noticePath ?? "NOTICE");
	const rootPackagePath = pathFor(config.rootPackagePath ?? "package.json");
	const result = {
		licensePath: relative(repositoryRoot, licensePath).replaceAll("\\", "/"),
		noticePath: relative(repositoryRoot, noticePath).replaceAll("\\", "/"),
		rootPackagePath: relative(repositoryRoot, rootPackagePath).replaceAll("\\", "/"),
		licenseBytes: existsSync(licensePath) ? statSync(licensePath).size : 0,
		rootPackageLicense: null,
		noticeLicensesFound: [],
		workspacePackages: [],
		errors,
		warnings,
	};

	if (!existsSync(licensePath)) {
		errors.push(`missing ${result.licensePath}`);
	} else if (result.licenseBytes < Number(config.minimumLicenseBytes ?? 128)) {
		errors.push(`${result.licensePath} is ${result.licenseBytes} byte(s); minimum is ${config.minimumLicenseBytes ?? 128}`);
	}
	if (!existsSync(noticePath)) {
		errors.push(`missing ${result.noticePath}`);
	}
	if (!existsSync(rootPackagePath)) {
		errors.push(`missing ${result.rootPackagePath}`);
	}

	const notice = existsSync(noticePath) ? readFileSync(noticePath, "utf8") : "";
	for (const name of config.noticeLicenseNames ?? []) {
		if (notice.toLowerCase().includes(String(name).toLowerCase())) result.noticeLicensesFound.push(name);
	}
	if (config.requireNoticeReferenceToLicenseFile && notice && !/\bLICENSE\b/i.test(notice)) {
		errors.push(`${result.noticePath} does not reference the repository LICENSE file`);
	}

	let rootPackage = null;
	if (existsSync(rootPackagePath)) {
		try {
			rootPackage = readJson(rootPackagePath);
			result.rootPackageLicense = rootPackage.license ?? null;
		} catch (error) {
			errors.push(`cannot parse ${result.rootPackagePath}: ${error.message}`);
		}
	}
	for (const pair of config.rootNoticeConflictPairs ?? []) {
		if (result.rootPackageLicense === pair.rootPackageLicense && result.noticeLicensesFound.includes(pair.noticeLicense)) {
			errors.push(`${result.rootPackagePath} declares ${pair.rootPackageLicense} while ${result.noticePath} declares ${pair.noticeLicense}`);
		}
	}

	for (const workspaceRoot of config.workspacePackageRoots ?? []) {
		for (const packagePath of collectFiles(resolvePath(workspaceRoot)).filter((file) => file.endsWith("package.json"))) {
			try {
				const packageJson = readJson(packagePath);
				const packageRecord = {
					path: relative(repositoryRoot, packagePath).replaceAll("\\", "/"),
					name: packageJson.name ?? null,
					license: packageJson.license ?? null,
				};
				result.workspacePackages.push(packageRecord);
				if (config.requirePackageLicenseField && !packageRecord.license) {
					errors.push(`${packageRecord.path} has no license field`);
				}
			} catch (error) {
				errors.push(`cannot parse workspace package ${relative(repositoryRoot, packagePath)}: ${error.message}`);
			}
		}
	}
	if (result.workspacePackages.some((item) => item.license === "MIT") && !result.noticeLicensesFound.includes("MIT License")) {
		warnings.push("workspace package metadata includes MIT but NOTICE does not enumerate the package-level MIT licence; Legal must reconcile the package matrix");
	}
	if (result.workspacePackages.some((item) => item.license === "Apache-2.0") && !result.noticeLicensesFound.includes("Apache License 2.0")) {
		warnings.push("workspace package metadata includes Apache-2.0 but NOTICE does not enumerate the package-level Apache licence; Legal must reconcile the package matrix");
	}
	for (const textPath of config.firstPartyLicenseTextPaths ?? []) {
		const fullPath = pathFor(textPath);
		if (!existsSync(fullPath)) {
			warnings.push(`first-party licence text path is missing: ${textPath}`);
			continue;
		}
		const text = readFileSync(fullPath, "utf8").toLowerCase();
		for (const forbidden of config.forbiddenFirstPartyLicenseText ?? []) {
			if (text.includes(String(forbidden).toLowerCase())) {
				errors.push(`${textPath} contains stale first-party licence text: ${forbidden}`);
			}
		}
	}
	for (const noticePathValue of config.requiredThirdPartyNoticePaths ?? []) {
		const fullPath = pathFor(noticePathValue);
		if (!existsSync(fullPath)) {
			errors.push(`required third-party notice is missing: ${noticePathValue}`);
		} else if (statSync(fullPath).size === 0) {
			errors.push(`required third-party notice is empty: ${noticePathValue}`);
		}
	}
	return result;
}

function scanFile(file, patterns) {
	const text = readFileSync(file, "utf8");
	const hits = [];
	for (const pattern of patterns) {
		pattern.regex.lastIndex = 0;
		let match;
		while ((match = pattern.regex.exec(text)) !== null) {
			const line = text.slice(0, match.index).split("\n").length;
			hits.push({
				patternId: pattern.id,
				line,
				match: match[0],
				reason: pattern.reason,
			});
			if (match[0].length === 0) {
				pattern.regex.lastIndex += 1;
			}
		}
	}
	return { path: relative(repositoryRoot, file).replaceAll("\\", "/"), sha256: sha256(text), hits };
}

function main() {
	const args = parseArgs(process.argv.slice(2));
	const registryPath = resolvePath(args.registry);
	if (!existsSync(registryPath)) {
		throw new Error(`Registry does not exist: ${registryPath}`);
	}
	const registry = readJson(registryPath);
	const registryErrors = [...validateRegistry(registry), ...validateCommercialDecision(registry)];
	const roots = (args.roots.length > 0 ? args.roots : registry.scanRoots ?? []).map(resolvePath);
	const artifactRoots = (registry.artifactRoots ?? []).map(resolvePath);
	const missingRoots = roots.filter((root) => !existsSync(root)).map((root) => relative(repositoryRoot, root).replaceAll("\\", "/"));
	const missingArtifactRoots = artifactRoots.filter((root) => !existsSync(root)).map((root) => relative(repositoryRoot, root).replaceAll("\\", "/"));
	const files = roots.flatMap(collectFiles);
	const uniqueFiles = [...new Set(files)].sort();
	const artifactFileLists = artifactRoots.map((root) => ({ root, files: collectFiles(root) }));
	const emptyArtifactRoots = artifactFileLists
		.filter(({ root, files: artifactFilesForRoot }) => existsSync(root) && artifactFilesForRoot.length === 0)
		.map(({ root }) => relative(repositoryRoot, root).replaceAll("\\", "/"));
	const artifactFiles = [...new Set(artifactFileLists.flatMap(({ files: artifactFilesForRoot }) => artifactFilesForRoot))].sort();
	const patterns = buildPatternIndex(registry);
	const scans = uniqueFiles.map((file) => scanFile(file, patterns));
	const artifactScans = artifactFiles.map((file) => {
		const content = readFileSync(file);
		return { path: relative(repositoryRoot, file).replaceAll("\\", "/"), sha256: sha256(content), bytes: content.length };
	});
	const hits = scans.flatMap((scan) => scan.hits.map((hit) => ({ ...hit, path: scan.path, sha256: scan.sha256 })));
	const licenseCheck = inspectLicenseMetadata(registry);
	const approvedPatternIds = new Set(
		(registry.claims ?? [])
			.filter((claim) => claim.salesApproved === true && claim.status === "closed")
			.flatMap((claim) => claim.patternIds ?? []),
	);
	const unapprovedHits = hits.filter((hit) => !approvedPatternIds.has(hit.patternId));
	const openHardGates = (registry.hardGates ?? []).filter((gate) => gate.class === "hard" && gate.status !== "closed");
	const gateFailure = registryErrors.length > 0 || missingRoots.length > 0 || missingArtifactRoots.length > 0 || emptyArtifactRoots.length > 0 || unapprovedHits.length > 0 || openHardGates.length > 0 || licenseCheck.errors.length > 0;
	const result = {
		registry: relative(repositoryRoot, registryPath).replaceAll("\\", "/"),
		registrySha256: sha256(readFileSync(registryPath)),
		mode: args.mode,
		decision: registry.decision,
		roots: roots.map((root) => relative(repositoryRoot, root).replaceAll("\\", "/")),
		artifactRoots: artifactRoots.map((root) => relative(repositoryRoot, root).replaceAll("\\", "/")),
		missingRoots,
		missingArtifactRoots,
		emptyArtifactRoots,
		filesScanned: uniqueFiles.length,
		artifactFilesScanned: artifactFiles.length,
		scans,
		artifactScans,
		hits,
		unapprovedHits,
		openHardGates: openHardGates.map((gate) => ({ id: gate.id, domain: gate.domain, status: gate.status, requirement: gate.requirement })),
		licenseCheck,
		registryErrors,
		result: args.mode === "gate" && gateFailure ? "FAIL" : "PASS",
	};

	if (args.json) {
		console.log(JSON.stringify(result, null, 2));
	} else {
		console.log(`Claim check (${args.mode}): ${result.result}`);
		console.log(`Registry: ${result.registry} (${result.registrySha256})`);
		console.log(`Claim-facing files scanned: ${result.filesScanned}; release artifact files hashed: ${result.artifactFilesScanned}; pattern hits: ${result.hits.length}; unapproved hits: ${result.unapprovedHits.length}`);
		if (result.missingRoots.length > 0) console.log(`Missing roots: ${result.missingRoots.join(", ")}`);
		if (result.missingArtifactRoots.length > 0) console.log(`Missing artifact roots: ${result.missingArtifactRoots.join(", ")}`);
		if (result.emptyArtifactRoots.length > 0) console.log(`Empty artifact roots: ${result.emptyArtifactRoots.join(", ")}`);
		if (result.openHardGates.length > 0) console.log(`Open hard gates: ${result.openHardGates.map((gate) => gate.id).join(", ")}`);
		if (result.licenseCheck.errors.length > 0) console.log(`License/NOTICE errors: ${result.licenseCheck.errors.join("; ")}`);
		if (result.licenseCheck.warnings.length > 0) console.log(`License/NOTICE warnings: ${result.licenseCheck.warnings.join("; ")}`);
		for (const hit of result.unapprovedHits) {
			console.log(`UNAPPROVED ${hit.path}:${hit.line} [${hit.patternId}] ${hit.match} — ${hit.reason}`);
		}
		if (result.registryErrors.length > 0) console.log(`Registry errors: ${result.registryErrors.join("; ")}`);
	}
	if (result.result === "FAIL") process.exitCode = 1;
}

try {
	main();
} catch (error) {
	console.error(`Claim check error: ${error.message}`);
	process.exitCode = 2;
}
