/**
 * Extract package names from shell commands and manifest file contents.
 * Handles npm, yarn, pnpm, bun, pip, pip3 install patterns.
 */

export interface ParsedPackage {
	name: string;
	registry: "npm" | "pypi" | "unknown";
	version?: string;
	source: "command" | "package.json" | "requirements.txt" | "dependency manifest";
	unverifiedReason?: string;
}

/** Package-manager commands covered by the runtime's package approval default. */
export function isPackageManagerCommand(command: string): boolean {
	return /\b(?:npm|yarn|pnpm|pip|pip3|uv|poetry|pipenv|gem|brew|apt|apk|choco|scoop|cargo|nuget|go\s+(?:get|install))\b/i.test(
		command,
	);
}

/**
 * Extract packages from a shell command string.
 * Handles: npm install/i/add, npx, yarn add, pnpm add/dlx, bun add/bunx, pip/pip3 install.
 */
export function extractPackagesFromCommand(command: string): ParsedPackage[] {
	const packages: ParsedPackage[] = [];

	// Normalize: strip leading env vars, sudo, etc.
	const normalized = command.replace(/^(\s*(sudo|env\s+\S+=\S+)\s+)+/g, "").trim();

	// Split on && or ; to handle chained commands
	const commands = normalized.split(/\s*(?:&&|;|\|)\s*/);

	for (const cmd of commands) {
		const tokens = shellTokenize(cmd.trim());
		if (tokens.length === 0) continue;

		const binary = normalizeCommandBinary(tokens[0] ?? "");
		let extracted: ParsedPackage[] = [];

		if (["npm", "npx"].includes(binary)) {
			extracted = extractNpmPackages(tokens);
		} else if (binary === "yarn") {
			extracted = extractYarnPackages(tokens);
		} else if (["pnpm", "bunx"].includes(binary)) {
			extracted = extractPnpmBunPackages(tokens, binary);
		} else if (binary === "bun") {
			extracted = extractBunPackages(tokens);
		} else if (["pip", "pip3"].includes(binary)) {
			extracted = extractPipPackages(tokens);
		} else if (["uv", "poetry", "pipenv", "go"].includes(binary)) {
			extracted = extractUnverifiedManagerPackages(tokens, binary);
		} else if (
			["python", "python3", "python.exe", "python3.exe"].includes(binary) ||
			binary.match(/python3?\.\d+/) ||
			binary.endsWith("/python") ||
			binary.endsWith("/python3")
		) {
			// Handle: python -m pip install <pkg>
			if (tokens[1] === "-m" && ["pip", "pip3"].includes(tokens[2] ?? "")) {
				extracted = extractPipPackages(tokens.slice(2));
			}
		}

		if (extracted.length === 0 && isManifestInstallCommand(tokens, binary)) {
			extracted.push(
				unverifiedPackage(
					"manifest dependencies",
					"npm",
					"command",
					"installs dependencies from a manifest whose contents were not supplied for inspection",
				),
			);
		}
		packages.push(...extracted);
	}

	return packages;
}

/** Manifest file names the extractor understands, independent of directory. */
const PACKAGE_MANIFEST_SUFFIXES = ["package.json", "requirements.txt"] as const;

function normalizeManifestPath(filePath: string): string {
	return filePath.toLowerCase().replace(/\\/g, "/");
}

/**
 * True when `filePath` names a manifest whose package entries this module can
 * extract. Exported so callers that must *prefer* a manifest (e.g. picking the
 * manifest section out of a multi-file patch) share one definition.
 */
export function isPackageManifestPath(filePath: string): boolean {
	const lowerPath = normalizeManifestPath(filePath);
	const name = lowerPath.slice(lowerPath.lastIndexOf("/") + 1);
	return (
		PACKAGE_MANIFEST_SUFFIXES.some((suffix) => lowerPath.endsWith(suffix)) ||
		/^requirements(?:[-_.][^/]*)?\.txt$/.test(name)
	);
}

/**
 * True for common dependency manifests, including ecosystems this lightweight
 * checker cannot parse. Callers must treat unsupported manifests as unknown,
 * never as an empty clean package set.
 */
export function isDependencyManifestPath(filePath: string): boolean {
	const path = normalizeManifestPath(filePath);
	const name = path.slice(path.lastIndexOf("/") + 1);
	if (isPackageManifestPath(path)) return true;
	if (/^constraints(?:[-_.][^/]*)?\.txt$/.test(name)) return true;
	return (
		[
			"package-lock.json",
			"npm-shrinkwrap.json",
			"yarn.lock",
			"pnpm-lock.yaml",
			"bun.lock",
			"bun.lockb",
			"pyproject.toml",
			"poetry.lock",
			"uv.lock",
			"pipfile",
			"pipfile.lock",
			"setup.py",
			"setup.cfg",
			"go.mod",
			"go.sum",
			"cargo.toml",
			"cargo.lock",
			"gemfile",
			"gemfile.lock",
			"composer.json",
			"composer.lock",
			"pom.xml",
			"build.gradle",
			"build.gradle.kts",
			"gradle.lockfile",
			"package.swift",
			"package.resolved",
			"mix.exs",
			"mix.lock",
			"packages.config",
		].includes(name) || /\.(?:csproj|fsproj)$/.test(name)
	);
}

export function isPackageJsonPath(filePath: string): boolean {
	return normalizeManifestPath(filePath).endsWith("package.json");
}

/** Detect repeated object keys before JSON.parse silently keeps only the last value. */
export function hasDuplicateJsonObjectKeys(content: string): boolean {
	const objectKeys: Set<string>[] = [];
	for (let index = 0; index < content.length; index++) {
		if (content[index] === '"') {
			const start = index;
			for (index++; index < content.length; index++) {
				if (content[index] === "\\") {
					index++;
				} else if (content[index] === '"') {
					break;
				}
			}

			let next = index + 1;
			while (next < content.length && /\s/.test(content[next] ?? "")) next++;
			if (content[next] === ":") {
				const keys = objectKeys[objectKeys.length - 1];
				if (keys) {
					let key: unknown;
					try {
						key = JSON.parse(content.slice(start, index + 1));
					} catch {
						return true;
					}
					if (typeof key !== "string" || keys.has(key)) return true;
					keys.add(key);
				}
			}
		} else if (content[index] === "{") {
			objectKeys.push(new Set());
		} else if (content[index] === "}") {
			objectKeys.pop();
		}
	}
	return false;
}

/**
 * Extract packages from manifest file content.
 * Supports package.json and requirements.txt.
 */
export function extractPackagesFromManifest(filePath: string, content: string): ParsedPackage[] {
	if (!isDependencyManifestPath(filePath)) return [];
	if (!isPackageManifestPath(filePath)) {
		return [
			unverifiedPackage(
				filePath,
				"unknown",
				"dependency manifest",
				"is an unsupported dependency manifest whose dependency changes were not inspected",
			),
		];
	}

	const lowerPath = normalizeManifestPath(filePath);
	if (lowerPath.endsWith("package.json")) {
		return extractFromPackageJson(content);
	}
	return extractFromRequirementsTxt(content);
}

// ── Internal helpers ──────────────────────────────────────────────

/** Simple shell tokenizer — splits on whitespace, respects quotes. */
function shellTokenize(cmd: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let inSingle = false;
	let inDouble = false;

	for (const ch of cmd) {
		if (ch === "'" && !inDouble) {
			inSingle = !inSingle;
		} else if (ch === '"' && !inSingle) {
			inDouble = !inDouble;
		} else if (/\s/.test(ch) && !inSingle && !inDouble) {
			if (current) tokens.push(current);
			current = "";
		} else {
			current += ch;
		}
	}
	if (current) tokens.push(current);
	return tokens;
}

function normalizeCommandBinary(token: string): string {
	return token.replace(/^.*[/\\]/, "").replace(/\.(?:cmd|ps1|exe)$/i, "");
}

function unverifiedPackage(
	name: string,
	registry: ParsedPackage["registry"],
	source: ParsedPackage["source"],
	unverifiedReason: string,
): ParsedPackage {
	return { name, registry, source, unverifiedReason };
}

function extractUnverifiedManagerPackages(tokens: string[], manager: string): ParsedPackage[] {
	const subcommand = (tokens[1] ?? "").toLowerCase();
	const subsubcommand = (tokens[2] ?? "").toLowerCase();
	const mutatesDependencies =
		(manager === "uv" &&
			(["add", "remove", "sync", "lock"].includes(subcommand) ||
				(subcommand === "pip" && ["install", "uninstall", "sync"].includes(subsubcommand)))) ||
		(manager === "poetry" &&
			["add", "remove", "install", "update", "sync", "lock"].includes(subcommand)) ||
		(manager === "pipenv" &&
			["install", "uninstall", "update", "sync", "lock"].includes(subcommand)) ||
		(manager === "go" &&
			(["get", "install"].includes(subcommand) ||
				(subcommand === "mod" && ["download", "tidy"].includes(subsubcommand))));

	if (!mutatesDependencies) return [];
	return [
		unverifiedPackage(
			`${manager} dependency operation`,
			"unknown",
			"command",
			`uses ${manager}, whose dependency operation is not supported by the package checker`,
		),
	];
}

const NPM_PACKAGE_INSTALL_COMMANDS = new Set([
	"install",
	"add",
	"i",
	"in",
	"ins",
	"inst",
	"insta",
	"instal",
	"isnt",
	"isnta",
	"isntal",
	"isntall",
]);
const NPM_MANIFEST_INSTALL_COMMANDS = new Set([
	...NPM_PACKAGE_INSTALL_COMMANDS,
	"ci",
	"clean-install",
	"ic",
	"install-cl",
	"install-cle",
	"install-clea",
	"install-clean",
	"isntall-",
	"isntall-cl",
	"isntall-cle",
	"isntall-clea",
	"isntall-clean",
	"clean-install-",
	"clean-install-te",
	"clean-install-tes",
	"install-ci-test",
	"install-ci",
	"install-ci-",
	"install-ci-t",
	"install-ci-te",
	"install-ci-tes",
	"cit",
	"clean-install-test",
	"clean-install-t",
	"sit",
	"install-test",
	"install-t",
	"install-te",
	"install-tes",
	"isntall-c",
	"si",
	"it",
]);

function isManifestInstallCommand(tokens: string[], binary: string): boolean {
	const subcommand = tokens[1] ?? "";
	return (
		(binary === "npm" && NPM_MANIFEST_INSTALL_COMMANDS.has(subcommand)) ||
		(binary === "yarn" && (subcommand === "install" || !subcommand)) ||
		(binary === "pnpm" && ["install", "i"].includes(subcommand)) ||
		(binary === "bun" && ["install", "i"].includes(subcommand))
	);
}

function unverifiedSourceReason(token: string): string | undefined {
	if (/^https?:\/\//i.test(token)) return "uses a direct URL that was not checked by a registry";
	if (/^(?:git\+|git:|ssh:|github:|gitlab:|bitbucket:|git@)/i.test(token)) {
		return "uses a Git source that was not checked by a registry";
	}
	if (
		/^(?:file:|link:|workspace:|\.{1,2}[\\/]|~[\\/]|[\\/]|[a-z]:[\\/])/i.test(token) ||
		token === "."
	) {
		return "uses a local dependency source that was not checked by a registry";
	}
	return undefined;
}

function packageSpecifierSourceReason(token: string): string | undefined {
	return (
		unverifiedSourceReason(token) ?? unverifiedSourceReason(splitNameVersion(token).version ?? "")
	);
}

function unverifiedPypiSource(reason: string): ParsedPackage {
	return unverifiedPackage("unverified pypi source", "pypi", "requirements.txt", reason);
}

/** Check if a token looks like a package name (not a flag, URL, or local path). */
function isPackageName(token: string): boolean {
	if (token.startsWith("-")) return false;
	// Package names must start with a letter or @ (scoped packages)
	if (!/^[a-zA-Z@]/.test(token)) return false;
	if (token.startsWith("https://") || token.startsWith("http://")) return false;
	if (token.startsWith("git+")) return false;
	if (token.startsWith("./") || token.startsWith("../") || token.startsWith("/")) return false;
	if (token.startsWith("file:")) return false;
	if (token === ".") return false;
	return true;
}

/** Split "express@4.18.0" into { name: "express", version: "4.18.0" }. */
function splitNameVersion(token: string): { name: string; version?: string } {
	// Scoped package: @scope/name@version
	if (token.startsWith("@")) {
		const afterScope = token.indexOf("/");
		if (afterScope === -1) return { name: token };
		const rest = token.slice(afterScope + 1);
		const atIdx = rest.indexOf("@");
		if (atIdx > 0) {
			return {
				name: `${token.slice(0, afterScope + 1)}${rest.slice(0, atIdx)}`,
				version: rest.slice(atIdx + 1),
			};
		}
		return { name: token };
	}

	// Regular package: name@version
	const atIdx = token.indexOf("@");
	if (atIdx > 0) {
		return { name: token.slice(0, atIdx), version: token.slice(atIdx + 1) };
	}
	return { name: token };
}

/** Flags that take a value argument (next token is not a package). */
const NPM_VALUE_FLAGS = new Set([
	"--registry",
	"--tag",
	"--workspace",
	"-w",
	"--prefix",
	"--cache",
	"--userconfig",
	"--globalconfig",
]);

function extractNpmPackages(tokens: string[]): ParsedPackage[] {
	const packages: ParsedPackage[] = [];
	const binary = normalizeCommandBinary(tokens[0] ?? "");

	if (binary === "npx") {
		// npx <pkg> — first non-flag token is the package
		for (let i = 1; i < tokens.length; i++) {
			const t = tokens[i] ?? "";
			if (t === "--" || t === "-y" || t === "--yes" || t === "-p" || t === "--package") continue;
			if (t.startsWith("-")) continue;
			const sourceReason = packageSpecifierSourceReason(t);
			if (sourceReason) {
				packages.push(unverifiedPackage("unverified npm source", "npm", "command", sourceReason));
				break;
			}
			if (!isPackageName(t)) break;
			const { name, version } = splitNameVersion(t);
			packages.push({ name, version, registry: "npm", source: "command" });
			break;
		}
		return packages;
	}

	if (["exec", "exe", "x"].includes(tokens[1] ?? "")) {
		return [
			unverifiedPackage(
				"unverified npm exec",
				"npm",
				"command",
				"may execute a package that was not checked by a registry",
			),
		];
	}

	// npm install/i/add/ci
	const subcommand = tokens[1] ?? "";
	if (!NPM_PACKAGE_INSTALL_COMMANDS.has(subcommand)) return packages;

	let skipNext = false;
	for (let i = 2; i < tokens.length; i++) {
		const t = tokens[i] ?? "";
		if (skipNext) {
			skipNext = false;
			continue;
		}
		if (NPM_VALUE_FLAGS.has(t)) {
			skipNext = true;
			continue;
		}
		if (t.startsWith("-")) continue;
		const sourceReason = packageSpecifierSourceReason(t);
		if (sourceReason) {
			packages.push(unverifiedPackage("unverified npm source", "npm", "command", sourceReason));
			continue;
		}
		if (!isPackageName(t)) break;
		const { name, version } = splitNameVersion(t);
		packages.push({ name, version, registry: "npm", source: "command" });
	}
	return packages;
}

function extractYarnPackages(tokens: string[]): ParsedPackage[] {
	const packages: ParsedPackage[] = [];
	const subcommand = tokens[1] ?? "";
	if (subcommand === "dlx") {
		for (let i = 2; i < tokens.length; i++) {
			const token = tokens[i] ?? "";
			if (token.startsWith("-")) continue;
			const sourceReason = packageSpecifierSourceReason(token);
			if (sourceReason) {
				packages.push(unverifiedPackage("unverified npm source", "npm", "command", sourceReason));
				break;
			}
			if (!isPackageName(token)) break;
			const { name, version } = splitNameVersion(token);
			packages.push({ name, version, registry: "npm", source: "command" });
			break;
		}
		return packages.length > 0
			? packages
			: [
					unverifiedPackage(
						"unverified yarn dlx package",
						"npm",
						"command",
						"could not identify the package executed by yarn dlx",
					),
				];
	}
	if (subcommand !== "add") return packages;

	for (let i = 2; i < tokens.length; i++) {
		const t = tokens[i] ?? "";
		if (t.startsWith("-")) continue;
		const sourceReason = packageSpecifierSourceReason(t);
		if (sourceReason) {
			packages.push(unverifiedPackage("unverified npm source", "npm", "command", sourceReason));
			continue;
		}
		if (!isPackageName(t)) break;
		const { name, version } = splitNameVersion(t);
		packages.push({ name, version, registry: "npm", source: "command" });
	}
	return packages;
}

function extractPnpmBunPackages(tokens: string[], binary: string): ParsedPackage[] {
	const packages: ParsedPackage[] = [];

	if (binary === "bunx") {
		// bunx <pkg> — first non-flag token
		for (let i = 1; i < tokens.length; i++) {
			const t = tokens[i] ?? "";
			if (t.startsWith("-")) continue;
			const sourceReason = packageSpecifierSourceReason(t);
			if (sourceReason) {
				packages.push(unverifiedPackage("unverified npm source", "npm", "command", sourceReason));
				return packages;
			}
			if (!isPackageName(t)) break;
			const { name, version } = splitNameVersion(t);
			packages.push({ name, version, registry: "npm", source: "command" });
			break;
		}
		return packages;
	}

	// pnpm add/install/dlx
	const subcommand = tokens[1] ?? "";
	if (subcommand === "dlx") {
		// pnpm dlx <pkg> — first non-flag
		for (let i = 2; i < tokens.length; i++) {
			const t = tokens[i] ?? "";
			if (t.startsWith("-")) continue;
			const sourceReason = packageSpecifierSourceReason(t);
			if (sourceReason) {
				packages.push(unverifiedPackage("unverified npm source", "npm", "command", sourceReason));
				return packages;
			}
			if (!isPackageName(t)) break;
			const { name, version } = splitNameVersion(t);
			packages.push({ name, version, registry: "npm", source: "command" });
			break;
		}
		return packages;
	}

	if (!["add", "install", "i"].includes(subcommand)) return packages;

	for (let i = 2; i < tokens.length; i++) {
		const t = tokens[i] ?? "";
		if (t.startsWith("-")) continue;
		const sourceReason = packageSpecifierSourceReason(t);
		if (sourceReason) {
			packages.push(unverifiedPackage("unverified npm source", "npm", "command", sourceReason));
			continue;
		}
		if (!isPackageName(t)) break;
		const { name, version } = splitNameVersion(t);
		packages.push({ name, version, registry: "npm", source: "command" });
	}
	return packages;
}

function extractBunPackages(tokens: string[]): ParsedPackage[] {
	const packages: ParsedPackage[] = [];
	const subcommand = tokens[1] ?? "";

	if (!["add", "install", "i"].includes(subcommand)) return packages;

	for (let i = 2; i < tokens.length; i++) {
		const t = tokens[i] ?? "";
		if (t.startsWith("-")) continue;
		const sourceReason = packageSpecifierSourceReason(t);
		if (sourceReason) {
			packages.push(unverifiedPackage("unverified npm source", "npm", "command", sourceReason));
			continue;
		}
		if (!isPackageName(t)) break;
		const { name, version } = splitNameVersion(t);
		packages.push({ name, version, registry: "npm", source: "command" });
	}
	return packages;
}

function extractPipPackages(tokens: string[]): ParsedPackage[] {
	const packages: ParsedPackage[] = [];
	const subcommand = tokens[1] ?? "";
	if (subcommand !== "install") return packages;

	let skipNext = false;
	for (let i = 2; i < tokens.length; i++) {
		const t = tokens[i] ?? "";
		if (skipNext) {
			skipNext = false;
			continue;
		}
		if (t === "-r" || t === "--requirement") {
			packages.push(
				unverifiedPackage(
					"requirements file",
					"pypi",
					"command",
					"references a requirements file whose package names were not available for inspection",
				),
			);
			skipNext = true;
			continue;
		}
		if (t.startsWith("--requirement=") || /^-r.+/.test(t)) {
			packages.push(
				unverifiedPackage(
					"requirements file",
					"pypi",
					"command",
					"references a requirements file whose package names were not available for inspection",
				),
			);
			continue;
		}
		if (t === "-e" || t === "--editable" || t.startsWith("--editable=")) {
			packages.push(
				unverifiedPackage(
					"editable package source",
					"pypi",
					"command",
					"uses an editable package source that was not checked by a registry",
				),
			);
			skipNext = !t.includes("=");
			continue;
		}
		// pip flags that take a value
		if (
			[
				"-c",
				"--constraint",
				"-t",
				"--target",
				"--prefix",
				"-i",
				"--index-url",
				"--extra-index-url",
				"-f",
				"--find-links",
			].includes(t)
		) {
			skipNext = true;
			continue;
		}
		if (t.startsWith("-")) continue;
		const sourceReason = packageSpecifierSourceReason(t);
		if (sourceReason) {
			packages.push(unverifiedPackage("unverified pypi source", "pypi", "command", sourceReason));
			continue;
		}
		if (!isPackageName(t)) break;

		// Handle version specifiers: requests==2.31.0, flask>=2.0
		const match = t.match(/^([a-zA-Z0-9._-]+)(?:[><=!~]+(.+))?$/);
		if (match) {
			packages.push({
				name: match[1] as string,
				version: match[2],
				registry: "pypi",
				source: "command",
			});
		} else {
			packages.push(
				unverifiedPackage(
					"unverified pypi source",
					"pypi",
					"command",
					"contains a package specification the package checker could not parse",
				),
			);
		}
	}
	return packages;
}

function extractFromPackageJson(content: string): ParsedPackage[] {
	const packages: ParsedPackage[] = [];
	try {
		const data = JSON.parse(content) as Record<string, unknown>;
		for (const section of [
			"dependencies",
			"devDependencies",
			"optionalDependencies",
			"peerDependencies",
		]) {
			const entries = data[section];
			if (!entries || typeof entries !== "object" || Array.isArray(entries)) continue;

			for (const [name, version] of Object.entries(entries)) {
				if (typeof version !== "string") {
					packages.push(
						unverifiedPackage(
							name,
							"npm",
							"package.json",
							"has a dependency specification the package checker could not parse",
						),
					);
					continue;
				}
				const sourceReason = unverifiedSourceReason(version);
				if (sourceReason) {
					packages.push(unverifiedPackage(name, "npm", "package.json", sourceReason));
					continue;
				}

				packages.push({
					name,
					version: version.replace(/^[\^~>=<]+/, ""),
					registry: "npm",
					source: "package.json",
				});
			}
		}
	} catch {
		// The evaluator rejects incomplete package.json content before using this result.
	}
	return packages;
}

function extractFromRequirementsTxt(content: string): ParsedPackage[] {
	const packages: ParsedPackage[] = [];
	const lines = content.split("\n");

	for (const rawLine of lines) {
		const line = rawLine.trim();
		if (!line || line.startsWith("#")) continue;

		if (/^(?:-r\s*|--requirement(?:\s|=)|-r\S|--requirement$)/i.test(line)) {
			packages.push(
				unverifiedPypiSource(
					"references a nested requirements file whose package names were not available for inspection",
				),
			);
			continue;
		}
		if (/^(?:-e(?:\s|=|$)|--editable(?:\s|=|$))/i.test(line)) {
			packages.push(
				unverifiedPypiSource("uses an editable package source that was not checked by a registry"),
			);
			continue;
		}
		if (
			/^(?:-i(?:\s|=|$)|--(?:index-url|extra-index-url|find-links|constraint|trusted-host)(?:\s|=|$)|-f(?:\s|$)|-c(?:\s|$))/i.test(
				line,
			)
		) {
			continue;
		}
		// Strip inline comments and environment markers
		const cleaned = line.split("#")[0]?.split(";")[0]?.trim() ?? "";
		if (!cleaned) continue;
		const sourceReason = unverifiedSourceReason(cleaned);
		if (
			sourceReason ||
			/\s@\s*(?:https?:|git\+|git:|ssh:)/i.test(cleaned) ||
			/\.(?:whl|tar\.gz|zip)$/i.test(cleaned)
		) {
			packages.push(
				unverifiedPypiSource(sourceReason ?? "uses an unsupported direct package reference"),
			);
			continue;
		}

		const match = cleaned.match(/^([a-zA-Z0-9._-]+)(?:\[.*\])?(?:[><=!~]+(.+))?$/);
		if (match) {
			packages.push({
				name: match[1] as string,
				version: match[2]?.trim(),
				registry: "pypi",
				source: "requirements.txt",
			});
		} else if (!cleaned.startsWith("-")) {
			packages.push(
				unverifiedPypiSource(
					"contains a package specification the package checker could not parse",
				),
			);
		}
	}
	return packages;
}
