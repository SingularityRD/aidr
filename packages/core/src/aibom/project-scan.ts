/**
 * AI component discovery in a project directory for the AI-BOM.
 *
 * Reads the project's own dependency manifests and lockfiles (root directory
 * only) and keeps the dependencies the data-driven catalog
 * (`ai-component-catalog.json`) recognises as AI SDKs, frameworks, runtimes or
 * packaged models. A bounded walk also lists model weight files by extension.
 *
 * Nothing is executed and no network request is made. A manifest that exists
 * but cannot be parsed is reported as `invalid`, never as "no AI components".
 */

import { type Dirent, readFileSync } from "node:fs";
import { lstat, readdir, readFile } from "node:fs/promises";
import { basename, dirname, extname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const CATALOG_FILE = "ai-component-catalog.json";

/** Directory of this module; CommonJS bundles replace import.meta with an empty object. */
function moduleDir(): string | null {
	try {
		if (typeof import.meta.dirname === "string") return import.meta.dirname;
		if (typeof import.meta.url === "string") return dirname(fileURLToPath(import.meta.url));
	} catch {
		/* fall through */
	}
	return null;
}

export type AiBomEcosystem = "npm" | "pypi";
type CycloneDxComponentType = "application" | "framework" | "library" | "machine-learning-model";

export interface AiCatalogEntry {
	ecosystem: AiBomEcosystem;
	name: string;
	match: "exact" | "prefix";
	type: CycloneDxComponentType;
	category: string;
	supplier?: string;
	cve_product?: string;
}

interface AiCatalog {
	schema: string;
	version: number;
	packages: AiCatalogEntry[];
	model_file_extensions: string[];
}

const COMPONENT_TYPES: readonly CycloneDxComponentType[] = [
	"application",
	"framework",
	"library",
	"machine-learning-model",
];

function isCatalogEntry(value: unknown): value is AiCatalogEntry {
	if (!value || typeof value !== "object") return false;
	const entry = value as Record<string, unknown>;
	return (
		(entry.ecosystem === "npm" || entry.ecosystem === "pypi") &&
		typeof entry.name === "string" &&
		entry.name.length > 0 &&
		(entry.match === "exact" || entry.match === "prefix") &&
		COMPONENT_TYPES.includes(entry.type as CycloneDxComponentType) &&
		typeof entry.category === "string" &&
		(entry.supplier === undefined || typeof entry.supplier === "string") &&
		(entry.cve_product === undefined || typeof entry.cve_product === "string")
	);
}

let cachedCatalog: AiCatalog | null = null;

function readCatalogFile(): unknown {
	const dir = moduleDir();
	const candidates = dir
		? [join(dir, CATALOG_FILE), join(dir, "..", "..", "src", "aibom", CATALOG_FILE)]
		: [];
	for (const candidate of candidates) {
		try {
			return JSON.parse(readFileSync(candidate, "utf8"));
		} catch {
			// Try the next location.
		}
	}
	throw new Error(`AI component catalog (${CATALOG_FILE}) is missing`);
}

/**
 * The bundled catalog, validated once. A missing or malformed catalog throws:
 * an empty catalog would silently report "no AI components".
 */
export function loadAiComponentCatalog(): AiCatalog {
	if (cachedCatalog) return cachedCatalog;
	const data = readCatalogFile() as AiCatalog;
	if (
		data.schema !== "aidr-ai-component-catalog/v1" ||
		!Array.isArray(data.packages) ||
		!data.packages.every(isCatalogEntry) ||
		!Array.isArray(data.model_file_extensions) ||
		!data.model_file_extensions.every((ext) => typeof ext === "string" && ext.startsWith("."))
	) {
		throw new Error("AI component catalog is malformed");
	}
	cachedCatalog = data;
	return data;
}

/** PEP 503 name normalisation; npm names are compared lowercased. */
export function normalizePackageName(ecosystem: AiBomEcosystem, name: string): string {
	const lowered = name.trim().toLowerCase();
	return ecosystem === "pypi" ? lowered.replace(/[-_.]+/g, "-") : lowered;
}

export function matchCatalogEntry(
	catalog: AiCatalog,
	ecosystem: AiBomEcosystem,
	name: string,
): AiCatalogEntry | undefined {
	const normalized = normalizePackageName(ecosystem, name);
	let prefixMatch: AiCatalogEntry | undefined;
	for (const entry of catalog.packages) {
		if (entry.ecosystem !== ecosystem) continue;
		const candidate = normalizePackageName(ecosystem, entry.name);
		if (entry.match === "exact" && candidate === normalized) return entry;
		if (
			entry.match === "prefix" &&
			normalized.startsWith(candidate) &&
			normalized.length > candidate.length &&
			(!prefixMatch || candidate.length > normalizePackageName(ecosystem, prefixMatch.name).length)
		) {
			prefixMatch = entry;
		}
	}
	return prefixMatch;
}

type ManifestStatus = "read" | "invalid";

interface ProjectManifest {
	/** Project-relative file name. */
	path: string;
	status: ManifestStatus;
	/** Dependencies declared (manifests) or resolved (lockfiles) in this file. */
	dependencies: number;
}

export interface AiProjectPackage {
	ecosystem: AiBomEcosystem;
	/** Name as declared (npm) or PEP 503-normalised (PyPI). */
	name: string;
	/** Exact version from a lockfile or an exact pin; null when only a range is declared. */
	version: string | null;
	/** Declared requirement, when a manifest declared one. */
	declared: string | null;
	version_source: "lockfile" | "manifest-pin" | null;
	/** Project-relative manifests and lockfiles naming this package, sorted. */
	manifests: string[];
	type: CycloneDxComponentType;
	category: string;
	supplier: string | null;
	cve_product: string | null;
}

export interface AiProjectModelFile {
	/** Project-relative path using `/` separators. */
	path: string;
	format: string;
	size_bytes: number;
}

export interface AiProjectScan {
	root: string;
	name: string;
	version: string | null;
	manifests: ProjectManifest[];
	packages: AiProjectPackage[];
	model_files: AiProjectModelFile[];
	/** False when the model-file walk hit its bound before finishing. */
	model_scan_complete: boolean;
}

interface Declared {
	ecosystem: AiBomEcosystem;
	name: string;
	spec: string | null;
	exact: string | null;
	manifest: string;
}

interface Resolved {
	ecosystem: AiBomEcosystem;
	name: string;
	version: string;
	manifest: string;
}

const NPM_EXACT_RE = /^=?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;
const PEP440_VERSION_RE = /^[0-9][0-9A-Za-z.+!_-]*$/;

function npmExact(spec: string): string | null {
	return NPM_EXACT_RE.exec(spec.trim())?.[1] ?? null;
}

/** `==1.2.3` / `===1.2.3` (no wildcard) is an exact pin. */
function pep440Exact(spec: string): string | null {
	const match = /^\s*===?\s*([^\s,;]+)\s*$/.exec(spec);
	const version = match?.[1];
	return version && PEP440_VERSION_RE.test(version) && !version.includes("*") ? version : null;
}

/** A PEP 508 requirement: name, extras, specifier, environment marker. */
function parsePep508(requirement: string): { name: string; spec: string | null } | null {
	const cleaned = requirement.split(";")[0]?.split(" #")[0]?.trim() ?? "";
	const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*\(?\s*([^()]*?)\s*\)?$/.exec(
		cleaned,
	);
	if (!match?.[1] || cleaned.includes("@")) {
		// Direct references (`name @ url`) keep their name but carry no version.
		const direct = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@/.exec(cleaned);
		return direct?.[1] ? { name: direct[1], spec: null } : null;
	}
	return { name: match[1], spec: match[2] ? match[2] : null };
}

/** Code-unit order: locale-independent, so the BOM is byte-for-byte reproducible. */
export function compareText(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

function asRecord(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

// ── npm ─────────────────────────────────────────────────────────────────────

const NPM_SECTIONS = [
	"dependencies",
	"devDependencies",
	"optionalDependencies",
	"peerDependencies",
] as const;

interface ProjectIdentity {
	name?: string;
	version?: string;
}

function recordIdentity(identity: ProjectIdentity, key: string, value: unknown): void {
	if (typeof value !== "string" || !value.trim()) return;
	if (key === "name") identity.name ??= value.trim();
	if (key === "version") identity.version ??= value.trim();
}

function readPackageJson(content: string, manifest: string, identity: ProjectIdentity): Declared[] {
	const data = asRecord(JSON.parse(content));
	if (!data) throw new Error("package.json root is not an object");
	recordIdentity(identity, "name", data.name);
	recordIdentity(identity, "version", data.version);
	return NPM_SECTIONS.flatMap((section) =>
		Object.entries(asRecord(data[section]) ?? {}).map(([name, spec]) => {
			const text = typeof spec === "string" ? spec : null;
			return {
				ecosystem: "npm" as const,
				name,
				spec: text,
				exact: text ? npmExact(text) : null,
				manifest,
			};
		}),
	);
}

function readPackageLock(content: string, manifest: string): Resolved[] {
	const data = asRecord(JSON.parse(content));
	if (!data) throw new Error("package-lock.json root is not an object");
	const packages = asRecord(data.packages);
	// lockfileVersion 2/3 key entries by install path; version 1 by package name.
	const entries = packages
		? Object.entries(packages).map(
				([path, entry]) => [/^node_modules\/((?:@[^/]+\/)?[^/]+)$/.exec(path)?.[1], entry] as const,
			)
		: Object.entries(asRecord(data.dependencies) ?? {});
	const resolved: Resolved[] = [];
	for (const [name, entry] of entries) {
		const version = asRecord(entry)?.version;
		if (name && typeof version === "string")
			resolved.push({ ecosystem: "npm", name, version, manifest });
	}
	return resolved;
}

function readPnpmLock(content: string, manifest: string): Resolved[] {
	const data = asRecord(parseYaml(content));
	if (!data) throw new Error("pnpm-lock.yaml root is not a mapping");
	const importer = asRecord(asRecord(data.importers)?.["."]) ?? data;
	const resolved: Resolved[] = [];
	for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
		for (const [name, entry] of Object.entries(asRecord(importer[section]) ?? {})) {
			const raw = typeof entry === "string" ? entry : asRecord(entry)?.version;
			// `1.2.3(peer@4.5.6)` → `1.2.3`; `link:` / `file:` are not registry versions.
			const version = typeof raw === "string" ? raw.replace(/\(.*$/, "") : "";
			if (NPM_EXACT_RE.test(version)) resolved.push({ ecosystem: "npm", name, version, manifest });
		}
	}
	return resolved;
}

// ── Python ──────────────────────────────────────────────────────────────────

function pep508Declared(requirement: string, manifest: string): Declared | null {
	const parsed = parsePep508(requirement);
	if (!parsed) return null;
	return {
		ecosystem: "pypi",
		name: parsed.name,
		spec: parsed.spec,
		exact: parsed.spec ? pep440Exact(parsed.spec) : null,
		manifest,
	};
}

function readRequirements(content: string, manifest: string): Declared[] {
	const declared: Declared[] = [];
	for (const rawLine of content.split(/\r?\n/)) {
		// Drop comments, a trailing line continuation and per-requirement options (`--hash=…`).
		const line = rawLine
			.replace(/\s+#.*$/, "")
			.replace(/\s*\\$/, "")
			.split(/\s--?[a-z]/)[0]
			?.trim();
		if (!line || line.startsWith("#") || line.startsWith("-")) continue;
		const requirement = pep508Declared(line, manifest);
		if (requirement) declared.push(requirement);
	}
	return declared;
}

const TOML_STRING_RE = /"((?:[^"\\]|\\.)*)"|'([^']*)'/g;

function tomlString(value: string): string | undefined {
	const text = /^"([^"]*)"|^'([^']*)'/.exec(value);
	return text?.[1] ?? text?.[2];
}

/** `]` outside quoted strings closes an array (extras such as `"torch[cpu]"` do not). */
function closesTomlArray(text: string): boolean {
	return text.replace(TOML_STRING_RE, "").includes("]");
}

function requirementsInArray(text: string, manifest: string): Declared[] {
	return [...text.matchAll(TOML_STRING_RE)]
		.map((match) => pep508Declared(match[1] ?? match[2] ?? "", manifest))
		.filter((entry): entry is Declared => entry !== null);
}

/** PEP 621 / PEP 735 tables whose values are arrays of PEP 508 requirements. */
function isRequirementArray(table: string, key: string): boolean {
	return (
		(table === "project" && key === "dependencies") ||
		table === "project.optional-dependencies" ||
		table === "dependency-groups"
	);
}

/** Poetry and Pipfile tables of `name = "spec"` / `name = { version = "spec" }`. */
function isNameSpecTable(table: string): boolean {
	return (
		table === "tool.poetry.dependencies" ||
		table === "tool.poetry.dev-dependencies" ||
		/^tool\.poetry\.group\.[^.]+\.dependencies$/.test(table) ||
		table === "packages" ||
		table === "dev-packages"
	);
}

function nameSpecDeclared(table: string, key: string, value: string, manifest: string): Declared {
	const spec = tomlString(value) ?? /version\s*=\s*"([^"]*)"/.exec(value)?.[1] ?? null;
	// Poetry treats a bare version as an exact pin; Pipfile uses `==`.
	const poetryPin =
		table.startsWith("tool.poetry") && spec !== null && PEP440_VERSION_RE.test(spec) ? spec : null;
	return {
		ecosystem: "pypi",
		name: key,
		spec,
		exact: spec === null ? null : (pep440Exact(spec) ?? poetryPin),
		manifest,
	};
}

function tomlLine(rawLine: string): string {
	const trimmed = rawLine.trim();
	return trimmed.startsWith("#") ? "" : trimmed.replace(/\s+#.*$/, "");
}

/**
 * Minimal TOML reader for the dependency tables of `pyproject.toml` and
 * `Pipfile`: table headers, string arrays (possibly multi-line) and
 * `name = "spec"` / `name = { version = "spec" }` entries. Anything else is
 * ignored rather than guessed.
 */
function readTomlDependencies(
	content: string,
	manifest: string,
	identity: ProjectIdentity,
): Declared[] {
	const reader = new TomlDependencyReader(manifest, identity);
	for (const rawLine of content.split(/\r?\n/)) reader.line(tomlLine(rawLine));
	return reader.declared;
}

class TomlDependencyReader {
	readonly declared: Declared[] = [];
	private table = "";
	private openArray: string | null = null;

	constructor(
		private readonly manifest: string,
		private readonly identity: ProjectIdentity,
	) {}

	line(line: string): void {
		if (this.openArray !== null) {
			this.continueArray(line);
			return;
		}
		const header = /^\[([^[\]]+)\]$/.exec(line)?.[1];
		if (header) {
			this.table = header
				.trim()
				.replace(/\s*\.\s*/g, ".")
				.replace(/"/g, "");
			return;
		}
		const assignment = /^("?[A-Za-z0-9_.-]+"?)\s*=\s*(.+)$/.exec(line);
		if (assignment?.[1] && assignment[2] !== undefined)
			this.assignment(assignment[1].replace(/"/g, ""), assignment[2].trim());
	}

	private continueArray(line: string): void {
		this.openArray = `${this.openArray ?? ""} ${line}`;
		if (!closesTomlArray(line)) return;
		this.declared.push(...requirementsInArray(this.openArray, this.manifest));
		this.openArray = null;
	}

	private assignment(key: string, value: string): void {
		if (this.table === "project") recordIdentity(this.identity, key, tomlString(value));
		if (isRequirementArray(this.table, key) && value.startsWith("[")) {
			if (closesTomlArray(value)) this.declared.push(...requirementsInArray(value, this.manifest));
			else this.openArray = value;
		} else if (isNameSpecTable(this.table) && key.toLowerCase() !== "python") {
			this.declared.push(nameSpecDeclared(this.table, key, value, this.manifest));
		}
	}
}

/** `poetry.lock` / `uv.lock`: `[[package]]` blocks whose head carries `name` and `version`. */
function readPythonLock(content: string, manifest: string): Resolved[] {
	const resolved: Resolved[] = [];
	for (const block of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
		// Only the block's own keys, before any sub-table such as `[package.dependencies]`.
		const head = block.split(/^\s*\[/m)[0] ?? "";
		const name = /^\s*name\s*=\s*"([^"]*)"/m.exec(head)?.[1];
		const version = /^\s*version\s*=\s*"([^"]*)"/m.exec(head)?.[1];
		if (name && version) resolved.push({ ecosystem: "pypi", name, version, manifest });
	}
	return resolved;
}

// ── Scan ────────────────────────────────────────────────────────────────────

type ManifestReader =
	| {
			kind: "declared";
			read: (content: string, manifest: string, id: ProjectIdentity) => Declared[];
	  }
	| { kind: "resolved"; read: (content: string, manifest: string) => Resolved[] };

const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;

function readerFor(fileName: string): ManifestReader | null {
	const name = fileName.toLowerCase();
	if (name === "package.json") return { kind: "declared", read: readPackageJson };
	if (name === "package-lock.json" || name === "npm-shrinkwrap.json")
		return { kind: "resolved", read: readPackageLock };
	if (name === "pnpm-lock.yaml") return { kind: "resolved", read: readPnpmLock };
	if (/^requirements(?:[-_.][^/]*)?\.txt$/.test(name) || name === "requirements.in")
		return { kind: "declared", read: readRequirements };
	if (name === "pyproject.toml" || name === "pipfile")
		return { kind: "declared", read: readTomlDependencies };
	if (name === "poetry.lock" || name === "uv.lock")
		return { kind: "resolved", read: readPythonLock };
	return null;
}

interface ManifestReadout {
	identity: ProjectIdentity;
	manifests: ProjectManifest[];
	declared: Declared[];
	resolved: Resolved[];
}

/** Manifest files in the project root, `package.json` / `pyproject.toml` first so they name it. */
async function manifestFileNames(projectDir: string): Promise<string[]> {
	let entries: Dirent[];
	try {
		entries = await readdir(projectDir, { withFileTypes: true });
	} catch (error) {
		throw new Error(
			`Cannot read project directory ${projectDir}: ${(error as NodeJS.ErrnoException).code ?? "error"}`,
		);
	}
	const primary = (name: string) => (["package.json", "pyproject.toml"].includes(name) ? 0 : 1);
	return entries
		.filter((entry) => entry.isFile() && readerFor(entry.name) !== null)
		.map((entry) => entry.name)
		.sort((a, b) => primary(a) - primary(b) || compareText(a, b));
}

async function readProjectManifests(projectDir: string): Promise<ManifestReadout> {
	const readout: ManifestReadout = { identity: {}, manifests: [], declared: [], resolved: [] };
	for (const fileName of await manifestFileNames(projectDir)) {
		const reader = readerFor(fileName) as ManifestReader;
		try {
			const content = await readFile(join(projectDir, fileName), "utf8");
			if (content.length > MAX_MANIFEST_BYTES) throw new Error("manifest too large");
			let count: number;
			if (reader.kind === "declared") {
				const found = reader.read(content, fileName, readout.identity);
				readout.declared.push(...found);
				count = found.length;
			} else {
				const found = reader.read(content, fileName);
				readout.resolved.push(...found);
				count = found.length;
			}
			readout.manifests.push({ path: fileName, status: "read", dependencies: count });
		} catch {
			readout.manifests.push({ path: fileName, status: "invalid", dependencies: 0 });
		}
	}
	return readout;
}

function packageKey(ecosystem: AiBomEcosystem, name: string): string {
	return `${ecosystem}:${normalizePackageName(ecosystem, name)}`;
}

function addManifest(pkg: AiProjectPackage, manifest: string): void {
	pkg.manifests = [...new Set([...pkg.manifests, manifest])].sort(compareText);
}

/**
 * Declared dependencies the catalog recognises, with versions resolved from
 * exact pins and lockfiles. A lockfile only resolves the version of a declared
 * AI dependency; packages that appear in a lockfile alone are transitive and
 * are not listed.
 */
function aiPackages(catalog: AiCatalog, readout: ManifestReadout): AiProjectPackage[] {
	const packages = new Map<string, AiProjectPackage>();
	for (const dependency of readout.declared) {
		const entry = matchCatalogEntry(catalog, dependency.ecosystem, dependency.name);
		if (!entry) continue;
		const key = packageKey(dependency.ecosystem, dependency.name);
		const existing = packages.get(key);
		if (existing) mergeDeclared(existing, dependency);
		else packages.set(key, newAiPackage(entry, dependency));
	}
	for (const lock of readout.resolved) {
		const existing = packages.get(packageKey(lock.ecosystem, lock.name));
		if (!existing) continue;
		existing.version = lock.version;
		existing.version_source = "lockfile";
		addManifest(existing, lock.manifest);
	}
	return [...packages.values()].sort((a, b) =>
		compareText(`${a.ecosystem}:${a.name}`, `${b.ecosystem}:${b.name}`),
	);
}

function newAiPackage(entry: AiCatalogEntry, dependency: Declared): AiProjectPackage {
	return {
		ecosystem: dependency.ecosystem,
		name:
			dependency.ecosystem === "pypi"
				? normalizePackageName("pypi", dependency.name)
				: dependency.name,
		version: dependency.exact,
		declared: dependency.spec,
		version_source: dependency.exact ? "manifest-pin" : null,
		manifests: [dependency.manifest],
		type: entry.type,
		category: entry.category,
		supplier: entry.supplier ?? null,
		cve_product: entry.cve_product ?? null,
	};
}

/** The same package declared again (another manifest or dependency group). */
function mergeDeclared(pkg: AiProjectPackage, dependency: Declared): void {
	addManifest(pkg, dependency.manifest);
	pkg.declared ??= dependency.spec;
	if (!pkg.version && dependency.exact) {
		pkg.version = dependency.exact;
		pkg.version_source = "manifest-pin";
	}
}

const SKIPPED_DIRECTORIES = new Set([
	"node_modules",
	"__pycache__",
	"site-packages",
	"venv",
	"env",
	"target",
]);
const MAX_WALK_DEPTH = 6;
const MAX_WALK_ENTRIES = 20_000;

/** Symlinks are not followed: they can leave the project or loop. */
function entryKind(entry: Dirent, extensions: ReadonlySet<string>): "directory" | "model" | "skip" {
	if (entry.isSymbolicLink()) return "skip";
	if (entry.isDirectory())
		return entry.name.startsWith(".") || SKIPPED_DIRECTORIES.has(entry.name) ? "skip" : "directory";
	return entry.isFile() && extensions.has(extname(entry.name).toLowerCase()) ? "model" : "skip";
}

async function modelFile(root: string, path: string): Promise<AiProjectModelFile | null> {
	try {
		const stats = await lstat(path);
		return {
			path: relative(root, path).split(sep).join("/"),
			format: extname(path).slice(1).toLowerCase(),
			size_bytes: stats.size,
		};
	} catch {
		return null;
	}
}

/** Bounded, symlink-free walk for model weight files. */
class ModelFileWalk {
	readonly files: AiProjectModelFile[] = [];
	complete = true;
	private visited = 0;
	private readonly pending: Array<{ dir: string; depth: number }>;

	constructor(
		private readonly root: string,
		private readonly extensions: ReadonlySet<string>,
	) {
		this.pending = [{ dir: root, depth: 0 }];
	}

	async run(): Promise<{ files: AiProjectModelFile[]; complete: boolean }> {
		for (let next = this.pending.pop(); next; next = this.pending.pop()) {
			if (!(await this.visit(next.dir, next.depth))) break;
		}
		return { files: this.files, complete: this.complete };
	}

	/** False once the entry bound is exceeded. */
	private async visit(dir: string, depth: number): Promise<boolean> {
		let entries: Dirent[];
		try {
			entries = await readdir(dir, { withFileTypes: true });
		} catch {
			this.complete = false;
			return true;
		}
		this.visited += entries.length;
		if (this.visited > MAX_WALK_ENTRIES) {
			this.complete = false;
			return false;
		}
		for (const entry of entries) await this.visitEntry(join(dir, entry.name), depth, entry);
		return true;
	}

	private async visitEntry(path: string, depth: number, entry: Dirent): Promise<void> {
		const kind = entryKind(entry, this.extensions);
		if (kind === "model") {
			const file = await modelFile(this.root, path);
			if (file) this.files.push(file);
			else this.complete = false;
		} else if (kind === "directory") {
			if (depth < MAX_WALK_DEPTH) this.pending.push({ dir: path, depth: depth + 1 });
			else this.complete = false;
		}
	}
}

/** Scan one project directory for AI components. */
export async function scanProjectForAiComponents(projectDir: string): Promise<AiProjectScan> {
	const catalog = loadAiComponentCatalog();
	const readout = await readProjectManifests(projectDir);
	const models = await new ModelFileWalk(projectDir, new Set(catalog.model_file_extensions)).run();
	return {
		root: projectDir,
		name: readout.identity.name ?? basename(projectDir),
		version: readout.identity.version ?? null,
		manifests: readout.manifests,
		packages: aiPackages(catalog, readout),
		model_files: models.files.sort((a, b) => compareText(a.path, b.path)),
		model_scan_complete: models.complete,
	};
}
