/**
 * Generate a deterministic CycloneDX SBOM for the production workspace.
 *
 * The dependency graph is read from pnpm's frozen lockfile view instead of
 * walking node_modules. This keeps the evidence independent of platform
 * symlinks and makes a commercial build fail when a dependency identity is
 * missing. The output is intentionally free of host paths, timestamps from
 * the current clock, and random UUIDs.
 *
 * Usage:
 *   node scripts/generate-sbom.mjs [--output <file>]
 *
 * `SOURCE_DATE_EPOCH` is used for the CycloneDX metadata timestamp. In
 * commercial mode the caller must provide it (the release wrapper derives it
 * from the checked-out commit when CI has not set it).
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { cycloneDxHashFromSri } from "./lib/release-evidence-digests.mjs";
import { parseHashLockedRequirements } from "./lib/python-requirements-sbom.mjs";

const exposedSigningMaterial = [
	"AIDR_SIGNING_PRIVATE_KEY_PEM_PATH",
	"AIDR_SIGNING_PRIVATE_KEY_PEM",
	"AIDR_RELEASE_SIGNING_PRIVATE_KEY_PATH",
	"AIG_DATA_SIGNING_PRIVATE_KEY_PEM",
	"AIG_PRIVATE_KEY_PEM",
	"AIG_SIGNING_PRIVATE_KEY",
	"AIG_SIGNING_PRIVATE_KEY_PATH",
	"SIGNING_PRIVATE_KEY",
].filter((name) => process.env[name]);
if (exposedSigningMaterial.length > 0) {
	console.error(`SBOM generation refuses private signing material: ${exposedSigningMaterial.join(", ")}`);
	process.exit(2);
}

const repoRoot = path.resolve(process.cwd());
const args = parseArgs(process.argv.slice(2));
const outputPath = path.resolve(repoRoot, args["--output"] ?? ".release-evidence/aidr-sbom.cdx.json");
const commercial = process.env.AIDR_RELEASE_MODE === "commercial" || process.env.AIDR_REQUIRE_SBOM === "1";
const sourceDateEpoch = resolveSourceDateEpoch();
const lockfilePath = path.join(repoRoot, "pnpm-lock.yaml");
const lockfileBytes = readFileSync(lockfilePath);
const lockfileDigest = createHash("sha256").update(lockfileBytes).digest("hex");
const lockIntegrities = parseLockIntegrities(lockfileBytes.toString("utf8"));
const pythonLockfileBytes = readFileSync(path.join(repoRoot, "services/aig-bridge/requirements-runtime.lock"));
const pythonLockfileDigest = createHash("sha256").update(pythonLockfileBytes).digest("hex");
const pythonPackages = parseHashLockedRequirements(pythonLockfileBytes.toString("utf8"));

const pnpmCommand = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const pnpmArgs = ["list", "--json", "--prod", "--recursive", "--depth", "Infinity", "--lockfile-only"];
const command = process.platform === "win32" ? process.env.ComSpec ?? "cmd.exe" : pnpmCommand;
const commandArgs =
	process.platform === "win32"
		? ["/d", "/s", "/c", `${pnpmCommand} ${pnpmArgs.join(" ")}`]
		: pnpmArgs;
const result = spawnSync(
	command,
	commandArgs,
	{
		cwd: repoRoot,
		encoding: "utf8",
		maxBuffer: 32 * 1024 * 1024,
	},
);

if (result.error || result.status !== 0) {
	const detail = result.error?.message ?? String(result.stderr ?? "").trim();
	console.error(`Unable to obtain the frozen pnpm dependency graph: ${detail}`);
	process.exit(1);
}

let workspaceGraph;
try {
	workspaceGraph = JSON.parse(result.stdout);
} catch (error) {
	console.error(`pnpm list returned invalid JSON: ${formatError(error)}`);
	process.exit(1);
}

if (!Array.isArray(workspaceGraph)) {
	console.error("pnpm list did not return a workspace array");
	process.exit(1);
}

const workspaceByName = new Map();
for (const workspace of workspaceGraph) {
	if (!workspace || typeof workspace !== "object") continue;
	if (typeof workspace.name !== "string" || !isVersion(workspace.version)) continue;
	workspaceByName.set(workspace.name, workspace.version);
}

const components = new Map();
const dependencyEdges = new Map();
const unresolved = [];
const missingLicenses = [];
const missingIntegrities = [];
const visited = new Set();

for (const workspace of workspaceGraph) {
	if (!workspace || typeof workspace !== "object") continue;
	if (typeof workspace.name !== "string" || !isVersion(workspace.version)) continue;
	const ref = addComponent(workspace.name, workspace.version, workspace, "application");
	visitNode(workspace, ref);
}

// The bridge image installs this exact hash-locked Python set. A flat edge
// records package presence without inventing transitive dependency edges.
const releaseVersion = process.env.AIDR_RELEASE_VERSION ?? "workspace";
const bridgeRef = "urn:aidr:aig-bridge";
components.set(bridgeRef, {
	type: "application",
	"bom-ref": bridgeRef,
	name: "AIDR AIG Bridge",
	version: releaseVersion,
});
const bridgeDependencies = new Set();
for (const pkg of pythonPackages) {
	const ref = `pkg:pypi/${pkg.name}@${encodeURIComponent(pkg.version)}`;
	// The hash lock proves distribution identity, not licence terms. Do not let
	// commercial generation succeed with an SBOM promotion will reject.
	missingLicenses.push(`${pkg.name}@${pkg.version} (PyPI runtime)`);
	components.set(ref, {
		type: "library",
		"bom-ref": ref,
		name: pkg.name,
		version: pkg.version,
		purl: ref,
		hashes: pkg.hashes.map((content) => ({ alg: "SHA-256", content })),
		properties: [{ name: "aidr:source-lockfile", value: "services/aig-bridge/requirements-runtime.lock" }],
	});
	bridgeDependencies.add(ref);
}
dependencyEdges.set(bridgeRef, bridgeDependencies);
dependencyEdges.set("urn:aidr:workspace", new Set([
	bridgeRef,
	...workspaceGraph
		.filter((workspace) => workspace && typeof workspace.name === "string" && isVersion(workspace.version))
		.map((workspace) => npmPurl(workspace.name, workspace.version)),
]));

if (unresolved.length > 0) {
	const unique = [...new Set(unresolved)].sort(compareStrings);
	console.error("Dependency graph contains packages without a locked identity:");
	for (const item of unique) console.error(`  - ${item}`);
	if (commercial) process.exit(1);
}
if (missingLicenses.length > 0 || missingIntegrities.length > 0) {
	if (missingLicenses.length > 0) {
		console.error(`Dependency packages without license metadata: ${[...new Set(missingLicenses)].sort(compareStrings).join(", ")}`);
	}
	if (missingIntegrities.length > 0) {
		console.error(`Dependency packages without lock integrity: ${[...new Set(missingIntegrities)].sort(compareStrings).join(", ")}`);
	}
	if (commercial) process.exit(1);
}

const componentList = [...components.values()].sort((a, b) => compareStrings(a["bom-ref"], b["bom-ref"]));
const dependencyList = [...dependencyEdges.entries()]
	.map(([ref, dependsOn]) => ({ ref, dependsOn: [...dependsOn].sort(compareStrings) }))
	.sort((a, b) => compareStrings(a.ref, b.ref));

const timestamp = new Date(sourceDateEpoch * 1000).toISOString();
const payload = {
	bomFormat: "CycloneDX",
	specVersion: "1.5",
	version: 1,
	metadata: {
		timestamp,
		properties: [
			{ name: "aidr:lockfile-sha256", value: lockfileDigest },
			{ name: "aidr:python-runtime-lockfile-sha256", value: pythonLockfileDigest },
			{
				name: "aidr:sbom-limitations",
				value: "Container base/OS layers, upstream Supabase images, and AI-Infra-Guard server components are not included; image SBOM acceptance remains open",
			},
			...(process.env.AIDR_RC_VERSION ? [{ name: "aidr:rc-version", value: process.env.AIDR_RC_VERSION }] : []),
			...(process.env.AIDR_SOURCE_DIGEST ? [{ name: "aidr:source-digest", value: process.env.AIDR_SOURCE_DIGEST }] : []),
			...(process.env.AIDR_DATA_DIGEST ? [{ name: "aidr:data-digest", value: process.env.AIDR_DATA_DIGEST }] : []),
			...(process.env.AIDR_IMAGE_DIGEST ? [{ name: "aidr:image-digest", value: process.env.AIDR_IMAGE_DIGEST }] : []),
		],
		tools: [{ vendor: "SingularityRD", name: "aidr-generate-sbom", version: "1.0.0" }],
		component: {
			type: "application",
			"bom-ref": "urn:aidr:workspace",
			name: "Singularity AIDR workspace",
			version: releaseVersion,
		},
	},
	components: componentList,
	dependencies: dependencyList,
};

const canonicalPayload = JSON.stringify(payload);
payload.serialNumber = `urn:uuid:${toUuid(createHash("sha256").update(canonicalPayload).digest("hex"))}`;
const output = `${JSON.stringify(payload, null, 2)}\n`;

await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, output, "utf8");
const digest = createHash("sha256").update(output, "utf8").digest("hex");
await writeFile(`${outputPath}.sha256`, `${digest}  ${path.basename(outputPath)}\n`, "utf8");

console.log(`Wrote ${outputPath} (${componentList.length} components, sha256 ${digest})`);

function visitNode(node, parentRef) {
	if (!node || typeof node !== "object") return;
	// pnpm's JSON graph may repeat a package at multiple edges. Keep the
	// component identity but avoid recursively traversing the same object.
	if (visited.has(node)) return;
	visited.add(node);

	const edgeSet = dependencyEdges.get(parentRef) ?? new Set();
	for (const [alias, dependency] of dependencyEntries(node)) {
		const resolved = resolveDependency(alias, dependency);
		if (!resolved) continue;
		const childRef = addComponent(resolved.name, resolved.version, dependency, "library");
		edgeSet.add(childRef);
		visitNode(dependency, childRef);
	}
	dependencyEdges.set(parentRef, edgeSet);
}

function dependencyEntries(node) {
	const out = [];
	for (const field of ["dependencies", "optionalDependencies"]) {
		if (!node[field] || typeof node[field] !== "object") continue;
		for (const [alias, dependency] of Object.entries(node[field])) out.push([alias, dependency]);
	}
	return out.sort(([a], [b]) => compareStrings(a, b));
}

function resolveDependency(alias, dependency) {
	if (!dependency || typeof dependency !== "object") {
		unresolved.push(`${alias}: missing lockfile node`);
		return null;
	}
	const name = typeof dependency.from === "string" ? dependency.from : alias;
	let version = typeof dependency.version === "string" ? dependency.version : null;
	if (version?.startsWith("link:")) version = workspaceByName.get(name) ?? null;
	if (!version || !isVersion(version)) {
		unresolved.push(`${name}: missing locked version`);
		return null;
	}
	return { name, version };
}

function addComponent(name, version, node, type) {
	const ref = npmPurl(name, version);
	if (!components.has(ref)) {
		const packageMetadata = readPackageMetadata(node);
		const lockIntegrity = resolveLockIntegrity(name, version);
		const isWorkspaceComponent = workspaceByName.has(name);
		const component = {
			type: isWorkspaceComponent ? "application" : type,
			"bom-ref": ref,
			name,
			version,
			purl: ref,
		};
		if (packageMetadata.license) component.licenses = packageMetadata.license;
		else if (!isWorkspaceComponent) missingLicenses.push(`${name}@${version}`);
		if (lockIntegrity) component.hashes = [lockIntegrity];
		else if (!isWorkspaceComponent) missingIntegrities.push(`${name}@${version}`);
		const lockKey = findLockKey(name, version);
		if (lockKey) component.properties = [{ name: "pnpm:lock-key", value: lockKey }];
		if (typeof node?.resolved === "string" && /^https:\/\//.test(node.resolved)) {
			component.externalReferences = [{ type: "distribution", url: node.resolved }];
		}
		components.set(ref, component);
	}
	return ref;
}

function npmPurl(name, version) {
	return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

function resolveSourceDateEpoch() {
	const raw = process.env.SOURCE_DATE_EPOCH;
	if (raw === undefined || raw === "") {
		if (commercial) {
			console.error("Commercial SBOM generation requires SOURCE_DATE_EPOCH.");
			process.exit(2);
		}
		return 0;
	}
	const value = Number(raw);
	if (!Number.isInteger(value) || value < 0) {
		console.error(`Invalid SOURCE_DATE_EPOCH: ${raw}`);
		process.exit(2);
	}
	return value;
}

function readPackageMetadata(node) {
	if (!node || typeof node.path !== "string") return {};
	const packageJson = path.join(node.path, "package.json");
	if (!existsSync(packageJson)) return {};
	try {
		const pkg = JSON.parse(readFileSync(packageJson, "utf8"));
		return { license: normalizeLicenses(pkg.license, pkg.licenses) };
	} catch {
		return {};
	}
}

function normalizeLicenses(license, licenses) {
	const values = licenses ?? license;
	const entries = Array.isArray(values) ? values : values ? [values] : [];
	const normalized = [];
	for (const entry of entries) {
		if (typeof entry === "string") {
			if (/^[A-Za-z0-9.-]+$/.test(entry)) normalized.push({ license: { id: entry } });
			else normalized.push({ license: { expression: entry } });
		} else if (entry && typeof entry === "object") {
			const name = typeof entry.name === "string" ? entry.name : typeof entry.type === "string" ? entry.type : undefined;
			const url = typeof entry.url === "string" ? entry.url : undefined;
			if (name || url) normalized.push({ license: { ...(name ? { name } : {}), ...(url ? { url } : {}) } });
		}
	}
	return normalized.length > 0 ? normalized : undefined;
}

function parseLockIntegrities(raw) {
	const map = new Map();
	let inPackages = false;
	let currentKey;
	for (const line of raw.split(/\r?\n/)) {
		if (/^packages:\s*$/.test(line)) {
			inPackages = true;
			continue;
		}
		if (inPackages && /^snapshots:\s*$/.test(line)) break;
		const keyMatch = inPackages ? line.match(/^  (.+):\s*$/) : null;
		if (keyMatch) {
			currentKey = unquoteYaml(keyMatch[1]);
			continue;
		}
		if (!inPackages || !currentKey) continue;
		const inline = line.match(/^\s{4}resolution:\s*\{[^}]*integrity:\s*([^,}]+)[^}]*\}/);
		const nested = line.match(/^\s{6}integrity:\s*(\S+)\s*$/);
		const value = inline?.[1] ?? nested?.[1];
		if (value) map.set(currentKey, unquoteYaml(value));
	}
	return map;
}

function findLockKey(name, version) {
	const prefix = `${name}@${version}`;
	for (const key of lockIntegrities.keys()) {
		if (key === prefix || key.startsWith(`${prefix}(`) || key.startsWith(`${prefix}_`)) return key;
	}
	return undefined;
}

function resolveLockIntegrity(name, version) {
	const value = lockIntegrities.get(findLockKey(name, version));
	return cycloneDxHashFromSri(value);
}

function unquoteYaml(value) {
	const trimmed = value.trim();
	if (trimmed.startsWith("'") && trimmed.endsWith("'")) return trimmed.slice(1, -1).replace(/''/g, "'");
	if (trimmed.startsWith('"') && trimmed.endsWith('"')) return trimmed.slice(1, -1);
	return trimmed;
}

function isVersion(value) {
	return typeof value === "string" && value.length > 0 && !value.startsWith("link:");
}

function toUuid(hex) {
	const h = hex.slice(0, 32).split("");
	h[12] = "5";
	h[16] = ((Number.parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
	return `${h.slice(0, 8).join("")}-${h.slice(8, 12).join("")}-${h.slice(12, 16).join("")}-${h
		.slice(16, 20)
		.join("")}-${h.slice(20, 32).join("")}`;
}

function compareStrings(a, b) {
	return a < b ? -1 : a > b ? 1 : 0;
}

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i++) {
		const flag = argv[i];
		if (!flag?.startsWith("--")) continue;
		const value = argv[i + 1];
		if (value && !value.startsWith("--")) {
			values[flag] = value;
			i++;
		} else {
			values[flag] = "true";
		}
	}
	return values;
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}
