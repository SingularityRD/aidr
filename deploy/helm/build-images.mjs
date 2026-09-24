#!/usr/bin/env node
/**
 * Stage, build and push the AIDR-owned container images the Helm chart runs.
 *
 * Upstream Supabase images (gotrue, postgrest, storage-api, envoy, postgres)
 * are used unchanged; only these images are built from this repository:
 *
 *   dashboard       deploy/dashboard + packages/dashboard/dist
 *   edge-functions  supabase/edge-runtime + reviewed upstream router + supabase/functions
 *   migrations      postgres client + the atomic plan rendered from supabase/migrations
 *   aig-server, aig-agent, aig-bridge   (optional AI-Infra-Guard stack)
 *
 * Usage:
 *   node deploy/helm/build-images.mjs --output <new-dir> [--only dashboard,edge-functions,migrations]
 *       [--upstream-dir deploy/upstream] [--registry <registry> [--tag <tag>] --build [--push]]
 *
 * Without --build the contexts are only staged and the exact docker commands
 * are printed. `images.json` in the output lists every image reference for the
 * air-gap bundler (one `--images <ref>` flag per reference):
 *   node scripts/build-airgap-images.mjs --output <bundle> $(jq -r '.images[].ref' <out>/images.json | sed 's/^/--images /')
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { buildAtomicMigrationSql, MIGRATION_FILENAME_PATTERN } from "../../scripts/lib/migration-contract.mjs";
import { compatibleInstalledHashes } from "../../scripts/lib/migration-hash-compat.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const requireCore = createRequire(join(root, "packages/core/package.json"));
const { parse } = requireCore("yaml");

/** Reviewed Supabase self-hosted release (same commit deployment-prepare verifies). */
export const UPSTREAM_SHA = "8c7a4d9dbbaf8b552893822e89d7bf06f33f9220";
export const COMPONENTS = ["dashboard", "edge-functions", "migrations", "aig-server", "aig-agent", "aig-bridge"];
const DEFAULT_COMPONENTS = ["dashboard", "edge-functions", "migrations"];
const REPOSITORIES = {
	dashboard: "aidr/dashboard",
	"edge-functions": "aidr/edge-functions",
	migrations: "aidr/migrations",
	"aig-server": "aidr/aig-server",
	"aig-agent": "aidr/aig-agent",
	"aig-bridge": "aidr/aig-bridge",
};

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function copyTree(source, destination, skip = () => false) {
	if (skip(source)) return;
	if (statSync(source).isDirectory()) {
		mkdirSync(destination, { recursive: true });
		for (const entry of readdirSync(source).sort()) copyTree(join(source, entry), join(destination, entry), skip);
	} else {
		mkdirSync(dirname(destination), { recursive: true });
		copyFileSync(source, destination);
		chmodSync(destination, 0o644);
	}
}

function inventory(directory, prefix = "") {
	return readdirSync(directory).sort().flatMap((name) => {
		const path = join(directory, name);
		const rel = prefix ? `${prefix}/${name}` : name;
		return statSync(path).isDirectory() ? inventory(path, rel) : [{ path: rel, sha256: sha256(readFileSync(path)) }];
	});
}

export function chartAppVersion() {
	return String(parse(readFileSync(join(here, "aidr/Chart.yaml"), "utf8")).appVersion);
}

function verifyUpstream(upstreamDir) {
	const git = (args) => spawnSync("git", ["-C", upstreamDir, ...args], { encoding: "utf8" });
	const head = git(["rev-parse", "HEAD"]);
	if (head.status !== 0 || head.stdout.trim() !== UPSTREAM_SHA) {
		throw new Error(`Upstream checkout ${upstreamDir} is not the reviewed Supabase commit ${UPSTREAM_SHA}; run: git submodule update --init deploy/upstream`);
	}
	const status = git(["status", "--porcelain", "--", "docker"]);
	if (status.status !== 0 || status.stdout.trim()) throw new Error("Upstream Docker configuration has local changes");
	const router = join(upstreamDir, "docker/volumes/functions/main/index.ts");
	if (!existsSync(router)) throw new Error("Upstream functions router docker/volumes/functions/main/index.ts is missing");
}

export function stageDashboard(context) {
	const dist = join(root, "packages/dashboard/dist");
	if (!existsSync(join(dist, "index.html"))) throw new Error("Build the dashboard first (pnpm -C packages/dashboard build)");
	for (const file of ["Dockerfile", "server.mjs", "monitoring.mjs"]) copyTree(join(root, "deploy/dashboard", file), join(context, file));
	copyTree(join(root, "deploy/saml-config.mjs"), join(context, "saml-config.mjs"));
	copyTree(join(root, "supabase/templates"), join(context, "auth-templates"));
	copyTree(dist, join(context, "public"), (path) => path.endsWith(".map"));
	return { context, dockerfile: join(context, "Dockerfile") };
}

export function stageEdgeFunctions(context, upstreamDir) {
	verifyUpstream(upstreamDir);
	const functions = join(context, "functions");
	// Upstream router and import map only; the "hello" sample is not served.
	const upstreamFunctions = join(upstreamDir, "docker/volumes/functions");
	copyTree(upstreamFunctions, functions, (path) => path === join(upstreamFunctions, "hello"));
	copyTree(join(root, "supabase/functions"), functions, (path) => path.split(/[\\/]/).includes("__tests__"));
	copyTree(join(here, "images/edge-functions.Dockerfile"), join(context, "Dockerfile"));
	return { context, dockerfile: join(context, "Dockerfile") };
}

export function stageMigrations(context, migrationsDir = join(root, "supabase/migrations")) {
	const names = readdirSync(migrationsDir).filter((name) => name.endsWith(".sql")).sort();
	const bad = names.find((name) => !MIGRATION_FILENAME_PATTERN.test(name));
	if (bad) throw new Error(`Invalid migration filename: ${bad}`);
	const migrations = names.map((name) => {
		const sql = readFileSync(join(migrationsDir, name), "utf8");
		return { name, sha256: sha256(sql), sql };
	});
	const plan = buildAtomicMigrationSql(migrations, compatibleInstalledHashes);
	copyTree(migrationsDir, join(context, "migrations"), (path) => statSync(path).isFile() && !path.endsWith(".sql"));
	writeFileSync(join(context, "migrate.sql"), plan, { mode: 0o644 });
	writeFileSync(join(context, "migrations.manifest.json"), `${JSON.stringify({
		schema_version: 1,
		plan_sha256: sha256(plan),
		migration_count: migrations.length,
		migrations: migrations.map(({ name, sha256: digest }) => ({ name, sha256: digest })),
	}, null, 2)}\n`, { mode: 0o644 });
	copyTree(join(here, "images/aidr-migrate.sh"), join(context, "aidr-migrate.sh"));
	chmodSync(join(context, "aidr-migrate.sh"), 0o755);
	copyTree(join(here, "images/migrations.Dockerfile"), join(context, "Dockerfile"));
	return { context, dockerfile: join(context, "Dockerfile") };
}

export function stageAigAgent(context) {
	copyTree(join(root, "services/aig-bridge/aig_compat"), join(context, "aig_compat"), (path) => path.includes("__pycache__"));
	copyTree(join(here, "images/aig-agent.Dockerfile"), join(context, "Dockerfile"));
	return { context, dockerfile: join(context, "Dockerfile") };
}

function buildPlan({ components, output, upstreamDir, registry, tag }) {
	const ref = (component) => `${registry || "<registry>"}/${REPOSITORIES[component]}:${tag}`;
	const steps = [];
	for (const component of components) {
		const context = join(output, component);
		if (component === "dashboard") steps.push({ component, ref: ref(component), ...stageDashboard(context) });
		else if (component === "edge-functions") steps.push({ component, ref: ref(component), ...stageEdgeFunctions(context, upstreamDir) });
		else if (component === "migrations") steps.push({ component, ref: ref(component), ...stageMigrations(context) });
		else if (component === "aig-server") {
			steps.push({ component, ref: ref(component), context: join(root, "vendor/ai-infra-guard"), dockerfile: join(root, "vendor/ai-infra-guard/Dockerfile") });
		} else if (component === "aig-bridge") {
			steps.push({ component, ref: ref(component), context: join(root, "services/aig-bridge"), dockerfile: join(root, "services/aig-bridge/Dockerfile") });
		} else if (component === "aig-agent") {
			const base = `${ref(component).replace(/:[^:/]+$/, "")}-base:${tag}`;
			steps.push({ component: "aig-agent-base", ref: base, context: join(root, "vendor/ai-infra-guard"), dockerfile: join(root, "vendor/ai-infra-guard/Dockerfile_Agent"), internal: true });
			steps.push({ component, ref: ref(component), ...stageAigAgent(context), buildArgs: { AIG_AGENT_BASE: base } });
		}
	}
	return steps;
}

function dockerArgs(step) {
	const args = ["build", "-f", step.dockerfile, "-t", step.ref];
	for (const [name, value] of Object.entries(step.buildArgs ?? {})) args.push("--build-arg", `${name}=${value}`);
	args.push(step.context);
	return args;
}

function run(args) {
	const result = spawnSync("docker", args, { stdio: "inherit" });
	if (result.status !== 0) throw new Error(`docker ${args[0]} failed for ${args.at(-1)}`);
}

export function main(argv = process.argv.slice(2)) {
	const { values } = parseArgs({
		args: argv,
		options: {
			output: { type: "string", default: ".aidr-images" },
			only: { type: "string" },
			"upstream-dir": { type: "string" },
			registry: { type: "string" },
			tag: { type: "string" },
			build: { type: "boolean", default: false },
			push: { type: "boolean", default: false },
		},
	});
	const components = values.only ? values.only.split(",").map((value) => value.trim()).filter(Boolean) : DEFAULT_COMPONENTS;
	const unknown = components.find((component) => !COMPONENTS.includes(component));
	if (unknown) throw new Error(`Unknown component "${unknown}"; choose from ${COMPONENTS.join(", ")}`);
	const tag = values.tag ?? chartAppVersion();
	if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag) || tag === "latest") throw new Error("--tag must be an immutable version tag (not latest)");
	const registry = values.registry?.replace(/\/+$/, "");
	if (registry !== undefined && !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(\/[a-z0-9._-]+)*$/.test(registry)) throw new Error("--registry must be a registry host[:port][/path]");
	if ((values.build || values.push) && !registry) throw new Error("--build and --push require --registry");
	if (values.push && !values.build) throw new Error("--push requires --build");
	const output = resolve(values.output);
	if (existsSync(output)) throw new Error(`Output ${output} already exists; choose a new directory`);
	mkdirSync(output, { recursive: true, mode: 0o700 });
	const upstreamDir = resolve(values["upstream-dir"] ?? join(root, "deploy/upstream"));
	const steps = buildPlan({ components, output, upstreamDir, registry, tag });
	const manifest = {
		schema_version: 1,
		kind: "aidr-helm-images",
		tag,
		registry: registry ?? null,
		upstream_sha: components.includes("edge-functions") ? UPSTREAM_SHA : null,
		images: steps.filter((step) => !step.internal).map((step) => ({
			component: step.component,
			ref: step.ref,
			context_inventory: step.context.startsWith(output) ? inventory(step.context) : null,
			context: relative(root, step.context) || ".",
		})),
	};
	writeFileSync(join(output, "images.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
	for (const step of steps) {
		const args = dockerArgs(step);
		if (values.build) run(args);
		else console.log(`docker ${args.map((arg) => (/\s/.test(arg) ? JSON.stringify(arg) : arg)).join(" ")}`);
	}
	if (values.push) for (const step of steps.filter((entry) => !entry.internal)) run(["push", step.ref]);
	console.log(`${values.build ? "Built" : "Staged"} ${manifest.images.length} image context(s) in ${output}; references in images.json.`);
	return manifest;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		main();
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exit(1);
	}
}
