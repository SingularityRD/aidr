import { readFileSync, statSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
	type AiBomAgentInput,
	aiInventoryGaps,
	buildCycloneDxBom,
	type CollectAiInventoryOptions,
	ConfigSchema,
	collectAiInventory,
	resolvePath,
} from "@singularityrd/aidr-core";
import { detectConnectorStatuses } from "../utils/connector-status.js";

interface AiBomOptions {
	format?: string;
	output?: string;
	path?: string;
	config?: string[];
	scanReport?: string;
}

/** Injectable collaborators, for tests. */
export interface AiBomDependencies {
	agents?: () => AiBomAgentInput[];
	collect?: typeof collectAiInventory;
	/** Extra collector inputs (plugin registry/cache paths, clock). */
	collectOptions?: Partial<CollectAiInventoryOptions>;
	serialNumber?: string;
	configPath?: string;
}

const FORMATS = ["cyclonedx-json", "json"] as const;

export default async function aibomCommand(options: AiBomOptions): Promise<void> {
	// Commander passes the Command as the second argument; never treat it as dependencies.
	await runAiBom(options);
}

/**
 * The saved infrastructure scan to include: `--scan-report`, otherwise the
 * report the AI-infrastructure policy is configured to read, if that policy is on.
 */
function infrastructureReportPath(options: AiBomOptions, configPath: string): string | undefined {
	if (options.scanReport) return resolve(options.scanReport);
	try {
		const config = ConfigSchema.parse(JSON.parse(readFileSync(configPath, "utf8")));
		const policy = config.policy.ai_infrastructure;
		return policy?.enabled ? resolvePath(policy.report_path) : undefined;
	} catch {
		// No or unreadable configuration: no configured report to include.
		return undefined;
	}
}

function fail(message: string): void {
	console.error(message);
	process.exitCode = 1;
}

function errorText(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function isDirectory(path: string): boolean {
	try {
		return statSync(path).isDirectory();
	} catch {
		return false;
	}
}

type Inventory = Awaited<ReturnType<typeof collectAiInventory>>;

async function collect(
	options: AiBomOptions,
	projectDir: string,
	dependencies: AiBomDependencies,
): Promise<Inventory> {
	const agents = (dependencies.agents ?? detectConnectorStatuses)().map(({ id, label, state }) => ({
		id,
		label,
		state,
	}));
	return (dependencies.collect ?? collectAiInventory)({
		projectDir,
		agents,
		...(options.config?.length ? { mcpConfigPaths: options.config } : {}),
		infrastructureReportPath: infrastructureReportPath(
			options,
			dependencies.configPath ?? resolvePath("~/.singularity-aidr/config.json"),
		),
		...dependencies.collectOptions,
	});
}

/** Writes a new private file; reports a failure and returns false. */
async function writeOutput(output: string, body: string, inventory: Inventory): Promise<boolean> {
	try {
		await writeFile(output, body, { encoding: "utf8", mode: 0o600, flag: "wx" });
	} catch (error) {
		fail(
			(error as NodeJS.ErrnoException).code === "EEXIST"
				? `${output} already exists; choose a new file name.`
				: `Could not write ${output}: ${errorText(error)}`,
		);
		return false;
	}
	console.error(
		`AI-BOM written to ${output}: ${inventory.agents.length} agent(s), ` +
			`${inventory.mcp_servers.length} MCP server(s), ${inventory.packages.length} AI package(s), ` +
			`${inventory.model_files.length} model file(s), ${inventory.plugins.length} plugin(s), ` +
			`${inventory.vulnerabilities.length} vulnerability record(s).`,
	);
	return true;
}

/** `aidr aibom [--format cyclonedx-json|json] [--output file] [--path dir]` */
export async function runAiBom(
	options: AiBomOptions,
	dependencies: AiBomDependencies = {},
): Promise<void> {
	const format = (options.format ?? "cyclonedx-json").toLowerCase();
	if (!(FORMATS as readonly string[]).includes(format)) {
		fail('--format must be "cyclonedx-json" or "json".');
		return;
	}
	const projectDir = resolve(options.path ?? process.cwd());
	if (!isDirectory(projectDir)) {
		fail(`--path ${projectDir} is not a readable directory.`);
		return;
	}

	let inventory: Inventory;
	try {
		inventory = await collect(options, projectDir, dependencies);
	} catch (error) {
		fail(`AI-BOM could not be built: ${errorText(error)}`);
		return;
	}
	const document =
		format === "json"
			? inventory
			: buildCycloneDxBom(
					inventory,
					dependencies.serialNumber ? { serialNumber: dependencies.serialNumber } : {},
				);
	const body = `${JSON.stringify(document, null, 2)}\n`;
	if (!options.output) process.stdout.write(body);
	else if (!(await writeOutput(options.output, body, inventory))) return;

	const gaps = aiInventoryGaps(inventory);
	// The BOM is still produced, but it is not presented as complete.
	for (const gap of gaps) console.error(`Incomplete inventory: ${gap}.`);
	if (gaps.length > 0) process.exitCode = 1;
}
