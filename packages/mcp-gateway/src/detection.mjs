import { createHash, randomBytes } from "node:crypto";
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	evaluateToolCall,
	extractFromToolCall,
	INPUT_NOT_FULLY_INSPECTED,
	loadContextPoisoningRules,
	scanMcpToolMetadata,
} from "@singularityrd/aidr-core";
import { EMBEDDED_RULE_SETS } from "./embedded-rules.mjs";

/**
 * Pre-execution threat and DLP evaluation of MCP `tools/call` arguments.
 *
 * The call is normalised to the core's MCP convention (`mcp__<server>__<tool>`)
 * and evaluated by the same `evaluateToolCall` pipeline every connector uses.
 * The gateway is a connector entry point, so it fails closed: `deny` and
 * `ask` both block the call (`ask` is pending out-of-band operator action,
 * never an agent-callable approval), and missing rules or an evaluator failure
 * block the call as `detection_unavailable` rather than passing it through.
 */

const RULE_KINDS = ["threats", "allowlists"];
const RULE_FILE = /^[A-Za-z0-9_.-]+\.yaml$/;
const CATEGORY = /^[a-z0-9_]{1,64}$/;
const THREAT_ID = /^[A-Za-z0-9._-]{1,64}$/;
const DECISION_SCHEMA_VERSION = "aidr-mcp-gateway-decision/v1";
const moduleDir = dirname(fileURLToPath(import.meta.url));

/** A pre-execution block with a stable reason code and a sanitised verdict summary. */
export class McpToolCallBlocked extends Error {
	constructor(code, verdict) {
		super(code);
		this.name = "McpToolCallBlocked";
		this.code = code;
		this.verdictDecision = ["deny", "ask"].includes(verdict?.decision) ? verdict.decision : null;
		this.category = CATEGORY.test(verdict?.category ?? "") ? verdict.category : null;
		// DLP rule identifiers are tenant policy names; keep them out of the
		// client-visible payload. Built-in threat IDs are public rule references.
		this.threatId =
			verdict?.source !== "dlp" && THREAT_ID.test(verdict?.matchedThreatId ?? "")
				? verdict.matchedThreatId
				: null;
	}
}

/** Client-visible JSON-RPC error data: codes and identifiers only, never tool input. */
export function decisionPayload(blocked) {
	return {
		type: "mcp_gateway_decision",
		schemaVersion: DECISION_SCHEMA_VERSION,
		code: blocked.code,
		decision: "deny",
		...(blocked.verdictDecision ? { verdict: blocked.verdictDecision } : {}),
		...(blocked.category ? { category: blocked.category } : {}),
		...(blocked.threatId ? { threatId: blocked.threatId } : {}),
		operatorActionRequired: blocked.code === "approval_required",
	};
}

async function isDirectory(path) {
	try {
		return (await stat(path)).isDirectory();
	} catch {
		return false;
	}
}

async function hasRuleFiles(path) {
	try {
		return (await readdir(path)).some((name) => RULE_FILE.test(name));
	} catch {
		return false;
	}
}

function ruleSetDigest(ruleSets) {
	const hash = createHash("sha256");
	for (const kind of RULE_KINDS) {
		for (const name of Object.keys(ruleSets[kind]).sort()) {
			hash.update(`${kind}\0${name}\0${ruleSets[kind][name]}\0`);
		}
	}
	return hash.digest("hex");
}

async function matchesRuleSets(directory, ruleSets) {
	try {
		for (const kind of RULE_KINDS) {
			const expected = Object.keys(ruleSets[kind]).sort();
			const actual = (await readdir(join(directory, kind))).sort();
			if (actual.length !== expected.length || actual.some((name, i) => name !== expected[i]))
				return false;
			for (const name of expected) {
				if ((await readFile(join(directory, kind, name), "utf8")) !== ruleSets[kind][name])
					return false;
			}
		}
		return true;
	} catch {
		return false;
	}
}

/**
 * Write the rule files embedded in the signed bundle to a content-addressed
 * directory under the operator-private state directory. Concurrent gateway
 * processes (for example several stdio bridges) stage separately and rename
 * atomically; an existing directory is used only if it matches byte for byte.
 */
export async function materializeEmbeddedRules(stateDir, ruleSets) {
	for (const kind of RULE_KINDS) {
		const names = Object.keys(ruleSets?.[kind] ?? {});
		if (names.length === 0 || names.some((name) => !RULE_FILE.test(name)))
			throw new Error("embedded_rules_invalid");
	}
	const root = join(stateDir, "detection-rules");
	const target = join(root, ruleSetDigest(ruleSets));
	if (await matchesRuleSets(target, ruleSets)) return target;
	await mkdir(root, { recursive: true, mode: 0o700 });
	const staging = `${target}.staging-${process.pid}-${randomBytes(6).toString("hex")}`;
	try {
		for (const kind of RULE_KINDS) {
			await mkdir(join(staging, kind), { recursive: true, mode: 0o700 });
			for (const [name, content] of Object.entries(ruleSets[kind])) {
				await writeFile(join(staging, kind, name), content, { mode: 0o600, flag: "wx" });
			}
		}
		await rename(staging, target);
	} catch {
		// Another process may have won the rename; its copy is verified below.
	} finally {
		await rm(staging, { recursive: true, force: true });
	}
	if (!(await matchesRuleSets(target, ruleSets))) throw new Error("embedded_rules_mismatch");
	return target;
}

async function resolveRuleDirs(config, embedded) {
	const detection = config.detection ?? {};
	let embeddedRoot;
	const dirs = {};
	for (const kind of RULE_KINDS) {
		const override = kind === "threats" ? detection.threatsDir : detection.allowlistsDir;
		let candidate = override;
		if (!candidate && embedded) {
			embeddedRoot ??= await materializeEmbeddedRules(config.stateDir, embedded);
			candidate = join(embeddedRoot, kind);
		}
		// Source checkouts (development and tests) read the repository rule set.
		candidate ??= resolve(moduleDir, "..", "..", "..", kind);
		if (!(await isDirectory(candidate)) || !(await hasRuleFiles(candidate)))
			throw new Error("detection_rules_unavailable");
		dirs[kind] = candidate;
	}
	return dirs;
}

/** Create the per-gateway tool-call evaluator. `evaluate` is injectable for tests. */
export function createToolCallDetector(
	config,
	{ evaluate = evaluateToolCall, embedded = EMBEDDED_RULE_SETS } = {},
) {
	let dirsPromise;

	async function ruleDirs() {
		dirsPromise ??= resolveRuleDirs(config, embedded);
		try {
			return await dirsPromise;
		} catch (cause) {
			dirsPromise = undefined;
			throw cause;
		}
	}

	return async function evaluateMcpToolCall({ server, client, toolName, args, description }) {
		const qualifiedName = `mcp__${server.id}__${toolName}`;
		let verdict;
		try {
			const dirs = await ruleDirs();
			verdict = await evaluate(
				{
					sessionId: `mcp-gateway:${client.tenantId}:${client.id}`,
					toolName: qualifiedName,
					toolInput: args,
					artifacts: extractFromToolCall(qualifiedName, args),
				},
				{
					threatsDir: dirs.threats,
					allowlistsDir: dirs.allowlists,
					...(config.detection?.agentConfigPath
						? { configPath: config.detection.agentConfigPath }
						: {}),
					...(typeof description === "string" ? { mcpToolDescription: description } : {}),
					...(server.dlpPolicy
						? {
								runtimeDetectors: {
									tenantId: server.tenantId,
									dlp: { enabled: true, policy: server.dlpPolicy, contentType: "application/json" },
								},
							}
						: {}),
				},
			);
		} catch {
			throw new McpToolCallBlocked("detection_unavailable");
		}
		if (verdict?.decision === "allow") return verdict;
		// Arguments beyond the extractor's inspection limits (nesting depth,
		// string count, string size, total size) are denied by the core rather
		// than forwarded half-inspected; the code tells the operator why.
		if (verdict?.decision === "deny" && verdict.category === INPUT_NOT_FULLY_INSPECTED)
			throw new McpToolCallBlocked(INPUT_NOT_FULLY_INSPECTED, verdict);
		if (verdict?.decision === "deny") throw new McpToolCallBlocked("arguments_blocked", verdict);
		if (verdict?.decision === "ask") throw new McpToolCallBlocked("approval_required", verdict);
		throw new McpToolCallBlocked("detection_unavailable");
	};
}

/**
 * Tool-poisoning scan of the observed tool list (names, descriptions and
 * input-schema strings) against the `mcp_tool_metadata` rules of the same rule
 * set the argument evaluator uses. A signed, operator-approved manifest proves
 * who published the descriptions, not that they are safe: a publisher (or a
 * compromised publisher key) can sign hidden instructions.
 *
 * Returns `{ blocking, suspicious }` finding lists. Rules that cannot be loaded
 * throw `detection_unavailable`, so the gateway fails closed. Results are cached
 * per toolset hash; the observed toolset already has to match the signed one.
 * `scan` is injectable for tests.
 */
export function createToolMetadataScanner(
	config,
	{ embedded = EMBEDDED_RULE_SETS, scan = scanMcpToolMetadata } = {},
) {
	let dirsPromise;
	let rulesPromise;
	const cache = new Map();

	async function rules() {
		dirsPromise ??= resolveRuleDirs(config, embedded);
		rulesPromise ??= dirsPromise.then((dirs) => loadContextPoisoningRules([dirs.threats]));
		try {
			const loaded = await rulesPromise;
			if (!loaded.some((rule) => rule.matchOn.has("mcp_tool_metadata")))
				throw new Error("detection_unavailable");
			return loaded;
		} catch {
			dirsPromise = undefined;
			rulesPromise = undefined;
			throw new McpToolCallBlocked("detection_unavailable");
		}
	}

	return async function scanToolMetadata(tools, toolsetHash) {
		const cached = toolsetHash ? cache.get(toolsetHash) : undefined;
		if (cached) return cached;
		let findings;
		try {
			findings = scan(tools, await rules());
		} catch (cause) {
			if (cause instanceof McpToolCallBlocked) throw cause;
			throw new McpToolCallBlocked("detection_unavailable");
		}
		if (!Array.isArray(findings)) throw new McpToolCallBlocked("detection_unavailable");
		const result = {
			blocking: findings.filter((finding) => finding.action === "block"),
			suspicious: findings.filter((finding) => finding.action !== "block"),
		};
		if (toolsetHash) {
			if (cache.size >= 256) cache.clear();
			cache.set(toolsetHash, result);
		}
		return result;
	};
}
