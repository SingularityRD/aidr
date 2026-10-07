/**
 * Loading agent permission profiles for a connector.
 *
 * Two layers, both optional:
 *
 *   local    ~/.singularity-aidr/agent-profiles.json (override: AIDR_AGENT_PROFILES_PATH),
 *            written by the machine's operator. JSON or YAML.
 *   managed  the `agent_profiles` section of the Ed25519-signed, entitlement-bound
 *            tenant detector bundle (`detector-provisioning.ts`).
 *
 * Failure policy:
 *   - an invalid local document is refused (never enforced as if valid), logged
 *     once, and reported by `aidr doctor`; detection is unaffected;
 *   - an invalid managed section becomes an `invalid` layer, which denies every
 *     call for that connector with a reason naming the problem (fail closed).
 *
 * Both layers are evaluated and the strictest outcome wins, so a local document
 * can narrow a managed profile but never widen it.
 */
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import {
	type AgentProfileConnector,
	type AgentProfileContext,
	type AgentProfileDiagnostic,
	type AgentProfileDocument,
	type AgentProfileEnvironment,
	type AgentProfileEvaluation,
	type AgentProfileLayer,
	evaluateAgentProfiles,
	validateAgentProfileDocument,
	validateAgentProfileSource,
} from "./agent-profile.js";
import { resolvePath } from "./config.js";
import { extractFromToolCall } from "./extractors.js";
import { normalizeToolEvaluationRequest } from "./tool-normalization.js";

export const LOCAL_AGENT_PROFILES_ENV = "AIDR_AGENT_PROFILES_PATH";
export const DEFAULT_LOCAL_AGENT_PROFILES_PATH = "~/.singularity-aidr/agent-profiles.json";
const MAX_LOCAL_PROFILE_BYTES = 256 * 1024;

export type LocalAgentProfilesState =
	| { status: "absent"; path: string }
	| {
			status: "loaded";
			path: string;
			document: AgentProfileDocument;
			diagnostics: AgentProfileDiagnostic[];
	  }
	| { status: "invalid"; path: string; reason: string };

export function localAgentProfilesPath(env: NodeJS.ProcessEnv = process.env): string {
	const override = env[LOCAL_AGENT_PROFILES_ENV]?.trim();
	return resolve(resolvePath(override ? override : DEFAULT_LOCAL_AGENT_PROFILES_PATH));
}

/** Read and validate the local profile document without applying it. */
export async function inspectLocalAgentProfiles(
	path: string = localAgentProfilesPath(),
): Promise<LocalAgentProfilesState> {
	let raw: string;
	try {
		const info = await stat(path);
		if (!info.isFile()) return { status: "invalid", path, reason: "path is not a regular file" };
		if (info.size > MAX_LOCAL_PROFILE_BYTES) {
			return { status: "invalid", path, reason: "file exceeds the 256 KiB size limit" };
		}
		raw = await readFile(path, "utf8");
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		if (code === "ENOENT") return { status: "absent", path };
		return { status: "invalid", path, reason: `file could not be read (${code ?? "error"})` };
	}
	const result = validateAgentProfileSource(raw);
	if (!result.ok) return { status: "invalid", path, reason: result.errors.join("; ") };
	return { status: "loaded", path, document: result.document, diagnostics: result.diagnostics };
}

/** The managed layer from a verified signed bundle's `agent_profiles` value. */
export function managedAgentProfileLayer(value: unknown, origin: string): AgentProfileLayer {
	const result = validateAgentProfileDocument(value);
	return result.ok
		? { status: "loaded", source: "managed", origin, document: result.document }
		: { status: "invalid", source: "managed", origin, reason: result.errors.join("; ") };
}

/** Combine the layers into the context the evaluator receives, or undefined when there are none. */
export function buildAgentProfileContext(
	connector: AgentProfileConnector,
	layers: readonly (AgentProfileLayer | null | undefined)[],
): AgentProfileContext | undefined {
	const present = layers.filter((layer): layer is AgentProfileLayer => !!layer);
	return present.length > 0 ? { connector, layers: present } : undefined;
}

/**
 * Dry-run one raw tool call (as a host would send it) against a profile
 * context, with the same tool normalization and extraction the evaluator uses.
 */
export async function evaluateAgentProfilesForToolCall(
	context: AgentProfileContext,
	toolName: string,
	toolInput: Record<string, unknown>,
	environment: AgentProfileEnvironment,
): Promise<AgentProfileEvaluation> {
	const normalized = normalizeToolEvaluationRequest({
		sessionId: "agent-profile-test",
		toolName,
		toolInput,
		artifacts: extractFromToolCall(toolName, toolInput),
	});
	return evaluateAgentProfiles(
		context,
		{
			toolName: normalized.toolName,
			toolInput: normalized.toolInput,
			artifacts: normalized.artifacts,
		},
		environment,
	);
}

/** The local layer when the local document is valid; null otherwise. */
export function localAgentProfileLayer(state: LocalAgentProfilesState): AgentProfileLayer | null {
	return state.status === "loaded"
		? { status: "loaded", source: "local", origin: state.path, document: state.document }
		: null;
}
