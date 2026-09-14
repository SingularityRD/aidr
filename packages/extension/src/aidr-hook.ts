#!/usr/bin/env node

import { join, resolve } from "node:path";
import {
	type Artifact,
	evaluateToolCall,
	extractFromBash,
	extractFromDelete,
	extractFromEdit,
	extractFromRead,
	extractFromToolCall,
	extractFromWebFetch,
	extractFromWrite,
	loadProvisionedDetectorContext,
	type Verdict,
} from "@singularityrd/aidr-core";
import {
	auditOutputInspection,
	inspectOutput,
	type OutputInspectionResult,
} from "./output-inspection.js";

declare const __dirname: string;

const MAX_HOOK_INPUT_BYTES = 1024 * 1024;
const HOOK_INPUT_LIMIT_EXCEEDED = Symbol("HOOK_INPUT_LIMIT_EXCEEDED");

type CursorEventName =
	| "preToolUse"
	| "postToolUse"
	| "afterAgentResponse"
	| "beforeShellExecution"
	| "beforeMCPExecution"
	| "beforeReadFile";
type HookMode = "cursor" | "vscode";

interface NormalizedHookCall {
	sessionId: string;
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: Artifact[];
}

let integrityChecked = false;
async function maybeVerifyIntegrity(artifactId: string): Promise<void> {
	if (integrityChecked) return;
	integrityChecked = true;

	try {
		// biome-ignore lint/suspicious/noExplicitAny: Transitional wiring
		const core = (await import("@singularityrd/aidr-core")) as any;
		const fn = core?.verifyArtifactIntegrityAndLog as
			| ((args: { artifactDir: string; artifactId: string }) => Promise<unknown>)
			| undefined;
		if (typeof fn !== "function") {
			throw new Error("artifact integrity verifier is unavailable");
		}
		await fn({ artifactDir: __dirname, artifactId });
	} catch (error) {
		integrityChecked = false;
		throw new Error(`artifact integrity verification failed: ${String(error)}`);
	}
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<void> {
	const mode = argv[0] as HookMode | undefined;
	await maybeVerifyIntegrity("extension/dist");
	const payload = await readStdinJson();
	if (payload === HOOK_INPUT_LIMIT_EXCEEDED) {
		writeHookInputLimitResponse(mode);
		return;
	}

	if (mode === "cursor") {
		await handleCursor(payload);
		return;
	}

	if (mode === "vscode") {
		await handleVsCode(payload);
		return;
	}

	writeJson({});
}

async function handleCursor(payload: unknown): Promise<void> {
	const eventName = detectCursorEvent(payload);
	if (!eventName) {
		writeJson(internalCursorResponse("deny", "Singularity AIDR could not identify hook event."));
		return;
	}
	if (eventName === "postToolUse") {
		await handleCursorToolOutput(payload);
		return;
	}
	if (eventName === "afterAgentResponse") {
		await handleCursorAssistantOutput(payload);
		return;
	}

	const normalized = normalizeCursorCall(payload, eventName);
	if (!normalized) {
		writeJson(internalCursorResponse("deny", "Singularity AIDR could not normalize hook payload."));
		return;
	}

	try {
		const verdict = await evaluateNormalizedCall(normalized, "cursor");
		writeJson(toCursorResponse(verdict));
	} catch {
		writeJson(
			internalCursorResponse("deny", "Singularity AIDR internal error; execution was denied."),
		);
	}
}

async function handleVsCode(payload: unknown): Promise<void> {
	if (isVsCodePostToolUse(payload)) {
		await handleVsCodeToolOutput(payload);
		return;
	}
	const normalized = normalizeVsCodeCall(payload);
	if (!normalized) {
		writeJson(internalVsCodeResponse("Singularity AIDR could not normalize hook payload."));
		return;
	}

	try {
		const verdict = await evaluateNormalizedCall(normalized, "vscode");
		writeJson(toVsCodeResponse(verdict));
	} catch {
		writeJson(internalVsCodeResponse("Singularity AIDR internal error; execution was denied."));
	}
}

async function handleCursorToolOutput(payload: unknown): Promise<void> {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		writeJson(cursorOutputCoverageResponse("Singularity AIDR could not normalize tool output."));
		return;
	}
	const input = payload as Record<string, unknown>;
	const result = inspectOutput(input.tool_output);
	if (result.status === "clean") {
		writeJson({});
		return;
	}

	const toolName = asString(input.tool_name) ?? "Unknown";
	const isMcp = toolName === "MCP" || toolName.startsWith("MCP:");
	const reason = cursorOutputReason(result, isMcp);
	await auditOutputInspection(result, {
		host: "cursor",
		surface: "tool_output",
		sessionId: cursorSessionId(input),
		toolName,
		preConsumptionEnforcement: isMcp ? "mcp_quarantine" : "advisory_only",
	});
	writeJson({
		...(isMcp ? { updated_mcp_tool_output: quarantinedMcpOutput(reason) } : {}),
		additional_context: reason,
	});
}

async function handleCursorAssistantOutput(payload: unknown): Promise<void> {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		writeJson({});
		return;
	}
	const input = payload as Record<string, unknown>;
	const result = inspectOutput(input.text);
	await auditOutputInspection(result, {
		host: "cursor",
		surface: "assistant_response",
		sessionId: cursorSessionId(input),
		preConsumptionEnforcement: "observe_only",
	});
	// Cursor's afterAgentResponse hook is observation-only: it runs after display and
	// currently supports no output fields. The audit record makes that boundary visible.
	writeJson({});
}

async function handleVsCodeToolOutput(payload: unknown): Promise<void> {
	const input = payload as Record<string, unknown>;
	const result = inspectOutput(input.tool_response);
	if (result.status === "clean") {
		writeJson({});
		return;
	}
	const toolName = asString(input.tool_name) ?? "Unknown";
	await auditOutputInspection(result, {
		host: "vscode",
		surface: "tool_output",
		sessionId: vsCodeSessionId(input),
		toolName,
		preConsumptionEnforcement: "block",
	});
	writeJson({
		decision: "block",
		reason: result.reason ?? "Singularity AIDR blocked untrusted tool output.",
		hookSpecificOutput: {
			hookEventName: "PostToolUse",
			additionalContext:
				result.reason ??
				"Singularity AIDR blocked untrusted tool output before further processing.",
		},
	});
}

function isVsCodePostToolUse(payload: unknown): payload is Record<string, unknown> {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
	const input = payload as Record<string, unknown>;
	return input.hook_event_name === "PostToolUse" || "tool_response" in input;
}

function cursorSessionId(input: Record<string, unknown>): string {
	return (
		asString(input.conversation_id) ??
		asString(input.conversationId) ??
		asString(input.session_id) ??
		asString(input.sessionId) ??
		"cursor"
	);
}

function vsCodeSessionId(input: Record<string, unknown>): string {
	return (
		asString(input.session_id) ??
		asString(input.sessionId) ??
		asString(input.conversation_id) ??
		asString(input.conversationId) ??
		"vscode"
	);
}

function cursorOutputReason(result: OutputInspectionResult, isMcp: boolean): string {
	const base = result.reason ?? "Singularity AIDR detected untrusted tool output.";
	return isMcp
		? `${base} The MCP result was replaced before model consumption.`
		: `${base} Cursor does not expose output replacement for this non-MCP tool; the original result could not be quarantined and this warning is advisory.`;
}

function quarantinedMcpOutput(reason: string): Record<string, unknown> {
	return {
		isError: true,
		content: [{ type: "text", text: reason }],
	};
}

function cursorOutputCoverageResponse(reason: string): Record<string, unknown> {
	return {
		updated_mcp_tool_output: quarantinedMcpOutput(reason),
		additional_context: `${reason} The output was not classified as clean.`,
	};
}

function writeHookInputLimitResponse(mode: HookMode | undefined): void {
	const reason = `Singularity AIDR hook input exceeds the ${MAX_HOOK_INPUT_BYTES}-byte processing limit. Output inspection coverage is incomplete and the payload was not classified as clean.`;
	if (mode === "vscode") {
		writeJson({
			decision: "block",
			reason,
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "deny",
				permissionDecisionReason: reason,
				additionalContext: reason,
			},
		});
		return;
	}
	writeJson({
		decision: "deny",
		permission: "deny",
		reason,
		user_message: reason,
		agent_message: reason,
		updated_mcp_tool_output: quarantinedMcpOutput(reason),
		additional_context: reason,
	});
}

async function evaluateNormalizedCall(call: NormalizedHookCall, mode: HookMode): Promise<Verdict> {
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	// Operator-provisioned tenant detector policy for this host runtime. The
	// policy file is selected by the reported runtime, which is the same closed
	// union value the evaluator receives; an unprovisioned host gets an empty
	// context and is evaluated exactly as before.
	const provisioned = await loadProvisionedDetectorContext(mode);
	return evaluateToolCall(
		{
			sessionId: call.sessionId,
			toolName: call.toolName,
			toolInput: call.toolInput,
			artifacts: call.artifacts,
		},
		{ threatsDir, allowlistsDir, agentRuntime: mode, ...provisioned },
	);
}

function detectCursorEvent(payload: unknown): CursorEventName | undefined {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		return undefined;
	}
	const input = payload as Record<string, unknown>;
	const fromField = asString(input.hook_event_name) ?? asString(input.hookEventName);
	if (fromField && isCursorEvent(fromField)) {
		return fromField;
	}
	if (typeof input.command === "string" && input.tool_name === undefined) {
		return "beforeShellExecution";
	}
	if (typeof input.file_path === "string" && input.tool_name === undefined) {
		return "beforeReadFile";
	}
	if (input.tool_name !== undefined && input.tool_input !== undefined) {
		const toolName = asString(input.tool_name) ?? "";
		if (toolName === "MCP") {
			return "beforeMCPExecution";
		}
		return "preToolUse";
	}
	return undefined;
}

function normalizeCursorCall(
	payload: unknown,
	eventName?: CursorEventName,
): NormalizedHookCall | undefined {
	if (!payload || typeof payload !== "object" || Array.isArray(payload) || !eventName) {
		return undefined;
	}

	const input = payload as Record<string, unknown>;
	const sessionId =
		asString(input.conversation_id) ??
		asString(input.conversationId) ??
		asString(input.session_id) ??
		asString(input.sessionId) ??
		"cursor";

	if (eventName === "beforeShellExecution") {
		const command = asString(input.command) ?? "";
		const toolInput: Record<string, unknown> = {
			command,
			cwd: asString(input.cwd),
		};
		return {
			sessionId,
			toolName: "Bash",
			toolInput,
			artifacts: command ? extractFromBash(command) : [],
		};
	}

	if (eventName === "beforeReadFile") {
		const filePath = readFilePath(input);
		const content = asString(input.content);
		const toolInput: Record<string, unknown> = {
			file_path: filePath ?? "",
			content: content ?? "",
			attachments: Array.isArray(input.attachments) ? input.attachments : [],
		};
		return {
			sessionId,
			toolName: "Read",
			toolInput,
			artifacts: extractFromRead(toolInput),
		};
	}

	if (eventName === "beforeMCPExecution") {
		const parsedToolInput = parseUnknownObject(input.tool_input);
		const toolInput: Record<string, unknown> = {
			tool_name: asString(input.tool_name),
			tool_input: parsedToolInput,
			command: asString(input.command),
			url: asString(input.url),
			server: asString(input.server),
		};
		return {
			sessionId,
			toolName: "MCP",
			toolInput,
			artifacts: extractFromToolCall("MCP", toolInput),
		};
	}

	const toolName = asString(input.tool_name) ?? "";
	const rawToolInput = parseUnknownObject(input.tool_input);
	const toolInput = normalizeFileToolInput(toolName, rawToolInput);
	return {
		sessionId,
		toolName: mapCursorToolToClaudeTool(toolName),
		toolInput,
		artifacts: extractFromCursorTool(toolName, toolInput),
	};
}

function normalizeVsCodeCall(payload: unknown): NormalizedHookCall | undefined {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		return undefined;
	}

	const input = payload as Record<string, unknown>;
	const toolName = asString(input.tool_name);
	if (!toolName) {
		return undefined;
	}

	const rawToolInput = parseUnknownObject(input.tool_input);
	const toolInput = normalizeFileToolInput(toolName, rawToolInput);
	const sessionId =
		asString(input.session_id) ??
		asString(input.sessionId) ??
		asString(input.conversation_id) ??
		asString(input.conversationId) ??
		"vscode";

	return {
		sessionId,
		toolName,
		toolInput,
		artifacts: extractFromVsCodeTool(toolName, toolInput),
	};
}

function extractFromVsCodeTool(toolName: string, toolInput: Record<string, unknown>): Artifact[] {
	switch (toolName) {
		case "Bash":
			return extractFromBash(asString(toolInput.command) ?? "");
		case "WebFetch":
			return extractFromWebFetch(toolInput);
		case "Write":
			return extractFromWrite(toolInput);
		case "Edit":
			return extractFromEdit(toolInput);
		case "Read":
			return extractFromRead(toolInput);
		case "Delete":
			return extractFromDelete(toolInput);
		default:
			return extractFromToolCall(toolName, toolInput);
	}
}

function mapCursorToolToClaudeTool(toolName: string): string {
	if (toolName === "Shell") return "Bash";
	return toolName || "Unknown";
}

function extractFromCursorTool(toolName: string, toolInput: Record<string, unknown>): Artifact[] {
	switch (toolName) {
		case "Shell":
			return extractFromBash(asString(toolInput.command) ?? "");
		case "WebFetch":
			return extractFromWebFetch(toolInput);
		case "Write": {
			const normalized = normalizeWriteLikeInput(toolInput);
			return extractFromWrite(normalized);
		}
		case "Edit": {
			const normalized = normalizeEditLikeInput(toolInput);
			return extractFromEdit(normalized);
		}
		case "Read":
			return extractFromRead(toolInput);
		case "Delete":
			return extractFromDelete(toolInput);
		default:
			return extractFromToolCall(mapCursorToolToClaudeTool(toolName), toolInput);
	}
}

function normalizeWriteLikeInput(toolInput: Record<string, unknown>): Record<string, unknown> {
	const filePath = readFilePath(toolInput);
	const content = asString(toolInput.content) ?? asString(toolInput.new_string) ?? "";
	return {
		...toolInput,
		file_path: filePath ?? "",
		content,
	};
}

function normalizeEditLikeInput(toolInput: Record<string, unknown>): Record<string, unknown> {
	const filePath = readFilePath(toolInput);
	const newString =
		asString(toolInput.new_string) ??
		asString(toolInput.newString) ??
		asString(toolInput.streamContent) ??
		asString(toolInput.stream_content) ??
		asString(toolInput.content) ??
		"";
	return {
		...toolInput,
		file_path: filePath ?? "",
		new_string: newString,
	};
}

function normalizeFileToolInput(
	toolName: string,
	toolInput: Record<string, unknown>,
): Record<string, unknown> {
	if (toolName === "Read" || toolName === "Delete") {
		return { ...toolInput, file_path: readFilePath(toolInput) ?? "" };
	}
	return toolInput;
}

function readFilePath(toolInput: Record<string, unknown>): string | undefined {
	return (
		asString(toolInput.file_path) ??
		asString(toolInput.path) ??
		asString(toolInput.filePath) ??
		asString(toolInput.target_file) ??
		asString(toolInput.filename)
	);
}

function toCursorResponse(verdict: Verdict): Record<string, unknown> {
	if (verdict.decision === "allow") {
		return { decision: "allow", permission: "allow" };
	}

	const reason = truncateReason(verdict);
	const agentMessage = `Singularity AIDR ${verdict.decision === "deny" ? "blocked" : "flagged"} this action (${verdict.severity}).`;

	return {
		decision: verdict.decision === "ask" ? "ask" : "deny",
		permission: verdict.decision === "ask" ? "ask" : "deny",
		reason,
		user_message: reason,
		agent_message: agentMessage,
	};
}

function toVsCodeResponse(verdict: Verdict): Record<string, unknown> {
	if (verdict.decision === "allow") {
		return {};
	}

	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: verdict.decision,
			permissionDecisionReason: truncateReason(verdict),
		},
	};
}

function internalCursorResponse(
	decision: "allow" | "deny",
	reason: string,
): Record<string, unknown> {
	return {
		decision,
		permission: decision,
		reason,
		user_message: reason,
		agent_message:
			decision === "allow" ? undefined : "Singularity AIDR internal error policy applied.",
	};
}

function internalVsCodeResponse(reason: string): Record<string, unknown> {
	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
			permissionDecisionReason: reason,
		},
	};
}

function truncateReason(verdict: Verdict): string {
	if (verdict.reasons.length === 0) {
		return `Singularity AIDR flagged this action (${verdict.category}).`;
	}
	const joined = verdict.reasons.slice(0, 5).join("; ");
	return joined.length <= 350 ? joined : `${joined.slice(0, 347)}...`;
}

function getBundledDataDirs(): { threatsDir: string; allowlistsDir: string } {
	const extensionRoot = resolve(__dirname, "..");
	return {
		threatsDir: join(extensionRoot, "resources", "threats"),
		allowlistsDir: join(extensionRoot, "resources", "allowlists"),
	};
}

function isCursorEvent(value: string): value is CursorEventName {
	return (
		value === "preToolUse" ||
		value === "postToolUse" ||
		value === "afterAgentResponse" ||
		value === "beforeShellExecution" ||
		value === "beforeMCPExecution" ||
		value === "beforeReadFile"
	);
}

function asString(value: unknown): string | undefined {
	return typeof value === "string" ? value : undefined;
}

function parseUnknownObject(value: unknown): Record<string, unknown> {
	if (value && typeof value === "object" && !Array.isArray(value)) {
		return value as Record<string, unknown>;
	}
	if (typeof value === "string") {
		try {
			const parsed = JSON.parse(value);
			if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
				return parsed as Record<string, unknown>;
			}
		} catch {
			// Ignore parse errors.
		}
	}
	return {};
}

async function readStdinJson(): Promise<unknown> {
	// Cursor hooks on Windows can deliver stdin as UTF-16LE (PowerShell pipeline encoding),
	// which breaks JSON.parse if we assume UTF-8. Read bytes and attempt both decodings.
	const raw = await new Promise<Buffer | typeof HOOK_INPUT_LIMIT_EXCEEDED>((resolve) => {
		const chunks: Buffer[] = [];
		let byteLength = 0;
		let exceeded = false;
		process.stdin.on("data", (chunk) => {
			// Node normally gives Buffer chunks when no encoding is set, but be defensive.
			const bytes = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
			byteLength += bytes.length;
			if (byteLength > MAX_HOOK_INPUT_BYTES) {
				exceeded = true;
				chunks.length = 0;
				return;
			}
			if (!exceeded) chunks.push(bytes);
		});
		process.stdin.on("end", () =>
			resolve(exceeded ? HOOK_INPUT_LIMIT_EXCEEDED : Buffer.concat(chunks)),
		);
	});
	if (raw === HOOK_INPUT_LIMIT_EXCEEDED) return raw;

	function stripBom(value: string): string {
		return value.charCodeAt(0) === 0xfeff ? value.slice(1) : value;
	}

	function tryParseJson(value: string): unknown | undefined {
		const trimmed = stripBom(value).trim();
		if (!trimmed) {
			return {};
		}
		try {
			return JSON.parse(trimmed);
		} catch {
			return undefined;
		}
	}

	const asUtf8 = raw.toString("utf8");
	const parsedUtf8 = tryParseJson(asUtf8);
	if (parsedUtf8 !== undefined) {
		return parsedUtf8;
	}

	const asUtf16le = raw.toString("utf16le");
	const parsedUtf16le = tryParseJson(asUtf16le);
	if (parsedUtf16le !== undefined) {
		return parsedUtf16le;
	}

	return {};
}

function writeJson(payload: Record<string, unknown>): void {
	process.stdout.write(`${JSON.stringify(payload)}\n`);
}

if (require.main === module) {
	runCli().catch(() => {
		// Protocol safety: emit valid JSON and never fail with non-JSON output.
		writeJson(
			process.argv[2] === "vscode"
				? internalVsCodeResponse("Singularity AIDR hook failed; execution was denied.")
				: internalCursorResponse("deny", "Singularity AIDR hook failed; execution was denied."),
		);
	});
}
