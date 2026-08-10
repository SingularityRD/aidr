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
	type Verdict,
} from "@singularityrd/aidr-core";

declare const __dirname: string;

type CursorEventName =
	| "preToolUse"
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

	const normalized = normalizeCursorCall(payload, eventName);
	if (!normalized) {
		writeJson(
			internalCursorResponse("deny", "Singularity AIDR could not normalize hook payload."),
		);
		return;
	}

	try {
		const verdict = await evaluateNormalizedCall(normalized, "cursor");
		writeJson(toCursorResponse(verdict));
	} catch {
		writeJson(
			internalCursorResponse(
				"deny",
				"Singularity AIDR internal error; execution was denied.",
			),
		);
	}
}

async function handleVsCode(payload: unknown): Promise<void> {
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

async function evaluateNormalizedCall(call: NormalizedHookCall, mode: HookMode): Promise<Verdict> {
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	return evaluateToolCall(
		{
			sessionId: call.sessionId,
			toolName: call.toolName,
			toolInput: call.toolInput,
			artifacts: call.artifacts,
		},
		{ threatsDir, allowlistsDir, agentRuntime: mode },
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
	const raw = await new Promise<Buffer>((resolve) => {
		const chunks: Buffer[] = [];
		process.stdin.on("data", (chunk) => {
			// Node normally gives Buffer chunks when no encoding is set, but be defensive.
			chunks.push(typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk);
		});
		process.stdin.on("end", () => resolve(Buffer.concat(chunks)));
	});

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
