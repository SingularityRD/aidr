/**
 * OpenClaw tools that run a command or feed input to a running process.
 *
 * `exec` is not the only way an OpenClaw agent executes code. Once a shell or
 * REPL runs in the background, the `process` tool writes to its stdin
 * (`write`, `paste`, `send-keys`, `submit`), the `terminal` tool types into an
 * operator-opened terminal (`input`), and `nodes` reaches a paired node's
 * command surface (`invoke`, plus the legacy `run` shape). Each of those is a
 * command channel, so the text it delivers is evaluated as shell input under
 * the `exec` name: the same rules, policy and package legs an `exec` call gets.
 *
 * Tool surface verified against the pinned host (openclaw 2026.9.6:
 * `PROCESS_TOOL_ACTIONS`, the terminal tool's `ACTIONS`, `NODES_TOOL_ACTIONS`).
 * An action this module does not recognise on one of these tools is denied, so
 * a new exec-capable action never passes uninspected. The tool-name dispatch
 * itself lives in `tool-handler.ts`, where the connector alias contract reads it.
 */

import { type Artifact, commandFromValue, extractFromBash } from "@singularityrd/aidr-core";

/** How a tool call is evaluated after OpenClaw exec-surface normalization. */
export type ExecSurfaceResolution =
	/** Not an exec-capable call: evaluate the original tool call unchanged. */
	| { kind: "passthrough" }
	/**
	 * Evaluate `command` as shell input; `commit` records the input once allowed.
	 * `stdin` marks input written to a running process, which may be a REPL
	 * rather than a shell.
	 */
	| { kind: "shell"; command: string; via: string; stdin?: boolean; commit?: () => void }
	/** The input cannot be inspected reliably: block it. */
	| { kind: "deny"; reason: string };

export const PASSTHROUGH: ExecSurfaceResolution = { kind: "passthrough" };

/** `process` actions that only read or manage a session (no input is delivered). */
const PROCESS_READ_ACTIONS = new Set(["list", "poll", "log"]);
/** `process` actions that end a session: its unfinished input line is dropped. */
const PROCESS_END_ACTIONS = new Set(["kill", "clear", "remove"]);
/** `terminal` actions that deliver no input. */
const TERMINAL_NON_INPUT_ACTIONS = new Set(["read", "list", "resize", "close"]);
/** `nodes` actions with no command surface (device, media, pairing, lookup). */
const NODES_NON_EXEC_ACTIONS = new Set([
	"status",
	"describe",
	"pending",
	"approve",
	"reject",
	"notify",
	"camera_snap",
	"camera_list",
	"camera_clip",
	"camera_ptz",
	"photos_latest",
	"screen_record",
	"screen_snapshot",
	"location_get",
	"notifications_list",
	"notifications_action",
	"device_status",
	"device_info",
	"device_permissions",
	"device_health",
	"which",
]);

/** Fields a node command or plugin tool may carry its command in. */
const COMMAND_FIELDS = ["command", "cmd", "argv", "rawCommand", "shellCommand"] as const;

/**
 * Node invoke commands that execute something. `system.run` is refused by the
 * host's generic invoke surface today, but a policy layer must not rely on that.
 */
const EXEC_INVOKE_SEGMENT = /^(?:run|exec|execute|launch|install|spawn|shell)$/;

/** Name tokens of a plugin tool that executes commands (`shell_exec`, `run-bash`, ...). */
const EXEC_TOOL_NAME_TOKEN =
	/^(?:exec|execute|shell|bash|zsh|sh|pwsh|powershell|terminal|pty|spawn|subprocess|cmd)$/;

/** Bound on one session's unfinished input line, mirroring a shell's line buffer. */
const MAX_PENDING_LINE = 64 * 1024;
/** Bound on the number of sessions whose unfinished line is remembered. */
const MAX_TRACKED_SESSIONS = 256;

/**
 * Remembers each process/terminal session's unfinished input line. Without it
 * `write("rm -rf ")` followed by `write("/\n")` would split one command across
 * two calls that are each harmless on their own.
 */
export class PendingInputLines {
	private readonly lines = new Map<string, string>();

	get(key: string): string {
		return this.lines.get(key) ?? "";
	}

	set(key: string, line: string): void {
		this.lines.delete(key);
		if (line === "") return;
		this.lines.set(key, line);
		while (this.lines.size > MAX_TRACKED_SESSIONS) {
			const oldest = this.lines.keys().next().value;
			if (oldest === undefined) break;
			this.lines.delete(oldest);
		}
	}

	clear(key: string): void {
		this.lines.delete(key);
	}
}

function str(value: unknown): string | undefined {
	return typeof value === "string" ? value : undefined;
}

function deny(reason: string): ExecSurfaceResolution {
	return { kind: "deny", reason };
}

// --- send-keys reassembly (mirrors the host's pty-keys encoder) ---------------

const ESC = "\x1b";
const NAMED_KEYS: ReadonlyMap<string, string> = new Map([
	["enter", "\r"],
	["return", "\r"],
	["tab", "\t"],
	["space", " "],
	["escape", ESC],
	["esc", ESC],
	["bspace", "\x7f"],
	["backspace", "\x7f"],
]);
/** Any other named key the host knows (cursor, function, keypad) is an escape sequence. */
const ESCAPE_SEQUENCE_KEY =
	/^(?:up|down|left|right|home|end|pageup|pgup|ppage|pagedown|pgdn|npage|insert|ic|delete|del|dc|btab|f(?:[1-9]|1[0-2])|kp[-/*+.0-9]|kpenter)$/;

function ctrlChar(char: string): string | undefined {
	if (char.length !== 1) return undefined;
	if (char === "?") return "\x7f";
	const code = char.toUpperCase().charCodeAt(0);
	return code >= 64 && code <= 95 ? String.fromCharCode(code & 31) : undefined;
}

function encodeKeyToken(raw: string): string {
	const token = raw.trim();
	if (token === "") return "";
	if (token.length === 2 && token.startsWith("^")) {
		const ctrl = ctrlChar(token.charAt(1));
		if (ctrl) return ctrl;
	}
	let rest = token;
	const mods = { ctrl: false, alt: false, shift: false };
	while (rest.length > 2 && rest[1] === "-") {
		const mod = rest[0]?.toLowerCase();
		if (mod === "c") mods.ctrl = true;
		else if (mod === "m") mods.alt = true;
		else if (mod === "s") mods.shift = true;
		else break;
		rest = rest.slice(2);
	}
	const lower = rest.toLowerCase();
	const named = NAMED_KEYS.get(lower);
	if (named !== undefined) return mods.alt || mods.ctrl ? `${ESC}${named}` : named;
	if (ESCAPE_SEQUENCE_KEY.test(lower)) return `${ESC}[`;
	if (rest.length === 1) {
		let value = mods.shift && /[a-z]/.test(rest) ? rest.toUpperCase() : rest;
		if (mods.ctrl) value = ctrlChar(value) ?? value;
		return mods.alt ? `${ESC}${value}` : value;
	}
	// The host sends an unknown multi-character token literally.
	return rest;
}

/** The bytes a `send-keys` call writes, or null when they cannot be reassembled. */
function sendKeysText(params: Record<string, unknown>): string | null {
	const literal = params.literal;
	const hex = params.hex;
	const keys = params.keys;
	if (literal !== undefined && typeof literal !== "string") return null;
	if (hex !== undefined && !(Array.isArray(hex) && hex.every((h) => typeof h === "string"))) {
		return null;
	}
	if (keys !== undefined && !(Array.isArray(keys) && keys.every((k) => typeof k === "string"))) {
		return null;
	}
	const bytes: number[] = [];
	for (const raw of (hex as string[] | undefined) ?? []) {
		const normalized = raw.toLowerCase().replace(/^0x/, "");
		if (!/^[0-9a-f]{1,2}$/.test(normalized)) return null;
		bytes.push(Number.parseInt(normalized, 16));
	}
	const hexText = new TextDecoder("utf-8", { fatal: false }).decode(Uint8Array.from(bytes));
	const keyText = ((keys as string[] | undefined) ?? []).map(encodeKeyToken).join("");
	return `${literal ?? ""}${hexText}${keyText}`;
}

// --- line assembly -------------------------------------------------------------

/** Line terminators, and keys that discard the current line (^C, ^U) or end input (^D). */
const LINE_END = /[\r\n]/;
const LINE_DISCARD = /[\x03\x04\x15]/;
/** Control bytes with a fixed meaning here: line end, discard, and tab. */
const UNDERSTOOD_CONTROLS = /[\t\r\n\x03\x04\x15]/g;
/** Any other control byte (cursor movement, backspace, word erase, escape) edits the line. */
const LINE_EDITING = /[\x00-\x1f\x7f]/;
/** An escape sequence (CSI, SS3 or a lone ESC-prefixed byte), for finding printable text. */
const ESCAPE_SEQUENCE = /\x1b(?:\[[0-9;?]*[ -/]*[@-~]|O.|.)?/g;
const CONTROL_BYTES = /[\x00-\x1f\x7f]/g;

interface AssembledInput {
	/** Complete lines plus the unfinished one: what the session's reader sees. */
	command: string;
	/** The unfinished line left after this input. */
	pending: string;
}

/**
 * Combine a session's unfinished line with new input. Returns a deny reason
 * when the input edits the line in a way that cannot be replayed faithfully
 * (cursor keys, backspace, escape sequences or tab completion next to
 * printable text).
 */
function assembleInput(pending: string, input: string): AssembledInput | string {
	if (LINE_EDITING.test(input.replace(UNDERSTOOD_CONTROLS, ""))) {
		const printable = input.replace(ESCAPE_SEQUENCE, "").replace(CONTROL_BYTES, "").trim();
		// Pure control input (an arrow key, Escape) on an empty line types nothing
		// that could be inspected; with a pending line or printable text it edits
		// a command this layer cannot reconstruct.
		if (printable === "" && pending.trim() === "") return { command: "", pending: "" };
		return "terminal input contains line-editing control keys, so the command it produces cannot be reconstructed for inspection";
	}
	let current = pending;
	const lines: string[] = [];
	for (const char of input) {
		if (char === "\t" && current.trim() !== "") {
			// A tab after text on the line triggers shell completion, which
			// rewrites the line into something this layer never sees.
			return "terminal input uses tab completion, so the command it produces cannot be reconstructed for inspection";
		}
		if (LINE_END.test(char)) {
			if (current.trim() !== "") lines.push(current);
			current = "";
		} else if (LINE_DISCARD.test(char)) {
			current = "";
		} else {
			current += char;
		}
	}
	if (current.length > MAX_PENDING_LINE) {
		return "terminal input line is too long to inspect";
	}
	const command = [...lines, current].filter((line) => line.trim() !== "").join("\n");
	return { command, pending: current };
}

function shellInput(
	store: PendingInputLines,
	key: string,
	input: string,
	via: string,
): ExecSurfaceResolution {
	const assembled = assembleInput(store.get(key), input);
	if (typeof assembled === "string") return deny(assembled);
	const commit = () => store.set(key, assembled.pending);
	if (assembled.command.trim() === "") {
		commit();
		return PASSTHROUGH;
	}
	return { kind: "shell", command: assembled.command, via, stdin: true, commit };
}

/** Interpreters an agent commonly runs in the background and drives through stdin. */
const REPL_INLINE_FORMS = ["python3 -c", "node -e", "perl -e", "ruby -e", "php -r"] as const;

function shellSingleQuote(text: string): string {
	return `'${text.replace(/'/g, "'\\''")}'`;
}

/**
 * Stdin of a background process may feed a REPL (`python3`, `node`) rather
 * than a shell. Present the same text in each interpreter's inline-code form
 * too, so the interpreter rules that catch `python3 -c '<payload>'` on `exec`
 * also catch the payload typed into a running interpreter.
 */
export function replInputArtifacts(text: string): Artifact[] {
	return REPL_INLINE_FORMS.flatMap((form) =>
		extractFromBash(`${form} ${shellSingleQuote(text)}`).map((artifact) => ({
			...artifact,
			context: `process_stdin:${form.split(" ")[0]}`,
		})),
	);
}

// --- per-tool resolution ---------------------------------------------------------

function sessionKeyFor(scope: string, tool: string, params: Record<string, unknown>): string {
	return `${scope}\u0000${tool}\u0000${str(params.sessionId) ?? ""}`;
}

export function resolveProcess(
	params: Record<string, unknown>,
	store: PendingInputLines,
	scope: string,
): ExecSurfaceResolution {
	const action = str(params.action)?.trim().toLowerCase() ?? "";
	const key = sessionKeyFor(scope, "process", params);
	if (PROCESS_READ_ACTIONS.has(action)) return PASSTHROUGH;
	if (PROCESS_END_ACTIONS.has(action)) {
		store.clear(key);
		return PASSTHROUGH;
	}
	switch (action) {
		case "write": {
			const data = params.data ?? "";
			if (typeof data !== "string") return deny("process write data is not a string");
			return shellInput(store, key, data, "process.write");
		}
		case "paste": {
			const text = params.text ?? "";
			if (typeof text !== "string") return deny("process paste text is not a string");
			return shellInput(store, key, text, "process.paste");
		}
		case "submit": {
			// The host sends CR; any `data` is evaluated too rather than trusted to be ignored.
			const data = params.data ?? "";
			if (typeof data !== "string") return deny("process submit data is not a string");
			return shellInput(store, key, `${data}\r`, "process.submit");
		}
		case "send-keys": {
			const text = sendKeysText(params);
			if (text === null) return deny("process send-keys input could not be reassembled");
			return shellInput(store, key, text, "process.send-keys");
		}
		default:
			return deny(`unrecognised process action "${action}"`);
	}
}

export function resolveTerminal(
	params: Record<string, unknown>,
	store: PendingInputLines,
	scope: string,
): ExecSurfaceResolution {
	const action = str(params.action)?.trim().toLowerCase() ?? "";
	const key = sessionKeyFor(scope, "terminal", params);
	if (action === "close") store.clear(key);
	if (TERMINAL_NON_INPUT_ACTIONS.has(action)) return PASSTHROUGH;
	if (action !== "input") return deny(`unrecognised terminal action "${action}"`);
	const data = params.data ?? "";
	if (typeof data !== "string") return deny("terminal input data is not a string");
	return shellInput(store, key, data, "terminal.input");
}

/** A command carried in a string or argv field; null when absent; false when malformed. */
function commandFromFields(record: Record<string, unknown>): string | null | false {
	for (const field of COMMAND_FIELDS) {
		if (record[field] === undefined) continue;
		const result = commandFromValue(record[field]);
		return result.ok && result.command.trim() !== "" ? result.command : false;
	}
	return null;
}

function isExecInvokeCommand(invokeCommand: string): boolean {
	return invokeCommand
		.toLowerCase()
		.split(/[.\-_/]/)
		.some((segment) => EXEC_INVOKE_SEGMENT.test(segment));
}

export function resolveNodes(params: Record<string, unknown>): ExecSurfaceResolution {
	const action = str(params.action)?.trim().toLowerCase() ?? "";
	if (NODES_NON_EXEC_ACTIONS.has(action)) return PASSTHROUGH;
	if (action === "run") {
		const command = commandFromFields(params);
		if (!command) return deny("nodes run carries no inspectable command");
		return { kind: "shell", command, via: "nodes.run" };
	}
	if (action !== "invoke") return deny(`unrecognised nodes action "${action}"`);

	const invokeCommand = str(params.invokeCommand)?.trim() ?? "";
	const rawParams = params.invokeParamsJson;
	let invokeParams: unknown = {};
	if (typeof rawParams === "string" && rawParams.trim() !== "") {
		try {
			invokeParams = JSON.parse(rawParams);
		} catch {
			return deny("nodes invoke parameters are not valid JSON");
		}
	} else if (rawParams !== undefined && typeof rawParams !== "string") {
		return deny("nodes invoke parameters are not a JSON string");
	}
	const command =
		invokeParams && typeof invokeParams === "object" && !Array.isArray(invokeParams)
			? commandFromFields(invokeParams as Record<string, unknown>)
			: null;
	if (command === false) return deny(`nodes invoke "${invokeCommand}" has a malformed command`);
	if (command) return { kind: "shell", command, via: `nodes.invoke:${invokeCommand}` };
	if (isExecInvokeCommand(invokeCommand)) {
		return deny(`nodes invoke "${invokeCommand}" executes code without an inspectable command`);
	}
	return PASSTHROUGH;
}

/**
 * A tool outside the host's built-in inventory whose name says it executes
 * commands (`shell_exec`, `run-bash`). Its command is evaluated as shell input;
 * without one it cannot be judged and is denied.
 */
export function resolveExecNamedTool(
	toolName: string,
	params: Record<string, unknown>,
): ExecSurfaceResolution {
	if (toolName.includes("__")) return PASSTHROUGH; // bundle MCP tool: MCP policy owns it
	const tokens = toolName.toLowerCase().split(/[^a-z0-9]+/);
	if (!tokens.some((token) => EXEC_TOOL_NAME_TOKEN.test(token))) return PASSTHROUGH;
	const command = commandFromFields(params);
	if (command) return { kind: "shell", command, via: toolName };
	return deny(
		`"${toolName}" looks like a command-execution tool but carries no inspectable command`,
	);
}
