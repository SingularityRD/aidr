/**
 * Scripted mock model server for the real-host E2E tier.
 *
 * The host programs (Claude Code, Codex, OpenCode, OpenClaw) are real, unmodified
 * binaries. Only the model is replaced: this loopback server answers the host's
 * model requests with a predetermined script, so a run is hermetic, free and
 * deterministic, and the host's own tool dispatcher, hook runner and plugin loader
 * are what decide whether a scripted tool call executes.
 *
 * A scenario is one tool call followed by a final text:
 *
 *   turn 1 (no tool result in the conversation yet)  -> the scripted tool call
 *   turn 2 (a tool result for that call is present)   -> `finalText`
 *
 * Requests that do not carry the host's agent tool set (title generation, quota
 * probes, summaries) get a short plain-text answer and never advance the script.
 *
 * Three wire protocols are spoken, each only as far as the hosts need it:
 *
 *   - Anthropic Messages (`POST /v1/messages`, SSE when `stream: true`) for
 *     Claude Code via ANTHROPIC_BASE_URL.
 *   - OpenAI Responses (`POST /v1/responses`, SSE) for Codex via a custom
 *     model provider.
 *   - OpenAI Chat Completions (`POST /v1/chat/completions`, SSE when
 *     `stream: true`) for OpenCode and OpenClaw via an OpenAI-compatible provider.
 *
 * Every request body is recorded, so a test can assert what the host sent back
 * after the tool call: the tool result the host produced, a hook denial, or no
 * model request at all (a prompt blocked before it reached the model).
 */
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

/** Generic tool kinds a scenario can script; each protocol maps them to host tool names. */
const TOOL_KINDS = ["shell", "read"];

const PLAIN_TEXT = "ok";

function readBody(request) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		request.on("data", (chunk) => chunks.push(chunk));
		request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		request.on("error", reject);
	});
}

function sendJson(response, status, value) {
	response.writeHead(status, { "content-type": "application/json" });
	response.end(JSON.stringify(value));
}

function startSse(response) {
	response.writeHead(200, {
		"content-type": "text/event-stream",
		"cache-control": "no-cache",
		connection: "keep-alive",
	});
}

function sseEvent(response, event, data) {
	if (event) response.write(`event: ${event}\n`);
	response.write(`data: ${typeof data === "string" ? data : JSON.stringify(data)}\n\n`);
}

function toolNames(tools) {
	if (!Array.isArray(tools)) return [];
	return tools
		.map((tool) => tool?.name ?? tool?.function?.name ?? null)
		.filter((name) => typeof name === "string");
}

// ── Anthropic Messages ──────────────────────────────────────────────────────

function anthropicHasToolResult(messages) {
	return (messages ?? []).some(
		(message) =>
			message?.role === "user" &&
			Array.isArray(message.content) &&
			message.content.some((block) => block?.type === "tool_result"),
	);
}

function anthropicToolUse(scenario, names) {
	const call = scenario.toolCall;
	if (call.kind === "shell" && names.includes("Bash")) {
		return { name: "Bash", input: { command: call.command, description: "Run the scripted command" } };
	}
	if (call.kind === "read" && names.includes("Read")) {
		return { name: "Read", input: { file_path: call.path } };
	}
	return null;
}

function anthropicMessage(body, content, stopReason) {
	return {
		id: `msg_${randomUUID().replaceAll("-", "")}`,
		type: "message",
		role: "assistant",
		model: body.model ?? "mock-model",
		content,
		stop_reason: stopReason,
		stop_sequence: null,
		usage: { input_tokens: 10, output_tokens: 10, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
	};
}

function writeAnthropic(response, body, content, stopReason) {
	const message = anthropicMessage(body, content, stopReason);
	if (body.stream !== true) {
		sendJson(response, 200, message);
		return;
	}
	startSse(response);
	sseEvent(response, "message_start", {
		type: "message_start",
		message: { ...message, content: [], stop_reason: null, usage: { ...message.usage, output_tokens: 1 } },
	});
	content.forEach((block, index) => {
		if (block.type === "text") {
			sseEvent(response, "content_block_start", {
				type: "content_block_start",
				index,
				content_block: { type: "text", text: "" },
			});
			sseEvent(response, "content_block_delta", {
				type: "content_block_delta",
				index,
				delta: { type: "text_delta", text: block.text },
			});
		} else {
			sseEvent(response, "content_block_start", {
				type: "content_block_start",
				index,
				content_block: { type: "tool_use", id: block.id, name: block.name, input: {} },
			});
			sseEvent(response, "content_block_delta", {
				type: "content_block_delta",
				index,
				delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) },
			});
		}
		sseEvent(response, "content_block_stop", { type: "content_block_stop", index });
	});
	sseEvent(response, "message_delta", {
		type: "message_delta",
		delta: { stop_reason: stopReason, stop_sequence: null },
		usage: { output_tokens: 10 },
	});
	sseEvent(response, "message_stop", { type: "message_stop" });
	response.end();
}

// ── OpenAI Responses (Codex) ────────────────────────────────────────────────

function responsesHasToolOutput(input) {
	return Array.isArray(input) && input.some((item) => item?.type === "function_call_output" || item?.type === "custom_tool_call_output");
}

function responsesToolCall(scenario, tools) {
	const call = scenario.toolCall;
	if (call.kind !== "shell") return null;
	const names = toolNames(tools);
	// Codex exposes one of these shell tools depending on the model family.
	if (names.includes("exec_command")) return { name: "exec_command", arguments: { cmd: call.command } };
	if (names.includes("shell_command")) return { name: "shell_command", arguments: { command: call.command } };
	if (names.includes("shell")) return { name: "shell", arguments: { command: ["bash", "-lc", call.command] } };
	return null;
}

function writeResponses(response, body, item) {
	const id = `resp_${randomUUID().replaceAll("-", "")}`;
	const base = { id, object: "response", created_at: Math.floor(Date.now() / 1000), model: body.model ?? "mock-model" };
	startSse(response);
	sseEvent(response, "response.created", { type: "response.created", response: { ...base, status: "in_progress", output: [] } });
	sseEvent(response, "response.output_item.added", { type: "response.output_item.added", output_index: 0, item });
	if (item.type === "message") {
		sseEvent(response, "response.output_text.delta", {
			type: "response.output_text.delta",
			item_id: item.id,
			output_index: 0,
			content_index: 0,
			delta: item.content[0].text,
		});
	}
	sseEvent(response, "response.output_item.done", { type: "response.output_item.done", output_index: 0, item });
	sseEvent(response, "response.completed", {
		type: "response.completed",
		response: {
			...base,
			status: "completed",
			output: [item],
			usage: { input_tokens: 10, input_tokens_details: { cached_tokens: 0 }, output_tokens: 10, output_tokens_details: { reasoning_tokens: 0 }, total_tokens: 20 },
		},
	});
	response.end();
}

// ── OpenAI Chat Completions (OpenCode, OpenClaw) ────────────────────────────

function chatHasToolResult(messages) {
	return Array.isArray(messages) && messages.some((message) => message?.role === "tool");
}

function chatToolCall(scenario, tools) {
	const call = scenario.toolCall;
	const names = toolNames(tools);
	const pick = (...candidates) => candidates.find((name) => names.includes(name));
	if (call.kind === "shell") {
		const name = pick("bash", "exec", "Bash", "shell");
		if (!name) return null;
		return { name, arguments: { command: call.command, description: "Run the scripted command" } };
	}
	if (call.kind === "read") {
		const name = pick("read", "Read", "read_file");
		if (!name) return null;
		return { name, arguments: { filePath: call.path, path: call.path, file_path: call.path } };
	}
	return null;
}

function writeChat(response, body, { text, toolCall }) {
	const id = `chatcmpl-${randomUUID().replaceAll("-", "")}`;
	const created = Math.floor(Date.now() / 1000);
	const model = body.model ?? "mock-model";
	const finishReason = toolCall ? "tool_calls" : "stop";
	const toolCalls = toolCall
		? [{ index: 0, id: `call_${randomUUID().replaceAll("-", "").slice(0, 24)}`, type: "function", function: { name: toolCall.name, arguments: JSON.stringify(toolCall.arguments) } }]
		: undefined;
	const usage = { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 };
	if (body.stream !== true) {
		sendJson(response, 200, {
			id,
			object: "chat.completion",
			created,
			model,
			choices: [{ index: 0, message: { role: "assistant", content: text ?? null, ...(toolCalls ? { tool_calls: toolCalls.map(({ index: _index, ...rest }) => rest) } : {}) }, finish_reason: finishReason }],
			usage,
		});
		return;
	}
	startSse(response);
	const chunk = (delta, finish = null, extra = {}) =>
		sseEvent(response, null, { id, object: "chat.completion.chunk", created, model, choices: [{ index: 0, delta, finish_reason: finish }], ...extra });
	chunk({ role: "assistant", content: "" });
	if (text) chunk({ content: text });
	if (toolCalls) chunk({ tool_calls: toolCalls });
	chunk({}, finishReason);
	sseEvent(response, null, { id, object: "chat.completion.chunk", created, model, choices: [], usage });
	sseEvent(response, null, "[DONE]");
	response.end();
}

// ── Reading what the host sent back ─────────────────────────────────────────

function textOf(content) {
	if (typeof content === "string") return content;
	if (Array.isArray(content)) {
		return content
			.map((part) => (typeof part === "string" ? part : typeof part?.text === "string" ? part.text : ""))
			.join("\n");
	}
	return "";
}

/**
 * The tool result the host returned to the model in one recorded request, in
 * any of the three protocols: the command output when the tool ran, or the
 * hook/plugin denial text when it did not. `null` when the request has none.
 */
export function toolResultText(record) {
	const body = record?.body ?? {};
	const results = [];
	for (const message of body.messages ?? []) {
		if (message?.role === "tool") results.push(textOf(message.content));
		if (message?.role === "user" && Array.isArray(message.content)) {
			for (const block of message.content) {
				if (block?.type === "tool_result") results.push(textOf(block.content));
			}
		}
	}
	for (const item of Array.isArray(body.input) ? body.input : []) {
		if (item?.type === "function_call_output" || item?.type === "custom_tool_call_output") {
			results.push(typeof item.output === "string" ? item.output : textOf(item.output?.content ?? item.output));
		}
	}
	return results.length > 0 ? results.join("\n") : null;
}

// ── Server ──────────────────────────────────────────────────────────────────

/**
 * Start the mock server on 127.0.0.1 with an ephemeral port.
 *
 * @returns {Promise<{ url: string, port: number, setScenario(s: object): void, requests: object[], agentRequests(): object[], reset(): void, close(): Promise<void> }>}
 */
export async function startMockLlmServer() {
	let scenario = null;
	const requests = [];

	const server = createServer(async (request, response) => {
		const url = new URL(request.url ?? "/", "http://127.0.0.1");
		const raw = request.method === "POST" ? await readBody(request) : "";
		let body = {};
		try {
			body = raw ? JSON.parse(raw) : {};
		} catch {
			body = { unparseable: raw.slice(0, 200) };
		}
		const record = { method: request.method, path: url.pathname, body, raw, agent: false, reply: null };
		requests.push(record);

		try {
			if (request.method === "GET" && url.pathname.endsWith("/models")) {
				sendJson(response, 200, { object: "list", data: [{ id: "mock-model", object: "model", owned_by: "aidr-e2e" }] });
				return;
			}
			if (request.method !== "POST") {
				sendJson(response, 404, { error: { type: "not_found", message: `${request.method} ${url.pathname}` } });
				return;
			}

			if (url.pathname.endsWith("/messages/count_tokens")) {
				sendJson(response, 200, { input_tokens: 10 });
				return;
			}

			if (url.pathname.endsWith("/messages")) {
				const names = toolNames(body.tools);
				const toolUse = scenario ? anthropicToolUse(scenario, names) : null;
				if (!toolUse) {
					record.reply = "plain";
					writeAnthropic(response, body, [{ type: "text", text: PLAIN_TEXT }], "end_turn");
					return;
				}
				record.agent = true;
				if (anthropicHasToolResult(body.messages)) {
					record.reply = "final";
					writeAnthropic(response, body, [{ type: "text", text: scenario.finalText }], "end_turn");
					return;
				}
				record.reply = "tool";
				const block = { type: "tool_use", id: `toolu_${randomUUID().replaceAll("-", "").slice(0, 24)}`, ...toolUse };
				writeAnthropic(response, body, [block], "tool_use");
				return;
			}

			if (url.pathname.endsWith("/responses")) {
				const call = scenario ? responsesToolCall(scenario, body.tools) : null;
				if (!call || responsesHasToolOutput(body.input)) {
					record.agent = Boolean(call);
					record.reply = call ? "final" : "plain";
					const text = call ? scenario.finalText : PLAIN_TEXT;
					writeResponses(response, body, {
						type: "message",
						id: `msg_${randomUUID().replaceAll("-", "")}`,
						role: "assistant",
						status: "completed",
						content: [{ type: "output_text", text, annotations: [] }],
					});
					return;
				}
				record.agent = true;
				record.reply = "tool";
				writeResponses(response, body, {
					type: "function_call",
					id: `fc_${randomUUID().replaceAll("-", "")}`,
					status: "completed",
					call_id: `call_${randomUUID().replaceAll("-", "").slice(0, 24)}`,
					name: call.name,
					arguments: JSON.stringify(call.arguments),
				});
				return;
			}

			if (url.pathname.endsWith("/chat/completions")) {
				const call = scenario ? chatToolCall(scenario, body.tools) : null;
				if (!call) {
					record.reply = "plain";
					writeChat(response, body, { text: PLAIN_TEXT });
					return;
				}
				record.agent = true;
				if (chatHasToolResult(body.messages)) {
					record.reply = "final";
					writeChat(response, body, { text: scenario.finalText });
					return;
				}
				record.reply = "tool";
				writeChat(response, body, { toolCall: call });
				return;
			}

			sendJson(response, 404, { error: { type: "not_found", message: url.pathname } });
		} catch (error) {
			if (!response.headersSent) sendJson(response, 500, { error: { type: "mock_error", message: String(error) } });
			else response.end();
		}
	});

	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	const { port } = server.address();

	return {
		url: `http://127.0.0.1:${port}`,
		port,
		requests,
		setScenario(next) {
			if (!next || !next.toolCall || !TOOL_KINDS.includes(next.toolCall.kind) || typeof next.finalText !== "string") {
				throw new Error("scenario needs toolCall.kind in TOOL_KINDS and a finalText");
			}
			scenario = next;
		},
		/** Requests that carried the host's agent tool set (the scripted conversation). */
		agentRequests() {
			return requests.filter((entry) => entry.agent);
		},
		reset() {
			requests.length = 0;
		},
		close() {
			return new Promise((resolve) => {
				server.closeAllConnections?.();
				server.close(() => resolve());
			});
		},
	};
}
