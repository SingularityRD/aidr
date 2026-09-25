/**
 * Protocol tests for the real-host E2E mock model (no host binaries needed).
 *
 *   node --test scripts/real-host-e2e/mock-llm-server.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";
import { summarizeProof } from "./run.mjs";
import { startMockLlmServer, toolResultText } from "./mock-llm-server.mjs";

const SCENARIO = { toolCall: { kind: "shell", command: "echo scripted" }, finalText: "all done" };

async function post(server, path, body) {
	const response = await fetch(`${server.url}${path}`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body),
	});
	return { status: response.status, text: await response.text() };
}

function sseData(text) {
	return text
		.split("\n")
		.filter((line) => line.startsWith("data: "))
		.map((line) => line.slice(6))
		.filter((line) => line !== "[DONE]")
		.map((line) => JSON.parse(line));
}

test("Anthropic Messages: tool_use on turn 1, final text once a tool_result is present", async (t) => {
	const server = await startMockLlmServer();
	t.after(() => server.close());
	server.setScenario(SCENARIO);
	const tools = [{ name: "Bash" }, { name: "Read" }];

	const first = await post(server, "/v1/messages?beta=true", { model: "m", stream: true, tools, messages: [{ role: "user", content: "go" }] });
	const events = sseData(first.text);
	assert.equal(events[0].type, "message_start");
	const start = events.find((event) => event.type === "content_block_start");
	assert.equal(start.content_block.type, "tool_use");
	assert.equal(start.content_block.name, "Bash");
	const delta = events.find((event) => event.type === "content_block_delta");
	assert.deepEqual(JSON.parse(delta.delta.partial_json).command, "echo scripted");
	assert.equal(events.find((event) => event.type === "message_delta").delta.stop_reason, "tool_use");
	assert.equal(events.at(-1).type, "message_stop");

	const secondBody = {
		model: "m",
		stream: false,
		tools,
		messages: [
			{ role: "user", content: "go" },
			{ role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Bash", input: {} }] },
			{ role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "Singularity AIDR blocked this" }] },
		],
	};
	const second = JSON.parse((await post(server, "/v1/messages", secondBody)).text);
	assert.equal(second.content[0].text, "all done");
	assert.equal(second.stop_reason, "end_turn");

	// A request without the agent tool set (title generation, quota probe) is plain text.
	const aux = JSON.parse((await post(server, "/v1/messages", { model: "m", messages: [] })).text);
	assert.equal(aux.content[0].text, "ok");

	assert.deepEqual(server.agentRequests().map((entry) => entry.reply), ["tool", "final"]);
	assert.equal(toolResultText(server.agentRequests()[1]), "Singularity AIDR blocked this");
	assert.equal(JSON.parse((await post(server, "/v1/messages/count_tokens", {})).text).input_tokens, 10);
});

test("OpenAI Responses: maps the shell call onto the tool Codex offers", async (t) => {
	const server = await startMockLlmServer();
	t.after(() => server.close());
	server.setScenario(SCENARIO);

	const unified = sseData((await post(server, "/v1/responses", { model: "m", tools: [{ type: "function", name: "exec_command" }], input: [] })).text);
	const call = unified.find((event) => event.type === "response.output_item.done").item;
	assert.equal(call.type, "function_call");
	assert.equal(call.name, "exec_command");
	assert.deepEqual(JSON.parse(call.arguments), { cmd: "echo scripted" });
	assert.equal(unified.at(-1).type, "response.completed");

	const legacy = sseData((await post(server, "/v1/responses", { model: "m", tools: [{ type: "function", name: "shell" }], input: [] })).text);
	assert.deepEqual(JSON.parse(legacy.find((event) => event.type === "response.output_item.done").item.arguments), {
		command: ["bash", "-lc", "echo scripted"],
	});

	const final = await post(server, "/v1/responses", {
		model: "m",
		tools: [{ type: "function", name: "exec_command" }],
		input: [{ type: "function_call_output", call_id: "c1", output: "Command blocked by PreToolUse hook" }],
	});
	const message = sseData(final.text).find((event) => event.type === "response.output_item.done").item;
	assert.equal(message.content[0].text, "all done");
	assert.equal(toolResultText(server.requests.at(-1)), "Command blocked by PreToolUse hook");
});

test("OpenAI Chat Completions: streamed tool_calls, then final text after a tool message", async (t) => {
	const server = await startMockLlmServer();
	t.after(() => server.close());
	server.setScenario({ toolCall: { kind: "read", path: "/tmp/key" }, finalText: "all done" });
	const tools = [{ type: "function", function: { name: "bash" } }, { type: "function", function: { name: "read" } }];

	const chunks = sseData((await post(server, "/v1/chat/completions", { model: "m", stream: true, tools, messages: [{ role: "user", content: "go" }] })).text);
	const toolChunk = chunks.find((chunk) => chunk.choices[0]?.delta?.tool_calls);
	const toolCall = toolChunk.choices[0].delta.tool_calls[0];
	assert.equal(toolCall.function.name, "read");
	assert.equal(JSON.parse(toolCall.function.arguments).filePath, "/tmp/key");
	assert.equal(chunks.find((chunk) => chunk.choices[0]?.finish_reason).choices[0].finish_reason, "tool_calls");

	const final = JSON.parse(
		(
			await post(server, "/v1/chat/completions", {
				model: "m",
				tools,
				messages: [
					{ role: "user", content: "go" },
					{ role: "tool", tool_call_id: "c1", content: "Singularity AIDR flagged this action" },
				],
			})
		).text,
	);
	assert.equal(final.choices[0].message.content, "all done");
	assert.equal(toolResultText(server.requests.at(-1)), "Singularity AIDR flagged this action");
});

test("a scenario must name a known tool kind and a final text", async (t) => {
	const server = await startMockLlmServer();
	t.after(() => server.close());
	assert.throws(() => server.setScenario({ toolCall: { kind: "delete-everything" }, finalText: "x" }), /TOOL_KINDS/u);
	assert.throws(() => server.setScenario({ toolCall: { kind: "shell", command: "ls" } }), /finalText/u);
});

test("proof summary: observations never prove a point and one failing scenario fails the point", () => {
	const summary = summarizeProof([
		{ id: "a", expectation: "assertion", proves: { point: "pre-tool" }, passed: true },
		{ id: "b", expectation: "assertion", proves: { point: "pre-tool" }, passed: false },
		{ id: "c", expectation: "assertion", proves: { point: "pre-prompt" }, passed: true },
		{ id: "d", expectation: "observation", proves: { point: "post-tool-output" }, passed: false },
		{ id: "e", expectation: "assertion", proves: { condition: "crashed-hook" }, passed: true, observedOutcome: "fail-open" },
		{ id: "f", expectation: "assertion", proves: { failurePolicy: "internal-error" }, passed: true, observedOutcome: "fail-closed" },
	]);
	assert.deepEqual(summary, {
		points: { "pre-tool": "failed", "pre-prompt": "passed" },
		conditions: { "crashed-hook": "fail-open" },
		failurePolicy: { "internal-error": "fail-closed" },
		observations: { d: "gap" },
	});
});
