import { type CodexInstrumentationOptions, createCodexInstrumentation } from "./instrumentation.js";
import type { CodexHookInput, CodexHookResult } from "./types.js";
export async function handleCodexHook(
	input: CodexHookInput,
	options: CodexInstrumentationOptions,
): Promise<CodexHookResult> {
	const instrumentation = createCodexInstrumentation(options);
	const phase = input.phase ?? input.event ?? input.type;
	return phase === "post_tool_use" || phase === "post_tool" || phase === "after_tool_call"
		? instrumentation.postToolUse(input)
		: instrumentation.preToolUse(input);
}
