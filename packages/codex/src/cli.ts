#!/usr/bin/env node
import { handleCodexHook } from "./hook.js";
import type { CodexHookInput, CodexRuntimeIdentity } from "./types.js";

function env(name: string): string {
	return process.env[name]?.trim() ?? "";
}
async function main(): Promise<void> {
	let input: CodexHookInput;
	try {
		let stdin = "";
		for await (const chunk of process.stdin) stdin += String(chunk);
		input = JSON.parse(stdin) as CodexHookInput;
	} catch {
		process.stdout.write(JSON.stringify({ decision: "deny", reasonCode: "codex_input_malformed" }));
		return;
	}
	const identity: CodexRuntimeIdentity = {
		tenantId: env("AUTOSECOPS_TENANT_ID"),
		teamId: env("AUTOSECOPS_TEAM_ID"),
		endpointId: env("AUTOSECOPS_ENDPOINT_ID"),
		agentId: env("AUTOSECOPS_AGENT_ID"),
		instanceId: env("AUTOSECOPS_INSTANCE_ID"),
		sessionId: env("AUTOSECOPS_SESSION_ID") || String(input.session_id ?? ""),
		connectorVersion: env("AUTOSECOPS_CONNECTOR_VERSION") || "codex-unknown",
	};
	const result = await handleCodexHook(input, {
		identity,
		policy: {
			endpoint: env("AUTOSECOPS_POLICY_ENDPOINT"),
			apiKey: env("AUTOSECOPS_API_KEY"),
			timeoutMs: Number(env("AUTOSECOPS_POLICY_TIMEOUT_MS") || "1000"),
		},
	});
	process.stdout.write(JSON.stringify(result));
}
await main();
