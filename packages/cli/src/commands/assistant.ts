import { openInBrowser } from "../assistant/open-browser.js";
import { createLocalOps, type LocalOpsDeps } from "../assistant/operations.js";
import {
	type AssistantServer,
	type CloseReason,
	startAssistantServer,
} from "../assistant/server.js";
import { ASSISTANT_UI } from "../generated/assistant-ui.js";
import { at } from "../i18n/index.js";

/**
 * `aidr assistant`: the Singularity AIDR Setup Assistant, a local setup wizard
 * in the person's default browser (Windows and Linux). It serves the page from
 * 127.0.0.1 with a one-time link (see assistant/server.ts) and stops when the
 * wizard finishes, after 30 minutes without activity, or on Ctrl+C.
 *
 * An AI agent must not run it: CLT-SELF-007 denies `aidr assistant` to agents,
 * the same way it denies `aidr setup --force`.
 */
export interface AssistantCommandDeps extends LocalOpsDeps {
	open?: typeof openInBrowser;
	/** Called once the server listens (tests). */
	onListening?: (server: AssistantServer) => void;
	idleMs?: number;
}

const CLOSED_TEXT: Record<CloseReason, Parameters<typeof at>[0]> = {
	done: "assistant.cli.closedDone",
	idle: "assistant.cli.closedIdle",
	signal: "assistant.cli.closedSignal",
	error: "assistant.cli.closedSignal",
};

export default async function assistantCommand(
	options: { open?: boolean } = {},
	deps: AssistantCommandDeps = {},
): Promise<void> {
	const server = await startAssistantServer({
		ops: createLocalOps(deps),
		assets: ASSISTANT_UI,
		idleMs: deps.idleMs,
	});
	const stop = () => void server.close("signal");
	process.once("SIGINT", stop);
	process.once("SIGTERM", stop);
	try {
		deps.onListening?.(server);
		console.log("");
		if (options.open === false) {
			console.log(at("assistant.cli.noOpen"));
		} else {
			const failure = await (deps.open ?? openInBrowser)(server.url);
			if (failure) {
				console.log(at("assistant.cli.openFailed", { reason: failure }));
				console.log(at("assistant.cli.openManually"));
			} else {
				console.log(at("assistant.cli.running"));
				console.log(at("assistant.cli.openManually"));
			}
		}
		console.log(`  ${server.url}`);
		console.log(at("assistant.cli.oneUse"));
		console.log("");
		const reason = await server.closed;
		console.log(at(CLOSED_TEXT[reason]));
	} finally {
		process.off("SIGINT", stop);
		process.off("SIGTERM", stop);
	}
}
