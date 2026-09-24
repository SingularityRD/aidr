import { userInfo } from "node:os";
import { createInterface } from "node:readline";

/**
 * Human confirmation for operator-only actions (`aidr approve`, `aidr allowlist add`).
 *
 * These commands widen what the policed agent may do, so they must not be
 * something the agent can run on its own. They therefore require one of:
 *
 * - an interactive terminal on BOTH stdin and stderr, where the operator types
 *   the confirmation word; or
 * - `--yes` AND `AIDR_OPERATOR_NONINTERACTIVE=1`, for operator automation.
 *
 * Neither is an absolute boundary: code running as the same OS user can allocate
 * a pseudo-terminal (`script`, `expect`, `unbuffer`, a pty module) or set the
 * variable. Agent tool calls normally have no TTY, and the self-defense rule
 * CLT-SELF-007 DENIES an agent command that runs these commands (through quoting,
 * executable lookups, package runners and pty wrappers alike, since it matches
 * the shell-normalized command) or sets the variable. The approval key itself is
 * kept in the OS credential vault. See docs/configuration.md.
 */

export const OPERATOR_NONINTERACTIVE_ENV = "AIDR_OPERATOR_NONINTERACTIVE";

export class OperatorConfirmationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "OperatorConfirmationError";
	}
}

export interface ConfirmationStreams {
	input: NodeJS.ReadableStream & { isTTY?: boolean };
	output: NodeJS.WritableStream & { isTTY?: boolean };
}

export interface ConfirmOptions {
	/** What the operator is confirming, printed before the prompt. */
	prompt: string;
	/** The word the operator must type. */
	word: string;
	yes?: boolean;
	env?: NodeJS.ProcessEnv;
	streams?: ConfirmationStreams;
}

export type ConfirmationMode = "interactive" | "non-interactive";

function readLine(streams: ConfirmationStreams, query: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const rl = createInterface({ input: streams.input, output: streams.output, terminal: true });
		let answered = false;
		rl.once("close", () => {
			if (!answered) reject(new OperatorConfirmationError("Confirmation input ended."));
		});
		rl.question(query, (answer) => {
			answered = true;
			rl.close();
			resolve(answer);
		});
	});
}

/** Resolve with how the action was confirmed, or throw when it was not. */
export async function confirmOperatorAction(options: ConfirmOptions): Promise<ConfirmationMode> {
	const env = options.env ?? process.env;
	const streams = options.streams ?? { input: process.stdin, output: process.stderr };

	if (options.yes) {
		if (env[OPERATOR_NONINTERACTIVE_ENV] !== "1") {
			throw new OperatorConfirmationError(
				`--yes is honoured only when ${OPERATOR_NONINTERACTIVE_ENV}=1 is also set by the operator. ` +
					"Run the command in an interactive terminal to confirm it by hand.",
			);
		}
		streams.output.write(`${options.prompt}\nConfirmed non-interactively (--yes).\n`);
		return "non-interactive";
	}

	if (!streams.input.isTTY || !streams.output.isTTY) {
		throw new OperatorConfirmationError(
			"This operator-only command needs an interactive terminal for confirmation. " +
				`For operator automation pass --yes with ${OPERATOR_NONINTERACTIVE_ENV}=1.`,
		);
	}

	streams.output.write(`${options.prompt}\n`);
	const answer = await readLine(streams, `Type "${options.word}" to confirm: `);
	if (answer.trim().toLowerCase() !== options.word) {
		throw new OperatorConfirmationError("Not confirmed; nothing was changed.");
	}
	return "interactive";
}

/** Who confirmed, for the approval record. The OS account name only. */
export function operatorIdentity(mode: ConfirmationMode): string {
	let name = "unknown";
	try {
		name = userInfo().username || name;
	} catch {
		// Some containers have no passwd entry for the uid.
	}
	return `${name} (${mode})`;
}
