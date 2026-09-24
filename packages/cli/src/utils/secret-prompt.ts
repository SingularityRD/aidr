import type { ReadStream, WriteStream } from "node:tty";

type RawInput = ReadStream & {
	isRaw?: boolean;
	setRawMode(mode: boolean): void;
};

/** Read a line with terminal echo disabled. Secrets never enter argv or shell history. */
export function readHiddenInput(
	query: string,
	input: RawInput = process.stdin as RawInput,
	output: WriteStream = process.stderr,
): Promise<string> {
	if (!input.isTTY || typeof input.setRawMode !== "function") {
		throw new Error(
			"Secret values require an interactive terminal; run this command without a value argument.",
		);
	}

	output.write(query);
	const wasRaw = input.isRaw ?? false;
	return new Promise((resolve, reject) => {
		let value = "";
		let finished = false;

		const finish = (error?: Error): void => {
			if (finished) return;
			finished = true;
			input.off("data", onData);
			input.off("end", onEnd);
			try {
				input.setRawMode(wasRaw);
			} catch {
				// Preserve the input result if the terminal has already closed.
			}
			output.write("\n");
			if (error) reject(error);
			else resolve(value);
		};

		const consumeCharacter = (character: string): boolean => {
			if (character === "\r" || character === "\n") {
				finish();
				return true;
			}
			if (character === "\u0003" || character === "\u001a") {
				finish(new Error("Secret input cancelled."));
				return true;
			}
			if (character === "\u0008" || character === "\u007f") {
				value = Array.from(value).slice(0, -1).join("");
			} else if (character >= " " && character !== "\u007f") {
				value += character;
			}
			return false;
		};

		const onData = (chunk: Buffer | string): void => {
			for (const character of Buffer.isBuffer(chunk) ? chunk.toString("utf8") : chunk) {
				if (consumeCharacter(character)) return;
			}
		};

		const onEnd = (): void => finish(new Error("Secret input ended before a value was entered."));

		try {
			input.setRawMode(true);
			input.resume();
			input.on("data", onData);
			input.once("end", onEnd);
		} catch (error) {
			finish(error instanceof Error ? error : new Error("Could not read secret input."));
		}
	});
}
