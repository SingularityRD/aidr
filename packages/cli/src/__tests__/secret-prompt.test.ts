import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { readHiddenInput } from "../utils/secret-prompt.js";

class FakeTtyInput extends EventEmitter {
	isTTY = true;
	isRaw = false;
	readonly rawModes: boolean[] = [];
	setRawMode(mode: boolean): void {
		this.isRaw = mode;
		this.rawModes.push(mode);
	}
	resume(): this {
		return this;
	}
}

describe("hidden secret prompt", () => {
	it("disables echo while reading and restores terminal mode", async () => {
		const input = new FakeTtyInput();
		const output = new PassThrough();
		const printed: string[] = [];
		output.on("data", (chunk: Buffer) => printed.push(chunk.toString("utf8")));
		const result = readHiddenInput("Secret value: ", input as never, output as never);

		input.emit("data", Buffer.from("abc\u007fD\r"));

		expect(await result).toBe("abD");
		expect(input.rawModes).toEqual([true, false]);
		expect(input.isRaw).toBe(false);
		expect(printed.join("")).toBe("Secret value: \n");
		expect(printed.join("")).not.toContain("abD");
	});

	it("refuses non-interactive input instead of reading a secret from arguments", () => {
		const input = new FakeTtyInput();
		input.isTTY = false;
		expect(() => readHiddenInput("Secret: ", input as never, new PassThrough() as never)).toThrow(
			/interactive terminal/i,
		);
	});
});
