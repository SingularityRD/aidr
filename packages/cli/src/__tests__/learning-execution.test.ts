import { describe, expect, it } from "vitest";
import { runLearningCommand } from "../utils/learning-execution.js";

const windows = process.platform === "win32";

describe("native supervised learning execution", () => {
	it("collects actual complete stdout and stderr only after shell exit zero", async () => {
		const command = windows
			? "Write-Output 'clean'; [Console]::Error.WriteLine('diagnostic')"
			: "printf clean; printf diagnostic >&2";
		await expect(runLearningCommand(command, 5_000)).resolves.toMatch(
			/STDOUT:[\s\S]*clean[\s\S]*STDERR:[\s\S]*diagnostic/,
		);
	});

	it("rejects a real nonzero shell exit", async () => {
		await expect(runLearningCommand("exit 7", 5_000)).rejects.toThrow(
			/did not finish successfully/,
		);
	});

	it("bounds combined stdout and stderr bytes before inspecting output", async () => {
		const command = windows
			? "[Console]::Out.Write(('a' * 1200000)); [Console]::Error.Write(('b' * 1200000))"
			: "head -c 1200000 /dev/zero; head -c 1200000 /dev/zero >&2";
		await expect(runLearningCommand(command, 5_000)).rejects.toThrow(/inspection limit/);
	});

	it("rejects actual invalid UTF-8 output rather than silently replacing bytes", async () => {
		const command = windows
			? "[Console]::OpenStandardOutput().Write([byte[]] @(255), 0, 1)"
			: "printf '\\377'";
		await expect(runLearningCommand(command, 5_000)).rejects.toThrow(/UTF-8/);
	});

	it("terminates a real command when the execution deadline expires", async () => {
		const command = windows ? "Start-Sleep -Seconds 10" : "sleep 10";
		await expect(runLearningCommand(command, 100)).rejects.toThrow(/deadline/);
	});

	// AIDR-SKIP: AIDR-063 qa-owner - POSIX process-group termination requires a Unix host; real Linux complement covers this case, Windows receipts cover foreground completion only
	it.skipIf(windows)(
		"rejects and stops a POSIX background process after the shell exits",
		async () => {
			await expect(runLearningCommand("sleep 10 >/dev/null 2>&1 &", 5_000)).rejects.toThrow(
				/background process/,
			);
		},
	);
});
