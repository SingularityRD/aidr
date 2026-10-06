import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const EXECUTION_TIMEOUT_MS = 60_000;

/** The broker executes exactly one inspected command with a fixed native shell. */
export function executeLearningCommand(command: string): Promise<string> {
	return runLearningCommand(command, EXECUTION_TIMEOUT_MS);
}

/** Shorter deadlines are injectable for regression checks, never selected by tool input. */
export function runLearningCommand(command: string, timeoutMs: number): Promise<string> {
	if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > EXECUTION_TIMEOUT_MS) {
		return Promise.reject(new Error("Learning execution deadline is invalid."));
	}
	return new Promise((resolve, reject) => {
		const windows = process.platform === "win32";
		const systemDirectory = join(process.env.SystemRoot || "C:\\Windows", "System32");
		const child = spawn(
			windows ? join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe") : "/bin/sh",
			windows ? ["-NoProfile", "-NonInteractive", "-Command", command] : ["-c", command],
			{ stdio: ["ignore", "pipe", "pipe"], windowsHide: true, detached: !windows },
		);
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		let bytes = 0;
		let failure: Error | undefined;
		let finished = false;
		let stopped = false;
		const stop = (): void => {
			if (stopped || !child.pid) return;
			stopped = true;
			if (windows) {
				const killed = spawnSync(
					join(systemDirectory, "taskkill.exe"),
					["/PID", String(child.pid), "/T", "/F"],
					{
						stdio: "ignore",
						windowsHide: true,
						timeout: 5_000,
					},
				);
				if (killed.error || killed.status !== 0) child.kill("SIGKILL");
			} else {
				try {
					process.kill(-child.pid, "SIGKILL");
				} catch {
					child.kill("SIGKILL");
				}
			}
		};
		const finish = (error?: Error, output?: string): void => {
			if (finished) return;
			finished = true;
			clearTimeout(timer);
			if (error) {
				child.stdout.destroy();
				child.stderr.destroy();
				child.unref();
				reject(error);
			} else resolve(output as string);
		};
		const collect = (target: Buffer[], chunk: Buffer): void => {
			if (finished || failure) return;
			bytes += chunk.length;
			if (bytes > MAX_OUTPUT_BYTES) {
				failure ??= new Error("Learning execution output exceeds the inspection limit.");
				stop();
				finish(failure);
			} else if (!failure) {
				target.push(chunk);
			}
		};
		const timer = setTimeout(() => {
			failure = new Error("Learning execution exceeded its deadline.");
			stop();
			finish(failure);
		}, timeoutMs);
		child.stdout.on("data", (chunk: Buffer) => collect(stdout, chunk));
		child.stderr.on("data", (chunk: Buffer) => collect(stderr, chunk));
		child.once("error", () => {
			finish(new Error("Learning execution could not start."));
		});
		child.once("close", (code, signal) => {
			if (failure) return finish(failure);
			if (code !== 0 || signal) {
				return finish(new Error("Learning execution did not finish successfully."));
			}
			if (!windows && child.pid) {
				try {
					process.kill(-child.pid, 0);
					stop();
					return finish(new Error("Learning execution left an unfinished background process."));
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code !== "ESRCH") {
						stop();
						return finish(new Error("Learning execution completion could not be confirmed."));
					}
				}
			}
			try {
				const decoder = new TextDecoder("utf-8", { fatal: true });
				const output = `STDOUT:\n${decoder.decode(Buffer.concat(stdout))}\nSTDERR:\n${decoder.decode(Buffer.concat(stderr))}`;
				finish(undefined, output);
			} catch {
				finish(new Error("Learning execution output is not inspectable UTF-8 text."));
			}
		});
	});
}
