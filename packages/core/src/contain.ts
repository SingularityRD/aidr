/**
 * Auto-Contain: Container isolation for suspicious operations.
 * Provides automatic containerized execution of untrusted operations.
 */

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { resolvePath } from "./config.js";
import type { ResponseAuditor } from "./response-audit.js";
import type { Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

export interface ContainConfig {
	runtime: "docker" | "podman";
	baseImage: string;
	networkMode: "none" | "restricted";
	readonlyMounts: string[];
	cpuLimit?: string;
	memoryLimit?: string;
	timeoutSeconds: number;
}

interface ContainerResult {
	exitCode: number;
	stdout: string;
	stderr: string;
}

export class AutoContain {
	private aidrDir: string;

	constructor(
		private config: ContainConfig,
		private logger: Logger = nullLogger,
		private auditor?: ResponseAuditor,
	) {
		this.aidrDir = resolvePath("~/.singularity-aidr");
	}

	async isolate<TResult>(
		operation: () => Promise<TResult>,
		context: { tool: string; input: string; verdict?: Verdict; threatId?: string },
	): Promise<{
		result: TResult;
		isolated: boolean;
		containerId?: string;
	}> {
		void operation;
		this.logger.warn("Generic operation isolation is unsupported; refusing to run it", {
			runtime: this.config.runtime,
			tool: context.tool,
		});
		if (this.auditor && context.verdict && context.threatId) {
			await this.auditor.log({
				action: "contain",
				threatId: context.threatId,
				tool: context.tool,
				input: context.input,
				verdict: context.verdict,
				responseTaken: "contain",
				metadata: { containerId: undefined },
				outcome: "failure",
				error: "Generic operation isolation is unsupported; use isolateCommand()",
			});
		}
		throw new Error(
			"Generic operation isolation is not supported; refusing to run the operation unisolated. " +
				"Use isolateCommand() or block the call instead.",
		);
	}

	/**
	 * Execute a shell command inside an isolated container.
	 * This is the practical way to use container isolation for command execution.
	 */
	async isolateCommand(
		command: string,
		args: string[],
		options?: {
			workingDir?: string;
			env?: Record<string, string>;
			input?: string;
			// Audit context
			verdict?: Verdict;
			threatId?: string;
		},
	): Promise<{
		success: boolean;
		exitCode: number;
		stdout: string;
		stderr: string;
		isolated: boolean;
		containerId?: string;
	}> {
		const runtimeAvailable = await this.isRuntimeAvailable();
		if (!runtimeAvailable) {
			this.logger.warn("Container runtime not available, refusing to run command", {
				runtime: this.config.runtime,
				command,
			});
			// Log the failure if auditor is available
			if (this.auditor && options?.verdict && options?.threatId) {
				await this.auditor.log({
					action: "contain",
					threatId: options.threatId,
					tool: command,
					input: args.join(" "),
					verdict: options.verdict,
					responseTaken: "contain",
					metadata: { containerId: undefined },
					outcome: "failure",
					error: "Container runtime not available",
				});
			}
			return {
				success: false,
				exitCode: -1,
				stdout: "",
				stderr: `Container runtime '${this.config.runtime}' not available`,
				isolated: false,
			};
		}

		const containerId = await this.createContainer();
		this.logger.debug("Created isolation container for command", { containerId, command });

		try {
			let result: ContainerResult;
			try {
				result = await this.runCommandInContainer(command, args, options, containerId);
			} catch (error) {
				await this.logCommandContainment(
					options,
					command,
					args,
					containerId,
					"failure",
					error instanceof Error ? error.message : String(error),
				);
				throw error;
			}
			const success = result.exitCode === 0;
			await this.logCommandContainment(
				options,
				command,
				args,
				containerId,
				success ? "success" : "failure",
				success ? undefined : result.stderr || `Command exited with code ${result.exitCode}`,
			);
			return {
				success,
				exitCode: result.exitCode,
				stdout: result.stdout,
				stderr: result.stderr,
				isolated: true,
				containerId,
			};
		} finally {
			await this.destroyContainer(containerId);
			this.logger.debug("Destroyed isolation container", { containerId });
		}
	}

	private async logCommandContainment(
		options: { verdict?: Verdict; threatId?: string } | undefined,
		command: string,
		args: string[],
		containerId: string,
		outcome: "success" | "failure",
		error?: string,
	): Promise<void> {
		if (!this.auditor || !options?.verdict || !options.threatId) return;
		await this.auditor.log({
			action: "contain",
			threatId: options.threatId,
			tool: command,
			input: args.join(" "),
			verdict: options.verdict,
			responseTaken: "contain",
			metadata: { containerId },
			outcome,
			error,
		});
	}

	private async isRuntimeAvailable(): Promise<boolean> {
		return new Promise((resolve) => {
			const proc = spawn(this.config.runtime, ["--version"], {
				stdio: ["ignore", "ignore", "ignore"],
				shell: false,
			});
			proc.on("exit", (code) => resolve(code === 0));
			proc.on("error", () => resolve(false));
			// Timeout after 5 seconds
			setTimeout(() => {
				try {
					proc.kill();
				} catch {
					// Ignore
				}
				resolve(false);
			}, 5000);
		});
	}

	private async createContainer(): Promise<string> {
		const containerId = `aidr-${randomBytes(8).toString("hex")}`;
		// A bridge network has unrestricted outbound access, so "restricted" fails
		// closed to no networking until a restricted-network adapter exists.
		const networkMode = this.config.networkMode === "restricted" ? "none" : this.config.networkMode;
		const args = [
			"create",
			"--name",
			containerId,
			"--rm",
			"--network",
			networkMode,
			"--read-only",
			...(this.config.cpuLimit ? ["--cpus", this.config.cpuLimit] : []),
			...(this.config.memoryLimit ? ["--memory", this.config.memoryLimit] : []),
			"--security-opt",
			"no-new-privileges:true",
			"--cap-drop",
			"ALL",
			...this.config.readonlyMounts.flatMap((mount) => {
				const resolved = resolvePath(mount);
				return ["-v", `${resolved}:${resolved}:ro`];
			}),
			this.config.baseImage,
			"sleep",
			(this.config.timeoutSeconds * 2).toString(),
		];

		return new Promise((resolve, reject) => {
			const proc = spawn(this.config.runtime, args, {
				stdio: ["ignore", "ignore", "pipe"],
				shell: false,
			});

			let stderr = "";
			proc.stderr?.on("data", (data) => {
				stderr += data.toString();
			});

			proc.on("exit", async (code) => {
				if (code === 0) {
					try {
						await this.startContainer(containerId);
						resolve(containerId);
					} catch (error) {
						await this.destroyContainer(containerId);
						reject(error);
					}
				} else {
					reject(new Error(`Failed to create container: ${stderr || `exit code ${code}`}`));
				}
			});

			proc.on("error", (err) => {
				reject(new Error(`Failed to spawn ${this.config.runtime}: ${err.message}`));
			});
		});
	}

	private async startContainer(containerId: string): Promise<void> {
		return new Promise((resolve, reject) => {
			const proc = spawn(this.config.runtime, ["start", containerId], {
				stdio: ["ignore", "ignore", "pipe"],
				shell: false,
			});

			let stderr = "";
			proc.stderr?.on("data", (data) => {
				stderr += data.toString();
			});

			proc.on("exit", (code) => {
				if (code === 0) resolve();
				else reject(new Error(`Failed to start container: ${stderr || `exit code ${code}`}`));
			});

			proc.on("error", (err) => {
				reject(new Error(`Failed to spawn ${this.config.runtime}: ${err.message}`));
			});
		});
	}

	private async runCommandInContainer(
		command: string,
		args: string[],
		options: { workingDir?: string; env?: Record<string, string>; input?: string } = {},
		containerId: string,
	): Promise<ContainerResult> {
		const execArgs = [
			"exec",
			"-i",
			...(options.workingDir ? ["-w", options.workingDir] : []),
			// Add environment variables
			...(options.env ? Object.entries(options.env).flatMap(([k, v]) => ["-e", `${k}=${v}`]) : []),
			containerId,
			command,
			...args,
		];

		return new Promise((resolve, reject) => {
			const proc = spawn(this.config.runtime, execArgs, {
				stdio: ["pipe", "pipe", "pipe"],
				shell: false,
			});

			let stdout = "";
			let stderr = "";

			proc.stdout?.on("data", (data) => {
				stdout += data.toString();
			});

			proc.stderr?.on("data", (data) => {
				stderr += data.toString();
			});

			// Handle input
			if (options.input) {
				proc.stdin?.write(options.input);
				proc.stdin?.end();
			}

			// Timeout handling
			const timeout = setTimeout(() => {
				proc.kill("SIGTERM");
				// Force kill after grace period
				setTimeout(() => proc.kill("SIGKILL"), 5000);
			}, this.config.timeoutSeconds * 1000);

			proc.on("exit", (code) => {
				clearTimeout(timeout);
				resolve({
					exitCode: code ?? -1,
					stdout,
					stderr,
				});
			});

			proc.on("error", (err) => {
				clearTimeout(timeout);
				reject(new Error(`Failed to execute in container: ${err.message}`));
			});
		});
	}

	private async destroyContainer(id: string): Promise<void> {
		return new Promise((resolve) => {
			const proc = spawn(this.config.runtime, ["rm", "-f", id], {
				stdio: ["ignore", "ignore", "ignore"],
				shell: false,
			});

			// Always resolve - destruction is best-effort
			proc.on("exit", () => resolve());
			proc.on("error", () => resolve());
			// Force resolve after 10 seconds
			setTimeout(resolve, 10000);
		});
	}
}

// Factory function for creating default configuration
export function createDefaultContainConfig(): ContainConfig {
	return {
		runtime: "docker",
		baseImage: "alpine:latest",
		networkMode: "none",
		readonlyMounts: [],
		timeoutSeconds: 60,
	};
}
