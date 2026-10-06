import { spawn } from "node:child_process";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import type {
	FleetResponseActionAdapter,
	FleetResponseCommand,
	FleetResponseCommandType,
	FleetResponseIdentity,
	FleetResponseSignedDelivery,
} from "./response-command-consumer-v6.js";
import {
	FleetResponseActionInterrupted,
	verifyFleetResponseCommandDelivery,
} from "./response-command-consumer-v6.js";

const RESULT_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_OUTPUT_BYTES = 16_384;
const ACTION_TIMEOUT_MS = 35_000;
const COMMANDS: readonly FleetResponseCommandType[] = [
	"agent_pause",
	"agent_resume",
	"network_isolate",
	"network_release",
];

export interface WindowsResponseAdapterOptions {
	identity: FleetResponseIdentity;
	installationId: string;
	keyHash: string;
	trustedCommandKeys: Readonly<Record<string, string>>;
	/** Only the authenticated persisted execute intent may be observed after rotation. */
	recoveryDelivery?: FleetResponseSignedDelivery;
	stateRoot: string;
	/** Fixed file from the verified Claude dist/native directory. */
	adapterPath: string;
	recoveryAddresses: readonly string[];
}

function record(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeCode(value: unknown, fallback: string): string {
	return typeof value === "string" && RESULT_CODE.test(value) ? value : fallback;
}

/** The process protocol contains signed evidence and public identity, never the bearer. */
export class WindowsResponseActionAdapter implements FleetResponseActionAdapter {
	readonly identity: FleetResponseIdentity;
	readonly supportedCommands = COMMANDS;
	private readonly options: WindowsResponseAdapterOptions;

	constructor(options: WindowsResponseAdapterOptions) {
		if (process.platform !== "win32") throw new Error("windows_response_unsupported_platform");
		if (
			!isAbsolute(options.adapterPath) ||
			!isAbsolute(options.stateRoot) ||
			basename(options.adapterPath) !== "Invoke-AidrResponseAction.ps1" ||
			basename(dirname(options.adapterPath)) !== "native"
		) {
			throw new Error("windows_response_invalid_adapter_path");
		}
		this.identity = { ...options.identity };
		this.options = {
			...options,
			adapterPath: resolve(options.adapterPath),
			stateRoot: resolve(options.stateRoot),
		};
	}

	private async invoke(
		operation: "execute" | "verify" | "dry_run" | "inspect_removal",
		command: FleetResponseCommand | null,
		signal?: AbortSignal,
		delivery?: FleetResponseSignedDelivery,
	): Promise<Record<string, unknown>> {
		if (signal?.aborted)
			throw new FleetResponseActionInterrupted("windows_response_action_interrupted");
		if (operation !== "inspect_removal" && !delivery) return { code: "missing_signed_delivery" };
		if (delivery && command && !this.validDelivery(command, delivery, operation === "verify"))
			return { code: "invalid_signed_delivery" };
		const input = JSON.stringify({
			schema_version: 1,
			operation,
			identity: {
				tenant_id: this.identity.tenantId,
				agent_id: this.identity.agentId,
				installation_id: this.options.installationId,
			},
			command: command
				? {
						id: command.id,
						command_type: command.commandType,
						expires_at: command.expiresAt,
						attempt: command.attempt,
						rollback_of: command.rollbackOf,
					}
				: null,
			delivery: delivery ?? null,
			state_root: this.options.stateRoot,
			recovery_addresses:
				operation === "inspect_removal" ? [] : [...this.options.recoveryAddresses],
		});
		if (Buffer.byteLength(input) > MAX_OUTPUT_BYTES)
			return { code: "native_action_input_too_large" };
		return new Promise((resolveResult, reject) => {
			let completed = false;
			let bytes = 0;
			const output: Buffer[] = [];
			const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
			const child = spawn(
				join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
				["-NoLogo", "-NoProfile", "-NonInteractive", "-File", this.options.adapterPath],
				{
					stdio: ["pipe", "pipe", "pipe"],
					windowsHide: true,
					shell: false,
					env: {
						...process.env,
						PSModulePath: join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "Modules"),
					},
				},
			);
			const finish = (value: Record<string, unknown>, interrupted = false) => {
				if (completed) return;
				completed = true;
				clearTimeout(timeout);
				signal?.removeEventListener("abort", abort);
				if (interrupted)
					reject(new FleetResponseActionInterrupted("windows_response_action_interrupted"));
				else resolveResult(value);
			};
			const stop = (code: string, interrupted = false) => {
				try {
					child.kill();
				} finally {
					finish({ code }, interrupted);
				}
			};
			const abort = () => stop("native_action_interrupted", true);
			const timeout = setTimeout(() => stop("native_action_timeout", true), ACTION_TIMEOUT_MS);
			signal?.addEventListener("abort", abort, { once: true });
			child.on("error", () => finish({ code: "native_action_unavailable" }));
			child.stdin.on("error", () => stop("native_action_input_failed", true));
			child.stdout.on("data", (data: Buffer) => {
				bytes += data.length;
				if (bytes > MAX_OUTPUT_BYTES) stop("native_action_output_too_large", true);
				else output.push(data);
			});
			// Never echo stderr: host exception text can contain credentials or private paths.
			child.stderr.on("data", (data: Buffer) => {
				bytes += data.length;
				if (bytes > MAX_OUTPUT_BYTES) stop("native_action_output_too_large", true);
			});
			child.on("close", (code) => {
				if (completed) return;
				try {
					const result: unknown = JSON.parse(
						Buffer.concat(output)
							.toString("utf8")
							.replace(/^\uFEFF/, "")
							.trim(),
					);
					if (code !== 0 || !record(result))
						return finish({ code: "native_action_outcome_unknown" });
					finish(result);
				} catch {
					finish({ code: "native_action_outcome_unknown" });
				}
			});
			child.stdin.end(input);
		});
	}

	private validDelivery(
		command: FleetResponseCommand,
		delivery: FleetResponseSignedDelivery,
		verification: boolean,
	): boolean {
		if (!record(delivery) || !record(delivery.payload)) return false;
		const recovery = this.options.recoveryDelivery;
		const historical =
			verification &&
			recovery &&
			delivery.sig_b64 === recovery.sig_b64 &&
			delivery.key_id === recovery.key_id &&
			JSON.stringify(delivery.payload) === JSON.stringify(recovery.payload);
		const verified = verifyFleetResponseCommandDelivery(delivery, {
			identity: this.identity,
			attestation: {
				schemaVersion: 1,
				installationId: this.options.installationId,
				keyHash: historical ? (delivery.payload.key_hash as string) : this.options.keyHash,
			},
			trustedCommandKeys: this.options.trustedCommandKeys,
			now: Date.now(),
			allowExpired: verification,
		});
		if ("status" in verified) return false;
		const actual = verified.command;
		return (
			actual.id === command.id &&
			actual.commandType === command.commandType &&
			actual.expiresAt === command.expiresAt &&
			actual.attempt === command.attempt &&
			actual.rollbackOf === command.rollbackOf
		);
	}

	async execute(
		command: FleetResponseCommand,
		signal?: AbortSignal,
		delivery?: FleetResponseSignedDelivery,
	): Promise<{ ok: true } | { ok: false; code: string }> {
		const result = await this.invoke("execute", command, signal, delivery);
		return result.ok === true
			? { ok: true }
			: { ok: false, code: safeCode(result.code, "execution_failed") };
	}

	async verify(
		command: FleetResponseCommand,
		signal?: AbortSignal,
		delivery?: FleetResponseSignedDelivery,
	): Promise<{ observed: true } | { observed: false; code: string }> {
		const result = await this.invoke("verify", command, signal, delivery);
		// Execute may already have changed the host. A failed observation cannot
		// prove rollback or justify clearing the durable execution intent.
		return result.observed === true
			? { observed: true }
			: { observed: false, code: "native_action_outcome_unknown" };
	}

	/** Plan only an authenticated command; this operation never applies it. */
	async dryRun(
		command: FleetResponseCommand,
		delivery: FleetResponseSignedDelivery,
		signal?: AbortSignal,
	): Promise<{ ok: true } | { ok: false; code: string }> {
		const result = await this.invoke("dry_run", command, signal, delivery);
		return result.ok === true
			? { ok: true }
			: { ok: false, code: safeCode(result.code, "native_validation_failed") };
	}

	/** Observe only; never deletes state, repairs rules or resumes an agent. */
	async inspectRemoval(
		signal?: AbortSignal,
	): Promise<{ removable: true } | { removable: false; code: string }> {
		const result = await this.invoke("inspect_removal", null, signal);
		const evidence = result.evidence;
		return result.ok === true &&
			result.observed === true &&
			result.removable === true &&
			record(evidence) &&
			evidence.tenant_id === this.identity.tenantId &&
			evidence.agent_id === this.identity.agentId &&
			evidence.installation_id === this.options.installationId &&
			evidence.owned_rule_count === 0 &&
			evidence.state === "native_inactive"
			? { removable: true }
			: { removable: false, code: safeCode(result.code, "native_removal_not_verified") };
	}
}
