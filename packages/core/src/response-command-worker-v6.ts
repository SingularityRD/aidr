import {
	type FleetResponseActionAdapter,
	type FleetResponseCommand,
	FleetResponseCommandConsumer,
	type FleetResponseConsumerOptions,
	type FleetResponseCycleResult,
	type FleetResponseSignedDelivery,
} from "./response-command-consumer-v6.js";
import {
	type FleetJournalCurrent,
	type FleetJournalState,
	type FleetResponseControlHead,
	FleetResponseJournal,
	MAX_RECENT_FLEET_COMMANDS,
	rememberCommand,
	retainRecentCommands,
} from "./response-command-journal-v6.js";

export interface FleetResponseWorkerOptions extends FleetResponseConsumerOptions {
	adapter: FleetResponseActionAdapter;
	/** Absolute, host-private journal prefix. Two authenticated slots are used. */
	statePath: string;
	/** Canonical base64 random 32-byte MAC secret stored in the native secret vault. */
	stableJournalKey?: string;
	/** Service telemetry hook for every cycle, including uncertain outcomes. */
	onCycle?: (result: FleetResponseCycleResult, signal?: AbortSignal) => void | Promise<void>;
}

/**
 * A single-device worker with a persisted state machine. The native adapter is
 * mandatory; callers should launch exactly one worker per enrollment identity.
 */
export class FleetResponseCommandWorker extends FleetResponseCommandConsumer {
	private readonly journal: FleetResponseJournal;
	private readonly actionAdapter: FleetResponseActionAdapter;
	private readonly onCycle?: (
		result: FleetResponseCycleResult,
		signal?: AbortSignal,
	) => void | Promise<void>;

	constructor(options: FleetResponseWorkerOptions) {
		super(options);
		this.journal = new FleetResponseJournal(
			options.statePath,
			options.identity,
			options.apiKey,
			options.installationId,
			options.stableJournalKey,
			options.now,
		);
		this.actionAdapter = options.adapter;
		this.onCycle = options.onCycle;
	}

	private async saveCurrent(
		state: FleetJournalState,
		command: FleetResponseCommand,
		phase: FleetJournalCurrent["phase"],
		resultCode: string | null = null,
		delivery: FleetResponseSignedDelivery | undefined = state.current?.delivery,
	): Promise<FleetJournalState> {
		if (!delivery) throw new Error("missing_fleet_command_delivery");
		let control: FleetResponseControlHead = state.response_control;
		if (phase === "result_pending" && resultCode === null) {
			if (command.commandType === "agent_pause")
				control = { status: "paused", pause_delivery: delivery, resume_delivery: null };
			if (command.commandType === "agent_resume") {
				if (this.controlError(state, command, delivery))
					throw new Error("fleet_response_rollback_state_mismatch");
				control = {
					status: "running",
					pause_delivery: state.response_control.pause_delivery,
					resume_delivery: delivery,
				};
			}
		}
		return this.journal.save({
			...state,
			response_control: control,
			current: { command, delivery, phase, resultCode },
		});
	}

	private controlError(
		state: FleetJournalState,
		command: FleetResponseCommand,
		delivery = state.current?.delivery,
	): string | null {
		if (command.commandType !== "agent_resume") return null;
		const pause = state.response_control.pause_delivery;
		return state.response_control.status === "paused" &&
			pause?.payload.id === command.rollbackOf &&
			Date.parse(String(delivery?.payload.created_at)) >=
				Date.parse(String(pause.payload.created_at))
			? null
			: "rollback_state_mismatch";
	}

	private async finish(state: FleetJournalState, commandId: string): Promise<void> {
		await this.journal.save(rememberCommand(state, commandId, this.now()));
	}

	private async resumeRejection(state: FleetJournalState): Promise<FleetResponseCycleResult> {
		const commandId = state.current?.command.id;
		if (!commandId)
			return { status: "outcome_unknown", stage: "ack", reason: "journal_missing_command" };
		const result = await this.rejectUnsupported(commandId);
		if (result.status === "rejected") await this.finish(state, commandId);
		return result;
	}

	private async resumeResult(state: FleetJournalState): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "result", reason: "journal_missing_command" };
		const result = await this.report(current.command.id, current.resultCode);
		if (result.status === "succeeded" || result.status === "failed") {
			await this.finish(state, current.command.id);
		}
		return result;
	}

	private async recoverExecutionIntent(
		state: FleetJournalState,
		signal?: AbortSignal,
	): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "result", reason: "journal_missing_command" };
		let observed = false;
		try {
			const verification = await this.runBoundedAction(
				(actionSignal) =>
					this.actionAdapter.verify(current.command, actionSignal, current.delivery),
				signal,
			);
			observed = verification.observed;
		} catch {
			// Timeout, cancellation, or an adapter exception cannot justify replaying an action.
		}
		if (!observed) {
			return {
				status: "outcome_unknown",
				commandId: current.command.id,
				stage: "result",
				reason: "execution_state_unverified",
			};
		}
		const pending = await this.saveCurrent(state, current.command, "result_pending");
		return this.resumeResult(pending);
	}

	private async startExecution(
		state: FleetJournalState,
		signal?: AbortSignal,
	): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "result", reason: "journal_missing_command" };
		const intent = await this.saveCurrent(state, current.command, "execute_intent");
		let code: string | null;
		try {
			code = await this.executeAndVerify(
				intent.current?.command ?? current.command,
				this.actionAdapter,
				intent.current?.delivery ?? current.delivery,
				signal,
			);
		} catch (error) {
			if (!this.isActionInterrupted(error)) throw error;
			return {
				status: "outcome_unknown",
				commandId: current.command.id,
				stage: "result",
				reason: "execution_state_unverified",
			};
		}
		const pending = await this.saveCurrent(intent, current.command, "result_pending", code);
		return this.resumeResult(pending);
	}

	private async resumeAcknowledged(
		state: FleetJournalState,
		signal?: AbortSignal,
	): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "ack", reason: "journal_missing_command" };
		const controlError = this.controlError(state, current.command);
		if (controlError) {
			const pending = await this.saveCurrent(
				state,
				current.command,
				"result_pending",
				controlError,
			);
			return this.resumeResult(pending);
		}
		// A service upgrade may remove an action from the installed adapter while
		// an acknowledged command is waiting in the journal. Never apply it then.
		if (!this.commandSupported(current.command, this.actionAdapter)) {
			const pending = await this.saveCurrent(
				state,
				current.command,
				"result_pending",
				"unsupported_action",
			);
			return this.resumeResult(pending);
		}
		if (Date.parse(current.command.expiresAt) <= this.now()) {
			const pending = await this.saveCurrent(
				state,
				current.command,
				"result_pending",
				"ttl_elapsed",
			);
			return this.resumeResult(pending);
		}
		return this.startExecution(state, signal);
	}

	private async resumePolled(
		state: FleetJournalState,
		signal?: AbortSignal,
	): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "ack", reason: "journal_missing_command" };
		if (Date.parse(current.command.expiresAt) <= this.now()) {
			await this.finish(state, current.command.id);
			return { status: "expired", commandId: current.command.id };
		}
		const controlError = this.controlError(state, current.command);
		if (controlError) {
			const result = await this.rejectUnsupported(current.command.id, controlError);
			if (result.status === "rejected") await this.finish(state, current.command.id);
			return result;
		}
		if (!this.commandSupported(current.command, this.actionAdapter)) {
			const rejecting = await this.saveCurrent(state, current.command, "reject_intent");
			return this.resumeRejection(rejecting);
		}
		if (!(await this.acknowledge(current.command.id))) {
			if (this.hasAccessRejection()) {
				return {
					status: "access_rejected",
					stage: "ack",
					code: this.accessRejectionCode(),
				};
			}
			return {
				status: "outcome_unknown",
				commandId: current.command.id,
				stage: "ack",
				reason: "ack_unconfirmed",
			};
		}
		const acknowledged = await this.saveCurrent(state, current.command, "acknowledged");
		return this.resumeAcknowledged(acknowledged, signal);
	}

	private async resume(
		state: FleetJournalState,
		signal?: AbortSignal,
	): Promise<FleetResponseCycleResult> {
		const phase = state.current?.phase;
		if (state.current && (phase === "polled" || phase === "acknowledged")) {
			const error = this.deliveryError(state.current.command, state.current.delivery);
			if (error) return { status: "invalid_command", reason: error };
		}
		if (phase === "polled") return this.resumePolled(state, signal);
		if (phase === "reject_intent") return this.resumeRejection(state);
		if (phase === "acknowledged") return this.resumeAcknowledged(state, signal);
		if (phase === "execute_intent") return this.recoverExecutionIntent(state, signal);
		if (phase === "result_pending") return this.resumeResult(state);
		return { status: "outcome_unknown", stage: "poll", reason: "invalid_journal_phase" };
	}

	private async tickLocked(signal?: AbortSignal): Promise<FleetResponseCycleResult> {
		let state = await this.journal.load();
		if (state.current) return this.resume(state, signal);
		state = retainRecentCommands(state, this.now());
		if (state.recent_ids.length >= MAX_RECENT_FLEET_COMMANDS)
			return { status: "outcome_unknown", stage: "poll", reason: "command_replay_cache_full" };
		const polled = await this.pollCommand();
		if ("status" in polled && polled.status !== "idle") return polled;
		if (!("status" in polled) && state.recent_ids.includes(polled.command.id)) {
			return {
				status: "outcome_unknown",
				commandId: polled.command.id,
				stage: "poll",
				reason: "replayed_command_id",
			};
		}
		const checkpointAt = this.now();
		if (
			state.last_successful_poll_at !== null &&
			checkpointAt < Date.parse(state.last_successful_poll_at)
		)
			throw new Error("fleet_journal_clock_moved_backwards");
		state = { ...state, last_successful_poll_at: new Date(checkpointAt).toISOString() };
		if ("status" in polled) {
			await this.journal.save(state);
			return polled;
		}
		state = await this.saveCurrent(state, polled.command, "polled", null, polled.delivery);
		return this.resume(state, signal);
	}

	/** One bounded cycle. Journal/lock failure leaves actions untouched. */
	async tick(signal?: AbortSignal): Promise<FleetResponseCycleResult> {
		let result: FleetResponseCycleResult;
		try {
			result = await this.journal.withLock(() => this.tickLocked(signal));
		} catch {
			result = { status: "outcome_unknown", stage: "poll", reason: "journal_unavailable" };
		}
		await this.emitAudit(result);
		return result;
	}

	/** Poll at a bounded cadence until the service supervisor aborts the worker. */
	async run(signal: AbortSignal, intervalMs = 5000): Promise<void> {
		const delay = Math.min(60_000, Math.max(5000, intervalMs));
		while (!signal.aborted) {
			const result = await this.tick(signal);
			if (this.onCycle) {
				try {
					await this.runBoundedAction(
						(cycleSignal) => Promise.resolve(this.onCycle?.(result, cycleSignal)),
						signal,
					);
				} catch {
					if (signal.aborted) return;
					throw new Error("fleet_response_worker_cycle_hook_failed");
				}
			}
			if (this.hasAccessRejection()) {
				throw new Error("fleet_response_worker_access_rejected");
			}
			if (result.status === "outcome_unknown" && result.reason === "journal_unavailable") {
				throw new Error("fleet_response_worker_journal_unavailable");
			}
			if (signal.aborted) break;
			await new Promise<void>((resolve) => {
				const timeout = setTimeout(finish, delay);
				function finish() {
					clearTimeout(timeout);
					signal.removeEventListener("abort", finish);
					resolve();
				}
				signal.addEventListener("abort", finish, { once: true });
			});
		}
	}
}
