import {
	type FleetResponseActionAdapter,
	type FleetResponseCommand,
	FleetResponseCommandConsumer,
	type FleetResponseConsumerOptions,
	type FleetResponseCycleResult,
} from "./response-command-consumer-v6.js";
import {
	type FleetJournalCurrent,
	type FleetJournalState,
	FleetResponseJournal,
	rememberCommand,
} from "./response-command-journal-v6.js";

export interface FleetResponseWorkerOptions extends FleetResponseConsumerOptions {
	adapter: FleetResponseActionAdapter;
	/** Absolute, host-private journal prefix. Two authenticated slots are used. */
	statePath: string;
	/** Service telemetry hook for every cycle, including uncertain outcomes. */
	onCycle?: (result: FleetResponseCycleResult) => void | Promise<void>;
}

/**
 * A single-device worker with a persisted state machine. The native adapter is
 * mandatory; callers should launch exactly one worker per enrollment identity.
 */
export class FleetResponseCommandWorker extends FleetResponseCommandConsumer {
	private readonly journal: FleetResponseJournal;
	private readonly actionAdapter: FleetResponseActionAdapter;
	private readonly onCycle?: (result: FleetResponseCycleResult) => void | Promise<void>;

	constructor(options: FleetResponseWorkerOptions) {
		super(options);
		this.journal = new FleetResponseJournal(
			options.statePath,
			options.identity,
			options.apiKey,
			options.installationId,
		);
		this.actionAdapter = options.adapter;
		this.onCycle = options.onCycle;
	}

	private async saveCurrent(
		state: FleetJournalState,
		command: FleetResponseCommand,
		phase: FleetJournalCurrent["phase"],
		resultCode: string | null = null,
	): Promise<FleetJournalState> {
		return this.journal.save({ ...state, current: { command, phase, resultCode } });
	}

	private async finish(state: FleetJournalState, commandId: string): Promise<void> {
		await this.journal.save(rememberCommand(state, commandId));
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
	): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "result", reason: "journal_missing_command" };
		let observed = false;
		try {
			const verification = await this.actionAdapter.verify(current.command);
			observed = verification.observed;
		} catch {
			// An adapter exception cannot justify a repeat of a possibly applied action.
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

	private async startExecution(state: FleetJournalState): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "result", reason: "journal_missing_command" };
		const intent = await this.saveCurrent(state, current.command, "execute_intent");
		const code = await this.executeAndVerify(
			intent.current?.command ?? current.command,
			this.actionAdapter,
		);
		const pending = await this.saveCurrent(intent, current.command, "result_pending", code);
		return this.resumeResult(pending);
	}

	private async resumeAcknowledged(state: FleetJournalState): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "ack", reason: "journal_missing_command" };
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
		return this.startExecution(state);
	}

	private async resumePolled(state: FleetJournalState): Promise<FleetResponseCycleResult> {
		const current = state.current;
		if (!current)
			return { status: "outcome_unknown", stage: "ack", reason: "journal_missing_command" };
		if (!this.commandSupported(current.command, this.actionAdapter)) {
			const rejecting = await this.saveCurrent(state, current.command, "reject_intent");
			return this.resumeRejection(rejecting);
		}
		if (!(await this.acknowledge(current.command.id))) {
			return {
				status: "outcome_unknown",
				commandId: current.command.id,
				stage: "ack",
				reason: "ack_unconfirmed",
			};
		}
		const acknowledged = await this.saveCurrent(state, current.command, "acknowledged");
		return this.resumeAcknowledged(acknowledged);
	}

	private async resume(state: FleetJournalState): Promise<FleetResponseCycleResult> {
		const phase = state.current?.phase;
		if (phase === "polled") return this.resumePolled(state);
		if (phase === "reject_intent") return this.resumeRejection(state);
		if (phase === "acknowledged") return this.resumeAcknowledged(state);
		if (phase === "execute_intent") return this.recoverExecutionIntent(state);
		if (phase === "result_pending") return this.resumeResult(state);
		return { status: "outcome_unknown", stage: "poll", reason: "invalid_journal_phase" };
	}

	private async tickLocked(): Promise<FleetResponseCycleResult> {
		let state = await this.journal.load();
		if (state.current) return this.resume(state);
		const polled = await this.pollCommand();
		if ("status" in polled) return polled;
		if (state.recent_ids.includes(polled.id)) {
			return {
				status: "outcome_unknown",
				commandId: polled.id,
				stage: "poll",
				reason: "replayed_command_id",
			};
		}
		state = await this.saveCurrent(state, polled, "polled");
		return this.resume(state);
	}

	/** One bounded cycle. Journal/lock failure leaves actions untouched. */
	async tick(): Promise<FleetResponseCycleResult> {
		let result: FleetResponseCycleResult;
		try {
			result = await this.journal.withLock(() => this.tickLocked());
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
			const result = await this.tick();
			await this.onCycle?.(result);
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
