import type { ConnectorState, ConnectorStatus } from "../utils/connector-status.js";

/**
 * The wire shapes between the Setup Assistant's server and its page. The
 * browser code (src/assistant/ui/app.ts) imports these types only.
 */

export type HostId = ConnectorStatus["id"];
export type Locale = "en" | "tr";

export interface DetectedTool {
	id: HostId;
	label: string;
	state: ConnectorState;
	/** Cursor and VS Code have no real-host acceptance evidence yet. */
	preview: boolean;
}

export interface PendingEnrollmentView {
	endpoint: string;
	/** The installer also left a one-time enrollment token. */
	hasToken: boolean;
}

export interface BrowserGuardView {
	chrome: string | null;
	edge: string | null;
	firefox: string | null;
	/** The dashboard's Download page, where the store links always are. */
	downloads: string;
}

export interface AssistantState {
	version: string;
	/** The CLI locale; the page carries both catalogs and lets the person switch. */
	locale: Locale;
	/** Company address already in use (managed mode), if any. */
	company: { endpoint: string; enrolled: boolean } | null;
	/** Left by the Windows installer's wizard; null when absent or rejected. */
	pending: PendingEnrollmentView | null;
	/** A pending file was found but was not safe to use. */
	pendingIgnored: boolean;
	browserGuard: BrowserGuardView;
	dashboard: string;
}

/** How a host ended up after setup, in the words the wizard shows. */
export type HostOutcome = "protected" | "restart" | "manual" | "failed" | "not_selected";

export interface HostSetupResult {
	id: HostId;
	label: string;
	outcome: HostOutcome;
	/** connector-install's one-sentence detail (English, technical). */
	detail: string;
	/** Exact commands / steps for `manual` (and follow-ups for other outcomes). */
	steps: string[];
}

export type SetupEvent =
	| { type: "rules"; rules: number }
	| { type: "host-start"; id: HostId; label: string }
	| { type: "host-done"; result: HostSetupResult };

export interface SetupSummary {
	ok: boolean;
	/** A message key when setup stopped before the hosts (rules, release key). */
	failure?: { key: "protect.setupFailed" | "protect.releaseKey"; detail: string };
	rules: number;
	hosts: HostSetupResult[];
}

interface HostVerifyView {
	id: HostId;
	label: string;
	outcome: "pass" | "fail" | "skip" | "not_registered";
	detail: string;
}

export interface VerifyReport {
	hosts: HostVerifyView[];
}

export interface StatusReport {
	detection: { ok: boolean; rules: number };
	protected: string[];
	restart: string[];
	manual: { label: string; command: string }[];
}

type EnrollPhase = "idle" | "waiting" | "enrolled" | "expired" | "denied" | "error" | "repair";

export interface EnrollView {
	phase: EnrollPhase;
	endpoint?: string;
	userCode?: string;
	verificationUrl?: string;
	expiresAt?: string;
	/** Seconds the page waits between polls. */
	interval?: number;
	/** Message key for the error / denied / repair phases. */
	message?: string;
	/** Machine-readable reason (shown as `{code}`). */
	code?: string;
}

export interface EnrollStartInput {
	endpoint: string;
	/** Exchange the installer's one-time token instead of starting a device code. */
	useInstallerToken: boolean;
}

/**
 * Every operation the assistant exposes. Nothing here removes AIDR, approves an
 * action, takes `--force`/`--release-key` or edits configuration beyond what
 * plain `aidr setup` and device-code enrollment write.
 */
export interface AssistantOps {
	state(): Promise<AssistantState>;
	detect(): Promise<DetectedTool[]>;
	setup(hosts: string[], progress: (event: SetupEvent) => void): Promise<SetupSummary>;
	verify(): Promise<VerifyReport>;
	status(): Promise<StatusReport>;
	enrollStart(input: EnrollStartInput): Promise<EnrollView>;
	enrollPoll(): Promise<EnrollView>;
	enrollCancel(): Promise<EnrollView>;
}
