import {
	currentLocale,
	DEFAULT_CONTROL_PLANE_ENDPOINT,
	isCommercialBuild,
	resolvePath,
	VERSION,
} from "@singularityrd/aidr-core";
import { applyReleaseKey, configReleaseKeys, type SetupReleaseKey } from "../commands/setup.js";
import { statusVerdictFor } from "../commands/status.js";
import { verifyHosts } from "../commands/verify.js";
import { type Config, createConfig, getConfig, updateConfig } from "../utils/config-manager.js";
import {
	HOST_IDS,
	type HostCommandRunner,
	type HostInstallResult,
	installConnectors,
} from "../utils/connector-install.js";
import { detectConnectorStatuses } from "../utils/connector-status.js";
import { verifiedCustomerPacket } from "../utils/customer-packet.js";
import { detectEnvironment } from "../utils/detect-env.js";
import { recordHooksInstalled } from "../utils/install-hooks.js";
import { installerReleaseKey } from "../utils/release-key.js";
import { writeSetupLedger } from "../utils/setup-ledger.js";
import { type runHookCommand, standaloneBundleRoot } from "../utils/standalone.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";
import { createEnrollment, type EnrollmentDeps } from "./enrollment.js";
import type {
	AssistantOps,
	BrowserGuardView,
	DetectedTool,
	HostId,
	HostOutcome,
	HostSetupResult,
	SetupEvent,
	SetupSummary,
} from "./types.js";

/**
 * The real operations behind the Setup Assistant's API. Each one is the code a
 * command already runs: detection is `aidr status`'s measurement, setup is
 * plain `aidr setup --host <selected>` (the installer's release key only, no
 * `--force`, no artifacts), verification is `aidr verify`, and the company
 * connection is the device-code enrollment session start implements.
 */

export interface LocalOpsDeps {
	home?: string;
	env?: NodeJS.ProcessEnv;
	/** Host CLI runner (tests). */
	run?: HostCommandRunner;
	/** Hook runner for verify (tests). */
	verifyRun?: typeof runHookCommand;
	/** Standalone bundle root (tests); default: the SEA this process runs from. */
	standaloneRoot?: string | null;
	commercial?: boolean;
	/** Enrollment overrides (tests): control-plane client, clock, exchange. */
	enrollment?: Partial<Omit<EnrollmentDeps, "home">>;
}

const PREVIEW_HOSTS = new Set<HostId>(["cursor", "vscode"]);

/** Store links come from the same build variables the dashboard's Download page reads. */
const BROWSER_GUARD_ENV = {
	chrome: "VITE_BROWSER_GUARD_CHROME_URL",
	edge: "VITE_BROWSER_GUARD_EDGE_URL",
	firefox: "VITE_BROWSER_GUARD_FIREFOX_URL",
} as const;

/** An https URL without credentials, else null (the page then hides the link). */
export function safeHttpsUrl(value: unknown): string | null {
	if (typeof value !== "string" || value.trim() === "") return null;
	try {
		const url = new URL(value.trim());
		return url.protocol === "https:" && !url.username && !url.password ? url.toString() : null;
	} catch {
		return null;
	}
}

/**
 * The dashboard origin for a company address. A Supabase Functions base serves
 * the API only, so it falls back to the hosted dashboard.
 */
export function dashboardFor(endpoint: string | undefined): string {
	const fallback = DEFAULT_CONTROL_PLANE_ENDPOINT;
	const url = safeHttpsUrl(endpoint);
	if (!url) return fallback;
	const parsed = new URL(url);
	if (parsed.hostname.endsWith(".supabase.co") || parsed.pathname.includes("/functions/")) {
		return fallback;
	}
	return parsed.origin;
}

export function browserGuardLinks(env: NodeJS.ProcessEnv, dashboard: string): BrowserGuardView {
	return {
		chrome: safeHttpsUrl(env[BROWSER_GUARD_ENV.chrome]),
		edge: safeHttpsUrl(env[BROWSER_GUARD_ENV.edge]),
		firefox: safeHttpsUrl(env[BROWSER_GUARD_ENV.firefox]),
		downloads: `${dashboard}/downloads`,
	};
}

/** connector-install's follow-up lines without their column indent. */
function steps(lines: string[]): string[] {
	const indent = Math.min(...lines.map((line) => line.match(/^ */u)?.[0].length ?? 0));
	return lines.map((line) => line.slice(Number.isFinite(indent) ? indent : 0).trimEnd());
}

/** What the wizard tells the person about one host after setup. */
export function hostOutcome(entry: HostInstallResult): HostOutcome {
	if (entry.action === "failed") return "failed";
	if (entry.action === "manual") return "manual";
	if (entry.state !== "installed") return entry.followUp.length > 0 ? "manual" : "failed";
	// A running host loads hooks at start: a new registration needs a restart.
	if (entry.action === "installed" || entry.action === "updated") return "restart";
	return "protected";
}

function parseSelection(hosts: string[]): HostId[] {
	const known = new Set<string>(HOST_IDS);
	const unknown = hosts.filter((host) => !known.has(host));
	if (unknown.length > 0 || hosts.length === 0) {
		throw new Error(`Unknown host ${unknown.join(", ") || "(none)"}`);
	}
	return HOST_IDS.filter((host) => hosts.includes(host));
}

export function createLocalOps(deps: LocalOpsDeps = {}): AssistantOps {
	const home = deps.home ?? resolvePath("~");
	const hostEnv = deps.env ?? process.env;

	/** Record managed mode and the company address, the keys a managed install reads. */
	async function persistCompany(endpoint: string): Promise<void> {
		if (!getConfig()) await createConfig(await detectEnvironment(home, hostEnv), false);
		const current = getConfig() as (Config & { control_plane?: Record<string, unknown> }) | null;
		updateConfig({
			mode: "managed",
			control_plane: { ...(current?.control_plane ?? {}), enabled: true, endpoint },
		} as Partial<Config>);
	}

	const enrollment = createEnrollment({
		home,
		persist: persistCompany,
		customerPacket: () =>
			verifiedCustomerPacket(
				deps.standaloneRoot === undefined ? standaloneBundleRoot() : deps.standaloneRoot,
			),
		...deps.enrollment,
	});

	async function setup(
		hosts: string[],
		progress: (event: SetupEvent) => void,
	): Promise<SetupSummary> {
		const selected = parseSelection(hosts);
		const standaloneRoot =
			deps.standaloneRoot === undefined ? standaloneBundleRoot() : deps.standaloneRoot;
		let releaseKey: SetupReleaseKey | null = null;
		try {
			const installed = standaloneRoot ? installerReleaseKey(standaloneRoot) : null;
			releaseKey = installed ? { key: installed.key, source: installed.path } : null;
		} catch (error) {
			return {
				ok: false,
				rules: 0,
				hosts: [],
				failure: { key: "protect.releaseKey", detail: (error as Error).message },
			};
		}

		const env = await detectEnvironment(home, hostEnv);
		await createConfig(env, false);
		const requireSignedBundle = deps.commercial ?? isCommercialBuild();
		const releaseKeys = applyReleaseKey(
			releaseKey,
			configReleaseKeys,
			{},
			requireSignedBundle && standaloneRoot !== null,
		);

		const rules = await loadBundledThreatCount();
		const detection = await verifyDetection();
		if (rules <= 0 || !detection.ok) {
			return {
				ok: false,
				rules,
				hosts: [],
				failure: {
					key: "protect.setupFailed",
					detail: detection.ok ? "no protection rules were found" : detection.reason,
				},
			};
		}
		progress({ type: "rules", rules });

		const results: HostSetupResult[] = [];
		const raw: HostInstallResult[] = [];
		for (const host of selected) {
			const label =
				detectConnectorStatuses(home, hostEnv).find((status) => status.id === host)?.label ?? host;
			progress({ type: "host-start", id: host, label });
			// Let the page's progress poll through between hosts.
			await new Promise((resolve) => setImmediate(resolve));
			const entry = installConnectors(
				{
					home,
					env: hostEnv,
					run: deps.run,
					version: VERSION,
					...(standaloneRoot ? { standaloneRoot, releaseKeys, requireSignedBundle } : {}),
				},
				{ hosts: [host] },
			).find((candidate) => candidate.host === host);
			if (!entry) continue;
			raw.push(entry);
			const result: HostSetupResult = {
				id: host,
				label: entry.label,
				outcome: hostOutcome(entry),
				detail: entry.detail,
				steps: steps(entry.followUp),
			};
			results.push(result);
			progress({ type: "host-done", result });
		}

		try {
			recordHooksInstalled(raw.some((entry) => entry.state === "installed"));
		} catch {
			// The measured connector state is what the page shows either way.
		}
		const registered = raw
			.filter((entry) => entry.action === "installed" || entry.action === "updated")
			.map((entry) => entry.host);
		try {
			if (registered.length > 0) writeSetupLedger(home, registered);
		} catch {
			// Only the restart hint in `aidr status` depends on it.
		}
		return {
			ok: results.every((entry) => entry.outcome === "protected" || entry.outcome === "restart"),
			rules,
			hosts: results,
		};
	}

	return {
		async state() {
			const company = await enrollment.current();
			const { pending, ignored } = await enrollment.pending();
			const dashboard = dashboardFor(company?.endpoint ?? pending?.endpoint);
			return {
				version: VERSION,
				locale: currentLocale() === "tr" ? "tr" : "en",
				company,
				pending: pending ? { endpoint: pending.endpoint, hasToken: pending.hasToken } : null,
				pendingIgnored: ignored,
				browserGuard: browserGuardLinks(hostEnv, dashboard),
				dashboard,
			};
		},
		async detect(): Promise<DetectedTool[]> {
			return detectConnectorStatuses(home, hostEnv).map((status) => ({
				id: status.id,
				label: status.label,
				state: status.state,
				preview: PREVIEW_HOSTS.has(status.id),
			}));
		},
		setup,
		async verify() {
			return {
				hosts: verifyHosts({ home, env: hostEnv, run: deps.verifyRun }).map((entry) => ({
					id: entry.host,
					label: entry.label,
					outcome: entry.outcome,
					detail: entry.detail,
				})),
			};
		},
		async status() {
			let rules = 0;
			let ok = false;
			try {
				rules = await loadBundledThreatCount();
				ok = (await verifyDetection()).ok && rules > 0;
			} catch {
				ok = false;
			}
			const verdict = statusVerdictFor(detectConnectorStatuses(home, hostEnv), home);
			return {
				detection: { ok, rules },
				protected: verdict.protected,
				restart: verdict.restart.map((entry) => entry.label),
				manual: verdict.manual,
			};
		},
		enrollStart: (input) => enrollment.start(input),
		enrollPoll: () => enrollment.poll(),
		enrollCancel: () => enrollment.cancel(),
	};
}
