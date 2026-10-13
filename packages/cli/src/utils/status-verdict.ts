import type { ConnectorStatus } from "./connector-status.js";
import type { SetupLedger } from "./setup-ledger.js";

/**
 * The one-line answer at the end of `aidr status`: which hosts are protected,
 * which must be restarted to load AIDR, and which still need a manual step
 * (with the exact command). Built only from measured connector state and the
 * last setup's ledger; it never claims host execution, which only a host-side
 * canary (`aidr verify`, or the host itself) can show.
 */
export interface StatusVerdict {
	protected: string[];
	restart: { label: string; since: string }[];
	manual: { label: string; command: string }[];
	/** True when at least one host is registered and nothing needs a manual step. */
	ok: boolean;
}

/** Hosts `aidr setup --host <id>` can register without an extra artifact. */
const SETUP_CAN_REGISTER = new Set<ConnectorStatus["id"]>(["opencode", "openclaw"]);

export function buildStatusVerdict(
	connectors: ConnectorStatus[],
	ledger: SetupLedger | null,
	options: { standalone?: boolean } = {},
): StatusVerdict {
	const verdict: StatusVerdict = { protected: [], restart: [], manual: [], ok: false };
	for (const connector of connectors) {
		if (connector.state === "installed") {
			if (ledger?.registered.includes(connector.id)) {
				verdict.restart.push({ label: connector.label, since: ledger.completed_at });
			} else {
				verdict.protected.push(connector.label);
			}
			continue;
		}
		if (connector.state === "not_detected") continue;
		const viaSetup =
			connector.state === "runtime_present_not_installed" &&
			(SETUP_CAN_REGISTER.has(connector.id) ||
				(connector.id === "claude-code" && options.standalone === true));
		verdict.manual.push({
			label: connector.label,
			command: viaSetup
				? `aidr setup --host ${connector.id}`
				: (connector.remedy ?? connector.detail),
		});
	}
	verdict.ok = verdict.protected.length + verdict.restart.length > 0 && verdict.manual.length === 0;
	return verdict;
}
