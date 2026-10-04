/**
 * Claude Code's short-lived hook has no trusted tenant in the tool payload.
 * Operator-delivered detector policy is accepted only when it is signed by a
 * configured entitlement key and bound to a verified managed entitlement.
 *
 * The implementation lives in `@singularityrd/aidr-core`
 * (`detector-provisioning.ts`) so every connector shares one set of checks; this
 * module only binds the shared helper to the Claude Code runtime. An
 * unprovisioned install still gets an empty context here.
 */
import {
	type DetectorProvisionedContext,
	detectorPolicyPath as coreDetectorPolicyPath,
	loadProvisionedDetectorContext as coreLoadProvisionedDetectorContext,
} from "@singularityrd/aidr-core";

/** Fixed, non-tool-selectable location under the local AIDR state directory. */
export function detectorPolicyPath(): string {
	return coreDetectorPolicyPath("claude-code");
}

;
export type { DetectorProvisionedContext };

export async function loadProvisionedDetectorContext(): Promise<DetectorProvisionedContext> {
	return coreLoadProvisionedDetectorContext("claude-code");
}
