import { agentsMessages } from "./agents";
import { approvalsMessages } from "./approvals";
import { commonMessages } from "./common";
import { notificationsMessages } from "./notifications";
import { policyMessages } from "./policy";
import { policyRolloutMessages } from "./policy-rollout";
import { policyRuntimeMessages } from "./policy-runtime";
import { settingsMessages } from "./settings";

/** Every page message module; en.ts and tr.ts take their halves from here. */
export const pageMessages = {
	...commonMessages,
	...approvalsMessages,
	...settingsMessages,
	...notificationsMessages,
	...agentsMessages,
	...policyMessages,
	...policyRuntimeMessages,
	...policyRolloutMessages,
};
