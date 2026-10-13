import { activityMessages } from "./activity";
import { agentsMessages } from "./agents";
import { approvalsMessages } from "./approvals";
import { billingMessages } from "./billing";
import { billingPlanMessages } from "./billing-plan";
import { commonMessages } from "./common";
import { downloadCenterMessages } from "./download-center";
import { notificationsMessages } from "./notifications";
import { onboardingMessages } from "./onboarding";
import { policyMessages } from "./policy";
import { policyRolloutMessages } from "./policy-rollout";
import { policyRuntimeMessages } from "./policy-runtime";
import { settingsMessages } from "./settings";
import { usageMessages } from "./usage";

/** Every page message module; en.ts and tr.ts take their halves from here. */
export const pageMessages = {
	...commonMessages,
	...activityMessages,
	...agentsMessages,
	...approvalsMessages,
	...billingMessages,
	...billingPlanMessages,
	...downloadCenterMessages,
	...notificationsMessages,
	...onboardingMessages,
	...policyMessages,
	...policyRolloutMessages,
	...policyRuntimeMessages,
	...settingsMessages,
	...usageMessages,
};

/** The same modules as a list, so a test can prove no key is defined twice. */
export const messageModules = [
	commonMessages,
	activityMessages,
	agentsMessages,
	approvalsMessages,
	billingMessages,
	billingPlanMessages,
	downloadCenterMessages,
	notificationsMessages,
	onboardingMessages,
	policyMessages,
	policyRolloutMessages,
	policyRuntimeMessages,
	settingsMessages,
	usageMessages,
];
