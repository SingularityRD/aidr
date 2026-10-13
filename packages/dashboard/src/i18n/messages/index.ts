import { activityMessages } from "./activity";
import { agentsMessages } from "./agents";
import { apiKeysMessages } from "./api-keys";
import { approvalsMessages } from "./approvals";
import { auditMessages } from "./audit";
import { billingMessages } from "./billing";
import { billingPlanMessages } from "./billing-plan";
import { commonMessages } from "./common";
import { dashboardMessages } from "./dashboard";
import { discoveryMessages } from "./discovery";
import { downloadCenterMessages } from "./download-center";
import { governanceErrorsMessages } from "./governance-errors";
import { notificationsMessages } from "./notifications";
import { onboardingMessages } from "./onboarding";
import { policyMessages } from "./policy";
import { policyRolloutMessages } from "./policy-rollout";
import { policyRuntimeMessages } from "./policy-runtime";
import { postureMessages } from "./posture";
import { privacyGuardMessages } from "./privacy-guard";
import { settingsMessages } from "./settings";
import { teamMessages } from "./team";
import { usageMessages } from "./usage";

/** Every page message module; en.ts and tr.ts take their halves from here. */
export const pageMessages = {
	...commonMessages,
	...activityMessages,
	...agentsMessages,
	...apiKeysMessages,
	...approvalsMessages,
	...auditMessages,
	...billingMessages,
	...billingPlanMessages,
	...dashboardMessages,
	...discoveryMessages,
	...downloadCenterMessages,
	...governanceErrorsMessages,
	...notificationsMessages,
	...onboardingMessages,
	...policyMessages,
	...policyRolloutMessages,
	...policyRuntimeMessages,
	...postureMessages,
	...privacyGuardMessages,
	...settingsMessages,
	...teamMessages,
	...usageMessages,
};

/** The same modules as a list, so a test can prove no key is defined twice. */
export const messageModules = [
	commonMessages,
	activityMessages,
	agentsMessages,
	apiKeysMessages,
	approvalsMessages,
	auditMessages,
	billingMessages,
	billingPlanMessages,
	dashboardMessages,
	discoveryMessages,
	downloadCenterMessages,
	governanceErrorsMessages,
	notificationsMessages,
	onboardingMessages,
	policyMessages,
	policyRolloutMessages,
	policyRuntimeMessages,
	postureMessages,
	privacyGuardMessages,
	settingsMessages,
	teamMessages,
	usageMessages,
];
