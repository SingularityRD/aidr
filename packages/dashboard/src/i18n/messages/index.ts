import { activityMessages } from "./activity";
import { agentsMessages } from "./agents";
import { apiKeysMessages } from "./api-keys";
import { approvalsMessages } from "./approvals";
import { auditMessages } from "./audit";
import { autosecopsMessages } from "./autosecops";
import { billingMessages } from "./billing";
import { billingPlanMessages } from "./billing-plan";
import { commonMessages } from "./common";
import { complianceMessages } from "./compliance";
import { dashboardMessages } from "./dashboard";
import { detectionExceptionsMessages } from "./detection-exceptions";
import { discoveryMessages } from "./discovery";
import { downloadCenterMessages } from "./download-center";
import { evidenceMessages } from "./evidence";
import { frameworkMessages } from "./framework";
import { governanceMessages } from "./governance";
import { governanceChangeMessages } from "./governance-change";
import { governanceErrorsMessages } from "./governance-errors";
import { governanceRequestsMessages } from "./governance-requests";
import { governanceScorecardMessages } from "./governance-scorecard";
import { notificationsMessages } from "./notifications";
import { onboardingMessages } from "./onboarding";
import { policyMessages } from "./policy";
import { policyRolloutMessages } from "./policy-rollout";
import { policyRuntimeMessages } from "./policy-runtime";
import { postureMessages } from "./posture";
import { privacyGuardMessages } from "./privacy-guard";
import { retentionMessages } from "./retention";
import { settingsMessages } from "./settings";
import { siemMessages } from "./siem";
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
	...autosecopsMessages,
	...billingMessages,
	...billingPlanMessages,
	...complianceMessages,
	...dashboardMessages,
	...detectionExceptionsMessages,
	...discoveryMessages,
	...downloadCenterMessages,
	...evidenceMessages,
	...frameworkMessages,
	...governanceMessages,
	...governanceChangeMessages,
	...governanceErrorsMessages,
	...governanceRequestsMessages,
	...governanceScorecardMessages,
	...notificationsMessages,
	...onboardingMessages,
	...policyMessages,
	...policyRolloutMessages,
	...policyRuntimeMessages,
	...postureMessages,
	...privacyGuardMessages,
	...retentionMessages,
	...settingsMessages,
	...siemMessages,
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
	autosecopsMessages,
	billingMessages,
	billingPlanMessages,
	complianceMessages,
	dashboardMessages,
	detectionExceptionsMessages,
	discoveryMessages,
	downloadCenterMessages,
	evidenceMessages,
	frameworkMessages,
	governanceMessages,
	governanceChangeMessages,
	governanceErrorsMessages,
	governanceRequestsMessages,
	governanceScorecardMessages,
	notificationsMessages,
	onboardingMessages,
	policyMessages,
	policyRolloutMessages,
	policyRuntimeMessages,
	postureMessages,
	privacyGuardMessages,
	retentionMessages,
	settingsMessages,
	siemMessages,
	teamMessages,
	usageMessages,
];
