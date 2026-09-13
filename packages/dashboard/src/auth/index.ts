// Auth module exports

export type {
	AzureADConfig,
	AzureADGroup,
	AzureADUser,
	GroupSyncResult,
} from "./azure-ad";
export {
	AzureADError,
	getAzureADGroups,
	handleAzureADCallback,
	mapGroupToRole,
	signInWithAzureAD,
} from "./azure-ad";
export type {
	AgentSync,
	CredentialShare,
	GoogleCredential,
	User,
} from "./google-provider";
export {
	GoogleAuthProvider,
	useGoogleAuth,
} from "./google-provider";
