import { isInvalidConfig, loadConfig } from "@singularityrd/aidr-core";

export const PRIVACY_ROUTE_UNAVAILABLE = "mandatory_privacy_requires_owned_gateway";

/** These exported adapters do not own the private model/output transport. */
export async function installedPrivacyRequired(): Promise<boolean> {
	try {
		const config = await loadConfig();
		return isInvalidConfig(config) || config.privacy?.required === true;
	} catch {
		return true;
	}
}
