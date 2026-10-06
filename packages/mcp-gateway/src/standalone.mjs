import { isInvalidConfig, loadConfig } from "../../core/dist/config.js";

// The standalone binaries do not install the private service's full MCP guards.
export async function requireStandaloneProfile() {
	const config = await loadConfig();
	if (isInvalidConfig(config)) throw new Error("standalone_profile_invalid");
	if (config.privacy?.required === true) throw new Error("standalone_privacy_unavailable");
}

export async function standalonePayloadGuard() {
	await requireStandaloneProfile();
	return { allowed: true, coverage: "full", opaqueInspected: false };
}
