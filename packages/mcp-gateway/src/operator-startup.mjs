import { readGatewayConfig, stage } from "./diagnostics.mjs";
import { createMcpGateway } from "./gateway.mjs";
import { requireGatewayIntegrity } from "./integrity.mjs";
import { requireStandaloneProfile, standalonePayloadGuard } from "./standalone.mjs";

/**
 * The common start of every operator CLI: verify this gateway's own artifact
 * integrity first, then read and validate the configuration. Each step fails
 * with its stage code (see diagnostics.mjs).
 *
 * `standalone: true` is the traffic-serving start used by the gateway and
 * stdio binaries: the standalone profile is checked before integrity and again
 * after the configuration is read, and the gateway is created with the
 * standalone privacy check, the standalone payload guards and stderr audit
 * events. `requireRouting: true` forces `routingRequired` whatever the
 * configuration file says.
 */
export async function openVerifiedGateway(
	configPath,
	{ standalone = false, requireRouting = false } = {},
) {
	if (standalone) await stage("standalone_profile_failed", () => requireStandaloneProfile());
	await stage("integrity_verification_failed", () => requireGatewayIntegrity());
	const config = await readGatewayConfig(configPath);
	if (standalone) await stage("standalone_profile_failed", () => requireStandaloneProfile());
	return stage("config_invalid", () =>
		createMcpGateway(
			requireRouting ? { ...config, routingRequired: true } : config,
			standalone
				? {
						assertInstalledPrivacySupported: requireStandaloneProfile,
						toolGuard: standalonePayloadGuard,
						outputGuard: standalonePayloadGuard,
						onEvent: (event) => process.stderr.write(`${JSON.stringify(event)}\n`),
					}
				: {},
		),
	);
}
