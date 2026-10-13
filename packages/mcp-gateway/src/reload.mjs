import { unwatchFile, watchFile } from "node:fs";
import { diagnosticReason, readGatewayConfig, stage } from "./diagnostics.mjs";

/**
 * Hot reload of signed manifests for the HTTP gateway CLI. The configuration
 * file is polled (which also survives editors that replace the file) and
 * re-read on SIGHUP. Only manifests, signer keys and revocations may change;
 * the gateway verifies every manifest before adopting the new configuration
 * and otherwise keeps the current one. Each outcome is one fixed stderr line.
 */
export function watchGatewayConfig(
	gateway,
	configPath,
	{ requireRouting = false, stderr = process.stderr, intervalMs = 2000 } = {},
) {
	let queue = Promise.resolve();
	const reload = () => {
		queue = queue.then(async () => {
			try {
				const config = await readGatewayConfig(configPath);
				const result = await stage("manifest_reload_failed", () =>
					gateway.reloadManifests(requireRouting ? { ...config, routingRequired: true } : config),
				);
				stderr.write(`AIDR MCP gateway reloaded ${result.reloaded} signed manifest(s)\n`);
			} catch (error) {
				stderr.write(
					`AIDR MCP gateway reload refused: ${diagnosticReason(error)}; the previous configuration remains in force\n`,
				);
			}
		});
		return queue;
	};
	const onChange = (current, previous) => {
		if (
			current.mtimeMs !== previous.mtimeMs ||
			current.size !== previous.size ||
			current.ino !== previous.ino
		)
			reload();
	};
	watchFile(configPath, { interval: intervalMs, persistent: false }, onChange);
	process.on("SIGHUP", reload);
	return {
		reload,
		stop() {
			unwatchFile(configPath, onChange);
			process.off("SIGHUP", reload);
		},
	};
}
