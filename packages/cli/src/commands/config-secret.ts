/**
 * `aidr config rotate-key` / `aidr config revoke-key` (gap B5).
 *
 * Both go through the selected secret store and record the outcome in the config
 * document (`secret_rotated_at` / `secret_revoked_at`) as well as on the terminal,
 * so a later reader can tell a rotated credential from one that was never touched.
 *
 * A rotation is ordered so the previous credential stays valid until the new one
 * is committed; see `rotateSecret` in `config-manager.ts`. These handlers only
 * report that outcome — they never touch the credential themselves.
 */

import { type ConfigManagerOptions, revokeSecret, rotateSecret } from "../utils/config-manager.js";
import { SECRET_STORE_ENV, SECRET_STORE_KINDS } from "../utils/secret-store.js";

interface SecretCommandOptions {
	secretStore?: string;
	json?: boolean;
}

/** Shared `--secret-store` description so the commands and `setup` agree. */
export const SECRET_STORE_OPTION_DESCRIPTION =
	`Credential store: ${SECRET_STORE_KINDS.join(", ")} (default: detect the OS vault; ` +
	`${SECRET_STORE_ENV}=file-acl accepts the reduced-protection file fallback)`;

function report(
	command: string,
	payload: Record<string, unknown>,
	options: SecretCommandOptions,
): void {
	if (options.json) {
		console.log(JSON.stringify({ command, ...payload }, null, 2));
	}
}

async function rotateKeyCommand(options: SecretCommandOptions = {}): Promise<void> {
	const manager: ConfigManagerOptions = { secretStoreSelection: options.secretStore };
	try {
		const result = rotateSecret(manager);
		if (options.json) {
			report("config rotate-key", { ...result, scope: "cli-setup-only" }, options);
			return;
		}
		console.log(`✅ Rotated the CLI setup credential in the ${result.store} store.`);
		console.log(
			"  Managed endpoint API keys are unchanged; renew or revoke them in the control plane.",
		);
		console.log(`  Config: ${result.path}`);
		console.log(
			`  Previous credential: ${
				result.previousRef
					? `${result.previousRef.store}:${result.previousRef.id} (revoked after the new credential committed)`
					: "file fallback — replaced atomically at commit"
			}`,
		);
		console.log(`  Recorded at: ${result.rotatedAt}`);
		if (result.warning) console.log(`  ⚠️  ${result.warning}`);
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : String(error);
		if (options.json) {
			report("config rotate-key", { error: message }, options);
		} else {
			console.error(`❌ Could not rotate the local credential: ${message}`);
		}
		process.exitCode = 1;
	}
}

async function revokeKeyCommand(options: SecretCommandOptions = {}): Promise<void> {
	const manager: ConfigManagerOptions = { secretStoreSelection: options.secretStore };
	try {
		const result = revokeSecret(manager);
		if (options.json) {
			report("config revoke-key", { ...result, scope: "cli-setup-only" }, options);
			return;
		}
		console.log(`✅ Revoked the CLI setup credential in the ${result.store} store.`);
		console.log("  Managed endpoint API keys remain active; revoke them in the control plane.");
		console.log(`  Config: ${result.path}`);
		console.log(
			`  Revoked credential: ${
				result.revokedRef
					? `${result.revokedRef.store}:${result.revokedRef.id}`
					: "file fallback — removed from the config document"
			}`,
		);
		console.log(`  Recorded at: ${result.revokedAt}`);
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : String(error);
		if (options.json) {
			report("config revoke-key", { error: message }, options);
		} else {
			console.error(`❌ Could not revoke the local credential: ${message}`);
		}
		process.exitCode = 1;
	}
}

export { revokeKeyCommand, rotateKeyCommand };
