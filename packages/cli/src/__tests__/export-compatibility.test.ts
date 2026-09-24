import { describe, expect, it } from "vitest";
import { printUninstallReport, type UninstallRefusalCode } from "../commands/uninstall.js";
import type { SecretReference } from "../utils/config-manager.js";
import type { ConnectorState } from "../utils/connector-status.js";
import { type ManagedHookRecord, writeGenericHookTemplate } from "../utils/install-hooks.js";
import {
	type PlatformSecretStoreKind,
	platformSecretStoreKind,
	SECRET_STORE_AUTO,
	SecretStoreError,
	SecretStoreSelectionError,
} from "../utils/secret-store.js";

describe("CLI deep-module export compatibility", () => {
	it("retains the runtime named exports", () => {
		expect(typeof printUninstallReport).toBe("function");
		expect(typeof writeGenericHookTemplate).toBe("function");
		expect(SECRET_STORE_AUTO).toBe("auto");
		expect(new SecretStoreError("store failed")).toBeInstanceOf(Error);
		expect(new SecretStoreSelectionError("selection failed")).toBeInstanceOf(SecretStoreError);
		expect(platformSecretStoreKind("win32")).toBe("windows-dpapi");
	});

	it("retains the named type exports", () => {
		const refusal: UninstallRefusalCode = "receipt_missing";
		const reference: SecretReference = {
			store: "windows-dpapi",
			id: "credential-id",
			created_at: "2026-09-22T00:00:00.000Z",
		};
		const connector: ConnectorState = "installed";
		const hook: ManagedHookRecord = {
			event: "PreToolUse",
			command: "node hook.cjs",
			statusMessage: "Singularity AIDR managed installation",
		};
		const platformStore: PlatformSecretStoreKind = "windows-dpapi";

		expect({ refusal, reference, connector, hook, platformStore }).toBeDefined();
	});
});
