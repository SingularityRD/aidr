// A copy of the built extension set up the way an enterprise deployment would leave it,
// for the scenarios that depend on administrator policy and user-granted host access
// (scenarios/managed-ai-sites.mjs). Two things cannot be done from a test in Chromium:
//
// 1. Writing chrome.storage.managed (policy comes from the OS/browser management
//    layer; the CDP Extensions domain refuses it as read-only). The copy's
//    background.js starts with a prelude that answers chrome.storage.managed.get with
//    the scenario's policy, so the product's own policy code (validation, locking,
//    DNR rules, content-script registration) runs unchanged on it at every worker start.
// 2. Accepting chrome.permissions.request's native prompt (it is browser UI, not page
//    DOM, and has no automation switch). The origins the user would grant from the
//    options page are added to the copy's manifest host_permissions instead: for the
//    browser a granted optional host permission and a manifest host permission are the
//    same active permission (permissions.contains() is true for both, and
//    tabs.onUpdated URL visibility and chrome.scripting act on either).
//
// Nothing else changes: every other file is the product build byte for byte.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HOST_ORIGIN = /^https:\/\/[a-z0-9.-]+\/\*$/;

/**
 * `grantedPermissions`: optional API permissions the user would grant on the options page
 * (only `nativeMessaging` exists); moved from `optional_permissions` to `permissions`, which
 * for the browser is the same active permission.
 */
export function createManagedDeployment(extDir, { managedPolicy, grantedOrigins, grantedPermissions = [] }) {
	for (const origin of grantedOrigins) {
		if (!HOST_ORIGIN.test(origin)) throw new Error(`not an exact https origin: ${origin}`);
	}
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-e2e-managed-"));
	fs.cpSync(extDir, dir, { recursive: true });

	const manifestPath = path.join(dir, "manifest.json");
	const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
	const optional = manifest.optional_host_permissions ?? [];
	if (!optional.includes("https://*/*")) {
		throw new Error("the build does not request optional https host permissions");
	}
	manifest.host_permissions = [...new Set([...(manifest.host_permissions ?? []), ...grantedOrigins])];
	for (const permission of grantedPermissions) {
		if (!(manifest.optional_permissions ?? []).includes(permission)) {
			throw new Error(`the build does not declare the optional permission ${permission}`);
		}
		manifest.permissions = [...new Set([...(manifest.permissions ?? []), permission])];
	}
	fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

	const backgroundPath = path.join(dir, manifest.background.service_worker);
	const prelude = `/* E2E: enterprise policy stand-in (see e2e/lib/managed-deployment.mjs) */
(() => {
	const policy = ${JSON.stringify(managedPolicy)};
	const area = chrome.storage.managed;
	const get = async () => JSON.parse(JSON.stringify(policy));
	try {
		Object.defineProperty(area, "get", { value: get, configurable: true, writable: true });
	} catch {
		area.get = get;
	}
})();
`;
	fs.writeFileSync(backgroundPath, prelude + fs.readFileSync(backgroundPath, "utf8"));
	return dir;
}
