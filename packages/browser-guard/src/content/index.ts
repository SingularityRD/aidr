/**
 * Content-script entry point (bundled by scripts/build.mjs).
 *
 * Wires the real engine, vault, site adapter and editor access into the guard via
 * `bootContentGuard` (see ./boot.ts for policy loading, the per-page vault and the
 * fail-closed behaviour before a policy arrives).
 */
import {
	findEditor,
	findEditorNear,
	findSendButton,
	insertAtSelection,
	isSyntheticEditorEvent,
} from "../dom/editor.js";
import { coachingFor } from "../engine/coaching.js";
import { createDetectionEngine } from "../engine/detect.js";
import { sanitizeFile } from "../engine/files.js";
import { createVault } from "../engine/vault.js";
import { adapterForUrl } from "../sites/index.js";
import { type BootedGuard, bootContentGuard, type RuntimeLike } from "./boot.js";

declare const chrome: { readonly runtime?: RuntimeLike } | undefined;

const BOOT_FLAG = "__aidrBrowserGuardBooted";

export function bootContentScript(runtime: RuntimeLike): BootedGuard {
	return bootContentGuard({
		window,
		document,
		url: location.href,
		runtime,
		adapterForUrl,
		createDetectionEngine,
		createVault,
		findEditor,
		findEditorNear,
		findSendButton,
		insertAtSelection,
		isSyntheticEvent: isSyntheticEditorEvent,
		sanitizeFile,
		coachingFor,
	});
}

const runtime = typeof chrome !== "undefined" ? chrome?.runtime : undefined;
if (runtime?.id) {
	const scope = globalThis as unknown as Record<string, unknown>;
	// Re-injection must not install a second set of listeners.
	if (!scope[BOOT_FLAG]) {
		scope[BOOT_FLAG] = true;
		bootContentScript(runtime);
	}
}
