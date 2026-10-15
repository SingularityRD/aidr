// Ordered scenario list. Ids are what `--only` selects (exact id or id prefix,
// e.g. `--only auto` runs every auto-* scenario).

import autoMask from "./auto-mask.mjs";
import blockedSite from "./blocked-site.mjs";
import editResend from "./edit-resend.mjs";
import editing from "./editing.mjs";
import fileUpload from "./file-upload.mjs";
import frames from "./frames.mjs";
import managedAiSites from "./managed-ai-sites.mjs";
import modes from "./modes.mjs";
import paste from "./paste.mjs";
import popup from "./popup.mjs";
import preflight from "./preflight.mjs";
import reloadRestore from "./reload-restore.mjs";
import restoreSideChannels from "./restore-side-channels.mjs";
import workAccounts from "./work-accounts.mjs";

export const SCENARIOS = [
	...preflight,
	...autoMask,
	...restoreSideChannels,
	...reloadRestore,
	...paste,
	...modes,
	...fileUpload,
	...popup,
	...editing,
	...editResend,
	...blockedSite,
	...frames,
	...managedAiSites,
	...workAccounts,
];

/** Selects scenarios by comma-separated ids or id prefixes (`auto` matches `auto-chatgpt`). */
export function selectScenarios(only) {
	if (!only) return SCENARIOS;
	const wanted = only
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
	const picked = SCENARIOS.filter((s) =>
		wanted.some((w) => s.id === w || s.id.startsWith(`${w}-`)),
	);
	const unknown = wanted.filter(
		(w) => !SCENARIOS.some((s) => s.id === w || s.id.startsWith(`${w}-`)),
	);
	if (unknown.length > 0) {
		throw new Error(
			`unknown scenario(s): ${unknown.join(", ")}. Known: ${SCENARIOS.map((s) => s.id).join(", ")}`,
		);
	}
	return picked;
}
