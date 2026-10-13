// Language selection shared by the on-prem operator commands
// (scripts/onprem-upgrade.mjs, scripts/onprem-offline-bundle.mjs). Messages are
// kept next to each command; this only decides which catalog to use.

/** `--lang` wins, then AIDR_LANG, then the POSIX locale variables. Default English. */
export function selectLanguage(requested, env = process.env) {
	const candidates = [requested, env.AIDR_LANG, env.LC_ALL, env.LC_MESSAGES, env.LANG];
	for (const value of candidates) {
		if (typeof value !== "string" || value.trim() === "") continue;
		return value.trim().toLowerCase().startsWith("tr") ? "tr" : "en";
	}
	return "en";
}
