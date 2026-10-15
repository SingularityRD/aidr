import {
	type Config,
	detectUnprotectedAiTools,
	formatPrivacyNotice,
	loadConfig,
	privacyNoticeFacts,
	resolvePath,
	type UnprotectedAiTool,
} from "@singularityrd/aidr-core";

/** Test seams; production callers pass nothing. */
export interface PrivacyNoticeDeps {
	config?: Config;
	unprotectedTools?: UnprotectedAiTool[];
	out?: (text: string) => void;
}

/**
 * `aidr privacy notice`: the same notice every connector shows once on first
 * run (what is guarded and what is not, what is recorded on this computer,
 * what leaves it, the organisation's privacy notice link), at any time.
 * `--json` prints the facts it is computed from.
 */
export async function privacyNoticeCommand(
	options: { json?: boolean } = {},
	deps: PrivacyNoticeDeps = {},
): Promise<void> {
	const out = deps.out ?? ((text: string) => console.log(text));
	const config = deps.config ?? (await loadConfig());
	const unprotected =
		deps.unprotectedTools ?? detectUnprotectedAiTools({ home: resolvePath("~"), env: process.env });
	if (options.json) {
		out(
			JSON.stringify(
				{
					...privacyNoticeFacts(config),
					unprotected_ai_tools: unprotected.map((tool) => tool.id),
				},
				null,
				2,
			),
		);
		return;
	}
	out(formatPrivacyNotice(config, { unprotectedTools: unprotected.map((tool) => tool.label) }));
}
