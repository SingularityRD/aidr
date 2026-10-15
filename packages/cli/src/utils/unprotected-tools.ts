import {
	detectUnprotectedAiTools,
	resolvePath,
	type UnprotectedAiTool,
} from "@singularityrd/aidr-core";

/**
 * AI coding tools on this computer that AIDR has no connector for (`aidr
 * status`, `aidr coverage`). A detection failure reports none rather than
 * failing the command; an injected list is used as is (tests).
 */
export function unprotectedAiTools(
	deps: { unprotectedTools?: UnprotectedAiTool[] } = {},
): UnprotectedAiTool[] {
	if (deps.unprotectedTools) return deps.unprotectedTools;
	try {
		return detectUnprotectedAiTools({ home: resolvePath("~"), env: process.env });
	} catch {
		return [];
	}
}
