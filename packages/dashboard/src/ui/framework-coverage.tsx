import coverageArtifact from "../generated/framework-coverage.json";
import type { DashboardMessageKey } from "../i18n/en";
import { type Translate, useRichT, useT } from "../i18n/I18nProvider";

/**
 * Security framework coverage (OWASP LLM Top 10 2025, OWASP Agentic Top 10
 * 2026, MITRE ATLAS).
 *
 * The data is `src/generated/framework-coverage.json`, rendered from
 * threats/*.yaml and threats/mappings/frameworks.yaml by
 * `pnpm coverage:frameworks -- --write` and bundled at build time. It describes
 * the rule set this dashboard release was built with; it is product data, not
 * tenant data, so it never depends on what an agent uploaded. Event and
 * incident views resolve framework IDs from the rule id through the same
 * artifact instead of trusting any framework field in a client payload.
 */

type CoverageStatus = "covered" | "partial" | "not_covered" | "not_applicable";

interface CoverageItem {
	id: string;
	label: string;
	title: string;
	status: CoverageStatus;
	rationale: string;
	rule_count: number;
	example_rules: string[];
	tactics?: string[];
}

interface CoverageTactic {
	id: string;
	name: string;
	techniques_mapped: number;
	techniques_total: number;
}

interface FrameworkCoverage {
	id: "owasp_llm" | "owasp_agentic" | "mitre_atlas";
	name: string;
	version: string;
	url: string;
	items_total: number;
	status_counts: Record<CoverageStatus, number>;
	items: CoverageItem[];
	tactics?: CoverageTactic[];
}

export interface RuleFrameworks {
	owasp_llm: string[];
	owasp_agentic: string[];
	mitre_atlas: string[];
}

interface CoverageArtifact {
	schema_version: number;
	matrix: { rule_count: number; rule_files: number; frameworks: FrameworkCoverage[] };
	rules: Record<string, RuleFrameworks>;
	titles: Record<string, string>;
}

const artifact = coverageArtifact as CoverageArtifact;

const STATUS_TEXT: Record<CoverageStatus, DashboardMessageKey> = {
	covered: "fw.status.covered",
	partial: "fw.status.partial",
	not_covered: "fw.status.notCovered",
	not_applicable: "fw.status.notApplicable",
};

const STATUS_BADGE: Record<CoverageStatus, string> = {
	covered: "badge badge-allow",
	partial: "badge badge-ask",
	not_covered: "badge badge-deny",
	not_applicable: "badge badge-neutral",
};

/** Framework IDs of a shipped rule, or null for an unknown/unmapped rule id. */
export function frameworksForRule(ruleId: unknown): RuleFrameworks | null {
	if (typeof ruleId !== "string" || !Object.hasOwn(artifact.rules, ruleId)) return null;
	return artifact.rules[ruleId] ?? null;
}

/** `LLM01:2025` / `ASI01:2026` / `AML.T0051` display label. */
function label(id: string): string {
	if (/^LLM\d\d$/.test(id)) return `${id}:2025`;
	if (/^ASI\d\d$/.test(id)) return `${id}:2026`;
	return id;
}

/**
 * Compact framework chips for an event or incident that names the rule it
 * matched. Renders nothing for a rule this build has no mapping for.
 */
export function FrameworkTags({ ruleId }: { ruleId: unknown }) {
	const refs = frameworksForRule(ruleId);
	if (!refs) return null;
	const ids = [...refs.owasp_llm, ...refs.owasp_agentic, ...refs.mitre_atlas];
	if (ids.length === 0) return null;
	return (
		<div className="row" style={{ marginTop: 4, gap: 4, flexWrap: "wrap" }}>
			<span className="muted small mono">{String(ruleId)}</span>
			{ids.map((id) => (
				<span
					key={id}
					className="badge badge-neutral badge-plain mono small"
					title={artifact.titles[id] ?? id}
				>
					{label(id)}
				</span>
			))}
		</div>
	);
}

function summaryText(framework: FrameworkCoverage, t: Translate): string {
	const s = framework.status_counts;
	if (framework.id === "mitre_atlas") {
		const tactics = framework.tactics ?? [];
		const touched = tactics.filter((tactic) => tactic.techniques_mapped > 0).length;
		return t("fw.atlasSummary", {
			mapped: framework.items.length,
			total: framework.items_total,
			covered: s.covered,
			partial: s.partial,
			touched,
			tactics: tactics.length,
		});
	}
	return t("fw.summary", {
		covered: s.covered,
		partial: s.partial,
		notCovered: s.not_covered,
		notApplicable: s.not_applicable,
		total: framework.items_total,
	});
}

function FrameworkTable({ framework }: { framework: FrameworkCoverage }) {
	const t = useT();
	return (
		<section className="card" aria-label={`${framework.name} ${framework.version}`}>
			<h3>
				{framework.name} {framework.version}
			</h3>
			<p className="muted small">{summaryText(framework, t)}</p>
			<div className="table-wrap" style={{ marginTop: 8 }}>
				<table className="table">
					<thead>
						<tr>
							<th>ID</th>
							<th>{t("fw.col.title")}</th>
							<th>{t("fw.col.status")}</th>
							<th>{t("fw.col.rules")}</th>
							<th>{t("fw.col.examples")}</th>
							<th>{t("fw.col.rationale")}</th>
						</tr>
					</thead>
					<tbody>
						{framework.items.map((item) => (
							<tr key={item.id}>
								<td className="mono">{item.label}</td>
								<td>{item.title}</td>
								<td>
									<span className={STATUS_BADGE[item.status]}>{t(STATUS_TEXT[item.status])}</span>
								</td>
								<td className="mono">{item.rule_count}</td>
								<td className="mono small">
									{item.example_rules.length > 0 ? item.example_rules.join(", ") : "—"}
								</td>
								<td className="small">{item.rationale}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
			{framework.tactics ? (
				<div className="row" style={{ marginTop: 8, flexWrap: "wrap", gap: 4 }}>
					{framework.tactics.map((tactic) => (
						<span
							key={tactic.id}
							className={tactic.techniques_mapped > 0 ? "badge badge-info" : "badge badge-neutral"}
							title={tactic.id}
						>
							{tactic.name}: {tactic.techniques_mapped}/{tactic.techniques_total}
						</span>
					))}
				</div>
			) : null}
		</section>
	);
}

/** "Framework coverage" view shown in the Posture area. */
export function FrameworkCoverageSection() {
	const t = useT();
	const richT = useRichT();
	const { matrix } = artifact;
	return (
		<section className="stack" aria-label={t("fw.title")}>
			<div className="card">
				<h2>{t("fw.title")}</h2>
				<p className="muted" style={{ maxWidth: 820 }}>
					{richT("fw.lead", {
						rules: matrix.rule_count,
						files: matrix.rule_files,
						command: <span className="mono">aidr coverage</span>,
					})}
				</p>
			</div>
			{matrix.frameworks.map((framework) => (
				<FrameworkTable key={framework.id} framework={framework} />
			))}
		</section>
	);
}
