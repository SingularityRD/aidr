import type { DashboardMessageKey } from "../i18n/en";
import { englishT, type Translate } from "../i18n/I18nProvider";
import { supabase } from "./supabase";

/**
 * Executive summary, team rollup, printable executive report and the
 * scheduled-report options, through the `reports` Edge Function (owners and
 * admins; AAL2 to change options). Headlines and section lines come from the
 * server in the requested language, so the dashboard, the e-mail and the
 * printable report say the same thing.
 */

export type ReportLanguage = "en" | "tr";
export const REPORT_WINDOWS = [7, 30, 90] as const;
export type ReportWindow = (typeof REPORT_WINDOWS)[number];

export interface ExecutiveView {
	period: { from: string; to: string };
	language: ReportLanguage;
	options: {
		language: ReportLanguage;
		attachment: boolean;
		digestEnabled: boolean;
		digestCadence: string;
	};
	status: "attention" | "ok";
	headlines: Array<{ level: "attention" | "info"; text: string }>;
	sections: Array<{ title: string; lines: string[] }>;
}

interface TeamRollupFigures {
	agentsActive: number;
	agentsEnrolled: number;
	browserActive: number;
	allow: number;
	ask: number;
	deny: number;
	masked: number;
	blocked: number;
	incidentsActive: number;
	incidentsCritical: number;
	incidentsUnassigned: number;
	approvalsPending: number;
}

export interface TeamRollupRow {
	tenantId: string;
	name: string;
	role: string;
	figures: TeamRollupFigures | null;
}

export type ReportResult<T> = { ok: true; value: T } | { ok: false; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const isLanguage = (value: unknown): value is ReportLanguage => value === "en" || value === "tr";
const count = (value: unknown): number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
const strings = (value: unknown): string[] =>
	Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

async function errorCode(error: unknown): Promise<string | null> {
	const context = (error as { context?: unknown } | null | undefined)?.context;
	if (!(context instanceof Response)) return null;
	try {
		const body: unknown = await context.clone().json();
		return isRecord(body) &&
			typeof body.error === "string" &&
			/^[a-z][a-z0-9_]{0,63}$/.test(body.error)
			? body.error
			: null;
	} catch {
		return null;
	}
}

async function invoke(
	body: Record<string, unknown>,
): Promise<ReportResult<Record<string, unknown>>> {
	try {
		const { data, error } = await supabase.functions.invoke("reports", { method: "POST", body });
		if (error) return { ok: false, error: (await errorCode(error)) ?? "report_unavailable" };
		if (!isRecord(data) || data.ok !== true) return { ok: false, error: "report_unavailable" };
		return { ok: true, value: data };
	} catch {
		return { ok: false, error: "report_unavailable" };
	}
}

export async function readExecutiveSummary(
	tenantId: string,
	days: ReportWindow,
	language: ReportLanguage,
): Promise<ReportResult<ExecutiveView>> {
	const result = await invoke({ action: "summary", tenant_id: tenantId, days, language });
	if (!result.ok) return result;
	const body = result.value;
	const executive = isRecord(body.executive) ? body.executive : {};
	const options = isRecord(body.options) ? body.options : {};
	const period = isRecord(body.period) ? body.period : {};
	if (
		!isLanguage(body.language) ||
		!Array.isArray(executive.headlines) ||
		!Array.isArray(body.sections)
	) {
		return { ok: false, error: "report_unavailable" };
	}
	return {
		ok: true,
		value: {
			period: { from: String(period.from ?? ""), to: String(period.to ?? "") },
			language: body.language,
			options: {
				language: isLanguage(options.language) ? options.language : "en",
				attachment: options.attachment !== false,
				digestEnabled: options.digestEnabled === true,
				digestCadence: options.digestCadence === "monthly" ? "monthly" : "weekly",
			},
			status: executive.status === "attention" ? "attention" : "ok",
			headlines: executive.headlines.filter(isRecord).map((line) => ({
				level: line.level === "attention" ? ("attention" as const) : ("info" as const),
				text: String(line.text ?? ""),
			})),
			sections: body.sections.filter(isRecord).map((section) => ({
				title: String(section.title ?? ""),
				lines: strings(section.lines),
			})),
		},
	};
}

function parseFigures(value: unknown): TeamRollupFigures | null {
	if (!isRecord(value)) return null;
	return {
		agentsActive: count(value.agentsActive),
		agentsEnrolled: count(value.agentsEnrolled),
		browserActive: count(value.browserActive),
		allow: count(value.allow),
		ask: count(value.ask),
		deny: count(value.deny),
		masked: count(value.masked),
		blocked: count(value.blocked),
		incidentsActive: count(value.incidentsActive),
		incidentsCritical: count(value.incidentsCritical),
		incidentsUnassigned: count(value.incidentsUnassigned),
		approvalsPending: count(value.approvalsPending),
	};
}

export async function readTeamRollup(
	tenantId: string,
	days: ReportWindow,
): Promise<ReportResult<TeamRollupRow[]>> {
	const result = await invoke({ action: "rollup", tenant_id: tenantId, days });
	if (!result.ok) return result;
	if (!Array.isArray(result.value.teams)) return { ok: false, error: "report_unavailable" };
	return {
		ok: true,
		value: result.value.teams.filter(isRecord).map((team) => ({
			tenantId: String(team.tenantId ?? ""),
			name: String(team.name ?? ""),
			role: String(team.role ?? ""),
			figures: parseFigures(team.figures),
		})),
	};
}

export async function downloadExecutiveReport(
	tenantId: string,
	days: ReportWindow,
	language: ReportLanguage,
	includeTeams: boolean,
): Promise<ReportResult<{ filename: string; html: string }>> {
	const result = await invoke({
		action: "document",
		tenant_id: tenantId,
		days,
		language,
		include_teams: includeTeams,
	});
	if (!result.ok) return result;
	const { filename, html } = result.value;
	if (
		typeof filename !== "string" ||
		!/^[A-Za-z0-9._-]{1,100}$/.test(filename) ||
		typeof html !== "string"
	) {
		return { ok: false, error: "report_unavailable" };
	}
	return { ok: true, value: { filename, html } };
}

export async function saveReportOptions(
	tenantId: string,
	language: ReportLanguage,
	attachment: boolean,
): Promise<ReportResult<{ language: ReportLanguage; attachment: boolean }>> {
	const result = await invoke({ action: "set_options", tenant_id: tenantId, language, attachment });
	if (!result.ok) return result;
	const options = isRecord(result.value.options) ? result.value.options : {};
	if (!isLanguage(options.language) || typeof options.attachment !== "boolean") {
		return { ok: false, error: "report_unavailable" };
	}
	return { ok: true, value: { language: options.language, attachment: options.attachment } };
}

const ERRORS: Readonly<Record<string, DashboardMessageKey>> = {
	mfa_required: "rpt.err.mfa",
	report_role_insufficient: "rpt.err.role",
	workspace_forbidden: "rpt.err.role",
	report_options_refused: "rpt.err.role",
	rate_limited: "rpt.err.rateLimited",
	report_invalid: "rpt.err.invalid",
};

export function reportErrorMessage(code: string, t: Translate = englishT): string {
	const key = ERRORS[code];
	return key ? t(key) : t("rpt.err.unavailable");
}
