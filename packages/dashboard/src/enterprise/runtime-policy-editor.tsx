import { useEffect, useRef, useState } from "react";
import { useT } from "../i18n/I18nProvider";
import { pendingPolicyChangeNotice } from "../lib/ai-governance";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { PolicyRollout } from "./policy-rollout";
import { useTeam } from "./team-provider";

const INITIAL_POLICY = {
	command_default: "allow",
	file_default: "allow",
	url_default: "allow",
	package_default: "allow",
	output_default: "ask",
	mcp_default: "ask",
	mcp_unknown: "ask",
	mcp_risky: "deny",
};

type ReviewedPolicyDocument = { id: string; version: number; source_sha256: string };

function isReviewedPolicyDocument(value: unknown): value is ReviewedPolicyDocument {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const source = value as Record<string, unknown>;
	return (
		typeof source.id === "string" &&
		/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(source.id) &&
		Number.isSafeInteger(source.version) &&
		Number(source.version) >= 1 &&
		typeof source.source_sha256 === "string" &&
		/^[0-9a-f]{64}$/.test(source.source_sha256)
	);
}

function sameReviewedPolicyDocument(left: unknown, right: ReviewedPolicyDocument): boolean {
	return (
		isReviewedPolicyDocument(left) &&
		left.id === right.id &&
		left.version === right.version &&
		left.source_sha256 === right.source_sha256
	);
}

async function isMissingSavedDocument(error: unknown): Promise<boolean> {
	const context = (error as { context?: unknown } | null | undefined)?.context;
	if (!(context instanceof Response) || context.status !== 404) return false;
	try {
		const body: unknown = await context.clone().json();
		return (
			body !== null &&
			typeof body === "object" &&
			!Array.isArray(body) &&
			(body as { error?: unknown }).error === "policy_document_not_found"
		);
	} catch {
		return false;
	}
}

export function RuntimePolicyEditor() {
	const { currentTeam, canManageTeam } = useTeam();
	const t = useT();
	const [text, setText] = useState(JSON.stringify(INITIAL_POLICY, null, 2));
	const [version, setVersion] = useState<number | null>(null);
	const [reviewedDocument, setReviewedDocument] = useState<ReviewedPolicyDocument | null>(null);
	const [message, setMessage] = useState("");
	const [busy, setBusy] = useState(false);
	const [refresh, setRefresh] = useState(0);
	const selectedTeamId = useRef(currentTeam?.id);
	selectedTeamId.current = currentTeam?.id;
	useEffect(() => {
		let cancelled = false;
		setVersion(null);
		setReviewedDocument(null);
		setMessage("");
		setBusy(false);
		if (!currentTeam) return;
		void supabase.functions
			.invoke("policy-management", { body: { action: "read", tenant_id: currentTeam.id } })
			.then(({ data, error }) => {
				if (cancelled) return;
				if (error || data?.ok !== true || !Number.isSafeInteger(data.version)) {
					setMessage(t("runtime.loadFailedPublishing"));
					return;
				}
				setVersion(data.version);
				setText(JSON.stringify(data.policy ?? INITIAL_POLICY, null, 2));
			})
			.catch(() => {
				if (!cancelled) setMessage(t("runtime.loadFailed"));
			});
		return () => {
			cancelled = true;
		};
	}, [currentTeam?.id, currentTeam, refresh]);

	async function publish() {
		if (!currentTeam || !canManageTeam || version === null) return;
		const requestedTeam = currentTeam.id;
		setBusy(true);
		setMessage("");
		try {
			const policy: unknown = JSON.parse(text);
			const { data, error } = await supabase.functions.invoke("policy-management", {
				body: { action: "publish", tenant_id: currentTeam.id, expected_version: version, policy },
			});
			if (selectedTeamId.current !== requestedTeam) return;
			const pendingChange = error ? null : pendingPolicyChangeNotice(data, t);
			if (pendingChange) {
				setMessage(pendingChange);
				return;
			}
			if (error || data?.ok !== true || !Number.isSafeInteger(data.version))
				throw new Error(t("runtime.publishFailedReload"));
			setVersion(data.version);
			setMessage(t("runtime.published", { version: data.version }));
		} catch (error) {
			if (selectedTeamId.current === requestedTeam)
				setMessage(readErrorMessage(error, t("runtime.publishFailed")));
		} finally {
			if (selectedTeamId.current === requestedTeam) setBusy(false);
		}
	}

	async function compileSavedDocument() {
		if (!currentTeam || !canManageTeam) return;
		const requestedTeam = currentTeam.id;
		setReviewedDocument(null);
		setBusy(true);
		setMessage("");
		try {
			const { data, error } = await supabase.functions.invoke("policy-management", {
				body: {
					action: "compile_document",
					tenant_id: currentTeam.id,
					simulation: {
						kind: "mcp",
						server: "unregistered-preview",
						tool: "call",
						inventory: "unknown",
					},
				},
			});
			if (selectedTeamId.current !== requestedTeam) return;
			if (await isMissingSavedDocument(error)) throw new Error(t("runtime.saveDraftFirst"));
			if (error || data?.ok !== true || (!data.policy && !data.runtime_policy))
				throw new Error(t("runtime.compileFailedReview"));
			if (!isReviewedPolicyDocument(data.source)) throw new Error(t("runtime.revisionUnknown"));
			setReviewedDocument({
				id: data.source.id,
				version: data.source.version,
				source_sha256: data.source.source_sha256,
			});
			setText(JSON.stringify(data.runtime_policy ?? data.policy, null, 2));
			const precedence = Array.isArray(data.semantics?.precedence)
				? data.semantics.precedence.join(" > ")
				: "deny > ask > allow";
			const simulation = data.simulation
				? t("runtime.unknownSimulation", {
						action: data.simulation.action,
						source: data.simulation.source,
					})
				: "";
			const warnings =
				Array.isArray(data.diagnostics) && data.diagnostics.length > 0
					? t("runtime.shadowed", { count: data.diagnostics.length })
					: "";
			setMessage(`${t("runtime.dryCompiled", { precedence })}${simulation}${warnings}`);
		} catch (error) {
			if (selectedTeamId.current === requestedTeam)
				setMessage(readErrorMessage(error, t("runtime.compileFailed")));
		} finally {
			if (selectedTeamId.current === requestedTeam) setBusy(false);
		}
	}

	async function publishSavedDocument() {
		if (!currentTeam || !canManageTeam || version === null || reviewedDocument === null) return;
		const requestedTeam = currentTeam.id;
		const reviewedSource = reviewedDocument;
		setBusy(true);
		setMessage("");
		try {
			const { data, error } = await supabase.functions.invoke("policy-management", {
				body: {
					action: "publish_document",
					tenant_id: currentTeam.id,
					expected_version: version,
					expected_document: reviewedSource,
				},
			});
			if (selectedTeamId.current !== requestedTeam) return;
			const pendingChange = error ? null : pendingPolicyChangeNotice(data, t);
			if (pendingChange) {
				setReviewedDocument(null);
				setMessage(pendingChange);
				return;
			}
			if (error || data?.ok !== true || (!data.policy && !data.runtime_policy))
				throw new Error(t("runtime.publishDocFailed"));
			if (!sameReviewedPolicyDocument(data.compiled_from, reviewedSource))
				throw new Error(t("runtime.changedAfterReview"));
			if (!Number.isSafeInteger(data.version)) throw new Error(t("runtime.notPublished"));
			setText(JSON.stringify(data.runtime_policy ?? data.policy, null, 2));
			setVersion(data.version);
			setReviewedDocument(null);
			setMessage(t("runtime.docPublished", { version: data.version }));
		} catch (error) {
			if (selectedTeamId.current === requestedTeam)
				setMessage(readErrorMessage(error, t("runtime.docPublishFailed")));
		} finally {
			if (selectedTeamId.current === requestedTeam) setBusy(false);
		}
	}

	if (!currentTeam) return null;
	return (
		<>
			<section className="card stack">
				<h2>{t("runtime.title")}</h2>
				<p className="muted">{t("runtime.intro")}</p>
				<p>
					{version === null
						? t("runtime.versionUnavailable")
						: version === 0
							? t("runtime.noneYet")
							: t("runtime.version", { version })}
				</p>
				<label htmlFor="runtime-policy">{t("runtime.json")}</label>
				<textarea
					id="runtime-policy"
					className="input mono"
					rows={14}
					value={text}
					onChange={(event) => setText(event.target.value)}
					disabled={!canManageTeam || busy}
				/>
				<p className="muted small">
					{t("runtime.fields", {
						actions:
							"command_default, file_default, url_default, package_default, output_default, mcp_default, mcp_unknown, mcp_risky",
						lists: "mcp_allow_servers, mcp_require_approval_servers, mcp_deny_servers",
					})}
				</p>
				<div className="row">
					<button
						type="button"
						className="btn"
						disabled={!canManageTeam || busy}
						onClick={() => void compileSavedDocument()}
					>
						{t("runtime.compile")}
					</button>
					<button
						type="button"
						className="btn"
						disabled={!canManageTeam || version === null || reviewedDocument === null || busy}
						onClick={() => void publishSavedDocument()}
					>
						{t("runtime.compilePublish")}
					</button>
					<button
						type="button"
						className="btn btn-primary"
						disabled={!canManageTeam || version === null || busy}
						onClick={() => void publish()}
					>
						{busy ? t("runtime.working") : t("runtime.publishJson")}
					</button>
				</div>
				{message && <p role="status">{message}</p>}
			</section>
			<PolicyRollout
				version={version}
				draft={text}
				onChanged={() => setRefresh((value) => value + 1)}
				onReview={(policy) => setText(JSON.stringify(policy, null, 2))}
			/>
		</>
	);
}
